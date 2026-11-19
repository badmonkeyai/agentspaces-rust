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

//! The audit's state on both sides (SPEC annex I.6, *Sessions*, *The audit*, *The fetch*), with
//! no I/O and no clock of its own: every call takes the time in epoch milliseconds.
//!
//! - [`Sessions`], the partner's half: at most [`SESSIONS_MAX`] sessions per asker, each for one
//!   stream, opened by a root answered with `nodes`, closed after [`SESSION_EXCHANGES_MAX`]
//!   exchanges (and then cooling for one round), after [`SESSION_IDLE_MILLIS`] with no
//!   exchange, when an opening shows the stream's hashes equal, or by a root answered with lines.
//!   A reopening reuses the session and counts toward its bound. Request nodes outside a session
//!   are dropped and counted.
//! - [`Asker`], the asker's half: each answer is checked against the fingerprint and count its
//!   parent gave, compared with the asker's own trie, and the children that differ are asked in
//!   the next exchange (at most 256 per stream, each path once); an answer of lines names the
//!   entries to fetch, each line looked up in the one slot it names. An opening admits one root
//!   answer per stream, and only the last [`ROOTS_OWED_MAX`] openings are owed one, so a partner
//!   cannot restart a descent. A body whose every answer is refused asks nothing and counts no
//!   exchange. A descent ends after [`SESSION_EXCHANGES_MAX`] answer bodies, as the partner's
//!   session does, so no partner holds the asker descending for as long as it likes.
//! - [`FetchQueue`], the fetch by ids: bodies of at most [`IDS_MAX`] ids under a budget, a few
//!   in flight per partner; an answer that carried a remainder continues at once with the same
//!   partner, and an id a partner did not send, or whose answer did not come, is queued again and
//!   asked of the next member in view after a jittered backoff. An id every member left out
//!   waits for an audit to name it again, so no repair is abandoned for good (SPEC §9.4).
//!
//! Every refusal and fallback is counted under one [`AuditRefusal`] key.
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::audit::{
    IDS_MAX, SESSION_EXCHANGES_MAX, SESSION_IDLE_MILLIS, SESSIONS_MAX, TREE_NODES_MAX, TreeForm,
    TreeNode, counts_sum_to,
};
use crate::trie::{
    AuditTrie, FANOUT, FINGERPRINT_BYTES, KEY_NIBBLES, LEAF_MAX, Path, child_of, entry_id_of_line,
    fingerprint,
};

/// Askers (or partners) whose sessions and descents are tracked at most; the least recent go.
pub const PARTNERS_MAX: usize = 64;
/// Fetch bodies kept in flight per partner.
pub const FETCH_WINDOW: usize = 4;
/// The shortest wait for a fetch's answer before its ids are asked of another member.
pub const FETCH_WAIT_FLOOR_MILLIS: i64 = 5_000;
/// How long a fetch's late answer is still taken: twice a session's idle time.
pub const LATE_COPY_MILLIS: i64 = 2 * SESSION_IDLE_MILLIS;
/// The backoff before an id is asked again: doubled per attempt up to the ceiling, jittered.
pub const RETRY_BASE_MILLIS: i64 = 1_000;
/// The longest backoff between two asks of one id.
pub const RETRY_CEILING_MILLIS: i64 = 30_000;
/// How long an id every member in view left out waits for an audit to name it again.
pub const PARKED_MILLIS: i64 = 600_000;
/// Ids kept wanted per stream at most; past it a new id waits for a later audit to name it.
pub const WANTED_MAX: usize = 1 << 17;
/// The fewest ids a fetch body names once a partner's answers have been cut by the budget.
pub const FETCH_IDS_FLOOR: usize = 64;
/// Openings a partner's root answers are owed for, at most: the last two, so that the answers to
/// a round and to the opening a continuation or a probe sent just after it are both read, and no
/// older opening admits a root (one root per stream per opening).
pub const ROOTS_OWED_MAX: u64 = 2;

/// The reasons a refusal or a fallback of the audit is counted under, one key each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum AuditRefusal {
    /// A `DIGEST` or `PULL_RESP` that did not decode (a stale card's frame among them).
    Undecodable,
    /// Audit fields that reached a member not on `wire.ae=2`, or came from a member whose current
    /// card no longer carries it (they draw no audit field back).
    LacksHint,
    /// A request node with no session open for its asker and stream.
    RequestWithoutSession,
    /// A root that waited, the asker's sessions at their bound.
    SessionBusy,
    /// A root that waited a round after its session hit the exchange bound.
    SessionCooling,
    /// A session closed at the exchange bound.
    SessionCapped,
    /// An answer for a path this member did not ask, or from a partner it opened nothing with.
    UnsolicitedAnswer,
    /// An answer whose preimage does not hash to the fingerprint its parent gave.
    FingerprintMismatch,
    /// An answer the trie's shape rules out: nodes at 64 nibbles, or counts that do not sum to
    /// the count its parent gave.
    ShapeMismatch,
    /// A descent the asker ended at the exchange bound.
    DescentCapped,
    /// A request body that named one path twice; each path is answered once.
    RepeatedRequest,
    /// A root answered for a stream this member keeps no trie for, answered by the text form.
    TextFallback,
}

impl AuditRefusal {
    /// The stable kebab-case key.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditRefusal::Undecodable => "undecodable",
            AuditRefusal::LacksHint => "lacks-hint",
            AuditRefusal::RequestWithoutSession => "request-without-session",
            AuditRefusal::SessionBusy => "session-busy",
            AuditRefusal::SessionCooling => "session-cooling",
            AuditRefusal::SessionCapped => "session-capped",
            AuditRefusal::UnsolicitedAnswer => "unsolicited-answer",
            AuditRefusal::FingerprintMismatch => "fingerprint-mismatch",
            AuditRefusal::ShapeMismatch => "shape-mismatch",
            AuditRefusal::DescentCapped => "descent-capped",
            AuditRefusal::RepeatedRequest => "repeated-request",
            AuditRefusal::TextFallback => "text-fallback",
        }
    }
}

impl fmt::Display for AuditRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evicts the least recently active key past [`PARTNERS_MAX`].
fn bound<V>(map: &mut HashMap<String, V>, last: impl Fn(&V) -> i64) {
    while map.len() > PARTNERS_MAX {
        let Some(eldest) = map
            .iter()
            .min_by_key(|(_, value)| last(value))
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        map.remove(&eldest);
    }
}

// ---------------------------------------------------------------------------------------------
// The partner's sessions

#[derive(Debug, Clone, Copy)]
struct Session {
    last_ms: i64,
    exchanges: u32,
}

#[derive(Debug, Default)]
struct AskerSessions {
    open: HashMap<String, Session>,
    cooling: HashSet<String>,
    rotation: usize,
    last_ms: i64,
}

/// What a partner does with an inner root it would answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootVerdict {
    /// Answer it within the session (opened or reused); `capped` when this exchange reached the
    /// bound and closed the session.
    Answer {
        /// Whether the session closed at the bound with this exchange.
        capped: bool,
    },
    /// The asker's sessions are at their bound: the stream waits for a later round.
    Busy,
    /// The stream's session closed at the exchange bound: it waits one round.
    Cooling,
}

/// The partner's sessions, per asker and stream (see the [module docs](self)).
#[derive(Debug)]
pub struct Sessions {
    max: usize,
    by_asker: HashMap<String, AskerSessions>,
    opened: u64,
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions::new(SESSIONS_MAX)
    }
}

impl Sessions {
    /// Sessions bounded at `max` per asker (1 to [`SESSIONS_MAX`], clamped).
    pub fn new(max: usize) -> Self {
        Sessions {
            max: max.clamp(1, SESSIONS_MAX),
            by_asker: HashMap::new(),
            opened: 0,
        }
    }

    /// Forgets every session idle for [`SESSION_IDLE_MILLIS`].
    pub fn expire(&mut self, now_ms: i64) {
        for asker in self.by_asker.values_mut() {
            asker
                .open
                .retain(|_, session| now_ms - session.last_ms < SESSION_IDLE_MILLIS);
        }
        self.by_asker.retain(|_, asker| {
            !asker.open.is_empty()
                || !asker.cooling.is_empty()
                || now_ms - asker.last_ms < SESSION_IDLE_MILLIS
        });
    }

    fn asker(&mut self, asker: &str, now_ms: i64) -> &mut AskerSessions {
        if !self.by_asker.contains_key(asker) {
            self.by_asker
                .insert(asker.to_owned(), AskerSessions::default());
            bound(&mut self.by_asker, |sessions| sessions.last_ms);
        }
        let sessions = self.by_asker.entry(asker.to_owned()).or_default();
        sessions.last_ms = now_ms;
        sessions
    }

    /// The index the streams that differ start from this round, moving on each round so that no
    /// stream waits for ever when the asker's sessions are at their bound.
    pub fn rotation(&mut self, asker: &str, streams: usize, now_ms: i64) -> usize {
        let sessions = self.asker(asker, now_ms);
        sessions.rotation = sessions.rotation.wrapping_add(1);
        if streams == 0 {
            0
        } else {
            sessions.rotation % streams
        }
    }

    /// Closes the session of a stream whose hashes an opening showed equal, or whose root was
    /// answered by lines.
    pub fn close(&mut self, asker: &str, stream: &str) {
        if let Some(sessions) = self.by_asker.get_mut(asker) {
            sessions.open.remove(stream);
        }
    }

    /// An inner root the partner would answer: within a session opened now or reused (each
    /// counting one exchange), or a wait when the asker's sessions are at their bound or the
    /// stream cools after a capped session.
    pub fn open_root(&mut self, asker: &str, stream: &str, now_ms: i64) -> RootVerdict {
        self.expire(now_ms);
        let max = self.max;
        let sessions = self.asker(asker, now_ms);
        if !sessions.open.contains_key(stream) {
            if sessions.cooling.remove(stream) {
                return RootVerdict::Cooling;
            }
            if sessions.open.len() >= max {
                return RootVerdict::Busy;
            }
            sessions.open.insert(
                stream.to_owned(),
                Session {
                    last_ms: now_ms,
                    exchanges: 0,
                },
            );
            self.opened += 1;
        }
        let capped = Self::exchange(self.asker(asker, now_ms), stream, now_ms);
        RootVerdict::Answer { capped }
    }

    /// A request body for a stream: `Ok(capped)` within the asker's session (the exchange
    /// counted; `capped` when it closed the session), else the refusal.
    pub fn request(
        &mut self,
        asker: &str,
        stream: &str,
        now_ms: i64,
    ) -> Result<bool, AuditRefusal> {
        self.expire(now_ms);
        let Some(sessions) = self.by_asker.get_mut(asker) else {
            return Err(AuditRefusal::RequestWithoutSession);
        };
        if !sessions.open.contains_key(stream) {
            return Err(AuditRefusal::RequestWithoutSession);
        }
        sessions.last_ms = now_ms;
        Ok(Self::exchange(sessions, stream, now_ms))
    }

    /// Counts one exchange; whether it closed the session at the bound (the stream then cools).
    fn exchange(sessions: &mut AskerSessions, stream: &str, now_ms: i64) -> bool {
        let Some(session) = sessions.open.get_mut(stream) else {
            return false;
        };
        session.last_ms = now_ms;
        session.exchanges += 1;
        if session.exchanges >= SESSION_EXCHANGES_MAX {
            sessions.open.remove(stream);
            sessions.cooling.insert(stream.to_owned());
            return true;
        }
        false
    }

    /// Sessions open now.
    pub fn open(&self) -> usize {
        self.by_asker.values().map(|asker| asker.open.len()).sum()
    }

    /// Sessions opened since this was made.
    pub fn opened(&self) -> u64 {
        self.opened
    }

    /// Whether a session is open for an asker and a stream.
    pub fn is_open(&self, asker: &str, stream: &str) -> bool {
        self.by_asker
            .get(asker)
            .is_some_and(|sessions| sessions.open.contains_key(stream))
    }
}

// ---------------------------------------------------------------------------------------------
// The asker's descents

#[derive(Debug, Default)]
struct Descent {
    /// What the answer at each asked path must hash to and count.
    expected: HashMap<Path, ([u8; FINGERPRINT_BYTES], u64)>,
    /// Paths to ask, with the asker's own count there.
    pending: VecDeque<(Path, u64)>,
    /// Paths asked in the last exchange, in order.
    in_flight: Vec<(Path, u64)>,
    last_ms: i64,
    /// Answer bodies accepted, the root's included.
    exchanges: u32,
}

#[derive(Debug, Default)]
struct PartnerDescents {
    streams: HashMap<String, Descent>,
    opened_ms: Option<i64>,
    /// The openings sent since the partner's openings were last forgotten.
    openings: u64,
    /// Per stream, the openings whose root answer was already admitted, counted from the
    /// oldest: one root per stream per opening, and only the last [`ROOTS_OWED_MAX`] openings
    /// are owed one, so a partner can neither restart a descent (and its exchange count) as often
    /// as it likes nor bank the credit of a burst of openings.
    roots: HashMap<String, u64>,
    last_ms: i64,
}

impl PartnerDescents {
    /// Takes the root answer of `stream` when an opening is owed one (Java `TrieAudit.takeRoot`).
    fn take_root(&mut self, stream: &str) -> bool {
        let taken = self
            .roots
            .get(stream)
            .copied()
            .unwrap_or(0)
            .max(self.openings.saturating_sub(ROOTS_OWED_MAX));
        if taken >= self.openings {
            return false;
        }
        self.roots.insert(stream.to_owned(), taken + 1);
        true
    }
}

/// What one stream's answers brought the asker.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DescentStep {
    /// The next request nodes for the stream, at most 256; empty when the descent is done.
    pub requests: Vec<TreeNode>,
    /// The entry ids an answer of lines named and the asker's set lacks, in the order found.
    pub ids: Vec<String>,
    /// The refusals counted on the way.
    pub refusals: Vec<AuditRefusal>,
    /// The paths whose node matched the asker's own.
    pub matched: Vec<Path>,
}

/// The asker's descents, per partner and stream (see the [module docs](self)).
#[derive(Debug, Default)]
pub struct Asker {
    partners: HashMap<String, PartnerDescents>,
}

impl Asker {
    /// No descent.
    pub fn new() -> Self {
        Asker::default()
    }

    fn partner(&mut self, partner: &str, now_ms: i64) -> &mut PartnerDescents {
        if !self.partners.contains_key(partner) {
            self.partners
                .insert(partner.to_owned(), PartnerDescents::default());
            bound(&mut self.partners, |descents| descents.last_ms);
        }
        let descents = self.partners.entry(partner.to_owned()).or_default();
        descents.last_ms = now_ms;
        descents
    }

    /// Forgets descents untouched for a session's idle time, and openings as old.
    pub fn expire(&mut self, now_ms: i64) {
        for descents in self.partners.values_mut() {
            descents
                .streams
                .retain(|_, descent| now_ms - descent.last_ms < SESSION_IDLE_MILLIS);
            if descents
                .opened_ms
                .is_some_and(|at| now_ms - at >= SESSION_IDLE_MILLIS)
            {
                descents.opened_ms = None;
                descents.openings = 0;
                descents.roots.clear();
            }
        }
        self.partners
            .retain(|_, descents| !descents.streams.is_empty() || descents.opened_ms.is_some());
    }

    /// Notes that this member opened a round with a partner, so its root answers are expected:
    /// one per stream for this opening, of the last [`ROOTS_OWED_MAX`] openings.
    pub fn opening(&mut self, partner: &str, now_ms: i64) {
        let descents = self.partner(partner, now_ms);
        descents.opened_ms = Some(now_ms);
        descents.openings = descents.openings.saturating_add(1);
    }

    /// Whether a round this member opened with a partner is still awaited.
    pub fn opened(&self, partner: &str, now_ms: i64) -> bool {
        self.partners
            .get(partner)
            .and_then(|descents| descents.opened_ms)
            .is_some_and(|at| now_ms - at < SESSION_IDLE_MILLIS)
    }

    /// Whether a descent of a stream with a partner is under way.
    pub fn descending(&self, partner: &str, stream: &str) -> bool {
        self.partners
            .get(partner)
            .is_some_and(|descents| descents.streams.contains_key(stream))
    }

    /// Takes one stream's answer nodes from a partner: checks each against what its parent gave,
    /// compares it with `trie`, and returns the next requests and the ids to fetch.
    pub fn on_answers(
        &mut self,
        partner: &str,
        stream: &str,
        answers: &[TreeNode],
        trie: &mut AuditTrie,
        now_ms: i64,
    ) -> DescentStep {
        self.expire(now_ms);
        let mut step = DescentStep::default();
        let opened = self.opened(partner, now_ms);
        let descents = self.partner(partner, now_ms);
        let mut accepted: Vec<(Path, &TreeNode)> = Vec::new();
        let mut exchanged = false;
        for answer in answers {
            let Some(path) = answer.trie_path() else {
                step.refusals.push(AuditRefusal::ShapeMismatch);
                continue;
            };
            if answer.is_request() {
                continue;
            }
            if path.is_empty() {
                // One root per stream per opening, of the last two: a replayed root would start
                // the descent afresh, its exchange count with it, for as long as the opening
                // lives.
                if !opened || !descents.take_root(stream) {
                    step.refusals.push(AuditRefusal::UnsolicitedAnswer);
                    continue;
                }
                // A root answer starts the stream's descent afresh: the partner's set may have
                // moved since the last round, so nothing asked before is kept.
                descents
                    .streams
                    .insert(stream.to_owned(), Descent::default());
                exchanged = true;
            } else {
                let Some(descent) = descents.streams.get_mut(stream) else {
                    step.refusals.push(AuditRefusal::UnsolicitedAnswer);
                    continue;
                };
                let asked = descent.in_flight.iter().any(|(at, _)| *at == path);
                let Some(&(expected_fp, expected_count)) =
                    descent.expected.get(&path).filter(|_| asked)
                else {
                    step.refusals.push(AuditRefusal::UnsolicitedAnswer);
                    continue;
                };
                exchanged = true;
                descent.expected.remove(&path);
                descent.in_flight.retain(|(at, _)| *at != path);
                let is_nodes = matches!(answer.form, TreeForm::Nodes(_));
                if (is_nodes || expected_count <= LEAF_MAX)
                    && fingerprint(answer.preimage()) != expected_fp
                {
                    step.refusals.push(AuditRefusal::FingerprintMismatch);
                    continue;
                }
                if is_nodes && !counts_sum_to(answer.preimage(), expected_count) {
                    step.refusals.push(AuditRefusal::ShapeMismatch);
                    continue;
                }
            }
            if matches!(answer.form, TreeForm::Nodes(_)) && path.len() >= KEY_NIBBLES {
                step.refusals.push(AuditRefusal::ShapeMismatch);
                continue;
            }
            accepted.push((path, answer));
        }
        if !exchanged {
            // Nothing here answered a request in flight or an opening: no exchange happened, so
            // nothing is asked again for it (a stray body would otherwise draw the requests in
            // flight again, uncounted, as often as it came).
            return step;
        }
        let Some(descent) = descents.streams.get_mut(stream) else {
            return step;
        };
        descent.last_ms = now_ms;
        descent.exchanges += 1;
        // Compare with this member's own trie.
        let mut differs: Vec<(Path, [u8; FINGERPRINT_BYTES], u64, u64)> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        for (path, answer) in accepted {
            match &answer.form {
                TreeForm::Nodes(nodes) => {
                    for c in 0..FANOUT {
                        let Some((theirs, count)) = child_of(nodes, c) else {
                            continue;
                        };
                        if count == 0 {
                            continue; // entries the partner lacks: its own round brings them
                        }
                        let Some(child) = path.child(c as u8) else {
                            continue;
                        };
                        let (own_count, own_fp) = trie.fingerprint_at(&child);
                        if own_count == count && own_fp == Some(theirs) {
                            step.matched.push(child);
                        } else {
                            differs.push((child, theirs, count, own_count));
                        }
                    }
                }
                TreeForm::Lines(lines) if !lines.is_empty() => {
                    // Each line is looked up in the one slot it names, never against every own
                    // line under the path, so the comparison costs what the answer holds.
                    for line in lines.split('\n') {
                        if !trie.holds_line_under(line, &path)
                            && let Some(id) = entry_id_of_line(line)
                            && seen_ids.insert(id.to_owned())
                        {
                            step.ids.push(id.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
        // Queue what differs, bounded by what the descent's remaining exchanges can carry.
        let room = (SESSION_EXCHANGES_MAX.saturating_sub(descent.exchanges) as usize)
            .saturating_mul(TREE_NODES_MAX);
        let mut dropped = false;
        for (child, fp, count, own) in differs {
            if descent.pending.len() >= room {
                dropped = true;
                break;
            }
            descent.expected.insert(child, (fp, count));
            descent.pending.push_back((child, own));
        }
        // A request the last exchange left unanswered was left out for the budget: asked first.
        let left: Vec<(Path, u64)> = std::mem::take(&mut descent.in_flight);
        for (path, own) in left.into_iter().rev() {
            if descent.expected.contains_key(&path) {
                descent.pending.push_front((path, own));
            }
        }
        if descent.exchanges >= SESSION_EXCHANGES_MAX {
            if dropped || !descent.pending.is_empty() {
                step.refusals.push(AuditRefusal::DescentCapped);
            }
            descent.pending.clear();
        }
        while step.requests.len() < TREE_NODES_MAX {
            let Some((path, own)) = descent.pending.pop_front() else {
                break;
            };
            if descent.in_flight.iter().any(|(at, _)| *at == path)
                || !descent.expected.contains_key(&path)
            {
                continue;
            }
            descent.in_flight.push((path, own));
            step.requests.push(TreeNode::request(&path, own));
        }
        if descent.pending.is_empty() && descent.in_flight.is_empty() {
            descents.streams.remove(stream);
        }
        step
    }
}

// ---------------------------------------------------------------------------------------------
// The fetch queue

/// One fetch body: the ids of one stream asked of one partner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchBatch {
    /// The body's own number, unique in its queue.
    pub id: u64,
    /// The partner asked.
    pub partner: String,
    /// The stream.
    pub stream: String,
    /// The entry ids, at most [`IDS_MAX`], each once.
    pub ids: Vec<String>,
    /// When it went.
    pub sent_ms: i64,
    late: bool,
}

#[derive(Debug, Default)]
struct Wanted {
    /// The member it is ready for or in flight at; `None` while it waits to be asked again.
    at: Option<String>,
    /// The body it is in flight in.
    batch: Option<u64>,
    /// The members that left it out since an audit last named it.
    asked: HashSet<String>,
    attempts: u32,
    due_ms: i64,
    parked_ms: Option<i64>,
}

/// The fetch queue's counters, which only grow.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FetchCounters {
    /// Ids asked for, each ask counted.
    pub requested: u64,
    /// Ids a budgeted answer left out and that went to the same partner at once.
    pub continued: u64,
    /// Ids a partner neither sent nor counted as left out, queued for another member.
    pub requeued: u64,
    /// Bodies whose answer did not come within the wait.
    pub timed_out: u64,
    /// Ids every member in view left out, left for an audit to name again.
    pub parked: u64,
    /// Ids the queue's bound turned away.
    pub queue_full: u64,
}

/// The asker's fetch by ids (see the [module docs](self)).
#[derive(Debug)]
pub struct FetchQueue {
    wanted: HashMap<String, HashMap<String, Wanted>>,
    ready: HashMap<String, Vec<(String, VecDeque<String>)>>,
    in_flight: HashMap<String, Vec<FetchBatch>>,
    late: HashMap<String, Vec<FetchBatch>>,
    answer_ms: HashMap<String, i64>,
    answer_yield: HashMap<String, usize>,
    next_batch: u64,
    window: usize,
    wait_floor_ms: i64,
    rng: u64,
    counters: FetchCounters,
}

impl FetchQueue {
    /// An empty queue; `seed` drives the backoff's jitter.
    pub fn new(seed: u64) -> Self {
        FetchQueue {
            wanted: HashMap::new(),
            ready: HashMap::new(),
            in_flight: HashMap::new(),
            late: HashMap::new(),
            answer_ms: HashMap::new(),
            answer_yield: HashMap::new(),
            next_batch: 0,
            window: FETCH_WINDOW,
            wait_floor_ms: FETCH_WAIT_FLOOR_MILLIS,
            rng: seed | 1,
            counters: FetchCounters::default(),
        }
    }

    /// Sets the shortest wait for an answer (1 s to [`LATE_COPY_MILLIS`], clamped).
    pub fn set_wait_floor(&mut self, millis: i64) {
        self.wait_floor_ms = millis.clamp(1_000, LATE_COPY_MILLIS);
    }

    /// The counters.
    pub fn counters(&self) -> FetchCounters {
        self.counters
    }

    /// Ids wanted now, in flight or waiting.
    pub fn queued(&self) -> usize {
        self.wanted.values().map(HashMap::len).sum()
    }

    /// Whether an id of a stream is wanted.
    pub fn wants(&self, stream: &str, entry_id: &str) -> bool {
        self.wanted
            .get(stream)
            .is_some_and(|by_id| by_id.contains_key(entry_id))
    }

    fn jitter(&mut self) -> f64 {
        // xorshift64
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Queues the ids an audit with `partner` found and returns the bodies the window lets go now.
    /// An id ready for or in flight at a member stays there; one waiting to be asked again goes to
    /// this partner and forgets who left it out, since the audit is new evidence.
    pub fn want(
        &mut self,
        partner: &str,
        stream: &str,
        ids: &[String],
        now_ms: i64,
    ) -> Vec<FetchBatch> {
        let by_id = self.wanted.entry(stream.to_owned()).or_default();
        let mut queued = Vec::new();
        for id in ids {
            match by_id.get_mut(id) {
                Some(wanted) if wanted.at.is_some() => continue,
                Some(wanted) => {
                    wanted.at = Some(partner.to_owned());
                    wanted.parked_ms = None;
                    wanted.asked.clear();
                }
                None => {
                    if by_id.len() >= WANTED_MAX {
                        self.counters.queue_full += 1;
                        continue;
                    }
                    by_id.insert(
                        id.clone(),
                        Wanted {
                            at: Some(partner.to_owned()),
                            ..Wanted::default()
                        },
                    );
                }
            }
            queued.push(id.clone());
        }
        if !queued.is_empty() {
            let queues = self.ready.entry(partner.to_owned()).or_default();
            match queues.iter_mut().find(|(name, _)| name == stream) {
                Some((_, queue)) => queue.extend(queued),
                None => queues.push((stream.to_owned(), queued.into())),
            }
        }
        self.pump(partner, now_ms)
    }

    /// The bodies the window lets go to a partner now, registered in flight.
    fn pump(&mut self, partner: &str, now_ms: i64) -> Vec<FetchBatch> {
        let per_body = self
            .answer_yield
            .get(partner)
            .map_or(IDS_MAX, |taken| (2 * taken).clamp(FETCH_IDS_FLOOR, IDS_MAX));
        let mut out = Vec::new();
        let flying = self.in_flight.get(partner).map_or(0, Vec::len);
        let mut room = self.window.saturating_sub(flying);
        let Some(queues) = self.ready.get_mut(partner) else {
            return out;
        };
        while room > 0 && !queues.is_empty() {
            let (stream, queue) = &mut queues[0];
            let take = queue.len().min(per_body);
            let ids: Vec<String> = queue.drain(..take).collect();
            let stream = stream.clone();
            if queue.is_empty() {
                queues.remove(0);
            }
            if ids.is_empty() {
                continue;
            }
            let batch = FetchBatch {
                id: self.next_batch,
                partner: partner.to_owned(),
                stream: stream.clone(),
                ids,
                sent_ms: now_ms,
                late: false,
            };
            self.next_batch += 1;
            if let Some(by_id) = self.wanted.get_mut(&stream) {
                for id in &batch.ids {
                    if let Some(wanted) = by_id.get_mut(id) {
                        wanted.batch = Some(batch.id);
                    }
                }
            }
            self.counters.requested += batch.ids.len() as u64;
            out.push(batch);
            room -= 1;
        }
        if queues.is_empty() {
            self.ready.remove(partner);
        }
        if !out.is_empty() {
            self.in_flight
                .entry(partner.to_owned())
                .or_default()
                .extend(out.iter().cloned());
        }
        out
    }

    /// The stream of a fetch an answer from `partner` naming `streams` belongs to: a body in
    /// flight there (or a late one whose copy is still taken). `None` for an answer that names
    /// no such stream, which is then no fetch's answer.
    pub fn answer_for(&mut self, partner: &str, streams: &[&str], now_ms: i64) -> Option<String> {
        self.expire_fetches(now_ms);
        [&self.in_flight, &self.late].iter().find_map(|by_partner| {
            by_partner.get(partner)?.iter().find_map(|batch| {
                streams
                    .contains(&batch.stream.as_str())
                    .then(|| batch.stream.clone())
            })
        })
    }

    /// Takes the body an answer settles: of the bodies in flight at the partner for the stream,
    /// the one whose ids the answer carried most of (the eldest on a tie), else a late one.
    pub fn settle(
        &mut self,
        partner: &str,
        stream: &str,
        received: &HashSet<String>,
        now_ms: i64,
    ) -> Option<FetchBatch> {
        if let Some(batch) = take_best(&mut self.in_flight, partner, stream, received) {
            self.answer_ms
                .insert(partner.to_owned(), now_ms - batch.sent_ms);
            bound(&mut self.answer_ms, |&ms| ms);
            return Some(batch);
        }
        take_best(&mut self.late, partner, stream, received)
    }

    /// What a fetch's answer brought: the ids it carried are no longer wanted; the ids of the body
    /// it left out go again to the same partner at once when the answer carried a remainder and
    /// made progress, and otherwise wait a jittered backoff for the next member in view. The
    /// bodies the window lets go next.
    pub fn fetched(
        &mut self,
        partner: &str,
        batch: &FetchBatch,
        received: &HashSet<String>,
        left: i64,
        now_ms: i64,
    ) -> Vec<FetchBatch> {
        let late = batch.late;
        let names: HashSet<&str> = batch.ids.iter().map(String::as_str).collect();
        let mut progress = 0usize;
        let mut missing = Vec::new();
        if let Some(by_id) = self.wanted.get_mut(&batch.stream) {
            for id in received {
                let Some(wanted) = by_id.get(id) else {
                    continue;
                };
                let ours = names.contains(id.as_str());
                if ours {
                    progress += 1;
                }
                if wanted.at.is_none() || (wanted.batch == Some(batch.id) && ours) {
                    by_id.remove(id);
                }
            }
            for id in &batch.ids {
                if by_id
                    .get(id)
                    .is_some_and(|wanted| wanted.batch == Some(batch.id))
                {
                    missing.push(id.clone());
                }
            }
        }
        if !late && left > 0 && progress > 0 {
            self.answer_yield.insert(partner.to_owned(), progress);
            bound(&mut self.answer_yield, |_| 0);
        }
        if !missing.is_empty() {
            if left > 0 && progress > 0 {
                // The continuation: the partner holds them and ran out of budget.
                if let Some(by_id) = self.wanted.get_mut(&batch.stream) {
                    for id in &missing {
                        if let Some(wanted) = by_id.get_mut(id) {
                            wanted.batch = None;
                            wanted.at = Some(partner.to_owned());
                        }
                    }
                }
                self.counters.continued += missing.len() as u64;
                let queues = self.ready.entry(partner.to_owned()).or_default();
                let mut front: VecDeque<String> = missing.into();
                if let Some(index) = queues.iter().position(|(name, _)| *name == batch.stream) {
                    let (_, rest) = queues.remove(index);
                    front.extend(rest);
                }
                queues.insert(0, (batch.stream.clone(), front));
            } else {
                for id in missing {
                    self.requeue(&batch.stream, &id, partner, now_ms);
                }
            }
        }
        if self
            .wanted
            .get(&batch.stream)
            .is_some_and(HashMap::is_empty)
        {
            self.wanted.remove(&batch.stream);
        }
        if late {
            Vec::new()
        } else {
            self.pump(partner, now_ms)
        }
    }

    fn requeue(&mut self, stream: &str, id: &str, left_out_by: &str, now_ms: i64) {
        let jitter = self.jitter();
        let Some(wanted) = self
            .wanted
            .get_mut(stream)
            .and_then(|by_id| by_id.get_mut(id))
        else {
            return;
        };
        wanted.batch = None;
        wanted.at = None;
        wanted.asked.insert(left_out_by.to_owned());
        wanted.attempts += 1;
        let base = RETRY_CEILING_MILLIS.min(RETRY_BASE_MILLIS << (wanted.attempts - 1).min(5));
        wanted.due_ms = now_ms + base / 2 + (jitter * base as f64) as i64;
        self.counters.requeued += 1;
    }

    fn wait_for(&self, partner: &str) -> i64 {
        let wait = self
            .answer_ms
            .get(partner)
            .map_or(self.wait_floor_ms, |last| 4 * last);
        wait.clamp(self.wait_floor_ms, LATE_COPY_MILLIS)
    }

    /// Moves every body whose wait passed from in flight to late, queueing its ids again, and
    /// forgets late bodies past [`LATE_COPY_MILLIS`].
    fn expire_fetches(&mut self, now_ms: i64) {
        let partners: Vec<String> = self.in_flight.keys().cloned().collect();
        for partner in partners {
            let wait = self.wait_for(&partner);
            let Some(batches) = self.in_flight.get_mut(&partner) else {
                continue;
            };
            let (overdue, keep): (Vec<FetchBatch>, Vec<FetchBatch>) = std::mem::take(batches)
                .into_iter()
                .partition(|batch| now_ms - batch.sent_ms >= wait);
            *batches = keep;
            if batches.is_empty() {
                self.in_flight.remove(&partner);
            }
            for mut batch in overdue {
                batch.late = true;
                self.counters.timed_out += 1;
                for id in &batch.ids {
                    let ours = self
                        .wanted
                        .get(&batch.stream)
                        .and_then(|by_id| by_id.get(id))
                        .is_some_and(|wanted| wanted.batch == Some(batch.id));
                    if ours {
                        self.requeue(&batch.stream, id, &partner, now_ms);
                    }
                }
                self.late.entry(partner.clone()).or_default().push(batch);
            }
        }
        for batches in self.late.values_mut() {
            batches.retain(|batch| now_ms - batch.sent_ms <= LATE_COPY_MILLIS);
        }
        self.late.retain(|_, batches| !batches.is_empty());
    }

    /// The queue's turn on a round: bodies whose answer did not come are asked of another member,
    /// ids whose backoff passed go to the next member of `view` (the members that audit with this
    /// one) that has not left them out, an id every such member left out is parked until an
    /// audit names it again, and what was ready for a member that left the view comes back.
    pub fn retry(&mut self, view: &[String], now_ms: i64) -> Vec<FetchBatch> {
        self.expire_fetches(now_ms);
        let mut members: Vec<String> = view.to_vec();
        if !members.is_empty() {
            let turn = (self.jitter() * members.len() as f64) as usize % members.len();
            members.rotate_left(turn);
        }
        let in_view: HashSet<&str> = members.iter().map(String::as_str).collect();
        let gone: Vec<String> = self
            .ready
            .keys()
            .filter(|partner| !in_view.contains(partner.as_str()))
            .cloned()
            .collect();
        for partner in gone {
            for (stream, queue) in self.ready.remove(&partner).unwrap_or_default() {
                let Some(by_id) = self.wanted.get_mut(&stream) else {
                    continue;
                };
                for id in queue {
                    if let Some(wanted) = by_id.get_mut(&id)
                        && wanted.batch.is_none()
                    {
                        wanted.at = None;
                        wanted.due_ms = now_ms;
                    }
                }
            }
        }
        let mut touched: Vec<String> = Vec::new();
        let mut assign: Vec<(String, String, String)> = Vec::new();
        for (stream, by_id) in &mut self.wanted {
            by_id.retain(|_, wanted| {
                !(wanted.at.is_none()
                    && wanted
                        .parked_ms
                        .is_some_and(|at| now_ms - at >= PARKED_MILLIS))
            });
            for (id, wanted) in by_id.iter_mut() {
                if wanted.at.is_some() || wanted.parked_ms.is_some() || wanted.due_ms > now_ms {
                    continue;
                }
                match members
                    .iter()
                    .find(|member| !wanted.asked.contains(*member))
                {
                    None => {
                        wanted.parked_ms = Some(now_ms);
                        wanted.asked.clear();
                        self.counters.parked += 1;
                    }
                    Some(next) => {
                        wanted.at = Some(next.clone());
                        assign.push((next.clone(), stream.clone(), id.clone()));
                    }
                }
            }
        }
        self.wanted.retain(|_, by_id| !by_id.is_empty());
        for (partner, stream, id) in assign {
            let queues = self.ready.entry(partner.clone()).or_default();
            match queues.iter_mut().find(|(name, _)| *name == stream) {
                Some((_, queue)) => queue.push_back(id),
                None => queues.push((stream, VecDeque::from([id]))),
            }
            if !touched.contains(&partner) {
                touched.push(partner);
            }
        }
        for partner in self.ready.keys() {
            if !touched.contains(partner) {
                touched.push(partner.clone());
            }
        }
        let mut out = Vec::new();
        for partner in touched {
            out.extend(self.pump(&partner, now_ms));
        }
        out
    }

    /// Forgets what is in flight at or ready for a partner that left: its ids wait to be asked of
    /// another member on the next [`FetchQueue::retry`].
    pub fn forget_partner(&mut self, partner: &str, now_ms: i64) {
        let batches = self.in_flight.remove(partner).unwrap_or_default();
        for batch in batches {
            for id in &batch.ids {
                let ours = self
                    .wanted
                    .get(&batch.stream)
                    .and_then(|by_id| by_id.get(id))
                    .is_some_and(|wanted| wanted.batch == Some(batch.id));
                if ours {
                    self.requeue(&batch.stream, id, partner, now_ms);
                }
            }
        }
        self.late.remove(partner);
    }
}

fn take_best(
    by_partner: &mut HashMap<String, Vec<FetchBatch>>,
    partner: &str,
    stream: &str,
    received: &HashSet<String>,
) -> Option<FetchBatch> {
    let batches = by_partner.get_mut(partner)?;
    let mut best: Option<(usize, usize)> = None;
    for (index, batch) in batches.iter().enumerate() {
        if batch.stream != stream {
            continue;
        }
        let shared = batch.ids.iter().filter(|id| received.contains(*id)).count();
        if best.is_none_or(|(_, most)| shared > most) {
            best = Some((index, shared));
        }
    }
    let (index, _) = best?;
    let batch = batches.remove(index);
    if batches.is_empty() {
        by_partner.remove(partner);
    }
    Some(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::answer_root;

    fn trie(ids: impl Iterator<Item = String>, hash: &str) -> AuditTrie {
        let mut trie = AuditTrie::new();
        for id in ids {
            let line = format!("e:{id}={hash}");
            trie.put(&id, vec![line]);
        }
        trie
    }

    #[test]
    fn sessions_open_bound_cool_and_idle() {
        let mut sessions = Sessions::new(4);
        for stream in ["s1", "s2", "s3", "s4"] {
            assert_eq!(
                sessions.open_root("a", stream, 0),
                RootVerdict::Answer { capped: false }
            );
        }
        assert_eq!(sessions.open_root("a", "s5", 0), RootVerdict::Busy);
        assert_eq!(
            sessions.open_root("b", "s5", 0),
            RootVerdict::Answer { capped: false }
        );
        // A reopening counts toward the bound; 64 exchanges close it and it cools one round.
        for _ in 1..63 {
            assert_eq!(sessions.request("a", "s1", 1), Ok(false));
        }
        assert_eq!(sessions.request("a", "s1", 1), Ok(true));
        assert_eq!(
            sessions.request("a", "s1", 1),
            Err(AuditRefusal::RequestWithoutSession)
        );
        assert_eq!(sessions.open_root("a", "s1", 2), RootVerdict::Cooling);
        assert_eq!(
            sessions.open_root("a", "s1", 3),
            RootVerdict::Answer { capped: false }
        );
        // Idle for 30 s closes it.
        assert!(sessions.is_open("a", "s2"));
        sessions.expire(30_001);
        assert!(!sessions.is_open("a", "s2"));
        assert_eq!(
            sessions.request("z", "s1", 0),
            Err(AuditRefusal::RequestWithoutSession)
        );
    }

    #[test]
    fn a_descent_finds_the_one_entry_that_differs() {
        let mut partner = trie((0..300).map(|i| format!("entry-{i}")), "1");
        let mut asker = trie((0..300).map(|i| format!("entry-{i}")), "1");
        asker.put("entry-7", vec!["e:entry-7=2".into()]);
        let mut descents = Asker::new();
        descents.opening("p", 0);
        let root = answer_root(&mut partner);
        let mut step = descents.on_answers("p", "space:x", &[root], &mut asker, 0);
        let mut ids = Vec::new();
        let mut rounds = 0;
        while !step.requests.is_empty() {
            rounds += 1;
            ids.extend(step.ids.clone());
            let (answers, _) =
                crate::audit::answer_requests(&mut partner, "space:x", &step.requests, None);
            step = descents.on_answers("p", "space:x", &answers, &mut asker, 0);
        }
        ids.extend(step.ids);
        assert_eq!(ids, vec!["entry-7"]);
        assert!(rounds >= 1);
        assert!(!descents.descending("p", "space:x"));
        // An answer nobody asked for is refused.
        let stray = TreeNode::lines(&Path::from_nibbles(&[1]).unwrap(), String::new());
        let step = descents.on_answers("p", "space:x", &[stray], &mut asker, 0);
        assert_eq!(step.refusals, vec![AuditRefusal::UnsolicitedAnswer]);
        let root = answer_root(&mut partner);
        let step = descents.on_answers("q", "space:x", &[root], &mut asker, 0);
        assert_eq!(step.refusals, vec![AuditRefusal::UnsolicitedAnswer]);
    }

    /// A hostile partner whose answers stay consistent (each preimage hashes to what its parent
    /// listed) but run 64 inner nodes deep along one path: the asker ends its descent at 64
    /// answer bodies, as the partner's session would, and counts `descent-capped`.
    #[test]
    fn a_descent_is_bounded_at_64_bodies() {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let mut below = b"e:x=1".to_vec();
        for _ in 0..64 {
            let mut nodes = vec![0u8; crate::trie::INNER_PREIMAGE_BYTES];
            nodes[..16].copy_from_slice(&fingerprint(&below));
            nodes[16..24].copy_from_slice(&33u64.to_be_bytes());
            chain.push(nodes.clone());
            below = nodes;
        }
        chain.reverse(); // chain[d] is the node at depth d
        let mut asker = Asker::new();
        let mut own = AuditTrie::new();
        asker.opening("p", 0);
        let mut step = asker.on_answers(
            "p",
            "s",
            &[TreeNode::inner(&Path::ROOT, chain[0].clone())],
            &mut own,
            0,
        );
        let mut bodies = 1;
        let mut path = Path::ROOT;
        while !step.requests.is_empty() {
            path = path.child(0).unwrap();
            let answer = TreeNode::inner(&path, chain[path.len()].clone());
            step = asker.on_answers("p", "s", &[answer], &mut own, 0);
            bodies += 1;
            assert!(bodies <= 64, "the descent ran past its bound");
        }
        assert_eq!(bodies, 64);
        assert_eq!(step.refusals, vec![AuditRefusal::DescentCapped]);
    }

    /// Comparing a partner's lines with this member's own set reads one slot per line the
    /// partner sent, never every own line under the path: a small partner's root answered by
    /// lines costs a member of thousands of entries what the answer holds, not what it holds.
    #[test]
    fn comparing_a_partners_lines_reads_one_slot_each() {
        let mut own = trie((0..5_000).map(|i| format!("entry-{i}")), "1");
        own.stream_hash();
        let mut lines: Vec<String> = (0..10).map(|i| format!("e:theirs-{i}=1")).collect();
        lines.push("e:entry-7=1".to_owned()); // held as it is: nothing to fetch
        lines.push("e:entry-8=2".to_owned()); // held otherwise: fetched
        lines.sort();
        let root = TreeNode::lines(&Path::ROOT, lines.join("\n"));
        let mut descents = Asker::new();
        descents.opening("p", 0);
        own.take_walked();
        let step = descents.on_answers("p", "space:x", &[root], &mut own, 0);
        assert_eq!(own.take_walked(), 0, "the comparison walked the own set");
        let mut ids = step.ids.clone();
        ids.sort();
        let mut want: Vec<String> = (0..10).map(|i| format!("theirs-{i}")).collect();
        want.push("entry-8".to_owned());
        want.sort();
        assert_eq!(ids, want);
        assert!(step.refusals.is_empty(), "{:?}", step.refusals);
    }

    /// An answer of `nodes` at 64 nibbles, where every node is a leaf, is refused as a shape the
    /// trie rules out, never followed.
    #[test]
    fn an_inner_answer_at_depth_64_is_refused() {
        let deep = Path::from_nibbles(&[0; 64]).unwrap();
        let mut nodes = vec![0u8; crate::trie::INNER_PREIMAGE_BYTES];
        nodes[16..24].copy_from_slice(&40u64.to_be_bytes());
        nodes[..16].copy_from_slice(&[7u8; 16]);
        let mut asker = Asker::new();
        let descents = asker.partner("p", 0);
        let mut descent = Descent::default();
        descent.expected.insert(deep, (fingerprint(&nodes), 40));
        descent.in_flight.push((deep, 0));
        descents.streams.insert("s".to_owned(), descent);
        let step = asker.on_answers(
            "p",
            "s",
            &[TreeNode::inner(&deep, nodes)],
            &mut AuditTrie::new(),
            0,
        );
        assert_eq!(step.refusals, vec![AuditRefusal::ShapeMismatch]);
        assert!(step.requests.is_empty());
    }

    /// A body naming one path twice is answered once for it, and counted.
    #[test]
    fn each_path_is_answered_once_per_body() {
        let mut partner = trie((0..100).map(|i| format!("e{i}")), "1");
        let path = Path::from_nibbles(&[3]).unwrap();
        let requests = vec![TreeNode::request(&path, 0); 200];
        let (answers, repeated) = crate::audit::answer_requests(&mut partner, "s", &requests, None);
        assert_eq!(answers.len(), 1);
        assert!(repeated);
    }

    /// An opening's hash is compared in both kinds: the trie stream hash and the text digest's.
    #[test]
    fn hashes_are_compared_in_both_kinds() {
        use crate::audit::same_stream;
        let trie_hash = [1u8; 32];
        let text_hash = [2u8; 32];
        assert!(same_stream(Some(&trie_hash), Some(&text_hash), &trie_hash));
        assert!(same_stream(Some(&trie_hash), Some(&text_hash), &text_hash));
        assert!(same_stream(None, Some(&text_hash), &text_hash));
        assert!(!same_stream(Some(&trie_hash), Some(&text_hash), &[3u8; 32]));
        assert!(!same_stream(None, None, &trie_hash));
    }

    #[test]
    fn a_fetch_continues_requeues_and_parks() {
        let mut queue = FetchQueue::new(7);
        let ids: Vec<String> = (0..10).map(|i| format!("e{i}")).collect();
        let sent = queue.want("p", "space:x", &ids, 0);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ids.len(), 10);
        assert_eq!(
            queue.answer_for("p", &["space:x"], 1),
            Some("space:x".to_owned())
        );
        // Six arrived, four left out for the budget: they go to p again at once.
        let received: HashSet<String> = ids[..6].iter().cloned().collect();
        let batch = queue.settle("p", "space:x", &received, 1).unwrap();
        let next = queue.fetched("p", &batch, &received, 4, 1);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].ids, ids[6..].to_vec());
        assert_eq!(queue.counters().continued, 4);
        // p sends nothing more and counts nothing left: they wait for another member.
        let none = HashSet::new();
        let batch = queue.settle("p", "space:x", &none, 2).unwrap();
        assert!(queue.fetched("p", &batch, &none, 0, 2).is_empty());
        assert_eq!(queue.counters().requeued, 4);
        assert!(
            queue.retry(&["p".into(), "q".into()], 2).is_empty(),
            "backoff first"
        );
        let later = queue.retry(&["p".into(), "q".into()], 60_000);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].partner, "q");
        // q has none either: with every member asked they park, and are kept for an audit.
        let batch = queue.settle("q", "space:x", &none, 60_001).unwrap();
        queue.fetched("q", &batch, &none, 0, 60_001);
        assert!(queue.retry(&["p".into(), "q".into()], 200_000).is_empty());
        assert_eq!(queue.counters().parked, 4);
        assert_eq!(queue.queued(), 4);
        // An audit naming them again sends them at once.
        let again = queue.want("p", "space:x", &ids[6..], 200_001);
        assert_eq!(again.len(), 1);
        // A body whose answer never comes is asked elsewhere after the wait.
        let lost = queue.retry(&["q".into()], 200_001 + FETCH_WAIT_FLOOR_MILLIS);
        assert!(lost.is_empty(), "backoff after the timeout");
        assert_eq!(queue.counters().timed_out, 1);
        let resent = queue.retry(&["q".into()], 400_000);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].partner, "q");
    }
}
