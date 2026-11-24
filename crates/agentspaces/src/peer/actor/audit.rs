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

//! The trie audit of SPEC annex I.6 (v0.1.35, `wire.ae=2`) on the actor: both halves of the
//! descent, the fetch by ids, and the budgeted answers.
//!
//! # The form per partner
//!
//! This peer advertises `wire.ae=2` in its resource hints unless
//! [`PeerConfig::audit`](crate::peer::PeerConfig::audit) turns it off. Before each round it reads
//! the partner's *current* card: toward a member whose card carries the hint it opens with
//! `hashes` (each space stream's trie stream hash, every other stream's text digest hash) and
//! repairs a space by the audit; toward any other member it sends today's full digests, and no
//! field of annex I.6 ever goes to it. A `PULL_RESP` carries `remainder` only in answer to a body
//! that carried `budget`.
//!
//! # As the partner (a listening peer)
//!
//! An opening's streams are compared in both kinds of hash, so a stale view of the asker's card
//! never makes two equal streams differ. A space stream that differs toward an auditing asker is
//! answered with its root (`nodes` within a session, at most four per asker, or `lines`); any
//! other stream that differs is named in `want`. Request nodes are answered only within a
//! session, each path once per body, under the body's budget; `ids` and a budgeted `digests` draw
//! one `PULL_RESP` filled in the order of *The fetch*, its first item always carried, with
//! `remainder`.
//!
//! # As the asker
//!
//! Each answer is checked against its parent's fingerprint and count, the children that differ are
//! asked in the next exchange, and the entries an answer of lines names go to the fetch queue,
//! which sends bodies of at most 4,096 ids under this peer's budget, continues a budget-cut answer
//! at once, and asks another member, after a jittered backoff, for an id a partner did not send
//! (SPEC §9.4). A budgeted pull that comes back with a remainder continues at once, at most 64
//! times per partner per round.
//!
//! A dial-only peer answers its seed's `DIGEST`s on its one link, as the partner above, so its own
//! rumors lost on that link are repaired by the seed's rounds; it opens no audit itself and
//! keeps no round partners. Toward a seed whose card carries the hint, its pulls of a
//! whole space carry a budget and continue with its own text digest while a remainder comes back.
//! Every refusal and fallback is counted under one key ([`AuditRefusal`]) and logged once per
//! member and reason.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use tokio::time::Instant;

use agentspaces_wire::audit::{
    self, BUDGET_CEILING, DigestBody, Offer, PULL_RESP_BASE, PullRespBody, TreeForm, TreeNode,
};
use agentspaces_wire::bodies::{KIND_DIGEST, KIND_PULL_RESP, STREAM_SPACE_PREFIX};
use agentspaces_wire::cbor::Map;
use agentspaces_wire::crypto;
use agentspaces_wire::fold::{self, AuditMirror};
use agentspaces_wire::limits::MAX_FRAME_BYTES;
use agentspaces_wire::reconcile::{
    Asker, AuditRefusal, FetchBatch, FetchQueue, RootVerdict, Sessions,
};
use agentspaces_wire::records;
use agentspaces_wire::serving;
use agentspaces_wire::trie::AuditTrie;

use super::serve::Via;
use super::{Actor, Budget, FRAME_OVERHEAD, Malformed, bump};
use crate::peer::AuditCounters;
use crate::peer::listen::TokenBucket;
use crate::peer::spaces::Spaces;

/// Budgeted pulls a partner's answers continue at once in one round, at most.
const PULL_CONTINUATIONS_MAX: u32 = 64;
/// A member's budgeted bodies (fetches and budgeted pulls) answered: a burst and a rate per
/// second.
const FETCH_BURST: u32 = 64;
const FETCH_RATE: u32 = 32;
/// Members whose fetch pace, continuations, and logged refusals are kept at most.
const TRACKED_MAX: usize = 1024;

/// The audit's state on the actor (see the [module docs](self)).
pub(in crate::peer) struct AuditState {
    /// Whether this peer advertises `wire.ae=2` and audits toward members that do.
    pub enabled: bool,
    /// The budget this peer asks for.
    pub budget: i64,
    tries: HashMap<String, AuditMirror>,
    sessions: Sessions,
    asker: Asker,
    fetch: FetchQueue,
    continuations: HashMap<String, u32>,
    fetch_pace: HashMap<String, TokenBucket>,
    /// Per member, the continuations of a budgeted text pull that this peer's answers invited
    /// (each answer that left states out for the budget invites one).
    invited: HashMap<String, u32>,
    /// Per partner, this peer's budgeted text pulls not yet answered: only the answer to one may
    /// carry a remainder this peer continues.
    budgeted: HashMap<String, u32>,
    logged: HashSet<(String, AuditRefusal)>,
    counters: AuditCounters,
    refusals: BTreeMap<AuditRefusal, u64>,
}

impl AuditState {
    /// The state of a peer that audits when `enabled`, asking for `budget` bytes.
    pub fn new(enabled: bool, budget: i64) -> Self {
        let mut seed = [0u8; 8];
        let _ = crypto::port().fill_random(&mut seed);
        Self {
            enabled,
            budget: budget.clamp(4 << 10, BUDGET_CEILING),
            tries: HashMap::new(),
            sessions: Sessions::default(),
            asker: Asker::new(),
            fetch: FetchQueue::new(u64::from_le_bytes(seed)),
            continuations: HashMap::new(),
            fetch_pace: HashMap::new(),
            invited: HashMap::new(),
            budgeted: HashMap::new(),
            logged: HashSet::new(),
            counters: AuditCounters::default(),
            refusals: BTreeMap::new(),
        }
    }

    /// The counters, with the gauges of now.
    pub fn counters(&self) -> AuditCounters {
        let mut counters = self.counters.clone();
        let fetch = self.fetch.counters();
        counters.ids_requested = fetch.requested;
        counters.fetch_continued = fetch.continued;
        counters.fetch_requeued = fetch.requeued;
        counters.fetch_timed_out = fetch.timed_out;
        counters.fetch_parked = fetch.parked;
        counters.fetch_queue_full = fetch.queue_full;
        counters.fetch_queued = self.fetch.queued() as u64;
        counters.sessions_opened = self.sessions.opened();
        counters.slots_derived = self.tries.values().map(AuditMirror::slots_derived).sum();
        counters.open_sessions = self.sessions.open() as u64;
        counters.refusals = self
            .refusals
            .iter()
            .map(|(reason, count)| (reason.as_str().to_owned(), *count))
            .collect();
        counters
    }
}

/// A space's trie, in step with its store ([`AuditMirror`]); `None` for a space that is not
/// open.
fn sync_trie<'a>(
    tries: &'a mut HashMap<String, AuditMirror>,
    spaces: &mut Spaces,
    space: &str,
    now_ms: i64,
) -> Option<&'a mut AuditTrie> {
    let Some(slot) = spaces.get_mut(space) else {
        tries.remove(space);
        return None;
    };
    let mirror = tries.entry(space.to_owned()).or_default();
    Some(mirror.sync(&mut slot.store, now_ms))
}

/// The entry ids a space's sync delta carries, states and claims alike.
fn ids_in_delta(delta: &[u8]) -> HashSet<String> {
    let Some(sync) = records::decode_sync_delta(delta) else {
        return HashSet::new();
    };
    let mut ids: HashSet<String> = sync.claims.iter().map(|(id, _)| id.clone()).collect();
    ids.extend(
        sync.states
            .iter()
            .filter_map(|state| records::state_entry_id(state).map(str::to_owned)),
    );
    ids
}

/// Where a stream's pieces go in an answer: the revocations, the view, the advertisements, then
/// the spaces, so a pull never brings a record before the revocation that judges it.
fn rank(stream: &str) -> u8 {
    match stream {
        agentspaces_wire::revocation::PEER_STREAM => 0,
        agentspaces_wire::revocation::CREDENTIAL_STREAM => 1,
        serving::STREAM_VIEW => 2,
        agentspaces_wire::bodies::STREAM_ADS => 3,
        _ => 4,
    }
}

impl Actor {
    // ------------------------------------------------------------------------- the card

    /// Whether this peer audits with `peer`: it audits at all and the peer's current card carries
    /// `wire.ae=2`.
    pub(super) fn partner_audits(&self, peer: &str) -> bool {
        self.audit.enabled
            && audit::hints_audit(
                self.members
                    .get(peer)
                    .and_then(|ad| ad.get("resourceHints")),
            )
    }

    /// Counts a refusal under its key and logs it once per member and reason.
    fn audit_refuse(&mut self, from: &str, stream: Option<&str>, reason: AuditRefusal) {
        *self.audit.refusals.entry(reason).or_default() += 1;
        if self.audit.logged.len() >= TRACKED_MAX {
            self.audit.logged.clear();
        }
        if self.audit.logged.insert((from.to_owned(), reason)) {
            tracing::info!(
                peer = %self.peer_id,
                from,
                stream = stream.unwrap_or(""),
                reason = reason.as_str(),
                "agentspaces: anti-entropy refusal; counted, logged once per member"
            );
        }
    }

    /// The SHA-256 of this peer's text digest of a stream it serves.
    pub(super) fn text_hash(&self, stream: &str) -> Option<[u8; 32]> {
        self.stream_digest(stream)
            .map(|digest| crypto::port().sha256(&digest))
    }

    /// Sends a DIGEST body to `partner`, on the link it is reached by.
    pub(super) fn send_digest_to(&mut self, partner: &str, body: &DigestBody, via: Option<Via>) {
        let bytes = body.encode();
        let sent = match via {
            Some(via) => self.reply_with(via, KIND_DIGEST, &bytes, partner, Budget::Half),
            None => self.send_addressed_with(KIND_DIGEST, &bytes, partner, Budget::Whole),
        };
        let _ = sent;
    }

    // ------------------------------------------------------------------------- receiving

    /// A DIGEST from `sender`: each field handled on its own (annex I.6). A body that breaks a
    /// form rule is undecodable and counted; a body carrying audit fields while this peer does
    /// not audit is dropped and counted (`lacks-hint`).
    pub(super) fn on_digest_body(
        &mut self,
        sender: &str,
        body: &[u8],
        via: Via,
    ) -> Result<(), Malformed> {
        let digest = match audit::parse_digest(body) {
            Ok(digest) => digest,
            Err(rule) => {
                tracing::debug!(
                    from = sender,
                    rule = rule.as_str(),
                    "agentspaces: undecodable DIGEST"
                );
                self.audit_refuse(sender, None, AuditRefusal::Undecodable);
                return Err(Malformed);
            }
        };
        if digest.carries_audit() && !self.audit.enabled {
            self.audit_refuse(sender, None, AuditRefusal::LacksHint);
            return Ok(());
        }
        let names_view = |pairs: &Option<Vec<(String, Vec<u8>)>>| {
            pairs
                .iter()
                .flatten()
                .any(|(stream, _)| stream == serving::STREAM_VIEW)
        };
        // A dial-only peer runs no rounds of its own with the members that send it DIGESTs.
        let owed = self.hub.listening
            && (names_view(&digest.digests) || names_view(&digest.hashes))
            && self.note_digester(sender);
        if let Some(hashes) = &digest.hashes {
            self.on_opening(sender, hashes, via);
        }
        if let Some(want) = &digest.want {
            self.on_want(sender, want);
        }
        if let Some(tree) = digest.tree.clone() {
            self.on_tree(sender, tree, digest.budget, via);
        }
        // sketch is reserved: never sent, and ignored when received.
        if digest.digests.is_some() || digest.ids.is_some() {
            if digest.budget.is_none() && digest.ids.is_none() {
                let mut digests = Map::new();
                for (stream, text) in digest.digests.iter().flatten() {
                    digests.insert(stream.as_str(), text.clone());
                }
                self.answer_text_digests(sender, &digests, via);
            } else {
                self.answer_budgeted(sender, &digest, via);
            }
        }
        if owed {
            self.round_with(sender);
        }
        Ok(())
    }

    /// The opening of a round: the streams both hold whose hashes differ, a space's toward an
    /// auditing asker answered with its root (a session permitting), any other named in `want`.
    fn on_opening(&mut self, sender: &str, hashes: &[(String, Vec<u8>)], via: Via) {
        if !self.pace_answer(sender) {
            return;
        }
        let audits = self.partner_audits(sender);
        let now = self.now();
        let local = self.local_ms();
        let mut want = Vec::new();
        let mut differs = Vec::new();
        let mut equal = Vec::new();
        let mut sorted: Vec<&(String, Vec<u8>)> = hashes.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (stream, theirs) in sorted {
            let space = stream
                .strip_prefix(STREAM_SPACE_PREFIX)
                .filter(|space| self.spaces.contains(space));
            let trie_hash = space.and_then(|space| {
                sync_trie(&mut self.audit.tries, &mut self.spaces, space, now)
                    .map(AuditTrie::stream_hash)
            });
            let audited = audits && trie_hash.is_some();
            // Compared in both kinds: a stale view of the asker's card never makes two equal
            // streams differ.
            let same = if audit::same_stream(trie_hash.as_ref(), None, theirs) {
                true
            } else {
                match self.text_hash(stream) {
                    Some(text) => audit::same_stream(None, Some(&text), theirs),
                    None => continue, // a stream this peer does not serve says nothing to it
                }
            };
            if !same {
                if audited {
                    differs.push(stream.clone());
                } else {
                    want.push(stream.clone());
                }
            } else if audited {
                equal.push(stream.clone());
            }
        }
        for stream in &equal {
            self.audit.sessions.close(sender, stream);
        }
        let mut tree: Vec<(String, Vec<TreeNode>)> = Vec::new();
        let start = self.audit.sessions.rotation(sender, differs.len(), local);
        for index in 0..differs.len() {
            let stream = differs[(start + index) % differs.len()].clone();
            let Some(space) = stream.strip_prefix(STREAM_SPACE_PREFIX) else {
                continue;
            };
            let Some(trie) = sync_trie(&mut self.audit.tries, &mut self.spaces, space, now) else {
                continue;
            };
            let root = audit::answer_root(trie);
            if matches!(root.form, TreeForm::Nodes(_)) {
                match self.audit.sessions.open_root(sender, &stream, local) {
                    RootVerdict::Answer { capped } => {
                        if capped {
                            self.audit_refuse(sender, Some(&stream), AuditRefusal::SessionCapped);
                        }
                    }
                    RootVerdict::Busy => {
                        self.audit_refuse(sender, Some(&stream), AuditRefusal::SessionBusy);
                        continue;
                    }
                    RootVerdict::Cooling => {
                        self.audit_refuse(sender, Some(&stream), AuditRefusal::SessionCooling);
                        continue;
                    }
                }
            } else {
                // A root answered by lines finishes the stream for the round.
                self.audit.sessions.close(sender, &stream);
            }
            tree.push((stream, vec![root]));
        }
        if want.is_empty() && tree.is_empty() {
            return;
        }
        bump(&mut self.audit.counters.openings_answered);
        self.audit.counters.roots_answered += tree.len() as u64;
        let body = DigestBody {
            want: (!want.is_empty()).then_some(want),
            tree: (!tree.is_empty()).then_some(tree),
            ..DigestBody::default()
        };
        self.send_digest_to(sender, &body, Some(via));
    }

    /// The streams the partner of a round this peer opened wants the text of.
    pub(super) fn on_want(&mut self, sender: &str, want: &[String]) {
        if want.is_empty() || !self.awaits(sender) {
            return; // nobody but the partner of a round this peer opened is answered
        }
        let digests: Vec<(String, Vec<u8>)> = want
            .iter()
            .filter_map(|stream| Some((stream.clone(), self.stream_digest(stream)?)))
            .collect();
        if digests.is_empty() {
            return;
        }
        let body = DigestBody {
            digests: Some(digests),
            budget: self.partner_audits(sender).then_some(self.audit.budget),
            ..DigestBody::default()
        };
        if body.budget.is_some() {
            self.note_budgeted_pull(sender);
        }
        self.send_digest_to(sender, &body, None);
    }

    /// A body's `tree`: request nodes as the partner, answer nodes as the asker.
    fn on_tree(
        &mut self,
        sender: &str,
        tree: Vec<(String, Vec<TreeNode>)>,
        budget: Option<i64>,
        via: Via,
    ) {
        let now = self.now();
        let local = self.local_ms();
        let mut replies: Vec<(String, Vec<TreeNode>)> = Vec::new();
        let mut requests: Vec<(String, Vec<TreeNode>)> = Vec::new();
        let mut fetches: Vec<(String, Vec<String>)> = Vec::new();
        let mut fallback: Vec<String> = Vec::new();
        let mut refused: Vec<(String, AuditRefusal)> = Vec::new();
        // A body of request nodes spends the member's pace of the audit's answers once.
        let paced = tree
            .iter()
            .any(|(_, nodes)| nodes.iter().any(TreeNode::is_request))
            && !self.pace_audit(sender);
        for (stream, nodes) in tree {
            let (asked, answered): (Vec<TreeNode>, Vec<TreeNode>) =
                nodes.into_iter().partition(TreeNode::is_request);
            let space = stream
                .strip_prefix(STREAM_SPACE_PREFIX)
                .filter(|space| self.spaces.contains(space))
                .map(str::to_owned);
            let Some(space) = space else {
                if !asked.is_empty() {
                    refused.push((stream.clone(), AuditRefusal::RequestWithoutSession));
                }
                if answered.iter().any(|node| node.path.is_empty())
                    && self.audit.asker.opened(sender, local)
                {
                    fallback.push(stream);
                }
                continue;
            };
            if !asked.is_empty() && !paced {
                match self.audit.sessions.request(sender, &stream, local) {
                    Err(reason) => refused.push((stream.clone(), reason)),
                    Ok(capped) => {
                        if capped {
                            refused.push((stream.clone(), AuditRefusal::SessionCapped));
                        }
                        if let Some(trie) =
                            sync_trie(&mut self.audit.tries, &mut self.spaces, &space, now)
                        {
                            let (answers, repeated) =
                                audit::answer_requests(trie, &stream, &asked, budget);
                            if repeated {
                                refused.push((stream.clone(), AuditRefusal::RepeatedRequest));
                            }
                            bump(&mut self.audit.counters.requests_answered);
                            self.audit.counters.nodes_answered += answers.len() as u64;
                            replies.push((stream.clone(), answers));
                        }
                    }
                }
            }
            if !answered.is_empty()
                && let Some(trie) = sync_trie(&mut self.audit.tries, &mut self.spaces, &space, now)
            {
                let accepted_roots = answered.iter().filter(|node| node.path.is_empty()).count();
                let step = self
                    .audit
                    .asker
                    .on_answers(sender, &stream, &answered, trie, local);
                self.audit.counters.answers_received +=
                    (answered.len() as u64).saturating_sub(step.refusals.len() as u64);
                self.audit.counters.roots_received += accepted_roots as u64;
                for reason in step.refusals {
                    refused.push((stream.clone(), reason));
                }
                if !step.requests.is_empty() {
                    requests.push((stream.clone(), step.requests));
                }
                if !step.ids.is_empty() {
                    fetches.push((stream.clone(), step.ids));
                }
            }
        }
        for (stream, reason) in refused {
            self.audit_refuse(sender, Some(&stream), reason);
        }
        // The form follows the sender's current card: one that no longer carries wire.ae=2
        // receives no audit field, as the asker's partner nor as the partner's asker; what it
        // still differs in, today's digests repair.
        if !self.partner_audits(sender)
            && (!replies.is_empty()
                || !requests.is_empty()
                || !fetches.is_empty()
                || !fallback.is_empty())
        {
            self.audit_refuse(sender, None, AuditRefusal::LacksHint);
            return;
        }
        if !replies.is_empty() {
            let body = DigestBody {
                tree: Some(replies),
                ..DigestBody::default()
            };
            self.send_digest_to(sender, &body, Some(via));
        }
        if !requests.is_empty() {
            bump(&mut self.audit.counters.requests_sent);
            let body = DigestBody {
                tree: Some(requests),
                budget: Some(self.audit.budget),
                ..DigestBody::default()
            };
            self.send_digest_to(sender, &body, None);
        }
        for (stream, ids) in fetches {
            let batches = self.audit.fetch.want(sender, &stream, &ids, local);
            self.send_fetches(batches);
        }
        if self.audit_waiting() {
            // The fetch queue asks again on the housekeeping (SPEC v0.1.36 §9.5: due work).
            let at = Instant::now();
            self.lower_housekeeping(at.checked_add(Duration::from_millis(500)).unwrap_or(at));
        }
        if !fallback.is_empty() {
            for stream in &fallback {
                self.audit_refuse(sender, Some(stream), AuditRefusal::TextFallback);
            }
            let digests: Vec<(String, Vec<u8>)> = fallback
                .iter()
                .filter_map(|stream| Some((stream.clone(), self.stream_digest(stream)?)))
                .collect();
            if !digests.is_empty() {
                self.expect_answer(sender);
                self.note_budgeted_pull(sender);
                let body = DigestBody {
                    digests: Some(digests),
                    budget: Some(self.audit.budget),
                    ..DigestBody::default()
                };
                self.send_digest_to(sender, &body, None);
            }
        }
    }

    /// Sends fetch bodies, each under this peer's budget, to partners whose current card still
    /// carries `wire.ae=2`; what was bound for any other goes back to the queue, for another
    /// member.
    fn send_fetches(&mut self, batches: Vec<FetchBatch>) {
        for batch in batches {
            if !self.partner_audits(&batch.partner) {
                let local = self.local_ms();
                self.audit.fetch.forget_partner(&batch.partner, local);
                continue;
            }
            let body = DigestBody {
                ids: Some(vec![(batch.stream.clone(), batch.ids.clone())]),
                budget: Some(self.audit.budget),
                ..DigestBody::default()
            };
            self.send_digest_to(&batch.partner, &body, None);
        }
    }

    /// The one `PULL_RESP` a body's `digests` (with a budget) and `ids` draw: the streams in the
    /// order of [`rank`], a space's items in the order of *The fetch* cut to the budget (the
    /// first item always), every other stream's delta whole; `remainder` when the body carried a
    /// budget. A budgeted fetch is answered even when nothing named is held here, so the asker
    /// learns at once to ask another member.
    fn answer_budgeted(&mut self, sender: &str, digest: &DigestBody, via: Via) {
        // A text digest is answered by a pass over the stream whatever its budget, so it spends
        // the member's digest pace as every digest does, unless an earlier answer of this peer
        // left states out and so invited it; a fetch by ids spends the pace of the audit's
        // answers, generous enough for a fetch window.
        let allowed = if digest.digests.is_some() {
            self.take_invitation(sender) || self.pace_answer(sender)
        } else {
            self.pace_audit(sender)
        };
        if !allowed {
            return;
        }
        let bound = match digest.budget {
            Some(budget) => usize::try_from(budget.min(BUDGET_CEILING)).unwrap_or(0),
            None => MAX_FRAME_BYTES.saturating_sub(FRAME_OVERHEAD.saturating_mul(2)),
        };
        let empty = Vec::new();
        let texts = digest.digests.as_ref().unwrap_or(&empty);
        let empty_ids = Vec::new();
        let named_ids = digest.ids.as_ref().unwrap_or(&empty_ids);
        let mut streams: Vec<&str> = texts
            .iter()
            .map(|(stream, _)| stream.as_str())
            .chain(named_ids.iter().map(|(stream, _)| stream.as_str()))
            .collect();
        streams.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.cmp(b)));
        streams.dedup();
        let now = self.now();
        let mut used = PULL_RESP_BASE;
        let mut deltas: Vec<(String, Vec<u8>)> = Vec::new();
        let mut remainder: Vec<(String, i64)> = Vec::new();
        for stream in streams {
            let text = texts
                .iter()
                .find(|(name, _)| name == stream)
                .map(|(_, t)| t);
            let ids = named_ids
                .iter()
                .find(|(name, _)| name == stream)
                .map(|(_, ids)| ids);
            let overhead = audit::stream_overhead(stream);
            let room = bound.saturating_sub(used.saturating_add(overhead));
            let first = deltas.is_empty();
            let (delta, left) = if let Some(space) = stream.strip_prefix(STREAM_SPACE_PREFIX)
                && let Some(slot) = self.spaces.get(space)
            {
                let store = &slot.store;
                let mut offers: Vec<Offer<'_>> = Vec::new();
                if let Some(text) = text {
                    let lines = serving::digest_lines(text);
                    for (entry_id, joined) in store.states() {
                        let state =
                            (!serving::names_line(&lines, &serving::state_line(entry_id, joined)))
                                .then(|| store.signed_state(entry_id))
                                .flatten();
                        let claim = store.claim_proof(entry_id).filter(|signed| {
                            !serving::names_line(&lines, &serving::claim_line(entry_id, signed))
                        });
                        if state.is_some() || claim.is_some() {
                            offers.push(Offer {
                                entry_id,
                                state,
                                present: fold::is_present(joined),
                                claim,
                            });
                        }
                    }
                    for (entry_id, signed) in store.claims() {
                        if store.state(entry_id).is_none()
                            && !serving::names_line(&lines, &serving::claim_line(entry_id, signed))
                        {
                            offers.push(Offer {
                                entry_id,
                                state: None,
                                present: false,
                                claim: Some(signed),
                            });
                        }
                    }
                } else if let Some(ids) = ids {
                    bump(&mut self.audit.counters.fetches_answered);
                    for entry_id in ids {
                        let state = store.signed_state(entry_id);
                        let claim = store.claim_proof(entry_id);
                        if state.is_some() || claim.is_some() {
                            offers.push(Offer {
                                entry_id,
                                state,
                                present: store.state(entry_id).is_some_and(fold::is_present),
                                claim,
                            });
                        }
                    }
                }
                let (delta, left) = audit::bounded_delta(offers, room, first);
                (delta, i64::try_from(left).unwrap_or(i64::MAX))
            } else if let Some(text) = text {
                (self.whole_delta(sender, stream, text), 0)
            } else {
                (None, 0) // nothing of the stream is held here: a zero remainder says so
            };
            if digest.budget.is_some() {
                remainder.push((stream.to_owned(), left));
            }
            if let Some(delta) = delta {
                used = used.saturating_add(delta.len()).saturating_add(overhead);
                deltas.push((stream.to_owned(), delta));
            }
        }
        let _ = now;
        let fetched = digest.ids.is_some();
        if deltas.is_empty() && !(fetched && digest.budget.is_some()) {
            return;
        }
        if digest.budget.is_some() {
            bump(&mut self.audit.counters.budgeted_answers);
        }
        if digest.digests.is_some() && remainder.iter().any(|(_, left)| *left > 0) {
            self.invite_continuation(sender);
        }
        let body = PullRespBody {
            deltas,
            remainder: digest.budget.map(|_| remainder),
        };
        self.note_hub_activity();
        if self
            .reply_with(via, KIND_PULL_RESP, &body.encode(), sender, Budget::Half)
            .is_ok()
        {
            bump(&mut self.hub.counters.pull_frames);
        }
        bump(&mut self.hub.counters.pulls_answered);
    }

    /// Spends one of `sender`'s answers of the audit (a fetch, a body of request nodes); `false`
    /// (counted) when its pace is spent. Each answer is bounded by its budget, so the pace bounds
    /// the bytes and the work a member can draw.
    fn pace_audit(&mut self, sender: &str) -> bool {
        if self.audit.fetch_pace.len() >= TRACKED_MAX && !self.audit.fetch_pace.contains_key(sender)
        {
            self.audit.fetch_pace.clear();
        }
        let allowed = self
            .audit
            .fetch_pace
            .entry(sender.to_owned())
            .or_insert_with(|| TokenBucket::new(FETCH_BURST, FETCH_RATE))
            .take();
        if !allowed {
            bump(&mut self.hub.counters.pulls_paced);
        }
        allowed
    }

    /// Notes that an answer to `sender` left states out for the budget: its continuation is
    /// invited, at most [`PULL_CONTINUATIONS_MAX`] waiting.
    fn invite_continuation(&mut self, sender: &str) {
        if self.audit.invited.len() >= TRACKED_MAX && !self.audit.invited.contains_key(sender) {
            self.audit.invited.clear();
        }
        let invited = self.audit.invited.entry(sender.to_owned()).or_default();
        *invited = (*invited + 1).min(PULL_CONTINUATIONS_MAX);
    }

    /// Notes a budgeted text pull sent to `partner`: the answer to it may carry a remainder this
    /// peer continues.
    pub(super) fn note_budgeted_pull(&mut self, partner: &str) {
        if self.audit.budgeted.len() >= TRACKED_MAX && !self.audit.budgeted.contains_key(partner) {
            self.audit.budgeted.clear();
        }
        let pending = self.audit.budgeted.entry(partner.to_owned()).or_default();
        *pending = (*pending + 1).min(PULL_CONTINUATIONS_MAX);
    }

    /// Whether a `PULL_RESP` from `partner` may answer a budgeted text pull of this peer's,
    /// spending it: a remainder in any other answer was never asked for.
    fn answered_budgeted_pull(&mut self, partner: &str) -> bool {
        match self.audit.budgeted.get_mut(partner) {
            Some(pending) if *pending > 0 => {
                *pending -= 1;
                if *pending == 0 {
                    self.audit.budgeted.remove(partner);
                }
                true
            }
            _ => false,
        }
    }

    /// Spends an invitation to continue a budgeted pull, when `sender` holds one.
    fn take_invitation(&mut self, sender: &str) -> bool {
        match self.audit.invited.get_mut(sender) {
            Some(invited) if *invited > 0 => {
                *invited -= 1;
                if *invited == 0 {
                    self.audit.invited.remove(sender);
                }
                true
            }
            _ => false,
        }
    }

    /// A PULL_RESP from `sender`: a fetch's answer (a body in flight there names its stream),
    /// else the answer to a pull or round this peer opened; the deltas applied, the fetch settled,
    /// and a budgeted pull continued while a remainder comes back.
    pub(super) fn on_pull_resp_frame(
        &mut self,
        sender: &str,
        body: &[u8],
        via: Via,
    ) -> Result<(), Malformed> {
        let resp = match audit::parse_pull_resp(body) {
            Ok(resp) => resp,
            Err(_) => {
                self.audit_refuse(sender, None, AuditRefusal::Undecodable);
                return Err(Malformed);
            }
        };
        let local = self.local_ms();
        let named: Vec<&str> = resp
            .deltas
            .iter()
            .map(|(stream, _)| stream.as_str())
            .chain(
                resp.remainder
                    .iter()
                    .flatten()
                    .map(|(stream, _)| stream.as_str()),
            )
            .collect();
        let fetch_stream = self.audit.fetch.answer_for(sender, &named, local);
        if fetch_stream.is_none() && !self.pull_resp_wanted(sender, via) {
            return Ok(());
        }
        if let Some(remainder) = &resp.remainder {
            self.audit.counters.remainder_received += remainder
                .iter()
                .map(|(_, left)| u64::try_from(*left).unwrap_or(0))
                .sum::<u64>();
        }
        let received = fetch_stream
            .as_ref()
            .and_then(|stream| resp.deltas.iter().find(|(name, _)| name == stream))
            .map(|(_, delta)| ids_in_delta(delta))
            .unwrap_or_default();
        let mut deltas = Map::with_capacity(resp.deltas.len());
        for (stream, delta) in &resp.deltas {
            deltas.insert(stream.as_str(), delta.clone());
        }
        let applied = self.on_pull_resp(deltas);
        if let Some(stream) = fetch_stream {
            if let Some(batch) = self.audit.fetch.settle(sender, &stream, &received, local) {
                let left = resp.remainder_of(&stream);
                let next = self
                    .audit
                    .fetch
                    .fetched(sender, &batch, &received, left, local);
                self.send_fetches(next);
            }
        } else if let Some(remainder) = &resp.remainder
            && self.answered_budgeted_pull(sender)
        {
            self.continue_pull(sender, remainder, via);
        }
        applied
    }

    /// A budgeted pull came back with a remainder: continue at once with this peer's own text
    /// digest under the same budget (it now lists what the answer brought), or, for a space this
    /// peer audits with the partner, with an audit; at most [`PULL_CONTINUATIONS_MAX`] per
    /// partner per round.
    fn continue_pull(&mut self, sender: &str, remainder: &[(String, i64)], via: Via) {
        let audits = self.hub.listening && self.partner_audits(sender);
        let mut text = Vec::new();
        let mut reopen = false;
        for (stream, left) in remainder {
            if *left <= 0 {
                continue;
            }
            if audits && stream.starts_with(STREAM_SPACE_PREFIX) {
                reopen = true;
            } else if let Some(digest) = self.stream_digest(stream) {
                text.push((stream.clone(), digest));
            }
        }
        if text.is_empty() && !reopen {
            return;
        }
        if self.audit.continuations.len() >= TRACKED_MAX {
            self.audit.continuations.clear();
        }
        let count = self
            .audit
            .continuations
            .entry(sender.to_owned())
            .or_default();
        *count += 1;
        if *count > PULL_CONTINUATIONS_MAX {
            return; // the next round carries on
        }
        let sofar = *count;
        bump(&mut self.audit.counters.pulls_continued);
        if !text.is_empty() {
            self.note_budgeted_pull(sender);
            let body = DigestBody {
                digests: Some(text),
                budget: Some(self.audit.budget),
                ..DigestBody::default()
            };
            if via == Via::Dialed && !self.hub.listening {
                let _ = self.send(KIND_DIGEST, &body.encode(), None);
            } else {
                self.expect_answer(sender);
                self.send_digest_to(sender, &body, None);
            }
        }
        if reopen {
            self.round_with(sender);
            self.audit.continuations.insert(sender.to_owned(), sofar);
        }
    }

    // ------------------------------------------------------------------------- the asker

    /// Opens a round with `partner` by the audit when its current card carries `wire.ae=2`:
    /// `hashes`, each space stream's trie stream hash and every other stream's text digest hash.
    /// Whether it did; the caller sends today's digests otherwise.
    pub(super) fn audit_opening(&mut self, partner: &str) -> bool {
        if !self.partner_audits(partner) {
            return false;
        }
        let now = self.now();
        let local = self.local_ms();
        let mut hashes = Vec::new();
        for stream in self.served_streams() {
            let hash = match stream.strip_prefix(STREAM_SPACE_PREFIX) {
                Some(space) => sync_trie(&mut self.audit.tries, &mut self.spaces, space, now)
                    .map(|trie| trie.stream_hash()),
                None => self.text_hash(&stream),
            };
            if let Some(hash) = hash {
                hashes.push((stream, hash.to_vec()));
            }
        }
        self.audit.asker.opening(partner, local);
        self.audit.continuations.remove(partner);
        bump(&mut self.audit.counters.openings_sent);
        let body = DigestBody {
            hashes: Some(hashes),
            ..DigestBody::default()
        };
        self.send_digest_to(partner, &body, None);
        true
    }

    /// This peer's hash of each stream it serves, as `partner` compares them (SPEC §5.2, annex
    /// I.6): toward a member whose current card carries `wire.ae=2` a space's trie stream hash,
    /// toward any other the SHA-256 of the space's text digest; every other stream's text digest
    /// hash for both.
    pub(super) fn stream_hashes_for(&mut self, partner: &str) -> BTreeMap<String, [u8; 32]> {
        let trie = self.partner_audits(partner);
        let now = self.now();
        let mut hashes = BTreeMap::new();
        for stream in self.served_streams() {
            let hash = match stream.strip_prefix(STREAM_SPACE_PREFIX) {
                Some(space) if trie => {
                    sync_trie(&mut self.audit.tries, &mut self.spaces, space, now)
                        .map(|trie| trie.stream_hash())
                }
                _ => self.text_hash(&stream),
            };
            if let Some(hash) = hash {
                hashes.insert(stream, hash);
            }
        }
        hashes
    }

    /// The body of a pull of whole streams (empty digests): toward a seed whose current card
    /// carries `wire.ae=2`, under this peer's budget.
    pub(super) fn pull_body(&self, streams: &[&str]) -> Vec<u8> {
        let budgeted = self
            .seed_peer
            .as_deref()
            .is_some_and(|seed| self.partner_audits(seed));
        DigestBody {
            digests: Some(
                streams
                    .iter()
                    .map(|stream| ((*stream).to_owned(), Vec::new()))
                    .collect(),
            ),
            budget: budgeted.then_some(self.audit.budget),
            ..DigestBody::default()
        }
        .encode()
    }

    /// A fresh pull from the seed: its continuations count anew.
    pub(super) fn reset_continuations(&mut self) {
        if let Some(seed) = &self.seed_peer {
            self.audit.continuations.remove(seed);
        }
    }

    /// Whether the audit waits on anything the housekeeping asks again: a queued fetch, an
    /// open session.
    pub(super) fn audit_waiting(&self) -> bool {
        self.audit.fetch.queued() > 0 || self.audit.sessions.open() > 0
    }

    /// The audit's turn on the listening role's housekeeping: the fetch queue asks again what is due, of
    /// the auditing members in view, and the tries of closed spaces are dropped.
    pub(super) fn audit_tick(&mut self) {
        if !self.audit.enabled {
            return;
        }
        let local = self.local_ms();
        let spaces = &self.spaces;
        self.audit.tries.retain(|space, _| spaces.contains(space));
        self.audit.sessions.expire(local);
        self.audit.asker.expire(local);
        let mut view: Vec<String> = self
            .admitted_members()
            .into_iter()
            .filter(|member| self.hub.routes.contains_key(member))
            .collect();
        if let Some(seed) = &self.seed_peer
            && self.link.is_some()
            && !view.contains(seed)
        {
            view.push(seed.clone());
        }
        view.retain(|member| self.partner_audits(member));
        let batches = self.audit.fetch.retry(&view, local);
        self.send_fetches(batches);
    }
}
