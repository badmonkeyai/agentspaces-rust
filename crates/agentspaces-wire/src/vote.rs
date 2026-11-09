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

//! The QUORUM vote (SPEC §8.4, TECH-SPEC §8.4) over folded ballot states, a port of `vote.py`
//! with Java `VoteCapability` as the authority on behavior: ballots, the tally, open proposals,
//! and the decision, as pure functions of the states they are given, plus the payloads a caller
//! writes to propose and cast, and the MAJORITY_GOSSIP helpers.
//!
//! # Which states to give them
//!
//! Java reads ballots and proposals through the space (`readAllIssued`, `read`), which returns
//! only *available* entries (`ReplicatedSpace.availableRecords`): present, whose `WRITE` lease
//! has not lapsed at the reader's time, and with no claim in force. For Java's answer, pass
//! [`live_vote_states`] of the store at the reader's time, so a ballot or proposal whose lease
//! lapsed, or that someone holds a claim on, neither counts nor opens a vote, and a decision
//! reopens when the ballots that made it lapse. `store.state_values()` gives every held state:
//! present ones count there whatever their lease and claims, as `vote.py` counts them.
//!
//! Ballots are ordinary entries of the reserved [`BALLOT_TYPE`]. The voter is the entry's
//! authenticated issuer, and a ballot whose declared `voter` differs from it is a forgery that
//! never counts. Counting follows a [`Granularity`]: under
//! [`Granularity::Peer`] the counted identity is the issuer's peer, so one peer is one counted
//! ballot however many names it writes; under [`Granularity::Agent`] each permitted agent counts
//! once, and only an agent-attested record (one whose state carried an `agentCertificate` the
//! two-key rule accepted) is eligible, because a peer-asserted name is exactly what that
//! granularity exists to distrust. One ballot per counted identity counts: the first in the
//! order the states are given (the store's insertion order, `vote.py`'s "first observed").
//!
//! Where `vote.py` would read any CBOR value, this module reads Java's record types: a ballot's
//! `proposalId`, `option`, and `voter` are text, and a proposal's `options` are text and its
//! `quorum` an integer; a ballot or proposal of another shape is skipped (Java cannot decode
//! one). Payloads are read inline only: a ballot or proposal written by reference is skipped, as
//! `vote.py` skips it. Every function also skips a state that is not present (completed or
//! withdrawn). Revoked voters are the caller's `permits` to refuse (Java applies its revocation
//! view at every recount).
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use crate::cbor::{self, Map, Value};
use crate::fold::{SpaceStore, is_present};
// Java `String.compareTo` (UTF-16 code unit order), the order Java breaks ties in.
use crate::util::{java_order, present, text};

/// The reserved entry type of a ballot (Java `VoteCapability.Ballot`, schema version 1).
pub const BALLOT_TYPE: &str = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Ballot#v1";

/// The reserved entry type of a proposal (Java `VoteCapability.Proposal`, schema version 1).
pub const PROPOSAL_TYPE: &str =
    "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Proposal#v1";

/// Whom a tally counts once (Java `Authorizer.Granularity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Granularity {
    /// One counted ballot per issuing peer, however many agent names it writes under.
    #[default]
    Peer,
    /// One counted ballot per agent, and only for agent-attested records.
    Agent,
}

impl Granularity {
    /// The wire name: `"PEER"` or `"AGENT"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Granularity::Peer => "PEER",
            Granularity::Agent => "AGENT",
        }
    }

    /// The granularity of a wire name.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "PEER" => Some(Granularity::Peer),
            "AGENT" => Some(Granularity::Agent),
            _ => None,
        }
    }
}

/// The states of `store` a Java replica's vote reads at `now_ms`: the proposals, then the
/// ballots, that are available ([`SpaceStore::available`], Java `availableRecords`: present, a
/// `WRITE` lease that has not lapsed, and no claim in force), each type in insertion order. Give
/// it to [`decision`], [`tally`], [`ballots`], [`proposals`], or [`proposal`] for Java's answer at
/// the reader's time.
///
/// ```
/// use agentspaces_wire::fold::SpaceStore;
/// use agentspaces_wire::vote::{Granularity, decision, live_vote_states};
///
/// let store = SpaceStore::new();
/// let now_ms = 1_767_225_600_000;
/// let decided = decision(live_vote_states(&store, now_ms), "q", Granularity::Peer, None);
/// assert!(decided.is_none());
/// ```
pub fn live_vote_states(store: &SpaceStore, now_ms: i64) -> Vec<&Map> {
    let mut states: Vec<&Map> = Vec::new();
    for type_name in [PROPOSAL_TYPE, BALLOT_TYPE] {
        states.extend(
            store
                .available(type_name, now_ms)
                .into_iter()
                .map(|(_, state)| state),
        );
    }
    states
}

/// The decoded inline payload of a state's record, when it is a map, with the record.
fn payload_of(state: &Map) -> Option<(&Map, Map)> {
    let record = state.get("record").and_then(Value::as_map)?;
    let payload = record.get("payload").and_then(Value::as_bytes)?;
    let decoded = cbor::decode(payload).ok()?.into_map()?;
    Some((record, decoded))
}

/// The present states of one reserved type with their records and decoded payloads.
fn present_of_type<'a, I>(
    states: I,
    type_name: &'a str,
) -> impl Iterator<Item = (&'a Map, &'a Map, Map)>
where
    I: IntoIterator<Item = &'a Map>,
{
    states.into_iter().filter_map(move |state| {
        let record = state.get("record").and_then(Value::as_map)?;
        if text(record, "type") != Some(type_name) || !is_present(state) {
            return None;
        }
        let (record, payload) = payload_of(state)?;
        Some((state, record, payload))
    })
}

// ---------------------------------------------------------------------------------------------
// Ballots and the tally

/// One folded ballot for a proposal: its state, its record, and its decoded payload
/// (`{proposalId, option, voter}`).
#[derive(Debug, Clone, PartialEq)]
pub struct Ballot<'a> {
    /// The ballot entry's joined state.
    pub state: &'a Map,
    /// The ballot entry's record.
    pub record: &'a Map,
    /// The decoded ballot.
    pub payload: Map,
}

impl Ballot<'_> {
    /// The record's authenticated issuer: the voter.
    pub fn issuer(&self) -> Option<&str> {
        text(self.record, "issuer")
    }

    /// The voter the ballot declares; it counts only when it is the issuer.
    pub fn voter(&self) -> Option<&str> {
        text(&self.payload, "voter")
    }

    /// The option voted for.
    pub fn option(&self) -> Option<&str> {
        text(&self.payload, "option")
    }

    /// Whether the record is agent-attested: its state carried an `agentCertificate`.
    pub fn is_attested(&self) -> bool {
        present(self.state, "agentCertificate").is_some()
    }
}

/// The folded, present ballots for one proposal, in the order the states are given (`vote.py`'s
/// `ballots`): states of [`BALLOT_TYPE`], not completed, not withdrawn (some add dot is not
/// removed), whose inline payload decodes to a map with this text `proposalId`.
pub fn ballots<'a, I>(states: I, proposal_id: &str) -> Vec<Ballot<'a>>
where
    I: IntoIterator<Item = &'a Map>,
{
    present_of_type(states, BALLOT_TYPE)
        .filter(|(_, _, payload)| text(payload, "proposalId") == Some(proposal_id))
        .map(|(state, record, payload)| Ballot {
            state,
            record,
            payload,
        })
        .collect()
}

/// Votes per option, in insertion order: the options a tally was given first (zero-filled, in
/// their order), then any other option in the order its first counted ballot was seen, as
/// `vote.py`'s `dict` keeps them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    counts: Vec<(String, u64)>,
    index: BTreeMap<String, usize>,
}

impl Tally {
    /// The slot of an option, added with no votes when it is new.
    fn slot(&mut self, option: &str) -> usize {
        if let Some(&slot) = self.index.get(option) {
            return slot;
        }
        let slot = self.counts.len();
        self.counts.push((option.to_owned(), 0));
        self.index.insert(option.to_owned(), slot);
        slot
    }

    /// One more vote for an option.
    fn count_one(&mut self, option: &str) {
        let slot = self.slot(option);
        if let Some((_, votes)) = self.counts.get_mut(slot) {
            *votes = votes.saturating_add(1);
        }
    }

    /// The votes of an option the tally names (`vote.py`'s `result.get(option)`).
    pub fn get(&self, option: &str) -> Option<u64> {
        let slot = self.index.get(option)?;
        self.counts.get(*slot).map(|(_, votes)| *votes)
    }

    /// The votes of an option, 0 when the tally does not name it.
    pub fn count(&self, option: &str) -> u64 {
        self.get(option).unwrap_or(0)
    }

    /// Every option with its votes, in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, u64)> + Clone {
        self.counts
            .iter()
            .map(|(option, votes)| (option.as_str(), *votes))
    }

    /// The number of options named.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether no option is named.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The counted voters: the sum of the votes.
    pub fn voters(&self) -> u64 {
        self.counts
            .iter()
            .fold(0u64, |sum, (_, votes)| sum.saturating_add(*votes))
    }

    /// The tally as a CBOR map of option to votes, in insertion order.
    pub fn to_map(&self) -> Map {
        self.iter().collect()
    }
}

/// Votes per option for one proposal (`vote.py`'s `tally`, Java `VoteCapability.tally`), over
/// the states given ([`live_vote_states`] for Java's reads at a time).
///
/// Each ballot of [`ballots`], in order, is skipped when its declared `voter` is not its record's
/// issuer (a forgery), when `options` is given and does not offer its option (spoiled; a
/// non-text option is always spoiled), under [`Granularity::Agent`] when its record is not
/// agent-attested, and when `permits(issuer)` refuses its issuer (the authorizer's per-agent
/// answer; everyone by default). Otherwise it counts once for its counted identity (the issuer
/// under [`Granularity::Agent`], the issuer's peer under [`Granularity::Peer`]) unless that
/// identity already counted. `options` zero-fill the tally in their order.
pub fn tally<'a, I>(
    states: I,
    proposal_id: &str,
    options: Option<&[&str]>,
    granularity: Granularity,
    permits: Option<&dyn Fn(&str) -> bool>,
) -> Tally
where
    I: IntoIterator<Item = &'a Map>,
{
    let mut result = Tally::default();
    for option in options.unwrap_or_default() {
        result.slot(option);
    }
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    let found = ballots(states, proposal_id);
    for ballot in &found {
        let Some(issuer) = ballot.issuer() else {
            continue;
        };
        if ballot.voter() != Some(issuer) {
            continue; // the declared voter is not the authenticated writer: forged
        }
        let Some(option) = ballot.option() else {
            continue; // Java cannot decode a ballot without a text option: spoiled
        };
        if options.is_some_and(|offered| !offered.contains(&option)) {
            continue; // not on the ballot: spoiled
        }
        if granularity == Granularity::Agent && !ballot.is_attested() {
            continue; // per-agent counting trusts only the agent's own key
        }
        if permits.is_some_and(|permits| !permits(issuer)) {
            continue;
        }
        let key = match granularity {
            Granularity::Agent => issuer,
            Granularity::Peer => issuer.split('/').next().unwrap_or(issuer),
        };
        if counted.insert(key) {
            result.count_one(option);
        }
    }
    result
}

// ---------------------------------------------------------------------------------------------
// Proposals and the decision

/// An open proposal (Java `VoteCapability.Proposal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The proposal's id, which its ballots name.
    pub proposal_id: String,
    /// The question asked, when the proposal states one.
    pub question: Option<String>,
    /// The options offered; a ballot for any other option is spoiled.
    pub options: Vec<String>,
    /// How many distinct counted voters close the decision.
    pub quorum: i64,
}

impl Proposal {
    /// The proposal a decoded payload holds: a text `proposalId`, an optional text `question`,
    /// `options` absent, null, or an array of text, and `quorum` absent, null (0), or an
    /// integer.
    fn from_payload(payload: &Map) -> Option<Proposal> {
        let proposal_id = text(payload, "proposalId")?.to_owned();
        let question = match payload.get("question") {
            None | Some(Value::Null) => None,
            Some(question) => Some(question.as_str()?.to_owned()),
        };
        let options = match payload.get("options") {
            None | Some(Value::Null) => Vec::new(),
            Some(options) => options
                .as_array()?
                .iter()
                .map(|option| option.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        };
        let quorum = match payload.get("quorum") {
            None | Some(Value::Null) => 0,
            Some(quorum) => quorum.as_i64()?,
        };
        Some(Proposal {
            proposal_id,
            question,
            options,
            quorum,
        })
    }
}

/// The open proposals (`vote.py`'s `proposals`): present states of [`PROPOSAL_TYPE`] whose inline
/// payload is a well-formed [`Proposal`], the first in the given order for each id, in that
/// order.
pub fn proposals<'a, I>(states: I) -> Vec<Proposal>
where
    I: IntoIterator<Item = &'a Map>,
{
    let mut seen = BTreeSet::new();
    present_of_type(states, PROPOSAL_TYPE)
        .filter_map(|(_, _, payload)| Proposal::from_payload(&payload))
        .filter(|proposal| seen.insert(proposal.proposal_id.clone()))
        .collect()
}

/// The open proposal of one id: the first in the given order (Java `VoteCapability.proposal`
/// reads only available entries: pass [`live_vote_states`] for its answer at a time).
pub fn proposal<'a, I>(states: I, proposal_id: &str) -> Option<Proposal>
where
    I: IntoIterator<Item = &'a Map>,
{
    present_of_type(states, PROPOSAL_TYPE)
        .filter_map(|(_, _, payload)| Proposal::from_payload(&payload))
        .find(|proposal| proposal.proposal_id == proposal_id)
}

/// A closed QUORUM decision (Java `VoteCapability.Decision`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The proposal decided.
    pub proposal_id: String,
    /// The winning option.
    pub winner: String,
    /// The tally that decided it, over the proposal's options.
    pub tally: Tally,
    /// The granularity it was counted at.
    pub granularity: Granularity,
}

/// The QUORUM decision as Java closes it (`vote.py`'s `decision`, SPEC §8.4): once the distinct
/// counted voters of the proposal's [`tally`] reach its quorum (and at least one voted), the
/// winner is the option with the most votes, ties broken to the first option in Java string
/// order, so every replica decides identically. `None` while open or unknown.
///
/// Pass [`live_vote_states`] at the reader's time for Java's decision: a proposal or ballot
/// whose lease lapsed, or that a claim holds, is not read, so the decision waits or reopens as
/// Java's does. Over `store.state_values()` every present state counts.
///
/// One deliberate difference from Java: no decision closes without a single counted voter.
/// Java decides once the voters reach the quorum, so a proposal of quorum 0 written straight to
/// the space (Java's own `propose` refuses one) would close there with no votes, and Java's
/// `decision` throws when such a proposal also offers no options. Python and Ruby keep this
/// guard too.
pub fn decision<'a, I>(
    states: I,
    proposal_id: &str,
    granularity: Granularity,
    permits: Option<&dyn Fn(&str) -> bool>,
) -> Option<Decision>
where
    I: IntoIterator<Item = &'a Map> + Clone,
{
    let proposal = proposal(states.clone(), proposal_id)?;
    let options: Vec<&str> = proposal.options.iter().map(String::as_str).collect();
    let counts = tally(states, proposal_id, Some(&options), granularity, permits);
    let voters = counts.voters();
    if voters == 0 || i128::from(voters) < i128::from(proposal.quorum) {
        return None;
    }
    let winner = options.iter().copied().min_by(|a, b| {
        counts
            .count(b)
            .cmp(&counts.count(a))
            .then_with(|| java_order(a, b))
    })?;
    Some(Decision {
        proposal_id: proposal.proposal_id.clone(),
        winner: winner.to_owned(),
        tally: counts,
        granularity,
    })
}

// ---------------------------------------------------------------------------------------------
// Payloads

/// A proposal's payload in Java field order (`{proposalId, question, options, quorum}`), as
/// `vote.py`'s `propose` writes it into a [`PROPOSAL_TYPE`] entry. Proposing is idempotent on the
/// id: the caller writes nothing when [`proposal`] already finds it open.
pub fn proposal_payload(proposal_id: &str, question: &str, options: &[&str], quorum: i64) -> Map {
    let mut payload = Map::with_capacity(4);
    payload.insert("proposalId", proposal_id);
    payload.insert("question", question);
    payload.insert(
        "options",
        options
            .iter()
            .map(|option| Value::from(*option))
            .collect::<Vec<_>>(),
    );
    payload.insert("quorum", quorum);
    payload
}

/// A ballot's payload in Java field order (`{proposalId, option, voter}`), as `vote.py`'s `cast`
/// writes it into a [`BALLOT_TYPE`] entry. `voter` must be the writing agent's id (the issuer the
/// record will name), or every tally skips the ballot.
pub fn ballot_payload(proposal_id: &str, option: &str, voter: &str) -> Map {
    let mut payload = Map::with_capacity(3);
    payload.insert("proposalId", proposal_id);
    payload.insert("option", option);
    payload.insert("voter", voter);
    payload
}

// ---------------------------------------------------------------------------------------------
// MAJORITY_GOSSIP

/// The push-sum epoch that carries one option's preference share (Java `VoteCapability.epoch`):
/// `vote:<voteId>:<option>`.
pub fn preference_epoch(vote_id: &str, option: &str) -> String {
    format!("vote:{vote_id}:{option}")
}

/// What `VoteCapability.castPreference` starts on the aggregator: for each option, its epoch
/// ([`preference_epoch`]) with 1.0 for the preferred option and 0.0 for the others. Every
/// participant casts over the same aggregator and ticks it to convergence, so each option's
/// estimate is its share of the fleet.
pub fn preference_shares(vote_id: &str, options: &[&str], preference: &str) -> Vec<(String, f64)> {
    options
        .iter()
        .map(|option| {
            let share = if *option == preference { 1.0 } else { 0.0 };
            (preference_epoch(vote_id, option), share)
        })
        .collect()
}

/// `VoteCapability.leader`: the option with the highest estimated share (the first on a tie), or
/// `None` before any estimate. `estimate` answers the aggregator's estimate for an epoch.
pub fn leader(
    estimate: impl Fn(&str) -> Option<f64>,
    vote_id: &str,
    options: &[&str],
) -> Option<String> {
    let mut best: Option<&str> = None;
    let mut best_share = -1.0;
    for option in options {
        if let Some(share) = estimate(&preference_epoch(vote_id, option))
            && share > best_share
        {
            best = Some(option);
            best_share = share;
        }
    }
    best.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_map;

    fn ballot_state(issuer: &str, payload: &Map, attested: bool, completed: bool) -> Map {
        let mut state = cbor_map! {
            "record" => cbor_map! {
                "type" => BALLOT_TYPE,
                "issuer" => issuer,
                "payload" => cbor::encode(&Value::Map(payload.clone())),
            },
            "adds" => vec![cbor_map! { "replica" => "p", "counter" => 1 }],
            "removes" => Vec::<Value>::new(),
            "completed" => completed,
        }
        .into_map()
        .unwrap();
        if attested {
            state.insert("agentCertificate", cbor_map! { "agent" => issuer });
        }
        state
    }

    fn proposal_state(payload: &Map) -> Map {
        let mut state = ballot_state("p/x", payload, false, false);
        if let Some(Value::Map(record)) = state.get_mut("record") {
            record.insert("type", PROPOSAL_TYPE);
        }
        state
    }

    #[test]
    fn granularity_names_round_trip() {
        for granularity in [Granularity::Peer, Granularity::Agent] {
            assert_eq!(Granularity::parse(granularity.as_str()), Some(granularity));
        }
        assert_eq!(Granularity::parse("peer"), None);
        assert_eq!(Granularity::default(), Granularity::Peer);
    }

    #[test]
    fn tally_counts_first_ballots_per_identity() {
        let states = [
            ballot_state("p/a", &ballot_payload("q", "yes", "p/a"), true, false),
            ballot_state("p/b", &ballot_payload("q", "no", "p/b"), true, false),
            ballot_state("r/a", &ballot_payload("q", "no", "r/a"), false, false),
            ballot_state("s/a", &ballot_payload("q", "maybe", "s/a"), true, false),
            ballot_state("t/a", &ballot_payload("q", "no", "t/a"), true, true),
            ballot_state("u/a", &ballot_payload("other", "no", "u/a"), true, false),
        ];
        let peer = tally(&states, "q", None, Granularity::Peer, None);
        assert_eq!(
            peer.iter().collect::<Vec<_>>(),
            [("yes", 1), ("no", 1), ("maybe", 1)]
        );
        let offered = tally(&states, "q", Some(&["no", "yes"]), Granularity::Agent, None);
        assert_eq!(offered.iter().collect::<Vec<_>>(), [("no", 1), ("yes", 1)]);
        assert_eq!(offered.voters(), 2);
        let only_b = |issuer: &str| issuer == "p/b";
        let narrowed = tally(&states, "q", None, Granularity::Agent, Some(&only_b));
        assert_eq!(narrowed.iter().collect::<Vec<_>>(), [("no", 1)]);
        assert_eq!(narrowed.to_map().get("no"), Some(&Value::from(1)));
    }

    #[test]
    fn decision_waits_for_quorum_and_breaks_ties_in_java_order() {
        let open = proposal_state(&proposal_payload("q", "Ship?", &["yes", "no"], 2));
        let mut states = vec![
            open.clone(),
            ballot_state("p/a", &ballot_payload("q", "yes", "p/a"), false, false),
        ];
        assert_eq!(decision(&states, "q", Granularity::Peer, None), None);
        states.push(ballot_state(
            "r/a",
            &ballot_payload("q", "no", "r/a"),
            false,
            false,
        ));
        let decided = decision(&states, "q", Granularity::Peer, None).unwrap();
        assert_eq!(decided.winner, "no");
        assert_eq!(decided.tally.voters(), 2);
        assert_eq!(decision(&states, "unknown", Granularity::Peer, None), None);
        let found = proposals(&states);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].question.as_deref(), Some("Ship?"));
        // A malformed proposal is skipped, and a later well-formed one with the same id is read.
        let malformed = proposal_state(
            &cbor_map! { "proposalId" => "q2", "options" => vec![Value::from(1)] }
                .into_map()
                .unwrap(),
        );
        let good = proposal_state(&proposal_payload("q2", "", &["a"], 0));
        assert_eq!(
            proposal([&malformed, &good], "q2").map(|p| p.options),
            Some(vec!["a".to_owned()])
        );
    }

    #[test]
    fn leader_reads_the_highest_estimate() {
        let estimates = |epoch: &str| match epoch {
            "vote:v:a" => Some(0.25),
            "vote:v:b" => Some(0.75),
            _ => None,
        };
        assert_eq!(
            leader(estimates, "v", &["a", "b", "c"]).as_deref(),
            Some("b")
        );
        assert_eq!(leader(|_| None, "v", &["a"]), None);
        assert_eq!(
            preference_shares("v", &["a", "b"], "b"),
            [("vote:v:a".to_owned(), 0.0), ("vote:v:b".to_owned(), 1.0)]
        );
    }
}
