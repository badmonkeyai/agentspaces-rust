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

//! The QUORUM tally over folded ballots, against the golden vectors Java produced
//! (`test_golden.py`'s `test_three_names_from_one_peer_tally_as_one_voter`): three peer-signed
//! ballots under three names from one peer count as one voter per peer and as nobody per agent,
//! a `permits` answer narrows, and a forged voter field never counts. Ballots and proposals
//! written here go through the real write path (`records::entry_state`) and the real fold.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::{FoldContext, FoldOutcome, SpaceStore};
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::records::{EntryWrite, entry_state, sign_state, signed_claim, take_claim};
use agentspaces_wire::revocation::Registry;
use agentspaces_wire::time::parse_instant_millis;
use agentspaces_wire::vote::{
    BALLOT_TYPE, Granularity, PROPOSAL_TYPE, Proposal, ballot_payload, ballots, decision,
    live_vote_states, proposal, proposal_payload, proposals, tally,
};
use common::{hex, s};

const OPTIONS: [&str; 2] = ["approve", "reject"];

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn subordinate() -> AgentIdentity {
    let key = Identity::from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap();
    peer()
        .subordinate("python", s("certificate_verify_at"), "PT24H", Some(key))
        .unwrap()
}

fn verify_at() -> i64 {
    parse_instant_millis(s("certificate_verify_at")).unwrap()
}

fn proposal_id() -> &'static str {
    s("vote_three_names_one_peer_proposal")
}

fn state_of(name: &str) -> Map {
    let delta = cbor::decode(&hex(name)).unwrap().into_map().unwrap();
    delta.get("state").unwrap().as_map().unwrap().clone()
}

/// A replica at `certificate_verify_at` holding the three golden ballots, folded in order.
fn golden_replica() -> (SpaceStore, Registry) {
    let registry = Registry::default();
    let mut store = SpaceStore::new();
    let ctx = FoldContext::new(verify_at(), &registry);
    for i in 1..=3 {
        let state = state_of(&format!("vote_three_names_one_peer_delta_{i}"));
        assert_eq!(store.fold_state(&state, &ctx), FoldOutcome::Applied, "{i}");
    }
    (store, registry)
}

/// A signed write of `payload` as an entry of `type_name`, by `writer` under `name` (or as
/// `agent`), stamped at the golden stamp.
fn write(
    entry_id: &str,
    type_name: &str,
    payload: &Map,
    writer: &Identity,
    name: &str,
    agent: Option<&AgentIdentity>,
) -> Map {
    let payload = cbor::encode(&Value::Map(payload.clone()));
    let issued = format!(
        "{}:0:{}",
        s("hlc_encoded").split(':').next().unwrap(),
        writer.peer_id()
    );
    let write = EntryWrite {
        entry_id,
        space_id: s("space_id"),
        type_name,
        payload: Some(&payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: &issued,
        expires_at_millis: verify_at() + 3_600_000,
        counter: 1,
    };
    entry_state(
        &write,
        writer,
        name,
        agent.map(|agent| (agent, issued.as_str())),
    )
    .unwrap()
}

fn counts(store: &SpaceStore, granularity: Granularity) -> Vec<(String, u64)> {
    tally(
        store.state_values(),
        proposal_id(),
        Some(&OPTIONS),
        granularity,
        None,
    )
    .iter()
    .map(|(option, votes)| (option.to_owned(), votes))
    .collect()
}

fn pairs(list: &[(&str, u64)]) -> Vec<(String, u64)> {
    list.iter()
        .map(|(option, votes)| ((*option).to_owned(), *votes))
        .collect()
}

#[test]
fn three_names_from_one_peer_tally_as_one_voter() {
    let (store, _) = golden_replica();
    assert_eq!(store.len(), 3);
    let found = ballots(store.state_values(), proposal_id());
    assert_eq!(found.len(), 3);
    for ballot in &found {
        let issuer = ballot.issuer().unwrap();
        assert!(issuer.starts_with(&format!("{}/", s("peer_id"))));
        assert_eq!(ballot.voter(), Some(issuer));
        assert_eq!(ballot.option(), Some("approve"));
        assert!(!ballot.is_attested());
        // The ballot payload is Java's record, field for field.
        let payload = ballot_payload(proposal_id(), "approve", issuer);
        assert_eq!(
            ballot.record.get("payload").and_then(Value::as_bytes),
            Some(cbor::encode(&Value::Map(payload)).as_slice())
        );
        assert_eq!(
            ballot.record.get("type").and_then(Value::as_str),
            Some(BALLOT_TYPE)
        );
    }
    // One voter per peer; nobody per agent, since no ballot is agent-attested.
    assert_eq!(
        counts(&store, Granularity::Peer),
        pairs(&[("approve", 1), ("reject", 0)])
    );
    assert_eq!(
        counts(&store, Granularity::Agent),
        pairs(&[("approve", 0), ("reject", 0)])
    );
    assert!(ballots(store.state_values(), "another-proposal").is_empty());
}

#[test]
fn permits_narrows_the_electorate() {
    let (store, _) = golden_replica();
    let nobody = |_: &str| false;
    let everyone = tally(
        store.state_values(),
        proposal_id(),
        None,
        Granularity::Peer,
        None,
    );
    assert_eq!(everyone.count("approve"), 1);
    let refused = tally(
        store.state_values(),
        proposal_id(),
        None,
        Granularity::Peer,
        Some(&nobody),
    );
    assert!(refused.is_empty()); // `{}`: no options to zero-fill, nothing counted
    assert_eq!(refused.get("approve"), None);
    // Refusing the first name leaves the peer counted once through another of its names.
    let one = format!("{}/one", s("peer_id"));
    let not_one = |agent: &str| agent != one;
    let narrowed = tally(
        store.state_values(),
        proposal_id(),
        Some(&OPTIONS),
        Granularity::Peer,
        Some(&not_one),
    );
    assert_eq!(narrowed.count("approve"), 1);
    assert_eq!(narrowed.voters(), 1);
}

#[test]
fn a_forged_voter_field_never_counts() {
    // test_golden.py: rewrite the first ballot's issuer; the other two still make one peer.
    let (store, _) = golden_replica();
    let mut forged: Vec<Map> = store.state_values().cloned().collect();
    let first = &mut forged[0];
    if let Some(Value::Map(record)) = first.get_mut("record") {
        record.insert("issuer", peer().agent("someone-else"));
    }
    let counted = tally(&forged, proposal_id(), None, Granularity::Peer, None);
    assert_eq!(counted.get("approve"), Some(1));

    // A stranger's ballot claiming to be the golden peer's agent is skipped; its own counts.
    let stranger = Identity::from_seed(&[7; 32]);
    let registry = Registry::default();
    let ctx = FoldContext::new(verify_at(), &registry);
    let mut replica = SpaceStore::new();
    let impostor = write(
        "55555555-0000-0000-0000-000000000001",
        BALLOT_TYPE,
        &ballot_payload(proposal_id(), "reject", &peer().agent("one")),
        &stranger,
        "mallory",
        None,
    );
    assert_eq!(
        replica.fold_state(&impostor, &ctx),
        FoldOutcome::Applied,
        "authentic as the stranger's entry"
    );
    let reject_only = ["reject"];
    let tallied = |store: &SpaceStore| {
        tally(
            store.state_values(),
            proposal_id(),
            Some(&reject_only),
            Granularity::Peer,
            None,
        )
        .count("reject")
    };
    assert_eq!(tallied(&replica), 0);
    let honest = write(
        "55555555-0000-0000-0000-000000000002",
        BALLOT_TYPE,
        &ballot_payload(proposal_id(), "reject", &stranger.agent("mallory")),
        &stranger,
        "mallory",
        None,
    );
    assert_eq!(replica.fold_state(&honest, &ctx), FoldOutcome::Applied);
    assert_eq!(tallied(&replica), 1);
}

#[test]
fn agent_granularity_counts_attested_ballots_once_per_agent() {
    let (mut store, registry) = golden_replica();
    let ctx = FoldContext::new(verify_at(), &registry);
    let agent = subordinate();
    for (i, option) in ["reject", "approve"].into_iter().enumerate() {
        let ballot = write(
            &format!("66666666-0000-0000-0000-00000000000{i}"),
            BALLOT_TYPE,
            &ballot_payload(proposal_id(), option, agent.agent_id()),
            &peer(),
            "python",
            Some(&agent),
        );
        assert!(ballot.get("agentCertificate").is_some());
        assert_eq!(store.fold_state(&ballot, &ctx), FoldOutcome::Applied);
    }
    // Per agent: the attested agent's first ballot counts; the peer-asserted names do not.
    assert_eq!(
        counts(&store, Granularity::Agent),
        pairs(&[("approve", 0), ("reject", 1)])
    );
    // Per peer: the golden peer's first ballot (a peer-signed "approve") counts, once.
    assert_eq!(
        counts(&store, Granularity::Peer),
        pairs(&[("approve", 1), ("reject", 0)])
    );
}

#[test]
fn a_decision_closes_at_quorum() {
    let (mut store, registry) = golden_replica();
    let ctx = FoldContext::new(verify_at(), &registry);
    assert!(decision(store.state_values(), proposal_id(), Granularity::Peer, None).is_none());
    let open = write(
        "77777777-0000-0000-0000-000000000001",
        PROPOSAL_TYPE,
        &proposal_payload(proposal_id(), "Approve the golden plan?", &OPTIONS, 1),
        &peer(),
        "chair",
        None,
    );
    assert_eq!(store.fold_state(&open, &ctx), FoldOutcome::Applied);
    let expected = Proposal {
        proposal_id: proposal_id().to_owned(),
        question: Some("Approve the golden plan?".to_owned()),
        options: OPTIONS.iter().map(|option| (*option).to_owned()).collect(),
        quorum: 1,
    };
    assert_eq!(
        proposals(store.state_values()),
        std::slice::from_ref(&expected)
    );
    assert_eq!(
        proposal(store.state_values(), proposal_id()),
        Some(expected)
    );
    let decided = decision(store.state_values(), proposal_id(), Granularity::Peer, None).unwrap();
    assert_eq!(decided.winner, "approve");
    assert_eq!(decided.proposal_id, proposal_id());
    assert_eq!(decided.granularity, Granularity::Peer);
    let tally: Vec<_> = decided.tally.iter().collect();
    assert_eq!(tally, [("approve", 1), ("reject", 0)]);
    // Per agent nobody voted, so nothing is decided.
    assert!(
        decision(
            store.state_values(),
            proposal_id(),
            Granularity::Agent,
            None
        )
        .is_none()
    );
    // A proposal needing two distinct voters stays open on one peer's three names.
    let (mut short, registry) = golden_replica();
    let ctx = FoldContext::new(verify_at(), &registry);
    let two = write(
        "77777777-0000-0000-0000-000000000002",
        PROPOSAL_TYPE,
        &proposal_payload(proposal_id(), "Approve?", &OPTIONS, 2),
        &peer(),
        "chair",
        None,
    );
    assert_eq!(short.fold_state(&two, &ctx), FoldOutcome::Applied);
    assert!(decision(short.state_values(), proposal_id(), Granularity::Peer, None).is_none());
}

/// A peer-signed write of `payload` as an entry of `type_name` by `writer` under `name`, stamped
/// at the golden stamp, whose write lease lapses at `expires`.
fn write_until(
    entry_id: &str,
    type_name: &str,
    payload: &Map,
    writer: &Identity,
    name: &str,
    expires: i64,
) -> Map {
    let payload = cbor::encode(&Value::Map(payload.clone()));
    let issued = format!(
        "{}:0:{}",
        s("hlc_encoded").split(':').next().unwrap(),
        writer.peer_id()
    );
    let write = EntryWrite {
        entry_id,
        space_id: s("space_id"),
        type_name,
        payload: Some(&payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: &issued,
        expires_at_millis: expires,
        counter: 1,
    };
    entry_state(&write, writer, name, None).unwrap()
}

/// Java's vote reads its proposal and ballots through the space, which returns only
/// available entries (`availableRecords`: present, an unlapsed WRITE lease, no claim in force).
/// Through `live_vote_states` a lapsed or claimed ballot or proposal is not read, so the decision
/// waits, or reopens when its ballots lapse, as Java's does; `state_values` still counts every
/// present state, as `vote.py` does.
#[test]
fn a_lapsed_or_claimed_vote_entry_is_not_read_as_java_reads_it() {
    const VOTE: &str = "lapse";
    let registry = Registry::default();
    let ctx = FoldContext::new(verify_at(), &registry);
    let mut store = SpaceStore::new();
    let voter = Identity::from_seed(&[9; 32]);
    let hour = 3_600_000;
    let open = write_until(
        "88888888-0000-0000-0000-000000000001",
        PROPOSAL_TYPE,
        &proposal_payload(VOTE, "Ship?", &OPTIONS, 1),
        &peer(),
        "chair",
        verify_at() + 2 * hour,
    );
    let ballot_id = "88888888-0000-0000-0000-000000000002";
    let ballot = write_until(
        ballot_id,
        BALLOT_TYPE,
        &ballot_payload(VOTE, "approve", &voter.agent("v")),
        &voter,
        "v",
        verify_at() + hour,
    );
    assert_eq!(store.fold_state(&open, &ctx), FoldOutcome::Applied);
    assert_eq!(store.fold_state(&ballot, &ctx), FoldOutcome::Applied);
    let decided_at = |store: &SpaceStore, at: i64| {
        decision(live_vote_states(store, at), VOTE, Granularity::Peer, None)
            .map(|decided| decided.winner)
    };

    // Both live: decided.
    let live = verify_at() + 1_000;
    assert_eq!(decided_at(&store, live).as_deref(), Some("approve"));
    assert_eq!(live_vote_states(&store, live).len(), 2);
    // The ballot's lease lapsed (Java: now >= expiresAtMillis): the decision reopens.
    let ballot_lapsed = verify_at() + hour;
    assert_eq!(decided_at(&store, ballot_lapsed), None);
    assert!(proposal(live_vote_states(&store, ballot_lapsed), VOTE).is_some());
    assert_eq!(
        tally(
            live_vote_states(&store, ballot_lapsed),
            VOTE,
            Some(&OPTIONS),
            Granularity::Peer,
            None
        )
        .voters(),
        0
    );
    // The proposal lapsed too: no proposal, no decision.
    let all_lapsed = verify_at() + 2 * hour;
    assert!(proposal(live_vote_states(&store, all_lapsed), VOTE).is_none());
    assert!(proposals(live_vote_states(&store, all_lapsed)).is_empty());
    assert_eq!(decided_at(&store, all_lapsed), None);
    // Every held state still counts over state_values, as vote.py reads them.
    assert!(decision(store.state_values(), VOTE, Granularity::Peer, None).is_some());

    // A claim in force on the ballot hides it; once the claim lapses the ballot counts again.
    let holder = Identity::from_seed(&[10; 32]);
    let claim = take_claim(
        ballot_id,
        s("space_id"),
        1,
        &format!("{live}:0:{}", holder.peer_id()),
        &holder.agent("taker"),
        0.0,
        live + 60_000,
    );
    let signed = signed_claim(&claim, &holder, None).unwrap();
    let live_ctx = FoldContext::new(live, &registry);
    assert_eq!(
        store.fold_claim(ballot_id, &signed, &live_ctx),
        FoldOutcome::Applied
    );
    assert_eq!(decided_at(&store, live), None);
    assert!(ballots(live_vote_states(&store, live), VOTE).is_empty());
    assert_eq!(
        decided_at(&store, live + 60_000).as_deref(),
        Some("approve")
    );

    // The zero-voter guard is kept on purpose: a quorum-0 proposal (Java's propose refuses one)
    // never closes without a vote, where Java would close it with none.
    let zero = write_until(
        "88888888-0000-0000-0000-000000000003",
        PROPOSAL_TYPE,
        &proposal_payload("zero", "Nobody?", &OPTIONS, 0),
        &peer(),
        "chair",
        verify_at() + hour,
    );
    assert_eq!(store.fold_state(&zero, &ctx), FoldOutcome::Applied);
    assert!(proposal(live_vote_states(&store, live), "zero").is_some());
    assert!(
        decision(
            live_vote_states(&store, live),
            "zero",
            Granularity::Peer,
            None
        )
        .is_none()
    );
}

/// Java's `liveRecords` lets only a WRITE lease lapse: a state whose lease register holds a
/// lease of another kind (`TAKE`) stays readable past its expiry, here as there.
#[test]
fn only_a_write_lease_lapses() {
    let registry = Registry::default();
    let ctx = FoldContext::new(verify_at(), &registry);
    let mut store = SpaceStore::new();
    let voter = Identity::from_seed(&[9; 32]);
    let hour = 3_600_000;
    let entry = "99999999-0000-0000-0000-000000000001";
    let mut ballot = write_until(
        entry,
        BALLOT_TYPE,
        &ballot_payload("kinds", "approve", &voter.agent("v")),
        &voter,
        "v",
        verify_at() + hour,
    );
    let mut lease = ballot
        .get("leaseValue")
        .and_then(Value::as_map)
        .unwrap()
        .clone();
    lease.insert("kind", "TAKE");
    ballot.insert("leaseValue", lease);
    let ballot = sign_state(&ballot, &voter, None).unwrap();
    assert_eq!(store.fold_state(&ballot, &ctx), FoldOutcome::Applied);
    let later = verify_at() + 2 * hour;
    assert_eq!(store.available(BALLOT_TYPE, later).len(), 1);
    assert_eq!(
        tally(
            live_vote_states(&store, later),
            "kinds",
            None,
            Granularity::Peer,
            None
        )
        .count("approve"),
        1
    );
}
