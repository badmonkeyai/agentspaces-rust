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

//! The space fold against the golden vectors Java produced (`test_golden.py`'s fold tests: the
//! agent-signed record that folds where its peer-signed state does not, agent-signed renew,
//! cancel, and complete, a completion without its claim, states out of their certificate's
//! window or beyond the drift ceiling, an out-of-window claim, a relabelled key epoch, and a
//! record under a renewed certificate judged at its signing time), plus the store's own rules:
//! the join, the freeze rule, the space and dot bindings, the claim bounds, take candidates, and
//! the entry bound. Each replica's clock is pinned at the vector's instant.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::{
    DEFAULT_MAX_ENTRIES, FoldContext, FoldOutcome, MAX_DOTS_PER_STATE, Refusal, SpaceStore,
    is_present, join, union_dots,
};
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::limits::{MAX_CLAIM_EPOCH_JUMP, MAX_DRIFT_MILLIS};
use agentspaces_wire::records::{sign_state, signed_claim, take_claim};
use agentspaces_wire::revocation::{CREDENTIAL_STREAM, Registry};
use agentspaces_wire::time::parse_instant_millis;
use agentspaces_wire::{cbor_array, cbor_map};
use common::{hex, s};

const ENTRY: &str = "11111111-2222-3333-4444-555555555555";
const RENEWED_ENTRY: &str = "44444444-5555-6666-7777-888888888888";
const TASK_TYPE: &str = "GoldenVectors$ResearchTask#v1";
const WRITE_EXPIRES: i64 = 1_735_693_200_000;
const HOUR: i64 = 3_600_000;

// ------------------------------------------------------------------------- helpers

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

/// The golden subordinate: `python`, issued at `certificate_verify_at` for a day.
fn subordinate() -> AgentIdentity {
    let key = Identity::from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap();
    peer()
        .subordinate("python", s("certificate_verify_at"), "PT24H", Some(key))
        .unwrap()
}

fn instant(iso: &str) -> i64 {
    parse_instant_millis(iso).unwrap()
}

fn verify_at() -> i64 {
    instant(s("certificate_verify_at"))
}

/// The physical milliseconds of the golden stamp `hlc_encoded`.
fn t0() -> i64 {
    s("hlc_encoded").split(':').next().unwrap().parse().unwrap()
}

/// `test_golden.py`'s `_stamp`: the golden stamp moved by `offset` milliseconds.
fn stamp(offset: i64, logical: u32) -> String {
    format!("{}:{logical}:{}", t0() + offset, s("peer_id"))
}

fn map(value: Value) -> Map {
    value.into_map().unwrap()
}

fn delta(name: &str) -> Map {
    map(cbor::decode(&hex(name)).unwrap())
}

/// The `state` of a golden delta.
fn state_of(name: &str) -> Map {
    delta(name).get("state").unwrap().as_map().unwrap().clone()
}

/// The signed `claim` of a golden delta and the entry id it travels under.
fn claim_of(name: &str) -> (String, Map) {
    let delta = delta(name);
    let entry = delta
        .get("claimEntry")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    (entry, delta.get("claim").unwrap().as_map().unwrap().clone())
}

/// A text field of a map.
fn text<'a>(map: &'a Map, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap()
}

/// A replica: a store, its group's revocations, and its pinned clock.
struct Replica {
    store: SpaceStore,
    registry: Registry,
    now: i64,
}

impl Replica {
    fn at(now: i64) -> Self {
        Replica {
            store: SpaceStore::new(),
            registry: Registry::new(None, Some(s("group_id").to_owned())),
            now,
        }
    }

    fn fold(&mut self, state: &Map) -> FoldOutcome {
        let ctx = FoldContext::new(self.now, &self.registry);
        self.store.fold_state(state, &ctx)
    }

    fn fold_claim(&mut self, entry_id: &str, signed: &Map) -> FoldOutcome {
        let ctx = FoldContext::new(self.now, &self.registry);
        self.store.fold_claim(entry_id, signed, &ctx)
    }

    /// Folds a golden delta as `peer.py`'s `_handle` does: its claim first, then its state.
    fn fold_delta(&mut self, name: &str) -> (Option<FoldOutcome>, Option<FoldOutcome>) {
        let delta = delta(name);
        let claim = match (delta.get("claimEntry"), delta.get("claim")) {
            (Some(Value::Text(entry)), Some(Value::Map(signed))) => {
                Some(self.fold_claim(entry, signed))
            }
            _ => None,
        };
        let state = match delta.get("state") {
            Some(Value::Map(state)) => Some(self.fold(state)),
            _ => None,
        };
        (claim, state)
    }

    fn ids(&self) -> Vec<&str> {
        self.store.states().map(|(entry_id, _)| entry_id).collect()
    }

    fn held(&self, entry_id: &str) -> &Map {
        self.store.state(entry_id).unwrap()
    }
}

const APPLIED: FoldOutcome = FoldOutcome::Applied;

fn refused(refusal: Refusal) -> FoldOutcome {
    FoldOutcome::Refused(refusal)
}

/// `state` with the given fields replaced, re-signed by the golden peer.
fn resigned(state: &Map, fields: &[(&str, Value)]) -> Map {
    let mut dto = state.clone();
    for (key, value) in fields {
        dto.insert(*key, value.clone());
    }
    sign_state(&dto, &peer(), None).unwrap()
}

/// A peer-signed claim of the golden peer on `ENTRY`.
fn peer_claim(epoch: i64, stamp: &str, holder: &str, expires: i64) -> Map {
    let claim = take_claim(ENTRY, s("space_id"), epoch, stamp, holder, 0.0, expires);
    signed_claim(&claim, &peer(), None).unwrap()
}

// ------------------------------------------------------------------------- test_golden.py

#[test]
fn an_attested_record_folds_only_with_an_agent_signed_state() {
    // test_subordinate_agent_certificate_and_record_match_java's fold: the peer-signed state of
    // the certified record is refused; the agent-signed state lands; the plain peer-signed
    // write of the same entry then joins it.
    let mut replica = Replica::at(verify_at());
    let attested = state_of("delta_with_certificate_cbor");
    assert!(attested.get("agentCertificate").unwrap().as_map().is_some());
    assert_eq!(replica.fold(&attested), refused(Refusal::UnverifiedState));
    assert!(replica.store.is_empty());

    let agent_signed = state_of("delta_agent_signed_cbor");
    assert_eq!(text(&agent_signed, "signer"), peer().agent("python"));
    assert_eq!(replica.fold(&agent_signed), APPLIED);
    assert!(!replica.fold(&state_of("delta_cbor")).is_refused());
    assert_eq!(replica.ids(), [ENTRY]);
    // The join keeps the first record and its certificate: the entry stays agent-attested.
    let held = replica.held(ENTRY);
    assert_eq!(
        held.get("record"),
        agent_signed.get("record"),
        "the record that folded first"
    );
    assert_eq!(
        held.get("agentCertificate"),
        agent_signed.get("agentCertificate")
    );
    assert_eq!(
        cbor::encode(held.get("agentCertificate").unwrap()),
        hex("agent_certificate_cbor")
    );
}

#[test]
fn agent_signed_renew_cancel_and_complete_fold() {
    // test_agent_signed_renew_cancel_and_complete_match_java_and_fold.
    let python = peer().agent("python");
    let adds = cbor_array![cbor_map! { "replica" => s("peer_id"), "counter" => 1 }];
    for name in ["renew", "cancel", "complete"] {
        let mut replica = Replica::at(verify_at());
        assert_eq!(replica.fold(&state_of("delta_agent_signed_cbor")), APPLIED);
        let vector = format!("delta_agent_{name}_cbor");
        let (claim, state) = replica.fold_delta(&vector);
        assert_eq!(state, Some(APPLIED), "{name}");
        let held = replica.held(ENTRY).clone();
        match name {
            "renew" => {
                assert_eq!(claim, None);
                assert_eq!(text(&held, "leaseStamp"), stamp(60_000, 0));
                let lease = held.get("leaseValue").unwrap();
                assert_eq!(
                    lease.get("expiresAtMillis").and_then(Value::as_i64),
                    Some(t0() + 7_200_000)
                );
                assert_eq!(
                    lease.get("holder").and_then(Value::as_str),
                    Some(python.as_str())
                );
                assert!(is_present(&held));
            }
            "cancel" => {
                assert_eq!(claim, None);
                assert_eq!(held.get("removes"), Some(&adds));
                assert!(!is_present(&held));
            }
            _ => {
                assert_eq!(claim, Some(APPLIED));
                assert_eq!(held.get("completed"), Some(&Value::Bool(true)));
                assert_eq!(
                    cbor::encode(held.get("stateCertificate").unwrap()),
                    cbor::encode(&Value::Map(subordinate().certificate().clone()))
                );
                assert!(!is_present(&held));
            }
        }
        // The transition is the most advanced signed state, kept verbatim for forwarding.
        assert_eq!(
            replica.store.signed_state(ENTRY),
            Some(&state_of(&vector)),
            "{name}"
        );
        // Replaying the original write rolls nothing back.
        assert_eq!(
            replica.fold(&state_of("delta_agent_signed_cbor")),
            FoldOutcome::Unchanged,
            "{name}"
        );
        assert_eq!(replica.held(ENTRY), &held, "{name}");
        assert_eq!(replica.fold(&state_of(&vector)), FoldOutcome::Unchanged);
    }
}

#[test]
fn a_completion_without_its_claim_is_refused() {
    let mut replica = Replica::at(verify_at());
    assert_eq!(replica.fold(&state_of("delta_agent_signed_cbor")), APPLIED);
    let complete = state_of("delta_agent_complete_cbor");
    assert_eq!(replica.fold(&complete), refused(Refusal::NoClaim)); // claim not folded
    assert_eq!(
        replica.held(ENTRY).get("completed"),
        Some(&Value::Bool(false))
    );
    // Claims before states: once the claim folds, the same completion lands.
    let (entry, signed) = claim_of("delta_agent_complete_cbor");
    assert_eq!(replica.fold_claim(&entry, &signed), APPLIED);
    assert_eq!(replica.fold(&complete), APPLIED);
    assert_eq!(
        replica.held(ENTRY).get("completed"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn a_state_signed_outside_its_window_or_beyond_the_drift_ceiling_is_refused() {
    let out_of_window = state_of("adv_agent_state_out_of_window_delta");
    assert_eq!(text(&out_of_window, "signedAt"), stamp(-HOUR, 0));
    let mut replica = Replica::at(verify_at());
    assert_eq!(
        replica.fold(&out_of_window),
        refused(Refusal::UnverifiedState)
    );
    assert!(replica.store.is_empty());
    // SPEC §9.2 F4 (v0.1.31): the certificate bounds `signedAt` by its window alone, and the
    // far-future rule judges how far it leads. The drift vector's `signedAt` lies eleven minutes
    // past the receiver's wall, so it is deferred: nothing merges, nobody is struck, and the
    // deferral counts once however often it is offered (the golden label says refused; SPEC
    // §9.2 records the corrected verdict).
    let drift = state_of("adv_agent_state_drift_delta");
    assert_eq!(
        text(&drift, "signedAt"),
        stamp(MAX_DRIFT_MILLIS + 60_000, 0)
    );
    let mut replica = Replica::at(verify_at());
    for _ in 0..3 {
        assert_eq!(replica.fold(&drift), FoldOutcome::Deferred);
    }
    assert!(replica.store.is_empty());
    assert_eq!(replica.store.stamps_far_future_deferred(), 1);
    assert_eq!(replica.store.stamps_far_future_refused(), 0);
    // The drift vector is inside the window: a receiver whose clock has caught up accepts it.
    let mut caught_up = Replica::at(t0() + 60_000);
    assert_eq!(
        caught_up.fold(&state_of("adv_agent_state_drift_delta")),
        APPLIED
    );
    assert_eq!(caught_up.ids(), [ENTRY]);
    // The out-of-window vector is refused at every clock.
    for now in [t0() - HOUR, t0(), t0() + 60_000, t0() + 23 * HOUR] {
        let mut replica = Replica::at(now);
        assert!(
            replica
                .fold(&state_of("adv_agent_state_out_of_window_delta"))
                .is_refused()
        );
    }
}

#[test]
fn an_out_of_window_agent_claim_is_refused() {
    let mut replica = Replica::at(verify_at());
    let (entry, signed) = claim_of("adv_claim_cert_out_of_window_delta");
    let claim = signed.get("claim").unwrap();
    assert_eq!(
        claim.get("stamp").and_then(Value::as_str),
        Some(stamp(-HOUR, 0).as_str())
    );
    assert_eq!(
        replica.fold_claim(&entry, &signed),
        refused(Refusal::UnverifiedClaim)
    );
    assert_eq!(replica.store.claim_count(), 0);
    let (entry, control) = claim_of("claim_delta_with_certificate_cbor");
    assert_eq!(replica.fold_claim(&entry, &control), APPLIED);
    let ids: Vec<_> = replica
        .store
        .claims()
        .map(|(entry_id, _)| entry_id)
        .collect();
    assert_eq!(ids, [ENTRY]);
    assert_eq!(replica.store.claim_proof(ENTRY), Some(&control));
    assert_eq!(
        replica.store.claim_of(ENTRY),
        control.get("claim").and_then(Value::as_map)
    );
}

#[test]
fn a_relabelled_key_epoch_never_verifies() {
    let relabelled = map(cbor::decode(&hex("adv_key_epoch_relabelled_record_cbor")).unwrap());
    let genuine = map(cbor::decode(&hex("entry_record_key_epoch_cbor")).unwrap());
    assert_eq!(relabelled.get("keyEpoch"), Some(&Value::from(3)));
    assert_eq!(relabelled.get("sig"), genuine.get("sig"));
    let state = state_of("adv_key_epoch_relabelled_delta");
    assert_eq!(state.get("record"), Some(&Value::Map(relabelled)));
    let mut replica = Replica::at(verify_at());
    assert_eq!(replica.fold(&state), refused(Refusal::UnverifiedRecord));
    assert!(replica.store.is_empty());
    let good = state_of("delta_key_epoch_cbor");
    assert_eq!(good.get("record"), Some(&Value::Map(genuine)));
    assert_eq!(replica.fold(&good), APPLIED);
    let record = replica.held(ENTRY).get("record").unwrap();
    assert_eq!(record.get("keyEpoch"), Some(&Value::from(2)));
}

#[test]
fn a_record_under_a_renewed_certificate_is_judged_at_signing_time() {
    let signed_at = instant(s("renewed_certificate_signed_at"));
    let state = state_of("delta_renewed_certificate_cbor");
    assert_eq!(
        cbor::encode(state.get("agentCertificate").unwrap()),
        hex("renewed_agent_certificate_cbor")
    );
    let mut replica = Replica::at(signed_at);
    assert_eq!(replica.fold(&state), APPLIED);
    assert_eq!(replica.ids(), [RENEWED_ENTRY]);
    // Long after the renewed certificate lapsed, the record is still judged at its stamp.
    let mut later = Replica::at(signed_at + 30 * HOUR);
    assert_eq!(later.fold(&state), APPLIED);
    // The certificate bounds the stamp by its window alone (SPEC §4.2, v0.1.30); the far-future
    // rule judges the lead. A receiver the stamp leads by more than an hour past its margin
    // refuses it as hostile, once per distinct state ...
    let mut behind = Replica::at(verify_at());
    assert_eq!(behind.fold(&state), refused(Refusal::StampFarFuture));
    assert_eq!(behind.fold(&state), refused(Refusal::StampFarFuture));
    assert!(behind.store.is_empty());
    assert_eq!(behind.store.stamps_far_future_refused(), 1);
    assert_eq!(behind.store.stamps_logical_refused(), 0);
    // ... a receiver within that hour defers it, and merges it once its wall has caught up.
    let mut skewed = Replica::at(signed_at - MAX_DRIFT_MILLIS - 30 * 60_000);
    assert_eq!(skewed.fold(&state), FoldOutcome::Deferred);
    assert!(skewed.store.is_empty());
    skewed.now = signed_at;
    assert_eq!(skewed.fold(&state), APPLIED);
    assert_eq!(skewed.store.stamps_far_future_deferred(), 1);
}

// ------------------------------------------------------------------------- the join

#[test]
fn the_join_unions_dots_takes_the_later_lease_and_keeps_completion() {
    let write = state_of("delta_agent_signed_cbor");
    let renew = state_of("delta_agent_renew_cbor");
    let cancel = state_of("delta_agent_cancel_cbor");
    let complete = state_of("delta_agent_complete_cbor");
    // Whatever the order, the CRDT fields converge.
    let forward = join(&join(&join(&write, &renew), &cancel), &complete);
    let backward = join(&join(&join(&write, &complete), &cancel), &renew);
    for field in ["adds", "removes", "leaseStamp", "leaseValue", "completed"] {
        assert_eq!(forward.get(field), backward.get(field), "{field}");
    }
    assert_eq!(text(&forward, "leaseStamp"), stamp(60_000, 0));
    assert_eq!(forward.get("completed"), Some(&Value::Bool(true)));
    assert_eq!(join(&forward, &write), forward);
    // The first state of an entry is stored as its own join.
    let mut replica = Replica::at(verify_at());
    assert_eq!(replica.fold(&write), APPLIED);
    assert_eq!(replica.held(ENTRY), &join(&write, &write));
    assert_eq!(replica.store.signed_state(ENTRY), Some(&write));
    assert_eq!(replica.fold(&write), FoldOutcome::Unchanged);
    assert_eq!(
        union_dots(write.get("adds"), cancel.get("removes")),
        union_dots(write.get("adds"), None)
    );
}

// ------------------------------------------------------------------------- revocation

fn revoke(registry: &mut Registry, kind: &str) {
    let now = instant("2026-06-01T00:00:00Z");
    let payload = hex(&format!("signed_credential_revocation_{kind}_cbor"));
    assert!(registry.accept(CREDENTIAL_STREAM, &payload, now), "{kind}");
}

#[test]
fn the_freeze_rule_keeps_history_and_refuses_what_follows() {
    // The golden peer retires its agent effective an hour before 2026-01-01: the 2025 history
    // folds, a renewal stamped after the effective instant does not, and the agent takes nothing.
    let mut replica = Replica::at(verify_at());
    revoke(&mut replica.registry, "agent");
    assert_eq!(replica.fold(&state_of("delta_cbor")), APPLIED);
    assert!(
        !replica
            .fold(&state_of("delta_agent_signed_cbor"))
            .is_refused()
    );
    let after = instant("2026-01-01T00:00:00Z");
    let late_stamp = format!("{after}:0:{}", s("peer_id"));
    let renewal = resigned(
        &state_of("delta_cbor"),
        &[
            ("leaseStamp", Value::from(late_stamp.as_str())),
            (
                "leaseValue",
                cbor_map! {
                    "holder" => peer().agent("python"),
                    "expiresAtMillis" => after + HOUR,
                    "kind" => "WRITE",
                },
            ),
        ],
    );
    assert_eq!(replica.fold(&renewal), refused(Refusal::Revoked));
    // The same renewal stamped before the effective instant folds, once the receiver's wall is
    // within the far-future margin of its stamp (an hour ahead, it waits as deferred).
    let early_stamp = stamp(HOUR, 0);
    let early = resigned(
        &state_of("delta_cbor"),
        &[("leaseStamp", Value::from(early_stamp.as_str()))],
    );
    assert_eq!(replica.fold(&early), FoldOutcome::Deferred);
    replica.now = verify_at() + HOUR;
    assert_eq!(replica.fold(&early), APPLIED);
    // A revoked holder takes nothing, whatever the claim's stamp.
    let (entry, signed) = claim_of("claim_delta_cbor");
    assert_eq!(
        replica.fold_claim(&entry, &signed),
        refused(Refusal::Revoked)
    );
}

#[test]
fn a_compromised_agent_key_refuses_everything_it_signed() {
    let mut replica = Replica::at(verify_at());
    revoke(&mut replica.registry, "agent_key");
    assert_eq!(
        replica.fold(&state_of("delta_agent_signed_cbor")),
        refused(Refusal::Revoked)
    );
    // The peer-signed write of the same entry carries no agent key: it folds.
    assert_eq!(replica.fold(&state_of("delta_cbor")), APPLIED);
    let (entry, attested) = claim_of("claim_delta_with_certificate_cbor");
    assert_eq!(
        replica.fold_claim(&entry, &attested),
        refused(Refusal::Revoked)
    );
    let (entry, plain) = claim_of("claim_delta_cbor");
    assert_eq!(replica.fold_claim(&entry, &plain), APPLIED);
}

#[test]
fn a_completion_by_a_holder_revoked_since_its_claim_is_refused() {
    let mut replica = Replica::at(verify_at());
    assert_eq!(replica.fold(&state_of("delta_agent_signed_cbor")), APPLIED);
    let (entry, signed) = claim_of("delta_agent_complete_cbor");
    assert_eq!(replica.fold_claim(&entry, &signed), APPLIED);
    revoke(&mut replica.registry, "agent_key");
    assert_eq!(
        replica.fold(&state_of("delta_agent_complete_cbor")),
        refused(Refusal::Revoked)
    );
    assert_eq!(
        replica.held(ENTRY).get("completed"),
        Some(&Value::Bool(false))
    );
}

// ------------------------------------------------------------------------- bindings and bounds

#[test]
fn a_store_bound_to_its_space_refuses_other_spaces() {
    let registry = Registry::default();
    let ctx = FoldContext::new(verify_at(), &registry);
    let (entry, signed) = claim_of("claim_delta_cbor");
    let mut ours = SpaceStore::new();
    let bound = ctx.with_space(s("space_id"));
    assert_eq!(ours.fold_state(&state_of("delta_cbor"), &bound), APPLIED);
    assert_eq!(ours.fold_claim(&entry, &signed, &bound), APPLIED);
    let mut theirs = SpaceStore::new();
    let other = ctx.with_space("z2zifgVUFH2KJqQSoZxoEsBTmVtcgYqDuemnhq9NS7L3b");
    assert_eq!(
        theirs.fold_state(&state_of("delta_cbor"), &other),
        refused(Refusal::ForeignSpace)
    );
    assert_eq!(
        theirs.fold_claim(&entry, &signed, &other),
        refused(Refusal::ForeignSpace)
    );
    assert!(theirs.is_empty() && theirs.claim_count() == 0);
}

#[test]
fn dots_must_name_the_issuers_peer_and_stay_bounded() {
    let own = |counter: i64| cbor_map! { "replica" => s("peer_id"), "counter" => counter };
    let base = state_of("delta_cbor");
    let mut replica = Replica::at(verify_at());
    // A validly signed state whose dot names another replica.
    let foreign = resigned(
        &base,
        &[(
            "adds",
            cbor_array![
                own(1),
                cbor_map! { "replica" => "zSomeoneElse", "counter" => 1 }
            ],
        )],
    );
    assert_eq!(replica.fold(&foreign), refused(Refusal::ForeignDots));
    // An inflated dot set is refused before any verification cost.
    let inflated = resigned(
        &base,
        &[(
            "adds",
            Value::Array((0..=MAX_DOTS_PER_STATE as i64).map(own).collect()),
        )],
    );
    assert_eq!(replica.fold(&inflated), refused(Refusal::TooManyDots));
    // A malformed lease stamp: Java cannot decode it, and the join cannot order it.
    let unstamped = resigned(&base, &[("leaseStamp", Value::from("garbage"))]);
    assert_eq!(replica.fold(&unstamped), refused(Refusal::MalformedStamp));
    assert!(replica.store.is_empty());
    // Two writes of the issuer's peer join into one entry with both dots.
    assert_eq!(replica.fold(&base), APPLIED);
    let rewrite = resigned(&base, &[("adds", cbor_array![own(2)])]);
    assert_eq!(replica.fold(&rewrite), APPLIED);
    assert_eq!(
        replica.held(ENTRY).get("adds"),
        Some(&cbor_array![own(1), own(2)])
    );
    // A forged state signature over the same fields is refused.
    let mut forged = rewrite.clone();
    forged.insert("adds", cbor_array![own(3)]);
    assert_eq!(replica.fold(&forged), refused(Refusal::UnverifiedState));
}

#[test]
fn claims_merge_by_the_lattice_within_their_bounds() {
    let python = peer().agent("python");
    let mut replica = Replica::at(verify_at());
    let (entry, plain) = claim_of("claim_delta_cbor");
    assert_eq!(replica.fold_claim(&entry, &plain), APPLIED);
    // The same claim agent-signed is the same lattice point: the held proof stays.
    let (_, attested) = claim_of("claim_delta_with_certificate_cbor");
    assert_eq!(
        replica.fold_claim(&entry, &attested),
        FoldOutcome::Unchanged
    );
    assert_eq!(replica.store.claim_proof(ENTRY), Some(&plain));
    // A higher epoch wins; one further than the epoch jump from it is refused.
    let second = peer_claim(2, &stamp(1, 0), &python, WRITE_EXPIRES);
    assert_eq!(replica.fold_claim(ENTRY, &second), APPLIED);
    let leap = peer_claim(
        3 + MAX_CLAIM_EPOCH_JUMP,
        &stamp(2, 0),
        &python,
        WRITE_EXPIRES,
    );
    assert_eq!(
        replica.fold_claim(ENTRY, &leap),
        refused(Refusal::OutOfBounds)
    );
    let reach = peer_claim(
        2 + MAX_CLAIM_EPOCH_JUMP,
        &stamp(2, 0),
        &python,
        WRITE_EXPIRES,
    );
    assert_eq!(replica.fold_claim(ENTRY, &reach), APPLIED);
    assert_eq!(
        replica
            .store
            .claim_of(ENTRY)
            .and_then(|claim| claim.get("epoch"))
            .and_then(Value::as_i64),
        Some(2 + MAX_CLAIM_EPOCH_JUMP)
    );
    // A claim travelling under another entry's key is a transplant.
    assert_eq!(
        replica.fold_claim("another-entry", &plain),
        refused(Refusal::ClaimMismatch)
    );
    // The receiver's own claim merges by the lattice alone.
    let own = peer_claim(
        3 + MAX_CLAIM_EPOCH_JUMP,
        &stamp(3, 0),
        &python,
        WRITE_EXPIRES,
    );
    assert_eq!(replica.store.merge_own_claim(ENTRY, &own), APPLIED);
    assert_eq!(
        replica.store.merge_own_claim(ENTRY, &plain),
        FoldOutcome::Unchanged
    );
}

#[test]
fn a_claim_predating_its_held_entry_or_contesting_late_is_refused() {
    let (entry, early) = claim_of("adv_claim_predates_issue_delta");
    // Without the entry the claim has nothing to predate.
    let mut blind = Replica::at(verify_at());
    assert_eq!(blind.fold_claim(&entry, &early), APPLIED);
    let mut holding = Replica::at(verify_at());
    assert_eq!(holding.fold(&state_of("delta_cbor")), APPLIED);
    assert_eq!(
        holding.fold_claim(&entry, &early),
        refused(Refusal::PredatesIssue)
    );
    assert_eq!(holding.store.claim_count(), 0);

    // A rival holder's claim older than the drift ceiling plus a settle window is a queue-jump;
    // a fresh rival claim, or the same holder's old one, is judged by the lattice.
    let now = t0() + HOUR;
    let mut replica = Replica::at(now);
    let (entry, held) = claim_of("claim_delta_cbor");
    assert_eq!(replica.fold_claim(&entry, &held), APPLIED);
    let rival = peer().agent("rival");
    let stale = peer_claim(1, &stamp(1, 0), &rival, WRITE_EXPIRES);
    assert_eq!(
        replica.fold_claim(ENTRY, &stale),
        refused(Refusal::LateContest)
    );
    let fresh_stamp = format!("{}:0:{}", now - 1_000, s("peer_id"));
    let fresh = peer_claim(1, &fresh_stamp, &rival, now + HOUR);
    assert_eq!(replica.fold_claim(ENTRY, &fresh), FoldOutcome::Unchanged);
    let own_old = peer_claim(2, &stamp(1, 0), &peer().agent("python"), now + HOUR);
    assert_eq!(replica.fold_claim(ENTRY, &own_old), APPLIED);
    // A wider settle window admits the stale rival, which then loses the lattice.
    let ctx = FoldContext::new(now, &replica.registry).with_settle_millis(HOUR);
    assert_eq!(
        replica.store.fold_claim(ENTRY, &stale, &ctx),
        FoldOutcome::Unchanged
    );
}

// ------------------------------------------------------------------------- takes

#[test]
fn available_lists_live_unclaimed_present_entries() {
    let names = |list: Vec<(&str, &Map)>| -> Vec<String> {
        list.into_iter().map(|(id, _)| id.to_owned()).collect()
    };
    let mut replica = Replica::at(verify_at());
    assert_eq!(replica.fold(&state_of("delta_agent_signed_cbor")), APPLIED);
    assert_eq!(
        names(replica.store.available(TASK_TYPE, verify_at())),
        [ENTRY]
    );
    assert!(replica.store.available("Other#v1", verify_at()).is_empty());
    assert!(replica.store.available(TASK_TYPE, WRITE_EXPIRES).is_empty());
    // A live claim holds it until the claim lapses.
    let (entry, signed) = claim_of("claim_delta_with_certificate_cbor");
    assert_eq!(replica.fold_claim(&entry, &signed), APPLIED);
    assert!(replica.store.available(TASK_TYPE, verify_at()).is_empty());
    // A renewal extends the write lease past the claim's: the entry is takeable again.
    assert_eq!(replica.fold(&state_of("delta_agent_renew_cbor")), APPLIED);
    let after_claim = WRITE_EXPIRES + 1;
    assert_eq!(
        names(replica.store.available(TASK_TYPE, after_claim)),
        [ENTRY]
    );
    // Withdrawn entries are not candidates.
    assert_eq!(replica.fold(&state_of("delta_agent_cancel_cbor")), APPLIED);
    assert!(replica.store.available(TASK_TYPE, after_claim).is_empty());
    let (_, complete) = replica.fold_delta("delta_agent_complete_cbor");
    assert_eq!(complete, Some(APPLIED));
    assert!(replica.store.available(TASK_TYPE, after_claim).is_empty());
}

#[test]
fn the_store_is_bounded_and_counts_what_it_refuses() {
    let signed_at = instant(s("renewed_certificate_signed_at"));
    let registry = Registry::default();
    let ctx = FoldContext::new(signed_at, &registry);
    let mut store = SpaceStore::with_max_entries(1);
    assert_eq!(store.max_entries(), 1);
    assert_eq!(SpaceStore::new().max_entries(), DEFAULT_MAX_ENTRIES);
    assert_eq!(
        store.fold_state(&state_of("delta_agent_signed_cbor"), &ctx),
        APPLIED
    );
    let renewed = state_of("delta_renewed_certificate_cbor");
    assert_eq!(store.fold_state(&renewed, &ctx), refused(Refusal::Full));
    assert_eq!(store.refused_inserts(), 1);
    // An entry already held keeps folding.
    assert_eq!(
        store.fold_state(&state_of("delta_agent_renew_cbor"), &ctx),
        APPLIED
    );
    let (entry, signed) = claim_of("claim_delta_cbor");
    assert_eq!(store.fold_claim(&entry, &signed, &ctx), APPLIED);
    assert_eq!(
        store.merge_own_claim("another-entry", &signed),
        refused(Refusal::Full)
    );
    assert_eq!(store.refused_inserts(), 2);
    // Removing an entry makes room; a removed entry folds again as new.
    assert!(store.remove(ENTRY).is_some());
    assert_eq!(store.claim_count(), 0);
    assert_eq!(store.fold_state(&renewed, &ctx), APPLIED);
    assert_eq!(store.len(), 1);
    assert!(format!("{store:?}").contains("refused_inserts: 2"));
}

#[test]
fn iteration_is_in_first_fold_order() {
    let mut replica = Replica::at(verify_at());
    let order = [3, 1, 2];
    for i in order {
        let name = format!("vote_three_names_one_peer_delta_{i}");
        assert_eq!(replica.fold_delta(&name), (None, Some(APPLIED)));
    }
    let expected: Vec<String> = order
        .iter()
        .map(|i| format!("33333333-4444-5555-6666-77777777777{i}"))
        .collect();
    assert_eq!(replica.ids(), expected);
    let signed: Vec<_> = replica.store.signed_states().map(|(id, _)| id).collect();
    assert_eq!(signed, expected);
    assert_eq!(replica.store.state_values().len(), 3);
}

#[test]
fn a_recordless_renewal_folds_over_the_held_record_and_waits_without_it() {
    // SPEC §7.3's recordless state delta: Java's state_delta_recordless_cbor renews the golden
    // entry without its record.
    let recordless = state_of("state_delta_recordless_cbor");
    let mut empty = Replica::at(t0());
    assert_eq!(empty.fold(&recordless), refused(Refusal::RecordPending));
    assert!(empty.store.is_empty());

    let mut holding = Replica::at(t0());
    assert_eq!(holding.fold(&state_of("delta_cbor")), APPLIED);
    assert_eq!(holding.fold(&recordless), APPLIED);
    assert_eq!(holding.fold(&recordless), FoldOutcome::Unchanged);
    // The store keeps the full form, so what it ships to others carries the record.
    let signed = holding.store.signed_state(ENTRY).unwrap();
    assert!(signed.get("record").is_some());
    assert!(signed.get("entryId").is_none());
    assert_eq!(
        signed.get("leaseStamp").and_then(Value::as_str),
        Some(stamp(60_000, 0).as_str())
    );
    // A recordless state that names no entry is malformed, and one that names another entry
    // waits for that entry's record.
    let mut nameless = recordless.clone();
    nameless.remove("entryId");
    assert_eq!(holding.fold(&nameless), refused(Refusal::Malformed));
    let mut elsewhere = recordless.clone();
    elsewhere.insert("entryId", RENEWED_ENTRY);
    assert_eq!(holding.fold(&elsewhere), refused(Refusal::RecordPending));
    // Re-signed under a forged key it is refused as any full state would be.
    let mut forged = recordless;
    forged.insert("stateSig", vec![0u8; 64]);
    assert_eq!(holding.fold(&forged), refused(Refusal::UnverifiedState));
}
