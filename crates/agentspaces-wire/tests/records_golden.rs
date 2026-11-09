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

//! Records, state transitions, deltas, and take claims against the golden vectors Java produced
//! (`test_golden.py`'s space write, subordinate record, agent transitions, take claims, lattice,
//! key epoch, and renewed certificate tests; `test_adversarial.py`'s hostile claims and
//! certificates, at the level of the pure checks). Ed25519 is deterministic, so every signature
//! matches byte for byte.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::limits::{MAX_CLAIM_EPOCH_JUMP, MAX_CLAIM_HOLD_MILLIS, MAX_DRIFT_MILLIS};
use agentspaces_wire::records::{
    EntryWrite, MAX_CLAIM_PREDATES_ISSUE_MILLIS, NULL_PAYLOAD, PayloadSource, RecordError,
    block_cid, claim_delta, claim_is_well_formed, claim_not_before_issue, claim_sort_key,
    claim_within_bounds, delta, entry_delta, entry_state, merge_claims, payload_source, sign_state,
    sign_view, sign_view_of, signed_claim, state_sign_view, state_sign_view_of, take_claim,
    verify_claim_proof, verify_record, verify_state_signature,
};
use agentspaces_wire::records::{is_recordless, state_entry_id, with_record, without_record};
use agentspaces_wire::time::parse_instant_millis;
use agentspaces_wire::{cbor_array, cbor_map};
use common::{hex, s};

const ENTRY: &str = "11111111-2222-3333-4444-555555555555";
const TASK_TYPE: &str = "GoldenVectors$ResearchTask#v1";
const WRITE_EXPIRES: i64 = 1_735_693_200_000;
const HOUR: i64 = 3_600_000;

// ------------------------------------------------------------------------- helpers

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn agent_key() -> Identity {
    Identity::from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap()
}

/// The golden subordinate: `python`, issued at `certificate_verify_at` for a day.
fn subordinate() -> AgentIdentity {
    peer()
        .subordinate(
            "python",
            s("certificate_verify_at"),
            "PT24H",
            Some(agent_key()),
        )
        .unwrap()
}

fn verify_at() -> i64 {
    parse_instant_millis(s("certificate_verify_at")).unwrap()
}

fn python() -> String {
    peer().agent("python")
}

fn decoded(name: &str) -> Value {
    cbor::decode(&hex(name)).unwrap()
}

fn map_of(name: &str) -> Map {
    decoded(name).into_map().unwrap()
}

fn map(value: Value) -> Map {
    value.into_map().unwrap()
}

fn encoded(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

/// The `state` of a golden delta.
fn state_of(name: &str) -> Map {
    map_of(name).get("state").unwrap().as_map().unwrap().clone()
}

/// The `claim` (a signed claim) of a golden delta.
fn signed_of(name: &str) -> Value {
    map_of(name).get("claim").unwrap().clone()
}

fn record_of(state: &Map) -> Map {
    state.get("record").unwrap().as_map().unwrap().clone()
}

/// The physical milliseconds of the golden stamp `hlc_encoded`.
fn t0() -> i64 {
    s("hlc_encoded").split(':').next().unwrap().parse().unwrap()
}

/// `test_golden.py`'s `_stamp`: the golden stamp moved by `offset` milliseconds.
fn stamp(offset: i64, logical: u32) -> String {
    format!("{}:{logical}:{}", t0() + offset, s("peer_id"))
}

fn golden_adds() -> Vec<Value> {
    vec![cbor_map! { "replica" => s("peer_id"), "counter" => 1 }]
}

fn write_lease() -> Value {
    cbor_map! {
        "holder" => python(),
        "expiresAtMillis" => WRITE_EXPIRES,
        "kind" => "WRITE",
    }
}

/// The golden record of `test_golden.py`'s space write, under the given signature.
fn golden_record(signature: &[u8]) -> Map {
    map(cbor_map! {
        "entryId" => ENTRY,
        "spaceId" => s("space_id"),
        "type" => TASK_TYPE,
        "payload" => hex("task_payload_cbor"),
        "payloadRef" => Value::Null,
        "issuer" => python(),
        "issued" => s("hlc_encoded"),
        "lease" => write_lease(),
        "tags" => Map::new(),
        "sig" => signature,
    })
}

/// The golden write, inline payload, peer dot counter 1.
fn golden_write(payload: &[u8]) -> EntryWrite<'_> {
    EntryWrite {
        entry_id: ENTRY,
        space_id: s("space_id"),
        type_name: TASK_TYPE,
        payload: Some(payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: s("hlc_encoded"),
        expires_at_millis: WRITE_EXPIRES,
        counter: 1,
    }
}

/// The verdict of the issuer rule on a non-completion state: the record, then the state
/// signature, with the record's issuer as the party (the fold's composition).
fn issuer_accepts(state: &Map, now_ms: i64) -> bool {
    let record = record_of(state);
    let issuer = record.get("issuer").and_then(Value::as_str).unwrap();
    let key = state
        .get("issuerPublicKey")
        .and_then(Value::as_bytes)
        .unwrap();
    let certificate = state.get("agentCertificate");
    let attested = certificate.is_some_and(|c| !c.is_null());
    verify_record(&record, key, certificate, now_ms)
        && verify_state_signature(state, issuer, key, attested, now_ms)
}

// ------------------------------------------------------------------------- space write

#[test]
fn space_write_matches_java() {
    let identity = peer();
    let payload = cbor::encode(&cbor_map! { "topic" => "golden vectors", "priority" => 3 });
    assert_eq!(payload, hex("task_payload_cbor"));

    let view = sign_view(
        ENTRY,
        s("space_id"),
        TASK_TYPE,
        Some(&payload),
        &python(),
        s("hlc_encoded"),
        None,
        None,
        None,
    );
    assert_eq!(encoded(&view), hex("sign_view_cbor"));
    let record_signature = identity.sign(&encoded(&view));
    assert_eq!(record_signature.as_slice(), hex("record_signature"));

    let state_view = state_sign_view(
        s("space_id"),
        ENTRY,
        &golden_adds(),
        &[],
        s("hlc_encoded"),
        &write_lease(),
        false,
        None,
        None,
    );
    assert_eq!(encoded(&state_view), hex("state_sign_view_cbor"));
    let state_signature = identity.sign(&encoded(&state_view));
    assert_eq!(state_signature.as_slice(), hex("state_signature"));

    let dto = map(cbor_map! {
        "record" => golden_record(&record_signature),
        "issuerPublicKey" => identity.public_raw(),
        "adds" => golden_adds(),
        "removes" => cbor_array![],
        "leaseStamp" => s("hlc_encoded"),
        "leaseValue" => write_lease(),
        "completed" => false,
        "stateSig" => state_signature,
    });
    assert_eq!(encoded(&dto), hex("entry_state_dto_cbor"));
    assert_eq!(delta(Some(&dto), None), hex("delta_cbor"));

    // The builders produce the same bytes from the write's inputs.
    let write = golden_write(&payload);
    let built = entry_state(&write, &identity, "python", None).unwrap();
    assert_eq!(encoded(&built), hex("entry_state_dto_cbor"));
    assert_eq!(
        entry_delta(&write, &identity, "python", None).unwrap(),
        hex("delta_cbor")
    );
    let mut unsigned = dto.clone();
    unsigned.remove("stateSig");
    assert_eq!(
        encoded(&sign_state(&unsigned, &identity, None).unwrap()),
        hex("entry_state_dto_cbor")
    );
    // Re-signing replaces the old signature in place of order, not beside it.
    assert_eq!(
        encoded(&sign_state(&dto, &identity, None).unwrap()),
        hex("entry_state_dto_cbor")
    );

    // A receiver recomputes both views from the decoded DTO and accepts it.
    let received = state_of("delta_cbor");
    assert_eq!(received, map_of("entry_state_dto_cbor"));
    let record = record_of(&received);
    assert_eq!(
        encoded(&sign_view_of(&record).unwrap()),
        hex("sign_view_cbor")
    );
    assert_eq!(
        encoded(&state_sign_view_of(&received).unwrap()),
        hex("state_sign_view_cbor")
    );
    assert!(verify_record(&record, identity.public_raw(), None, 0));
    assert!(verify_record(
        &record,
        identity.public_raw(),
        Some(&Value::Null),
        0
    ));
    assert!(issuer_accepts(&received, verify_at()));
    // A peer-signed state is refused for an agent-attested party.
    assert!(!verify_state_signature(
        &received,
        &python(),
        identity.public_raw(),
        true,
        0
    ));
}

#[test]
fn subordinate_record_matches_java() {
    let identity = peer();
    let agent = subordinate();
    let now = verify_at();
    let certificate = Value::Map(agent.certificate().clone());

    let signature = agent.sign(&hex("sign_view_cbor"));
    assert_eq!(signature.as_slice(), hex("record_signature_agent_key"));
    let record = golden_record(&signature);
    let dto = map(cbor_map! {
        "record" => record.clone(),
        "issuerPublicKey" => identity.public_raw(),
        "adds" => golden_adds(),
        "removes" => cbor_array![],
        "leaseStamp" => s("hlc_encoded"),
        "leaseValue" => write_lease(),
        "completed" => false,
        "stateSig" => hex("state_signature"),
        "agentCertificate" => certificate.clone(),
    });
    assert_eq!(encoded(&dto), hex("entry_state_with_certificate_cbor"));
    assert_eq!(delta(Some(&dto), None), hex("delta_with_certificate_cbor"));

    // TECH-SPEC §7.2's two-key rule.
    assert!(verify_record(
        &record,
        identity.public_raw(),
        Some(&certificate),
        now
    ));
    assert!(!verify_record(&record, identity.public_raw(), None, now));
    assert!(!verify_record(
        &record,
        agent.public_raw(),
        Some(&certificate),
        now
    ));
    let peer_signed = record_of(&state_of("delta_cbor"));
    assert!(!verify_record(
        &peer_signed,
        identity.public_raw(),
        Some(&certificate),
        now
    ));
    // Judged at the record's issue stamp: long after the certificate lapsed it still verifies,
    // and a stamp may lead the receiver by the drift ceiling and no more.
    assert!(verify_record(
        &record,
        identity.public_raw(),
        Some(&certificate),
        now + 30 * HOUR
    ));
    assert!(verify_record(
        &record,
        identity.public_raw(),
        Some(&certificate),
        t0() - MAX_DRIFT_MILLIS
    ));
    assert!(!verify_record(
        &record,
        identity.public_raw(),
        Some(&certificate),
        t0() - MAX_DRIFT_MILLIS - 1
    ));
    // A malformed issue stamp cannot be judged.
    let mut unstamped = record.clone();
    unstamped.insert("issued", "not-a-stamp");
    assert!(!verify_record(
        &unstamped,
        identity.public_raw(),
        Some(&certificate),
        now
    ));
    // That state is peer-signed on an agent-attested entry: refused (v0.1.13).
    assert!(!issuer_accepts(
        &state_of("delta_with_certificate_cbor"),
        now
    ));
}

#[test]
fn agent_signed_state_matches_java() {
    let identity = peer();
    let agent = subordinate();
    let now = verify_at();
    let hlc = s("hlc_encoded");

    let view = state_sign_view(
        s("space_id"),
        ENTRY,
        &golden_adds(),
        &[],
        hlc,
        &write_lease(),
        false,
        Some(&python()),
        Some(hlc),
    );
    assert_eq!(encoded(&view), hex("state_sign_view_agent_cbor"));
    let signature = agent.sign(&encoded(&view));
    assert_eq!(signature.as_slice(), hex("state_signature_agent_key"));

    // sign_state turns the peer-signed certified DTO into the agent-signed one.
    let certified = state_of("delta_with_certificate_cbor");
    let signed = sign_state(&certified, &identity, Some((&agent, hlc))).unwrap();
    assert_eq!(encoded(&signed), hex("entry_state_agent_signed_cbor"));
    assert_eq!(delta(Some(&signed), None), hex("delta_agent_signed_cbor"));
    // Re-signing as the agent is idempotent; as the peer it drops the agent fields again.
    assert_eq!(
        encoded(&sign_state(&signed, &identity, Some((&agent, hlc))).unwrap()),
        hex("entry_state_agent_signed_cbor")
    );
    assert_eq!(
        encoded(&sign_state(&signed, &identity, None).unwrap()),
        hex("entry_state_with_certificate_cbor")
    );

    // The whole agent write from its inputs.
    let payload = hex("task_payload_cbor");
    let write = golden_write(&payload);
    let built = entry_state(&write, &identity, "unused", Some((&agent, hlc))).unwrap();
    assert_eq!(encoded(&built), hex("entry_state_agent_signed_cbor"));
    assert_eq!(
        entry_delta(&write, &identity, "unused", Some((&agent, hlc))).unwrap(),
        hex("delta_agent_signed_cbor")
    );

    // A receiver: the view from the DTO, the record under the certificate, the state under the
    // certificate's agent key.
    let received = state_of("delta_agent_signed_cbor");
    assert_eq!(
        encoded(&state_sign_view_of(&received).unwrap()),
        hex("state_sign_view_agent_cbor")
    );
    assert!(issuer_accepts(&received, now));
    // The party must be exactly the signer.
    assert!(!verify_state_signature(
        &received,
        &identity.agent("other"),
        identity.public_raw(),
        true,
        now
    ));
}

#[test]
fn agent_renew_cancel_and_complete_match_java() {
    let identity = peer();
    let agent = subordinate();
    let now = verify_at();
    let python = python();
    let adds = golden_adds();
    let renewed_lease = cbor_map! {
        "holder" => python.as_str(),
        "expiresAtMillis" => t0() + 2 * HOUR,
        "kind" => "WRITE",
    };
    let hlc = s("hlc_encoded").to_owned();
    // (name, removes, leaseStamp, leaseValue, completed, signedAt)
    let cases = [
        (
            "renew",
            vec![],
            stamp(60_000, 0),
            renewed_lease,
            false,
            stamp(60_000, 1),
        ),
        (
            "cancel",
            adds.clone(),
            hlc.clone(),
            write_lease(),
            false,
            stamp(120_000, 0),
        ),
        (
            "complete",
            vec![],
            hlc.clone(),
            write_lease(),
            true,
            stamp(180_000, 0),
        ),
    ];
    let record = record_of(&state_of("delta_agent_signed_cbor"));
    let claim_proof = signed_of("claim_delta_with_certificate_cbor");
    let claim_proof = claim_proof.as_map().unwrap();
    for (name, removes, lease_stamp, lease_value, completed, signed_at) in cases {
        let view = state_sign_view(
            s("space_id"),
            ENTRY,
            &adds,
            &removes,
            &lease_stamp,
            &lease_value,
            completed,
            Some(&python),
            Some(&signed_at),
        );
        assert_eq!(
            encoded(&view),
            hex(&format!("state_sign_view_agent_{name}_cbor")),
            "{name}"
        );
        let unsigned = map(cbor_map! {
            "record" => record.clone(),
            "issuerPublicKey" => identity.public_raw(),
            "adds" => adds.clone(),
            "removes" => removes.clone(),
            "leaseStamp" => lease_stamp.as_str(),
            "leaseValue" => lease_value.clone(),
            "completed" => completed,
            "agentCertificate" => agent.certificate().clone(),
        });
        let signed = sign_state(&unsigned, &identity, Some((&agent, &signed_at))).unwrap();
        assert_eq!(
            signed.get("stateSig").and_then(Value::as_bytes).unwrap(),
            agent.sign(&encoded(&view)).as_slice(),
            "{name}"
        );
        assert_eq!(
            encoded(&signed),
            hex(&format!("entry_state_agent_{name}_cbor")),
            "{name}"
        );
        let bytes = if completed {
            delta(Some(&signed), Some((ENTRY, claim_proof)))
        } else {
            delta(Some(&signed), None)
        };
        assert_eq!(bytes, hex(&format!("delta_agent_{name}_cbor")), "{name}");

        // The receiver's verdict: the issuer for a renewal or cancellation, the claim holder
        // (authenticated by the proof that travels with it) for a completion.
        let received = state_of(&format!("delta_agent_{name}_cbor"));
        if completed {
            let delta = map_of("delta_agent_complete_cbor");
            let proof = delta.get("claim").unwrap();
            assert!(verify_claim_proof(proof, now));
            let holder = proof.get("claim").unwrap().get("holder").unwrap();
            let holder_key = proof.get("holderKey").and_then(Value::as_bytes).unwrap();
            let attested = proof.get("holderCertificate").is_some();
            assert!(verify_record(
                &record_of(&received),
                identity.public_raw(),
                received.get("agentCertificate"),
                now
            ));
            assert!(verify_state_signature(
                &received,
                holder.as_str().unwrap(),
                holder_key,
                attested,
                now
            ));
        } else {
            assert!(issuer_accepts(&received, now), "{name}");
        }
    }
}

// ------------------------------------------------------------------------- take claims

#[test]
fn take_claims_match_java() {
    let identity = peer();
    let now = verify_at();
    let claim = take_claim(
        ENTRY,
        s("space_id"),
        1,
        s("hlc_encoded"),
        &python(),
        0.0,
        WRITE_EXPIRES,
    );
    assert_eq!(encoded(&claim), hex("take_claim_cbor"));
    assert_eq!(
        identity.sign(&encoded(&claim)).as_slice(),
        hex("take_claim_signature")
    );
    let signed = signed_claim(&claim, &identity, None).unwrap();
    assert_eq!(claim_delta(ENTRY, &signed), hex("claim_delta_cbor"));
    assert!(claim_is_well_formed(&claim));
    assert!(verify_claim_proof(&Value::Map(signed), now));
    assert!(verify_claim_proof(&signed_of("claim_delta_cbor"), now));
    assert!(claim_within_bounds(&claim, 0, now));
    assert!(claim_not_before_issue(&claim, s("hlc_encoded")));
}

#[test]
fn agent_signed_claims_match_java() {
    let identity = peer();
    let agent = subordinate();
    let now = verify_at();
    let claim = map_of("take_claim_cbor");
    assert_eq!(
        agent.sign(&hex("take_claim_cbor")).as_slice(),
        hex("take_claim_agent_signature")
    );
    let signed = signed_claim(&claim, &identity, Some(&agent)).unwrap();
    // Without an agent the proof is byte-identical to the peer-signed one.
    assert_eq!(
        cbor::encode(&Value::Map(signed_claim(&claim, &identity, None).unwrap())),
        cbor::encode(&signed_of("claim_delta_cbor"))
    );
    assert_eq!(
        claim_delta(ENTRY, &signed),
        hex("claim_delta_with_certificate_cbor")
    );
    let proof = Value::Map(signed.clone());
    assert!(verify_claim_proof(&proof, now));
    assert!(verify_claim_proof(
        &signed_of("claim_delta_with_certificate_cbor"),
        now
    ));

    // An agent signature without its certificate (absent or null) is refused.
    let mut stripped = signed.clone();
    stripped.remove("holderCertificate");
    assert!(!verify_claim_proof(&Value::Map(stripped), now));
    let mut nulled = signed.clone();
    nulled.insert("holderCertificate", Value::Null);
    assert!(!verify_claim_proof(&Value::Map(nulled), now));
    // A peer signature beside a certificate is refused.
    let mut peer_signed = signed_claim(&claim, &identity, None).unwrap();
    peer_signed.insert("holderCertificate", agent.certificate().clone());
    assert!(!verify_claim_proof(&Value::Map(peer_signed), now));
    // Judged at the claim's own stamp: after the certificate lapsed it still verifies; a stamp
    // leading the receiver beyond the drift ceiling does not.
    assert!(verify_claim_proof(&proof, now + 23 * HOUR));
    assert!(verify_claim_proof(&proof, t0() - MAX_DRIFT_MILLIS));
    assert!(!verify_claim_proof(&proof, t0() - MAX_DRIFT_MILLIS - 1));
    // The holder key must hash to the holder's peer.
    let mut foreign = signed.clone();
    foreign.insert("holderKey", agent.public_raw());
    assert!(!verify_claim_proof(&Value::Map(foreign), now));
}

#[test]
fn claim_lattice_order_matches_the_java_merge() {
    let (e, sp) = ("entry-1", "space-1");
    let claim = |epoch, stamp: &str, holder: &str, bid, expires| {
        take_claim(e, sp, epoch, stamp, holder, bid, expires)
    };
    let wrap = |claim: &Map| map(cbor_map! { "claim" => claim.clone() });
    let winner = |a: &Map, b: &Map| {
        merge_claims(Some(&wrap(a)), &wrap(b))
            .get("claim")
            .unwrap()
            .as_map()
            .unwrap()
            .clone()
    };

    let base = claim(1, "100:0:node-a", "peer/a", 0.0, 1000);
    let rows = [
        // (other, the winner over base, why)
        (
            claim(2, "200:0:node-b", "peer/b", 0.0, 1000),
            "other",
            "epoch descending",
        ),
        (
            claim(1, "200:0:node-b", "peer/b", -1.0, 1000),
            "other",
            "bid ascending",
        ),
        (
            claim(1, "50:0:node-b", "peer/b", 0.0, 1000),
            "other",
            "stamp ascending",
        ),
        (
            claim(1, "100:1:node-a", "peer/a", 0.0, 1000),
            "base",
            "logical ascending",
        ),
        (
            claim(1, "100:0:node-b", "peer/a", 0.0, 1000),
            "base",
            "node ascending",
        ),
        (
            claim(1, "100:0:node-a", "peer/b", 0.0, 1000),
            "base",
            "holder ascending",
        ),
        (
            claim(1, "100:0:node-a", "peer/a", 0.0, 2000),
            "other",
            "expiry descending (a renewal)",
        ),
        (
            claim(1, "100:0:node-a", "peer/a", -0.0, 1000),
            "other",
            "Double.compare puts -0.0 first",
        ),
        (
            claim(0, "1:0:node-a", "peer/a", -5.0, 1),
            "base",
            "a lower epoch never wins",
        ),
    ];
    for (other, expected, why) in rows {
        let want = if expected == "base" { &base } else { &other };
        assert_eq!(&winner(&base, &other), want, "{why}");
        assert_eq!(&winner(&other, &base), want, "{why} (commuted)");
    }
    // Idempotent; and a tie keeps the first.
    assert_eq!(winner(&base, &base), base);
    let twin = take_claim("entry-2", sp, 1, "100:0:node-a", "peer/a", 0.0, 1000);
    assert_eq!(winner(&base, &twin), base);
    assert_eq!(winner(&twin, &base), twin);

    // Java String.compareTo is UTF-16 order: a supplementary character (a surrogate pair from
    // U+D83D) sorts before U+FF5E, the reverse of code point order.
    let emoji = claim(1, "100:0:node-a", "peer/\u{1F600}", 0.0, 1000);
    let fullwidth = claim(1, "100:0:node-a", "peer/\u{FF5E}", 0.0, 1000);
    assert_eq!(winner(&fullwidth, &emoji), emoji);
    assert_eq!(winner(&emoji, &fullwidth), emoji);

    // No first claim: the second. A claim with no lattice key never displaces one with a key.
    let nan = claim(9, "100:0:node-a", "peer/a", f64::NAN, 1000);
    assert!(claim_sort_key(&nan).is_none());
    assert_eq!(merge_claims(None, &wrap(&base)), wrap(&base));
    assert_eq!(winner(&base, &nan), base);
    assert_eq!(winner(&nan, &base), base);
    assert_eq!(merge_claims(Some(&Map::new()), &wrap(&base)), wrap(&base));
    assert_eq!(merge_claims(Some(&wrap(&base)), &Map::new()), wrap(&base));

    // wire.py's defaults for absent fields, and refusals for present malformed ones.
    let empty = Map::new();
    let key = claim_sort_key(&empty).unwrap();
    assert_eq!((key.epoch(), key.bid(), key.holder()), (0, 0.0, ""));
    assert!(claim_sort_key(&base).unwrap() < key);
    for (field, value) in [
        ("epoch", Value::from("1")),
        ("bid", Value::from("0")),
        ("stamp", Value::from("100:0:")),
        ("stamp", Value::from("-1:0:n")),
        ("stamp", Value::from("1:-1:n")),
        ("stamp", Value::from("1:0:a:b")),
        ("stamp", Value::from(100)),
        ("holder", Value::Null),
        ("expiresAtMillis", Value::Int(i128::from(i64::MAX) + 1)),
    ] {
        let mut bad = base.clone();
        bad.insert(field, value.clone());
        assert!(claim_sort_key(&bad).is_none(), "{field} = {value:?}");
    }
    // An integer bid reads as a double, as Jackson reads it.
    let mut integral = base.clone();
    integral.insert("bid", 0);
    assert_eq!(claim_sort_key(&integral), claim_sort_key(&base));

    // The merge is a semilattice join: every order of folding the same claims picks one winner.
    let pool = [
        base.clone(),
        claim(1, "50:0:node-b", "peer/b", 0.0, 1000),
        claim(1, "50:0:node-b", "peer/b", 0.0, 5000),
        claim(1, "50:0:node-a", "peer/c", 0.5, 1000),
        claim(2, "900:0:node-z", "peer/z", 3.0, 10),
        claim(2, "900:0:node-z", "peer/y", 3.0, 10),
    ];
    let expected = claim(2, "900:0:node-z", "peer/y", 3.0, 10);
    for rotation in 0..pool.len() {
        for reversed in [false, true] {
            let mut order: Vec<&Map> = pool
                .iter()
                .cycle()
                .skip(rotation)
                .take(pool.len())
                .collect();
            if reversed {
                order.reverse();
            }
            let mut held: Option<Map> = None;
            for claim in order {
                held = Some(merge_claims(held.as_ref(), &wrap(claim)));
            }
            assert_eq!(held.unwrap(), wrap(&expected));
        }
    }
}

// ------------------------------------------------------------------------- key epochs

#[test]
fn a_record_sealed_under_epoch_two_names_its_epoch() {
    let identity = peer();
    let record = map_of("entry_record_key_epoch_cbor");
    assert_eq!(record.get("keyEpoch"), Some(&Value::from(2)));
    let text = |name: &str| record.get(name).and_then(Value::as_str).unwrap();
    let payload = record.get("payload").and_then(Value::as_bytes).unwrap();
    let view = sign_view(
        text("entryId"),
        text("spaceId"),
        text("type"),
        Some(payload),
        text("issuer"),
        text("issued"),
        Some(2),
        None,
        None,
    );
    assert_eq!(encoded(&view), hex("sign_view_key_epoch_cbor"));
    assert_eq!(
        encoded(&sign_view_of(&record).unwrap()),
        hex("sign_view_key_epoch_cbor")
    );
    assert!(verify_record(&record, identity.public_raw(), None, 0));

    // A relabelled epoch keeps the signature and never verifies.
    let relabelled = map_of("adv_key_epoch_relabelled_record_cbor");
    assert_eq!(relabelled.get("keyEpoch"), Some(&Value::from(3)));
    assert_eq!(relabelled.get("sig"), record.get("sig"));
    assert!(!verify_record(&relabelled, identity.public_raw(), None, 0));
    let mut stripped = record.clone();
    stripped.remove("keyEpoch");
    assert!(!verify_record(&stripped, identity.public_raw(), None, 0));
    let mut textual = record.clone();
    textual.insert("keyEpoch", "2");
    assert!(sign_view_of(&textual).is_none());
    assert!(!verify_record(&textual, identity.public_raw(), None, 0));

    // The deltas carrying them.
    let genuine = state_of("delta_key_epoch_cbor");
    assert_eq!(record_of(&genuine), record);
    assert!(issuer_accepts(&genuine, verify_at()));
    assert!(!issuer_accepts(
        &state_of("adv_key_epoch_relabelled_delta"),
        verify_at()
    ));

    // The write builder reproduces the sealed record and its state byte for byte.
    let write = EntryWrite {
        key_epoch: Some(2),
        ..golden_write(payload)
    };
    let built = entry_state(&write, &identity, "python", None).unwrap();
    assert_eq!(
        encoded(&record_of(&built)),
        hex("entry_record_key_epoch_cbor")
    );
    assert_eq!(built, genuine);

    // A record without an epoch signs the v0.1.12 view, byte for byte.
    let plain = record_of(&map_of("entry_state_dto_cbor"));
    assert_eq!(
        encoded(&sign_view_of(&plain).unwrap()),
        hex("sign_view_cbor")
    );
}

/// The content-key epoch vectors around the sealed record (SPEC §11a.1, §11a.3, v0.1.13), as far
/// as this crate's primitives reach: the AAD the payload was sealed under, the sealed payload's
/// layout and its place in the record, and the epoch commitment the rotator signs over the
/// key's digest (Java `GroupKeyDistributor.EpochCommitment`). Opening the payload needs
/// AES-256-GCM, which this crate does not carry.
#[test]
fn the_epoch_two_key_vectors_hold_together() {
    let identity = peer();
    let key = hex("content_key_epoch_2");
    assert_eq!(key.len(), 32);
    assert_eq!(
        s("content_key_aad_epoch_2"),
        format!("{}|{ENTRY}|2", s("space_id"))
    );
    // nonce (12) || ciphertext (the payload's length) || tag (16), the record's payload.
    let sealed = hex("key_epoch_sealed_payload");
    assert_eq!(sealed.len(), 12 + hex("task_payload_cbor").len() + 16);
    let record = map_of("entry_record_key_epoch_cbor");
    assert_eq!(
        record.get("payload").and_then(Value::as_bytes),
        Some(sealed.as_slice())
    );

    // EpochCommitment{group, epoch, cutover, keyDigest = sha-256(key)}, signed by the rotator.
    let commitment = |key: &[u8]| {
        cbor::encode(&cbor_map! {
            "group" => s("group_id"),
            "epoch" => 2,
            "cutover" => "2025-01-01T00:00:00Z",
            "keyDigest" => crypto::port().sha256(key),
        })
    };
    let bytes = commitment(&key);
    assert_eq!(bytes, hex("epoch_commitment_cbor"));
    let proof = hex("epoch_proof_signature");
    assert_eq!(identity.sign(&bytes).as_slice(), proof.as_slice());
    assert!(Identity::verify(identity.public_raw(), &bytes, &proof));
    // Another key commits to another digest, which the proof does not cover.
    let other = commitment(&[0; 32]);
    assert_ne!(other, bytes);
    assert!(!Identity::verify(identity.public_raw(), &other, &proof));
}

// ------------------------------------------------------------------------- renewed certificate

#[test]
fn a_record_under_a_renewed_certificate_matches_java_and_is_judged_at_signing_time() {
    let identity = peer();
    let verify_at = verify_at();
    let signed_at = parse_instant_millis(s("renewed_certificate_signed_at")).unwrap();
    let mut agent = identity
        .renewing_subordinate("python", "PT24H", Some(agent_key()), verify_at)
        .unwrap();
    assert_eq!(encoded(agent.certificate()), hex("agent_certificate_cbor"));
    assert!(
        agent
            .renew_if_due(&identity, verify_at + 13 * HOUR)
            .unwrap()
    );
    let renewed = agent.certificate_covering(signed_at).unwrap().clone();
    assert_eq!(encoded(&renewed), hex("renewed_agent_certificate_cbor"));

    let python = python();
    let issued = format!("{signed_at}:0:{}", s("peer_id"));
    let state_stamp = format!("{signed_at}:1:{}", s("peer_id"));
    let entry = "44444444-5555-6666-7777-888888888888";
    let payload = hex("task_payload_cbor");
    let view = sign_view(
        entry,
        s("space_id"),
        TASK_TYPE,
        Some(&payload),
        &python,
        &issued,
        None,
        None,
        None,
    );
    assert_eq!(encoded(&view), hex("sign_view_renewed_certificate_cbor"));

    let write = EntryWrite {
        entry_id: entry,
        issued: &issued,
        expires_at_millis: signed_at + HOUR,
        counter: 21,
        ..golden_write(&payload)
    };
    let state = entry_state(&write, &identity, "python", Some((&agent, &state_stamp))).unwrap();
    assert_eq!(
        state.get("agentCertificate"),
        Some(&Value::Map(renewed.clone()))
    );
    assert_eq!(state.get("stateCertificate"), Some(&Value::Map(renewed)));
    assert_eq!(encoded(&state), hex("entry_state_renewed_certificate_cbor"));
    assert_eq!(
        entry_delta(&write, &identity, "python", Some((&agent, &state_stamp))).unwrap(),
        hex("delta_renewed_certificate_cbor")
    );

    // Receivers judge at the signing time: long after it the history stays valid, and a
    // receiver whose clock lags beyond the drift ceiling refuses it.
    let received = state_of("delta_renewed_certificate_cbor");
    assert!(issuer_accepts(&received, signed_at));
    assert!(issuer_accepts(&received, signed_at + 30 * HOUR));
    assert!(!issuer_accepts(&received, verify_at));
    // The first certificate does not cover the renewed record's stamp.
    let mut first = received.clone();
    first.insert("agentCertificate", decoded("agent_certificate_cbor"));
    assert!(!verify_record(
        &record_of(&first),
        identity.public_raw(),
        first.get("agentCertificate"),
        signed_at
    ));
}

// ------------------------------------------------------------------------- hostile claims

#[test]
fn hostile_claims_are_refused_by_the_proof_alone() {
    let now = verify_at();
    let clocks = [
        now,
        parse_instant_millis("2024-12-31T00:30:00Z").unwrap(),
        t0() + 60_000,
    ];
    for name in [
        "adv_claim_bad_signature_delta",
        "adv_claim_nan_bid_delta",
        "adv_claim_epoch_zero_delta",
        "adv_claim_eternal_delta",
        "adv_claim_cert_peer_signed_delta",
        "adv_claim_cert_expired_delta",
        "adv_claim_cert_wrong_holder_delta",
        "adv_claim_cert_out_of_window_delta",
    ] {
        let delta = map_of(name);
        assert_eq!(delta.get("state"), Some(&Value::Null), "{name}");
        let signed = delta.get("claim").unwrap();
        assert!(
            signed.as_map().is_some(),
            "{name} decodes to a signed claim"
        );
        for at in clocks {
            assert!(!verify_claim_proof(signed, at), "{name} at {at}");
        }
    }
    // The controls verify at the same clock.
    assert!(verify_claim_proof(&signed_of("claim_delta_cbor"), now));
    assert!(verify_claim_proof(
        &signed_of("claim_delta_with_certificate_cbor"),
        now
    ));

    // Each refusal is for the vector's own reason.
    let claim_of = |name: &str| {
        signed_of(name)
            .get("claim")
            .unwrap()
            .as_map()
            .unwrap()
            .clone()
    };
    let nan = claim_of("adv_claim_nan_bid_delta");
    assert!(nan.get("bid").and_then(Value::as_f64).unwrap().is_nan());
    assert!(!claim_is_well_formed(&nan));
    assert!(claim_sort_key(&nan).is_none());
    let zero = claim_of("adv_claim_epoch_zero_delta");
    assert_eq!(zero.get("epoch"), Some(&Value::from(0)));
    assert!(!claim_is_well_formed(&zero));
    let eternal = claim_of("adv_claim_eternal_delta");
    assert_eq!(eternal.get("expiresAtMillis"), Some(&Value::from(i64::MAX)));
    assert!(claim_is_well_formed(&eternal));
    assert!(!claim_within_bounds(&eternal, 1, now));
    let out_of_window = claim_of("adv_claim_cert_out_of_window_delta");
    assert_eq!(
        out_of_window.get("stamp").and_then(Value::as_str),
        Some(stamp(-3_600_000, 0).as_str())
    );
    assert!(claim_is_well_formed(&out_of_window));
}

#[test]
fn hostile_claims_the_fold_refuses_with_its_own_state() {
    let now = verify_at();
    // An epoch jump: a valid proof, beyond reach of a replica that observed nothing; a late
    // joiner that observed a high epoch may still converge.
    let jump = signed_of("adv_claim_epoch_jump_delta");
    assert!(verify_claim_proof(&jump, now));
    let jump_claim = jump.get("claim").unwrap().as_map().unwrap();
    let epoch = jump_claim.get("epoch").and_then(Value::as_i64).unwrap();
    assert!(epoch > MAX_CLAIM_EPOCH_JUMP);
    assert!(!claim_within_bounds(jump_claim, 0, now));
    assert!(claim_within_bounds(
        jump_claim,
        epoch - MAX_CLAIM_EPOCH_JUMP,
        now
    ));
    assert!(!claim_within_bounds(
        jump_claim,
        epoch - MAX_CLAIM_EPOCH_JUMP - 1,
        now
    ));

    // A claim predating its entry by more than the drift ceiling.
    let early = signed_of("adv_claim_predates_issue_delta");
    assert!(verify_claim_proof(&early, now));
    let early_claim = early.get("claim").unwrap().as_map().unwrap();
    assert!(!claim_not_before_issue(early_claim, s("hlc_encoded")));
    let mut at_bound = early_claim.clone();
    at_bound.insert("stamp", stamp(-MAX_CLAIM_PREDATES_ISSUE_MILLIS, 0).as_str());
    assert!(claim_not_before_issue(&at_bound, s("hlc_encoded")));
    assert!(!claim_not_before_issue(&at_bound, "garbage"));

    // A transplanted claim: valid, but signed for another entry than the key it travels under.
    let transplanted = map_of("adv_claim_transplanted_delta");
    let signed = transplanted.get("claim").unwrap();
    assert!(verify_claim_proof(signed, now));
    assert_ne!(
        transplanted.get("claimEntry"),
        signed.get("claim").unwrap().get("entryId")
    );

    // The hold bound is inclusive at now + MAX_CLAIM_HOLD_MILLIS.
    let claim = map_of("take_claim_cbor");
    let expires = claim
        .get("expiresAtMillis")
        .and_then(Value::as_i64)
        .unwrap();
    assert!(claim_within_bounds(
        &claim,
        0,
        expires - MAX_CLAIM_HOLD_MILLIS
    ));
    assert!(!claim_within_bounds(
        &claim,
        0,
        expires - MAX_CLAIM_HOLD_MILLIS - 1
    ));
    assert!(verify_claim_proof(
        &signed_of("claim_delta_cbor"),
        expires - MAX_CLAIM_HOLD_MILLIS
    ));
    assert!(!verify_claim_proof(
        &signed_of("claim_delta_cbor"),
        expires - MAX_CLAIM_HOLD_MILLIS - 1
    ));
}

#[test]
fn every_bit_flip_of_a_signed_claim_is_refused_or_harmless() {
    let now = verify_at();
    for name in ["claim_delta_cbor", "claim_delta_with_certificate_cbor"] {
        let original = cbor::encode(&signed_of(name));
        let mut refused = 0;
        for index in 0..original.len() {
            for bit in 0..8 {
                let mut flipped = original.clone();
                flipped[index] ^= 1 << bit;
                let Ok(value) = cbor::decode(&flipped) else {
                    continue;
                };
                if cbor::encode(&value) == original {
                    continue; // the same signed claim, spelled another way
                }
                assert!(
                    !verify_claim_proof(&value, now),
                    "{name}: byte {index} bit {bit}"
                );
                refused += 1;
            }
        }
        assert!(refused > 0, "{name}");
    }
}

// ------------------------------------------------------------------------- hostile records

#[test]
fn hostile_certificates_never_authenticate_a_record() {
    let now = verify_at();
    let control = state_of("delta_agent_signed_cbor");
    assert!(issuer_accepts(&control, now));
    for name in [
        "adv_cert_wrong_peer_delta",
        "adv_cert_wrong_agent_delta",
        "adv_cert_expired_delta",
        "adv_cert_uncertified_key_delta",
        "adv_cert_peer_signed_record_delta",
    ] {
        let state = state_of(name);
        assert!(state.get("agentCertificate").unwrap().as_map().is_some());
        let key = state
            .get("issuerPublicKey")
            .and_then(Value::as_bytes)
            .unwrap();
        assert!(
            !verify_record(&record_of(&state), key, state.get("agentCertificate"), now),
            "{name}"
        );
    }
    // An expired certificate is refused whatever the receiver's clock.
    let expired = state_of("adv_cert_expired_delta");
    for at in [parse_instant_millis("2024-12-31T00:30:00Z").unwrap(), now] {
        assert!(!issuer_accepts(&expired, at));
    }
}

#[test]
fn an_attested_entrys_state_must_be_signed_by_its_agent() {
    let now = verify_at();
    assert!(issuer_accepts(&state_of("delta_agent_signed_cbor"), now));
    for name in [
        "adv_legacy_state_on_attested_entry_delta_cbor",
        "delta_with_certificate_cbor",
        "adv_agent_state_peer_key_delta",
        "adv_agent_state_wrong_signer_delta",
    ] {
        assert!(!issuer_accepts(&state_of(name), now), "{name}");
    }
    let legacy = map_of("adv_legacy_state_on_attested_entry_dto_cbor");
    assert_eq!(
        legacy,
        state_of("adv_legacy_state_on_attested_entry_delta_cbor")
    );
    assert!(!issuer_accepts(&legacy, now));
}

#[test]
fn a_state_signed_outside_its_window_or_beyond_the_drift_ceiling_is_refused() {
    let now = verify_at();
    for (name, offset) in [
        ("adv_agent_state_out_of_window_delta", -HOUR),
        ("adv_agent_state_drift_delta", MAX_DRIFT_MILLIS + 60_000),
    ] {
        let state = state_of(name);
        assert_eq!(
            state.get("signedAt").and_then(Value::as_str),
            Some(stamp(offset, 0).as_str()),
            "{name}"
        );
        assert!(!issuer_accepts(&state, now), "{name}");
    }
    // The drift vector is inside the window: a receiver whose clock has caught up accepts it.
    let drift = state_of("adv_agent_state_drift_delta");
    assert!(issuer_accepts(&drift, t0() + 60_000));
    // The out-of-window vector stays refused at every clock.
    let early = state_of("adv_agent_state_out_of_window_delta");
    assert!(!issuer_accepts(&early, t0() - HOUR));
}

// ------------------------------------------------------------------------- other records

#[test]
fn credential_and_join_ticket_records_round_trip_and_verify() {
    let identity = peer();
    for name in ["space_credential_record_cbor", "join_ticket_record_cbor"] {
        let bytes = hex(name);
        let record = map(cbor::decode(&bytes).unwrap());
        assert_eq!(encoded(&record), bytes, "{name} re-encodes");
        assert!(
            verify_record(&record, identity.public_raw(), None, 0),
            "{name}"
        );
        let text = |field: &str| record.get(field).and_then(Value::as_str).unwrap();
        let tags = record.get("tags").and_then(Value::as_map).unwrap();
        let view = sign_view(
            text("entryId"),
            text("spaceId"),
            text("type"),
            record.get("payload").and_then(Value::as_bytes),
            text("issuer"),
            text("issued"),
            None,
            Some(tags),
            None,
        );
        assert_eq!(view, sign_view_of(&record).unwrap(), "{name}");
        assert!(Identity::verify(
            identity.public_raw(),
            &encoded(&view),
            record.get("sig").and_then(Value::as_bytes).unwrap()
        ));
        // Not the agent's key, and not a tampered payload.
        assert!(!verify_record(&record, subordinate().public_raw(), None, 0));
        let mut tampered = record.clone();
        tampered.insert("type", "Other#v1");
        assert!(!verify_record(&tampered, identity.public_raw(), None, 0));
    }

    // The ticket's tags are signed, in canonical order whatever order they arrive in.
    let ticket = map_of("join_ticket_record_cbor");
    let tags = ticket.get("tags").and_then(Value::as_map).unwrap();
    let keys: Vec<_> = tags.keys().filter_map(Value::as_str).collect();
    assert_eq!(keys, ["key", "join"]);
    let mut reordered = ticket.clone();
    reordered.insert(
        "tags",
        cbor_map! { "join" => "golden.join", "key" => "golden-key" },
    );
    assert!(verify_record(&reordered, peer().public_raw(), None, 0));
    let mut retagged = ticket.clone();
    retagged.insert(
        "tags",
        cbor_map! { "key" => "golden-key", "join" => "other.join" },
    );
    assert!(!verify_record(&retagged, peer().public_raw(), None, 0));
    let mut untagged = ticket.clone();
    untagged.insert("tags", "key=golden-key");
    assert!(sign_view_of(&untagged).is_none());
    assert!(!verify_record(&untagged, peer().public_raw(), None, 0));
}

#[test]
fn payload_references_resolve_as_the_python_peer_resolves_them() {
    let payload = hex("task_payload_cbor");
    let record = record_of(&state_of("delta_cbor"));
    assert_eq!(
        payload_source(&record),
        Some(PayloadSource::Inline(&payload))
    );

    let with = |payload: Value, reference: Value| {
        map(cbor_map! { "payload" => payload, "payloadRef" => reference })
    };
    let cid = block_cid(&payload);
    // The id is multibase base58btc of SHA-256 (wire.py's block_cid gives the same text).
    assert_eq!(cid, "z5WhCe9fiRF44saPZeCtnhT4WYa2Su3EFRUcHi6aCsmE");
    assert_eq!(
        block_cid(b""),
        "zGKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn"
    );
    let block = with(Value::Null, Value::from(cid.as_str()));
    assert_eq!(payload_source(&block), Some(PayloadSource::Block(&cid)));
    let root = "bafkreiefyvre27n5elfkamnlml7jdbetvb66cunboxmafofld5npi5q64y";
    let content = with(Value::Null, Value::from(root));
    assert_eq!(payload_source(&content), Some(PayloadSource::Content(root)));
    // An inline payload wins over a reference.
    let both = with(Value::from(payload.as_slice()), Value::from(root));
    assert_eq!(payload_source(&both), Some(PayloadSource::Inline(&payload)));
    // Neither, an empty reference, or a reference that is not text: the CBOR null.
    for reference in [Value::Null, Value::from(""), Value::from(7)] {
        let none = with(Value::Null, reference);
        assert_eq!(payload_source(&none), Some(PayloadSource::Null));
    }
    assert_eq!(payload_source(&Map::new()), Some(PayloadSource::Null));
    assert_eq!(cbor::decode(&NULL_PAYLOAD).unwrap(), Value::Null);
    // A payload that is neither null nor bytes is not a record Java could hold.
    assert_eq!(
        payload_source(&with(Value::from("text"), Value::Null)),
        None
    );

    // A referenced payload is signed as null with its reference.
    let identity = peer();
    let write = EntryWrite {
        payload: None,
        payload_ref: Some(&cid),
        ..golden_write(&payload)
    };
    let state = entry_state(&write, &identity, "python", None).unwrap();
    let record = record_of(&state);
    assert_eq!(record.get("payload"), Some(&Value::Null));
    assert_eq!(record.get("payloadRef"), Some(&Value::from(cid.as_str())));
    assert!(issuer_accepts(&state, verify_at()));
    let mut swapped = record.clone();
    swapped.insert("payloadRef", root);
    assert!(!verify_record(&swapped, identity.public_raw(), None, 0));
}

// ------------------------------------------------------------------------- refusals

#[test]
fn signing_refuses_what_receivers_would_refuse() {
    let identity = peer();
    let agent = subordinate();
    let certified = state_of("delta_with_certificate_cbor");
    let late = stamp(25 * HOUR, 0);
    assert_eq!(
        sign_state(&certified, &identity, Some((&agent, &late))),
        Err(RecordError::NoCoveringCertificate {
            agent: python(),
            stamp: late.clone(),
        })
    );
    assert_eq!(
        sign_state(&certified, &identity, Some((&agent, "soon"))),
        Err(RecordError::MalformedStamp { field: "signedAt" })
    );
    let mut recordless = certified.clone();
    recordless.remove("record");
    assert_eq!(
        sign_state(&recordless, &identity, None),
        Err(RecordError::Malformed { field: "record" })
    );
    let mut dotless = certified.clone();
    dotless.insert("adds", "dots");
    assert_eq!(
        sign_state(&dotless, &identity, None),
        Err(RecordError::Malformed { field: "adds" })
    );
    let mut half_done = certified.clone();
    half_done.insert("completed", 1);
    assert_eq!(
        sign_state(&half_done, &identity, None),
        Err(RecordError::Malformed { field: "completed" })
    );

    let payload = hex("task_payload_cbor");
    let unstamped = EntryWrite {
        issued: "yesterday",
        ..golden_write(&payload)
    };
    assert_eq!(
        entry_state(&unstamped, &identity, "python", None),
        Err(RecordError::MalformedStamp { field: "issued" })
    );
    let late_write = EntryWrite {
        issued: &late,
        ..golden_write(&payload)
    };
    assert!(matches!(
        entry_state(&late_write, &identity, "python", Some((&agent, &late))),
        Err(RecordError::NoCoveringCertificate { .. })
    ));

    let claim = take_claim(
        ENTRY,
        s("space_id"),
        1,
        &late,
        &python(),
        0.0,
        WRITE_EXPIRES,
    );
    assert!(matches!(
        signed_claim(&claim, &identity, Some(&agent)),
        Err(RecordError::NoCoveringCertificate { .. })
    ));
    let mut stampless = claim.clone();
    stampless.remove("stamp");
    assert_eq!(
        signed_claim(&stampless, &identity, Some(&agent)),
        Err(RecordError::MalformedStamp { field: "stamp" })
    );
    // The peer signs any claim; receivers judge it.
    assert!(signed_claim(&stampless, &identity, None).is_ok());
}

#[test]
fn hostile_shapes_are_refused_without_panicking() {
    let identity = peer();
    let now = verify_at();
    let record = record_of(&state_of("delta_cbor"));
    let key = identity.public_raw();

    // Records.
    assert!(!verify_record(&record, &key[..31], None, 0));
    assert!(!verify_record(&Map::new(), key, None, 0));
    for (field, value) in [
        ("issuer", Value::from(7)),
        ("issuer", Value::from(identity.peer_id())),
        (
            "issuer",
            Value::from(format!("{}python", identity.peer_id())),
        ),
        ("sig", Value::from("signature")),
        ("sig", Value::Null),
        ("payload", Value::from(hex("sign_view_cbor"))),
        ("issued", Value::from(s("hlc_encoded").to_uppercase())),
    ] {
        let mut hostile = record.clone();
        hostile.insert(field, value.clone());
        assert!(
            !verify_record(&hostile, key, None, 0),
            "{field} = {value:?}"
        );
    }
    for certificate in [Value::from("certificate"), Value::from(7), cbor_map! {}] {
        assert!(!verify_record(&record, key, Some(&certificate), now));
    }

    // States.
    let state = state_of("delta_agent_signed_cbor");
    assert!(!verify_state_signature(
        &state,
        &python(),
        &key[..16],
        true,
        now
    ));
    for (field, value) in [
        ("record", Value::from("record")),
        ("adds", Value::from("adds")),
        ("adds", cbor_array![7]),
        (
            "removes",
            cbor_array![cbor_map! { "replica" => 7, "counter" => 1 }],
        ),
        ("completed", Value::from("false")),
        ("signer", Value::from(7)),
        ("signedAt", Value::from(7)),
        ("signedAt", Value::from("later")),
        ("stateCertificate", Value::from("certificate")),
        ("stateCertificate", Value::Null),
        ("stateSig", Value::from("signature")),
    ] {
        let mut hostile = state.clone();
        hostile.insert(field, value.clone());
        assert!(
            !verify_state_signature(&hostile, &python(), key, true, now),
            "{field} = {value:?}"
        );
    }
    assert!(state_sign_view_of(&Map::new()).is_none());
    // Absent dot lists and completion read as empty and false, as wire.py reads them.
    let mut sparse = state_of("delta_cbor");
    sparse.remove("removes");
    sparse.remove("completed");
    assert_eq!(
        encoded(&state_sign_view_of(&sparse).unwrap()),
        hex("state_sign_view_cbor")
    );

    // Dots sort by replica, then counter, wherever they arrive from.
    let unsorted = [
        cbor_map! { "replica" => "b", "counter" => 1 },
        cbor_map! { "replica" => "a", "counter" => 2 },
        cbor_map! { "replica" => "a", "counter" => 1 },
    ];
    let view = state_sign_view(
        "s",
        "e",
        &unsorted,
        &[],
        "1:0:n",
        &Value::Null,
        false,
        None,
        None,
    );
    let sorted = [
        cbor_map! { "replica" => "a", "counter" => 1 },
        cbor_map! { "replica" => "a", "counter" => 2 },
        cbor_map! { "replica" => "b", "counter" => 1 },
    ];
    assert_eq!(view.get("adds"), Some(&Value::Array(sorted.to_vec())));

    // Claims.
    let signed = signed_of("claim_delta_with_certificate_cbor");
    for hostile in [Value::Null, Value::from("claim"), cbor_map! {}] {
        assert!(!verify_claim_proof(&hostile, now));
    }
    for (field, value) in [
        ("claim", Value::from("claim")),
        ("holderKey", Value::from(&key[..31])),
        ("holderKey", Value::from("key")),
        ("signature", Value::Null),
        ("holderCertificate", Value::from(7)),
    ] {
        let mut hostile = signed.as_map().unwrap().clone();
        hostile.insert(field, value.clone());
        assert!(
            !verify_claim_proof(&Value::Map(hostile), now),
            "{field} = {value:?}"
        );
    }
    let claim = map_of("take_claim_cbor");
    for (field, value) in [
        ("entryId", Value::Null),
        ("spaceId", Value::from(1)),
        ("holder", Value::from(b"holder".as_slice())),
        ("epoch", Value::from(-1)),
        ("epoch", Value::Int(i128::from(i64::MAX) + 1)),
        ("epoch", Value::Float(1.0)),
        ("stamp", Value::from("1735689600000:3")),
        ("bid", Value::Float(f64::INFINITY)),
        ("bid", Value::Null),
        ("bid", Value::from(true)),
        ("expiresAtMillis", Value::Float(1.0)),
    ] {
        let mut hostile = claim.clone();
        hostile.insert(field, value.clone());
        assert!(!claim_is_well_formed(&hostile), "{field} = {value:?}");
        let mut proof = signed.as_map().unwrap().clone();
        proof.insert("claim", hostile);
        assert!(!verify_claim_proof(&Value::Map(proof), now));
    }
    let mut bidless = claim.clone();
    bidless.remove("bid");
    assert!(claim_is_well_formed(&bidless));
    assert!(!claim_within_bounds(&Map::new(), 0, now));
    assert!(!claim_not_before_issue(&Map::new(), s("hlc_encoded")));
}

// ------------------------------------------------------------------------- the recordless form

/// The full form of `state_delta_recordless_cbor`'s state (SPEC §7.3): the
/// golden record, a renewal stamped t0+PT1M to t0+PT2H, signed by the golden peer.
fn renewal_over_golden_record() -> Map {
    let record = record_of(&state_of("delta_cbor"));
    let renewal_stamp = stamp(60_000, 0);
    let dto = map(cbor_map! {
        "record" => record,
        "issuerPublicKey" => peer().public_raw(),
        "adds" => golden_adds(),
        "removes" => cbor_array![],
        "leaseStamp" => renewal_stamp.as_str(),
        "leaseValue" => cbor_map! {
            "holder" => python(),
            "expiresAtMillis" => t0() + 2 * HOUR,
            "kind" => "WRITE",
        },
        "completed" => false,
    });
    sign_state(&dto, &peer(), None).unwrap()
}

#[test]
fn the_recordless_form_is_javas_byte_for_byte() {
    let full = renewal_over_golden_record();
    assert!(!is_recordless(&full));
    let recordless = without_record(&full).unwrap();
    assert!(is_recordless(&recordless));
    assert_eq!(
        delta(Some(&recordless), None),
        hex("state_delta_recordless_cbor")
    );
    // The decoded vector is that DTO: no record, the entry named last, the signature kept.
    let received = state_of("state_delta_recordless_cbor");
    assert_eq!(received, recordless);
    assert!(received.get("record").is_none());
    assert_eq!(
        received.keys().next_back().and_then(Value::as_str),
        Some("entryId")
    );
    assert_eq!(state_entry_id(&received), Some(ENTRY));
    assert_eq!(state_entry_id(&full), Some(ENTRY));
    assert_eq!(received.get("stateSig"), full.get("stateSig"));
    // Recordless again is the same DTO.
    assert_eq!(without_record(&received).unwrap(), received);
}

#[test]
fn a_recordless_state_verifies_only_over_the_record_it_names() {
    let now = t0();
    let received = state_of("state_delta_recordless_cbor");
    // Without its record the state cannot be judged: there is no space or entry to sign over.
    assert!(state_sign_view_of(&received).is_none());
    assert!(!verify_state_signature(
        &received,
        &python(),
        peer().public_raw(),
        false,
        now
    ));
    // Over the held record it is the full form again, byte for byte, and verifies as one.
    let record = record_of(&state_of("delta_cbor"));
    let restored = with_record(&received, &record).unwrap();
    assert_eq!(restored, renewal_over_golden_record());
    assert!(restored.get("entryId").is_none());
    assert!(verify_state_signature(
        &restored,
        &python(),
        peer().public_raw(),
        false,
        now
    ));
    // A record of another entry is not put under it (Java's IllegalArgumentException).
    let mut other = record.clone();
    other.insert("entryId", "99999999-2222-3333-4444-555555555555");
    assert!(with_record(&received, &other).is_none());
    // A full DTO takes the held record in place of its own, as Java's withRecord does.
    assert_eq!(
        with_record(&renewal_over_golden_record(), &record).unwrap(),
        renewal_over_golden_record()
    );
    // A record without a text entryId has no recordless form.
    let mut nameless = renewal_over_golden_record();
    nameless.insert("record", cbor_map! { "spaceId" => s("space_id") });
    assert!(without_record(&nameless).is_none());
}
