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

//! Java decodes every signed object into its typed record and verifies the signature over its own
//! re-encoding (`verifyClaim`, `signableBytes`, `stateSignBytes`, `WireCodec.decodeDetailed`,
//! `GroupFounding.verify`, `AgentCertificates.verify`). The verifiers of this crate judge the
//! decoded map they are given, so they must accept an object only in the form Java writes back;
//! otherwise a hostile member could sign a non-canonical object that Rust replicas admit and Java
//! replicas refuse, and a mixed group would split for good.
//!
//! Every case here is signed by its author over exactly the non-canonical bytes it carries and
//! must be refused, beside a canonical control that still verifies. Java's re-encodings were
//! confirmed against the 0.5.0 jars: an integer bid re-encodes as a double, `HlcTimestamp` drops
//! `+` and leading zeros, `Instant` prints its fraction in groups of three, and `Duration`
//! normalises to hours, minutes, and seconds.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::envelope::{
    decode_frame, decode_frame_detailed, encode_frame, encode_session_frame, envelope,
};
use agentspaces_wire::fold::{FoldContext, FoldOutcome, Refusal, SpaceStore};
use agentspaces_wire::founding::{
    found_group, founding_document, founding_fields, group_advertisement,
    group_id_from_founding_document, verify_signed_group_ad,
};
use agentspaces_wire::identity::{
    Identity, agent_certificate, sign_agent_certificate, verify_agent_certificate,
};
use agentspaces_wire::records::{
    EntryWrite, claim_delta, claim_is_canonical, claim_is_well_formed, delta, entry_state,
    record_is_well_formed, sign_state, sign_view_of, signed_claim, state_sign_view_of, take_claim,
    verify_claim_proof, verify_record, verify_state_signature,
};
use agentspaces_wire::revocation::Registry;
use agentspaces_wire::time::parse_instant_millis;
use common::{hex, s};

const ENTRY: &str = "11111111-2222-3333-4444-555555555555";
const TASK_TYPE: &str = "GoldenVectors$ResearchTask#v1";
const HOUR: i64 = 3_600_000;

// ------------------------------------------------------------------------- helpers

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

/// A second member of the group.
fn member() -> Identity {
    Identity::from_seed(&[7; 32])
}

fn agent_key() -> Identity {
    Identity::from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap()
}

/// The physical milliseconds of the golden stamp `hlc_encoded`.
fn t0() -> i64 {
    s("hlc_encoded").split(':').next().unwrap().parse().unwrap()
}

fn now() -> i64 {
    t0() + 1_000
}

fn stamp_of(identity: &Identity) -> String {
    format!("{}:0:{}", t0(), identity.peer_id())
}

fn map(value: Value) -> Map {
    value.into_map().unwrap()
}

fn record_of(state: &Map) -> Map {
    state.get("record").unwrap().as_map().unwrap().clone()
}

/// A write of the golden payload by `issued`, with the given tags.
fn write<'a>(payload: &'a [u8], issued: &'a str, tags: Option<&'a Map>) -> EntryWrite<'a> {
    EntryWrite {
        entry_id: ENTRY,
        space_id: s("space_id"),
        type_name: TASK_TYPE,
        payload: Some(payload),
        payload_ref: None,
        tags,
        key_epoch: None,
        issued,
        expires_at_millis: t0() + HOUR,
        counter: 1,
    }
}

/// A fresh replica of the golden space at [`now`] folding one state.
fn fold_state(state: &Map) -> FoldOutcome {
    let registry = Registry::default();
    let mut store = SpaceStore::new();
    store.fold_state(state, &FoldContext::new(now(), &registry))
}

/// The issuer rule on a non-completion state, as the fold composes it.
fn issuer_accepts(state: &Map) -> bool {
    let record = record_of(state);
    let issuer = record.get("issuer").and_then(Value::as_str).unwrap();
    let key = state
        .get("issuerPublicKey")
        .and_then(Value::as_bytes)
        .unwrap();
    verify_record(&record, key, None, now())
        && verify_state_signature(state, issuer, key, false, now())
}

/// A claim on the golden entry by `holder` (an agent of `identity`), as the given value of `bid`.
fn claim(identity: &Identity, bid: Value) -> Map {
    let mut claim = take_claim(
        ENTRY,
        s("space_id"),
        1,
        &stamp_of(identity),
        &identity.agent("worker"),
        0.0,
        t0() + HOUR,
    );
    claim.insert("bid", bid);
    claim
}

// ------------------------------------------------------------------------- claims

#[test]
fn a_claim_java_would_re_encode_never_verifies() {
    let member = member();
    let canonical = claim(&member, Value::Float(-1.0));
    assert!(claim_is_canonical(&canonical));
    let proof = signed_claim(&canonical, &member, None).unwrap();
    assert!(verify_claim_proof(&Value::Map(proof.clone()), now()));

    let mut hostile: Vec<(&str, Map)> = Vec::new();
    hostile.push(("an integer bid", claim(&member, Value::from(-1))));
    let mut reordered = Map::new();
    for name in [
        "spaceId",
        "entryId",
        "epoch",
        "stamp",
        "holder",
        "bid",
        "expiresAtMillis",
    ] {
        reordered.insert(name, canonical.get(name).unwrap().clone());
    }
    hostile.push(("reordered fields", reordered));
    let mut extended = canonical.clone();
    extended.insert("note", "extra");
    hostile.push(("an extra field", extended));
    let mut bidless = canonical.clone();
    bidless.remove("bid");
    hostile.push(("no bid", bidless));
    for stamp in [
        format!("+{}:0:{}", t0(), member.peer_id()),
        format!("0{}:0:{}", t0(), member.peer_id()),
        format!("{}:00:{}", t0(), member.peer_id()),
    ] {
        let mut odd = canonical.clone();
        odd.insert("stamp", stamp);
        hostile.push(("a non-canonical stamp", odd));
    }
    for holder in [
        format!("{}/", member.peer_id()),
        format!("{}/worker/extra", member.peer_id()),
    ] {
        let mut odd = canonical.clone();
        odd.insert("holder", holder);
        hostile.push(("a holder Java cannot parse", odd));
    }
    let mut empty_space = canonical.clone();
    empty_space.insert("spaceId", "");
    hostile.push(("an empty space id", empty_space));
    for (name, claim) in &hostile {
        assert!(!claim_is_canonical(claim), "{name}");
        // The member signs exactly the bytes it sends: the form the old verifier accepted.
        let proof = signed_claim(claim, &member, None).unwrap();
        assert!(!verify_claim_proof(&Value::Map(proof), now()), "{name}");
    }
    // Jackson still decodes an integer bid, so the claim is well formed; it is the proof that
    // cannot be verified alike everywhere.
    assert!(claim_is_well_formed(&claim(&member, Value::from(-1))));

    // Signed over the canonical bytes but sent as an integer bid (which Java would decode, re-encode,
    // and accept): refused here, and the canonical copy a Java replica forwards still verifies.
    let mut sent = proof.clone();
    sent.insert("claim", claim(&member, Value::from(-1)));
    assert!(!verify_claim_proof(&Value::Map(sent), now()));
    assert!(verify_claim_proof(&Value::Map(proof), now()));
}

#[test]
fn an_integer_bid_cannot_take_an_entry_from_its_holder() {
    // The attack: the entry is held at epoch 1 with bid 0.0, and a member signs an
    // epoch-1 claim with the CBOR integer -1 as its bid. Java refuses its proof, so a replica
    // here must too, or the lower bid would win the lattice only here, for good.
    let holder = peer();
    let member = member();
    let registry = Registry::default();
    let ctx = FoldContext::new(now(), &registry).with_space(s("space_id"));
    let mut store = SpaceStore::new();
    let held = signed_claim(&claim(&holder, Value::Float(0.0)), &holder, None).unwrap();
    assert_eq!(store.fold_claim(ENTRY, &held, &ctx), FoldOutcome::Applied);
    let integral = signed_claim(&claim(&member, Value::from(-1)), &member, None).unwrap();
    assert_eq!(
        store.fold_claim(ENTRY, &integral, &ctx),
        FoldOutcome::Refused(Refusal::UnverifiedClaim)
    );
    assert_eq!(store.claim_proof(ENTRY), Some(&held));
    // The canonical bid of the same member does win, as it wins on a Java replica.
    let canonical = signed_claim(&claim(&member, Value::Float(-1.0)), &member, None).unwrap();
    assert_eq!(
        store.fold_claim(ENTRY, &canonical, &ctx),
        FoldOutcome::Applied
    );
    assert_eq!(store.claim_proof(ENTRY), Some(&canonical));
}

// ------------------------------------------------------------------------- records

/// An edit of a received record, before the writer re-signs it.
type RecordEdit<'a> = &'a dyn Fn(&mut Map);

#[test]
fn a_record_java_would_re_encode_or_refuse_never_verifies() {
    let identity = peer();
    let payload = hex("task_payload_cbor");
    let canonical = entry_state(
        &write(&payload, s("hlc_encoded"), None),
        &identity,
        "python",
        None,
    )
    .unwrap();
    assert!(record_is_well_formed(&record_of(&canonical)));
    assert!(issuer_accepts(&canonical));
    assert_eq!(fold_state(&canonical), FoldOutcome::Applied);

    // Built (and so signed) by the writer exactly as they arrive.
    let plus = format!("+{}", s("hlc_encoded"));
    let zero = format!("0{}", s("hlc_encoded"));
    let numeric_tags = map(cbor_map! { "k" => 5 });
    let built = [
        (
            "a + issue stamp",
            entry_state(&write(&payload, &plus, None), &identity, "python", None),
        ),
        (
            "a zero-led issue stamp",
            entry_state(&write(&payload, &zero, None), &identity, "python", None),
        ),
        (
            "an empty local name",
            entry_state(
                &write(&payload, s("hlc_encoded"), None),
                &identity,
                "",
                None,
            ),
        ),
        (
            "a local name with /",
            entry_state(
                &write(&payload, s("hlc_encoded"), None),
                &identity,
                "a/b",
                None,
            ),
        ),
        (
            "a numeric tag",
            entry_state(
                &write(&payload, s("hlc_encoded"), Some(&numeric_tags)),
                &identity,
                "python",
                None,
            ),
        ),
    ];
    for (name, state) in built {
        let state = state.unwrap();
        assert!(sign_view_of(&record_of(&state)).is_none(), "{name}");
        assert!(!issuer_accepts(&state), "{name}");
        assert_eq!(
            fold_state(&state),
            FoldOutcome::Refused(Refusal::UnverifiedRecord),
            "{name}"
        );
    }

    // Records Java cannot decode at all, re-signed over the view this crate would verify.
    let resigned = |edit: RecordEdit<'_>| {
        let mut state = canonical.clone();
        let mut record = record_of(&state);
        edit(&mut record);
        if let Some(view) = sign_view_of(&record) {
            record.insert("sig", identity.sign(&cbor::encode(&Value::Map(view))));
        }
        state.insert("record", record);
        sign_state(&state, &identity, None).unwrap()
    };
    let undecodable: [(&str, RecordEdit<'_>); 7] = [
        ("no tags", &|record| {
            record.remove("tags");
        }),
        ("null tags", &|record| {
            record.insert("tags", Value::Null);
        }),
        ("no payload and no reference", &|record| {
            record.insert("payload", Value::Null);
        }),
        ("a payload and a reference", &|record| {
            record.insert("payloadRef", "zBlock");
        }),
        ("no lease", &|record| {
            record.remove("lease");
        }),
        ("a lease of an unknown kind", &|record| {
            let mut lease = record.get("lease").unwrap().as_map().unwrap().clone();
            lease.insert("kind", "LEND");
            record.insert("lease", lease);
        }),
        ("key epoch 0", &|record| {
            record.insert("keyEpoch", 0);
        }),
    ];
    for (name, edit) in undecodable {
        let state = resigned(edit);
        assert!(!record_is_well_formed(&record_of(&state)), "{name}");
        assert!(!issuer_accepts(&state), "{name}");
    }
    // The unsigned record lease may arrive in any field order: Java ignores the order there.
    let reordered_lease = resigned(&|record| {
        let lease = record.get("lease").unwrap().as_map().unwrap().clone();
        let mut reordered = Map::new();
        for name in ["kind", "expiresAtMillis", "holder"] {
            reordered.insert(name, lease.get(name).unwrap().clone());
        }
        record.insert("lease", reordered);
    });
    assert!(issuer_accepts(&reordered_lease));
}

// ------------------------------------------------------------------------- states

#[test]
fn a_state_java_would_re_encode_never_verifies() {
    let identity = peer();
    let payload = hex("task_payload_cbor");
    let canonical = entry_state(
        &write(&payload, s("hlc_encoded"), None),
        &identity,
        "python",
        None,
    )
    .unwrap();
    // Each edit re-signed by the issuer's peer over exactly the fields it carries.
    let resigned = |name: &str, value: Option<Value>| {
        let mut dto = canonical.clone();
        match value {
            Some(value) => dto.insert(name, value),
            None => dto.remove(name),
        };
        sign_state(&dto, &identity, None).unwrap()
    };
    let lease = canonical
        .get("leaseValue")
        .unwrap()
        .as_map()
        .unwrap()
        .clone();
    let mut reordered_lease = Map::new();
    for name in ["expiresAtMillis", "holder", "kind"] {
        reordered_lease.insert(name, lease.get(name).unwrap().clone());
    }
    let mut extended_lease = lease.clone();
    extended_lease.insert("note", "extra");
    let mut sloppy_holder = lease.clone();
    sloppy_holder.insert("holder", format!("{}/", identity.peer_id()));
    let mut zero_expiry = lease.clone();
    zero_expiry.insert("expiresAtMillis", 0);
    let peer_id = identity.peer_id();
    let hostile = [
        (
            "a reordered leaseValue",
            "leaseValue",
            Some(Value::Map(reordered_lease)),
        ),
        (
            "an extended leaseValue",
            "leaseValue",
            Some(Value::Map(extended_lease)),
        ),
        (
            "a leaseValue holder Java cannot parse",
            "leaseValue",
            Some(Value::Map(sloppy_holder)),
        ),
        (
            "a leaseValue expiring at 0",
            "leaseValue",
            Some(Value::Map(zero_expiry)),
        ),
        ("a null leaseValue", "leaseValue", Some(Value::Null)),
        (
            "a reordered dot",
            "adds",
            Some(dot_list(&[
                cbor_map! { "counter" => 1, "replica" => peer_id },
            ])),
        ),
        (
            "an extended dot",
            "adds",
            Some(dot_list(&[
                cbor_map! { "replica" => peer_id, "counter" => 1, "note" => "x" },
            ])),
        ),
        (
            "a dot counted from 0",
            "adds",
            Some(dot_list(&[
                cbor_map! { "replica" => peer_id, "counter" => 0 },
            ])),
        ),
        (
            "a + lease stamp",
            "leaseStamp",
            Some(Value::from(format!("+{}", s("hlc_encoded")))),
        ),
        (
            "a zero-led lease stamp",
            "leaseStamp",
            Some(Value::from(format!("0{}", s("hlc_encoded")))),
        ),
        ("no removes", "removes", None),
        ("null adds", "adds", Some(Value::Null)),
    ];
    assert!(issuer_accepts(&canonical));
    for (name, field, value) in hostile {
        let state = resigned(field, value);
        assert!(!issuer_accepts(&state), "{name}");
        assert!(fold_state(&state).is_refused(), "{name}");
    }
    // A state with no removes still has a view (wire.py reads the list as empty), but no
    // verifiable signature: Java cannot sort a missing list.
    assert!(state_sign_view_of(&resigned("removes", None)).is_some());

    // An agent-signed state whose signedAt is not canonical.
    let agent = identity
        .subordinate(
            "python",
            s("certificate_verify_at"),
            "PT24H",
            Some(agent_key()),
        )
        .unwrap();
    let verify_at = parse_instant_millis(s("certificate_verify_at")).unwrap();
    let signed_at = format!("{}:0:{}", verify_at + 1_000, identity.peer_id());
    let honest = sign_state(&canonical, &identity, Some((&agent, &signed_at))).unwrap();
    assert!(state_sign_view_of(&honest).is_some());
    for odd in [format!("+{signed_at}"), format!("0{signed_at}")] {
        let state = sign_state(&canonical, &identity, Some((&agent, &odd))).unwrap();
        assert!(state_sign_view_of(&state).is_none(), "{odd}");
    }
}

/// A dot list value.
fn dot_list(dots: &[Value]) -> Value {
    Value::Array(dots.to_vec())
}

// ------------------------------------------------------------------------- frames

#[test]
fn a_frame_whose_envelope_java_would_re_encode_never_verifies() {
    let identity = peer();
    let stamp = s("hlc_encoded");
    let canonical = envelope(s("group_id"), "PING", identity.peer_id(), stamp, b"x", None);
    assert!(decode_frame(&encode_frame(&canonical, &identity)).is_some());
    let key = [b'k'; 32];
    let session = Some((identity.peer_id(), &key));
    assert!(
        decode_frame_detailed(&encode_session_frame(&canonical, &key), None, session).is_some()
    );

    let mut hostile: Vec<(&str, Map)> = Vec::new();
    for odd in [format!("+{stamp}"), format!("0{stamp}")] {
        let mut env = canonical.clone();
        env.insert("stamp", odd);
        hostile.push(("a non-canonical stamp", env));
    }
    let mut toless = canonical.clone();
    toless.remove("to");
    hostile.push(("no to", toless));
    let mut extended = canonical.clone();
    extended.insert("note", "extra");
    hostile.push(("an extra field", extended));
    let mut reordered = Map::new();
    for name in ["group", "ver", "kind", "from", "to", "stamp", "body"] {
        reordered.insert(name, canonical.get(name).unwrap().clone());
    }
    hostile.push(("reordered fields", reordered));
    let mut empty_to = canonical.clone();
    empty_to.insert("to", "");
    hostile.push(("an empty to", empty_to));
    for (name, env) in &hostile {
        assert_eq!(decode_frame(&encode_frame(env, &identity)), None, "{name}");
        assert_eq!(
            decode_frame_detailed(&encode_session_frame(env, &key), None, session),
            None,
            "{name}"
        );
    }
}

// ------------------------------------------------------------------------- stamps in chunks

/// `bytes` with the stamp `text` that follows the key `key` (both in Jackson's definite form)
/// sent instead as an indefinite-length text of `chunks` chunks, one or two, as the documents
/// `stamp row 10` (`7F 65 35 3A 30 3A 6E FF`) and `stamp row 11` (`7F 62 35 3A 63 30 3A 6E FF`)
/// of `jackson-wire-vectors.json` send the stamp `5:0:n`, here for the carrier's own stamp.
fn stamp_in_chunks(bytes: &[u8], key: &str, text: &str, chunks: usize) -> Vec<u8> {
    let key_item = cbor::encode(&Value::from(key));
    let from = [key_item.clone(), cbor::encode(&Value::from(text))].concat();
    let split = if chunks == 1 {
        text.len()
    } else {
        text.len() / 2
    };
    let mut to = key_item;
    to.push(0x7F);
    for piece in [&text[..split], &text[split..]] {
        if !piece.is_empty() {
            to.extend_from_slice(&cbor::encode(&Value::from(piece)));
        }
    }
    to.push(0xFF);
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .unwrap_or_else(|| panic!("the carrier holds {key}: {text}"));
    [&bytes[..at], &to, &bytes[at + from.len()..]].concat()
}

/// A stamp that arrives as chunked text (SPEC §9; the forms of `stamp row 10` and `stamp row
/// 11`) is undecodable wherever a stamp belongs, as Java, Python, TypeScript, and Ruby refuse it:
/// an envelope's stamp (the frame drops before any signature check), a record's `issued`, and a
/// claim's `stamp` in a space delta. The chunked text of the stamp re-encodes to the canonical
/// one, so the signature covers it; refusing it at decode is what keeps a relay from
/// relabelling the carrier into a form Java drops and a lenient reader would fold.
#[test]
fn a_stamp_in_chunks_never_decodes_in_a_frame_a_record_or_a_claim() {
    let row = |chunks: usize| if chunks == 1 { "row 10" } else { "row 11" };
    let not_wire = |bytes: &[u8]| {
        matches!(
            cbor::decode(bytes),
            Err(cbor::CborError::NotWireEncoding {
                rule: cbor::WireRule::TextChunks,
                ..
            })
        )
    };
    // The frame stamp, through decode_frame.
    let identity = peer();
    let stamp = s("hlc_encoded");
    let env = envelope(s("group_id"), "PING", identity.peer_id(), stamp, b"x", None);
    let frame = encode_frame(&env, &identity);
    assert!(decode_frame(&frame).is_some());
    for chunks in [1, 2] {
        let hostile = stamp_in_chunks(&frame, "stamp", stamp, chunks);
        assert!(not_wire(&hostile), "{}", row(chunks));
        assert_eq!(decode_frame(&hostile), None, "{}", row(chunks));
        // The stamp's chunks re-encode to the canonical stamp the signature covers.
        let relabelled = cbor::decode_lenient(&hostile).expect("a lenient read");
        assert_eq!(cbor::encode(&relabelled), frame, "{}", row(chunks));
    }

    // A record's issued, in the delta a rumor carries.
    let author = member();
    let issued = stamp_of(&author);
    let payload = hex("task_payload_cbor");
    let state = entry_state(&write(&payload, &issued, None), &author, "worker", None).unwrap();
    let delta = delta(Some(&state), None);
    let decoded = cbor::decode(&delta).expect("the honest delta decodes");
    let folded = map(decoded.get("state").unwrap().clone());
    assert_eq!(fold_state(&folded), FoldOutcome::Applied);
    for chunks in [1, 2] {
        let hostile = stamp_in_chunks(&delta, "issued", &issued, chunks);
        assert!(not_wire(&hostile), "issued, {}", row(chunks));
    }

    // A claim's stamp, in the delta a claim rumor carries.
    let proof = signed_claim(&claim(&author, Value::Float(0.0)), &author, None).unwrap();
    let delta = claim_delta(ENTRY, &proof);
    assert!(cbor::decode(&delta).is_ok());
    for chunks in [1, 2] {
        let hostile = stamp_in_chunks(&delta, "stamp", &stamp_of(&author), chunks);
        assert!(not_wire(&hostile), "claim stamp, {}", row(chunks));
    }
}

// ------------------------------------------------------------------------- founding

/// The signed group advertisement of exactly these founding fields, signed by `founder`.
fn signed_ad(
    founder: &Identity,
    issued: &str,
    ttl: &str,
    policy: &str,
    strategy: &str,
    fanout: i64,
    period: &str,
) -> Value {
    let fields = founding_fields(
        "g",
        founder.peer_id(),
        issued,
        ttl,
        policy,
        strategy,
        fanout,
        period,
    );
    let signature = founder.sign(&cbor::encode(&Value::Map(fields.clone())));
    let document = founding_document(&fields, &signature);
    let group = group_id_from_founding_document(&cbor::encode(&Value::Map(document)));
    let advertisement = group_advertisement(&group, &fields).unwrap();
    cbor_map! {
        "advertisement" => advertisement,
        "founderPublicKey" => founder.public_raw(),
        "signature" => signature,
    }
}

#[test]
fn founding_fields_java_would_re_encode_never_verify() {
    let founder = Identity::from_seed(&[5; 32]);
    let honest = found_group(
        &founder,
        "g",
        "OPEN",
        "AUCTION",
        3,
        "PT1S",
        "2026-01-01T00:00:00Z",
        "PT24H",
    )
    .unwrap();
    assert!(verify_signed_group_ad(&Value::Map(honest)).is_some());
    let ok = (
        "2026-01-01T00:00:00Z",
        "PT24H",
        "OPEN",
        "AUCTION",
        3,
        "PT1S",
    );
    let control = signed_ad(&founder, ok.0, ok.1, ok.2, ok.3, ok.4, ok.5);
    assert!(verify_signed_group_ad(&control).is_some());
    // Sub-millisecond instants are canonical to Java (Instant.now() carries them).
    let micros = signed_ad(
        &founder,
        "2026-01-01T00:00:00.000100Z",
        ok.1,
        ok.2,
        ok.3,
        ok.4,
        ok.5,
    );
    assert!(verify_signed_group_ad(&micros).is_some());
    for (name, ad) in [
        (
            "a .000 instant",
            signed_ad(
                &founder,
                "2026-01-01T00:00:00.000Z",
                ok.1,
                ok.2,
                ok.3,
                ok.4,
                ok.5,
            ),
        ),
        (
            "a one-digit fraction",
            signed_ad(
                &founder,
                "2026-01-01T00:00:00.1Z",
                ok.1,
                ok.2,
                ok.3,
                ok.4,
                ok.5,
            ),
        ),
        (
            "PT1440M",
            signed_ad(&founder, ok.0, "PT1440M", ok.2, ok.3, ok.4, ok.5),
        ),
        (
            "PT01H",
            signed_ad(&founder, ok.0, "PT01H", ok.2, ok.3, ok.4, ok.5),
        ),
        (
            "PT1.0S period",
            signed_ad(&founder, ok.0, ok.1, ok.2, ok.3, ok.4, "PT1.0S"),
        ),
        (
            "a zero period",
            signed_ad(&founder, ok.0, ok.1, ok.2, ok.3, ok.4, "PT0S"),
        ),
        (
            "a lower-case policy",
            signed_ad(&founder, ok.0, ok.1, "open", ok.3, ok.4, ok.5),
        ),
        (
            "an unknown strategy",
            signed_ad(&founder, ok.0, ok.1, ok.2, "FIFO", ok.4, ok.5),
        ),
        (
            "a zero fanout",
            signed_ad(&founder, ok.0, ok.1, ok.2, ok.3, 0, ok.5),
        ),
        (
            "a fanout beyond int",
            signed_ad(
                &founder,
                ok.0,
                ok.1,
                ok.2,
                ok.3,
                i64::from(i32::MAX) + 1,
                ok.5,
            ),
        ),
    ] {
        assert_eq!(verify_signed_group_ad(&ad), None, "{name}");
    }
}

// ------------------------------------------------------------------------- certificates

#[test]
fn a_certificate_java_would_re_encode_never_verifies() {
    let identity = peer();
    let key = <[u8; 32]>::try_from(hex("agent_public_key_raw").as_slice()).unwrap();
    let python = identity.agent("python");
    let at = parse_instant_millis("2026-01-01T00:00:00Z").unwrap() + 1_000;
    let certify = |agent: &str, issued: &str, ttl: &str| {
        let body = agent_certificate(agent, &key, issued, ttl, None, None);
        Value::Map(sign_agent_certificate(&body, &identity).unwrap())
    };
    let verify = |certificate: &Value, agent: &str| {
        verify_agent_certificate(certificate, identity.public_raw(), agent, at)
    };
    assert!(verify(
        &certify(&python, "2026-01-01T00:00:00Z", "PT24H"),
        &python
    ));
    assert!(verify(
        &certify(&python, "2026-01-01T00:00:00.000100Z", "PT24H"),
        &python
    ));
    for (issued, ttl) in [
        ("2026-01-01T00:00:00.000Z", "PT24H"),
        ("2026-01-01T00:00:00.100000Z", "PT24H"),
        ("2026-01-01T00:00:00Z", "PT1440M"),
        ("2026-01-01T00:00:00Z", "PT24H0M"),
        ("2026-01-01T00:00:00Z", "PT0S"),
    ] {
        assert!(
            !verify(&certify(&python, issued, ttl), &python),
            "{issued} {ttl}"
        );
    }
    let nested = format!("{}/python/extra", identity.peer_id());
    assert!(!verify(
        &certify(&nested, "2026-01-01T00:00:00Z", "PT24H"),
        &nested
    ));
    // The agent's certificate rides with the golden agent key.
    assert_eq!(key.as_slice(), agent_key().public_raw());
}
