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

//! Seams between modules: envelope, bodies, ads, records, revocation, social, and beacon
//! composed the way a peer composes them, so a mismatch between two modules' shapes fails here
//! even when each module's own golden vectors pass.
//!
//! - A space write travels as a signed `RUMOR` frame and verifies at the receiver.
//! - A session agreed over signed `SESSION_HELLO` frames tags the next frame.
//! - A founded group reaches a joiner through a beacon document, and the joiner's delegated
//!   credential rides its peer advertisement.
//! - An agent-attested write still verifies after its agent is revoked; the registry refuses it.
//! - A payload above the inline limit travels as a block the record references.

use agentspaces_wire::ads::{peer_advertisement, signed_peer_ad, verify_signed_peer_ad};
use agentspaces_wire::beacon::{
    BeaconDocument, Group, group_from_document, seeds_of, sign_document, to_json,
    verified_group_id, verify_document,
};
use agentspaces_wire::bodies::{
    self, KIND_GROUP_AD, KIND_PING, KIND_RUMOR, KIND_SESSION_HELLO, RUMOR_HOPS,
    STREAM_SPACE_PREFIX, block_body, group_ad_body, parse_block, parse_ping, parse_rumor,
    ping_body, rumor_body,
};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::envelope::{
    Auth, FrameFilter, accepts, decode_frame_detailed, encode_frame, envelope, stamp_physical,
};
use agentspaces_wire::founding::{found_group, verify_signed_group_ad};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids;
use agentspaces_wire::limits::{INLINE_PAYLOAD_LIMIT, MAX_FRAME_BYTES};
use agentspaces_wire::records::{
    self, EntryWrite, PayloadSource, entry_delta, entry_state, payload_source, verify_record,
    verify_state_signature,
};
use agentspaces_wire::revocation::{
    CREDENTIAL_STREAM, Registry, agent_target, credential_revocation, sign_revocation,
};
use agentspaces_wire::session::{HelloOutcome, Session, encode_session_frame};
use agentspaces_wire::social::{
    GroupSecret, HINT_KEY, InviteKey, JoinVerdict, delegate, hints_for, judge_delegated_credential,
};
use agentspaces_wire::time::parse_instant_millis;

const ISSUED: &str = "2026-11-08T12:00:00Z";
const MINUTE: i64 = 60_000;
const DAY: i64 = 24 * 60 * MINUTE;

fn now() -> i64 {
    parse_instant_millis(ISSUED).unwrap()
}

/// An HLC stamp `physical:logical:node` at `now() + offset`.
fn stamp(peer: &Identity, offset: i64, logical: u32) -> String {
    format!("{}:{logical}:{}", now() + offset, peer.peer_id())
}

fn body_of(env: &Map) -> &[u8] {
    env.get("body").and_then(Value::as_bytes).unwrap()
}

fn map_field<'a>(map: &'a Map, key: &str) -> &'a Map {
    map.get(key).and_then(Value::as_map).unwrap()
}

/// The fold's composition for a non-completion state: the record under the issuer's key (and
/// certificate, when attested), then the state signature with the issuer as the party.
fn issuer_accepts(state: &Map, now_ms: i64) -> bool {
    let record = map_field(state, "record");
    let issuer = record.get("issuer").and_then(Value::as_str).unwrap();
    let key = state
        .get("issuerPublicKey")
        .and_then(Value::as_bytes)
        .unwrap();
    let certificate = state.get("agentCertificate");
    let attested = certificate.is_some_and(|c| !c.is_null());
    verify_record(record, key, certificate, now_ms)
        && verify_state_signature(state, issuer, key, attested, now_ms)
}

fn founded(founder: &Identity) -> (Map, String) {
    let signed = found_group(
        founder,
        "seams",
        "INVITE",
        "LEASE_RACE",
        3,
        "PT1S",
        ISSUED,
        "PT720H",
    )
    .unwrap();
    let group_id = verify_signed_group_ad(&Value::Map(signed.clone())).unwrap();
    (signed, group_id)
}

#[test]
fn a_space_write_travels_as_a_signed_rumor_frame_and_verifies() {
    let writer = Identity::from_seed(&[7; 32]);
    let reader = Identity::from_seed(&[8; 32]);
    let (_, group) = founded(&writer);
    let space = ids::space_id_local("tasks");
    let issued = stamp(&writer, 0, 0);
    let payload = cbor::encode(&cbor_map! { "topic" => "seams", "priority" => 3 });
    let write = EntryWrite {
        entry_id: "e-1",
        space_id: &space,
        type_name: "Task#v1",
        payload: Some(&payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: &issued,
        expires_at_millis: now() + MINUTE,
        counter: 1,
    };
    let delta = entry_delta(&write, &writer, "worker", None).unwrap();
    let body = rumor_body(
        &format!("{STREAM_SPACE_PREFIX}tasks"),
        "w:e-1",
        RUMOR_HOPS,
        &delta,
    );
    let env = envelope(&group, KIND_RUMOR, writer.peer_id(), &issued, &body, None);
    let frame = encode_frame(&env, &writer);
    assert!(frame.len() <= MAX_FRAME_BYTES);

    // The reader: verify the frame, filter it, read the rumor, judge the state.
    let (received, auth) = decode_frame_detailed(&frame, None, None).unwrap();
    assert_eq!(auth, Auth::Signed);
    assert_eq!(received, env);
    assert!(accepts(&received, &group, reader.peer_id()));
    assert!(!accepts(&received, "zSomeOtherGroup", reader.peer_id()));
    assert_eq!(stamp_physical(&received), Some(now()));
    let mut filter = FrameFilter::new();
    assert!(filter.admit(&received, now() + 5));
    assert!(!filter.admit(&received, now() + 6), "a replay is dropped");
    assert_eq!(filter.replayed(), 1);

    let rumor = parse_rumor(body_of(&received)).unwrap();
    assert_eq!(rumor.stream_id, "space:tasks");
    assert_eq!(rumor.item_id, "w:e-1");
    assert_eq!(rumor.payload, delta);
    let decoded = cbor::decode(&rumor.payload).unwrap().into_map().unwrap();
    let state = map_field(&decoded, "state");
    assert_eq!(
        state.get("issuerPublicKey").and_then(Value::as_bytes),
        Some(&writer.public_raw()[..])
    );
    assert_eq!(
        map_field(state, "record")
            .get("issuer")
            .and_then(Value::as_str),
        Some(writer.agent("worker").as_str())
    );
    assert!(issuer_accepts(state, now() + 5));
    assert_eq!(
        payload_source(map_field(state, "record")),
        Some(PayloadSource::Inline(&payload))
    );

    // No flipped bit anywhere in the frame verifies a different envelope. A flip may still
    // verify when it decodes to the same values (null `0xF6` to undefined `0xF7`, both
    // `Value::Null`), because the signature covers the canonical re-encoding.
    let mut same = 0;
    for at in 0..frame.len() {
        for bit in 0..8 {
            let mut tampered = frame.clone();
            tampered[at] ^= 1 << bit;
            if let Some((other, _)) = decode_frame_detailed(&tampered, None, None) {
                assert_eq!(
                    other, env,
                    "a flip of bit {bit} at {at} verified another envelope"
                );
                same += 1;
            }
        }
    }
    assert!(same <= 4, "{same} flips decoded to the same envelope");
}

#[test]
fn a_session_agreed_over_signed_hellos_tags_the_next_frame() {
    let a = Identity::from_seed(&[3; 32]);
    let b = Identity::from_seed(&[4; 32]);
    let (_, group) = founded(&a);
    let mut sa = Session::new(a.peer_id()).unwrap();
    let mut sb = Session::new(b.peer_id()).unwrap();

    // a opens: a signed SESSION_HELLO addressed to b.
    let opening = sa.open(b.peer_id(), now()).unwrap();
    let hello = envelope(
        &group,
        KIND_SESSION_HELLO,
        a.peer_id(),
        &stamp(&a, 0, 0),
        &opening,
        Some(b.peer_id()),
    );
    let (got, auth) = decode_frame_detailed(&encode_frame(&hello, &a), None, None).unwrap();
    assert_eq!(auth, Auth::Signed);
    assert!(accepts(&got, &group, b.peer_id()));
    let HelloOutcome::Answer(answer) = sb.on_hello(
        a.peer_id(),
        body_of(&got),
        stamp_physical(&got).unwrap(),
        now() + 10,
    ) else {
        panic!("b answers the opening");
    };

    // b answers: also signed; a confirms.
    let reply = envelope(
        &group,
        KIND_SESSION_HELLO,
        b.peer_id(),
        &stamp(&b, 10, 0),
        &answer,
        Some(a.peer_id()),
    );
    let (got, _) = decode_frame_detailed(&encode_frame(&reply, &b), None, None).unwrap();
    assert_eq!(
        sa.on_hello(
            b.peer_id(),
            body_of(&got),
            stamp_physical(&got).unwrap(),
            now() + 20
        ),
        HelloOutcome::Confirmed
    );
    assert_eq!(sa.key(), sb.key(), "both sides derived the same key");

    // a tags a PING; b verifies it under its established (not yet confirmed) key.
    let ping = envelope(
        &group,
        KIND_PING,
        a.peer_id(),
        &stamp(&a, 30, 0),
        &ping_body(42),
        Some(b.peer_id()),
    );
    let key = sa.key_for(Some(b.peer_id()), KIND_PING).unwrap();
    let tagged = encode_session_frame(&Value::Map(ping.clone()), key);
    assert!(tagged.len() < encode_frame(&ping, &a).len());
    let (got, auth) = decode_frame_detailed(&tagged, None, sb.established()).unwrap();
    assert_eq!(auth, Auth::Session);
    assert_eq!(got, ping);
    assert_eq!(parse_ping(body_of(&got)), Some(42));
    sb.confirm();
    assert!(sb.is_confirmed());

    // A hello is never tagged, a tag is no signature, and another session cannot verify it.
    assert!(sa.key_for(Some(b.peer_id()), KIND_SESSION_HELLO).is_none());
    assert!(decode_frame_detailed(&tagged, None, None).is_none());
    let stranger = [9u8; 32];
    assert!(decode_frame_detailed(&tagged, None, Some((a.peer_id(), &stranger))).is_none());
}

#[test]
fn a_founded_group_reaches_a_joiner_through_a_beacon_and_an_invite() {
    let founder = Identity::from_seed(&[1; 32]);
    let joiner = Identity::from_seed(&[2; 32]);
    let (signed, group_id) = founded(&founder);

    // GROUP_AD carries the same proof the founding returned.
    let body = group_ad_body(&signed).unwrap();
    assert_eq!(
        verify_signed_group_ad(&cbor::decode(&body).unwrap()),
        Some(group_id.clone())
    );
    let ad_env = envelope(
        &group_id,
        KIND_GROUP_AD,
        founder.peer_id(),
        &stamp(&founder, 0, 0),
        &body,
        Some(joiner.peer_id()),
    );
    let (got, _) = decode_frame_detailed(&encode_frame(&ad_env, &founder), None, None).unwrap();
    assert_eq!(body_of(&got), &body[..]);

    // The founder publishes a signed beacon document; the joiner pins the founder.
    let doc = sign_document(
        &founder,
        ISSUED,
        3_600,
        vec![
            Group::new("seams")
                .with_id(&group_id)
                .with_signed_founding(&signed)
                .with_seed("tcp", "127.0.0.1:7460"),
        ],
    )
    .unwrap();
    let fetched = BeaconDocument::parse(&to_json(&doc)).unwrap();
    assert_eq!(fetched, doc);
    assert_eq!(
        verify_document(&fetched, Some(founder.peer_id())),
        Ok(Some(founder.peer_id().to_owned()))
    );
    assert!(verify_document(&fetched, Some(joiner.peer_id())).is_err());
    let group = group_from_document(&fetched, Some(&group_id), None).unwrap();
    assert_eq!(
        verified_group_id(group, Some(&group_id)),
        Ok(group_id.clone())
    );
    let seeds = seeds_of(group, &["tcp"]);
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].address(), "127.0.0.1:7460");

    // The founder delegates the group to an invite key; the joiner presents its credential in
    // its peer advertisement, and a member judges it against the group ad's issuer.
    let invite = InviteKey::of(GroupSecret::new([5; 16]).unwrap());
    let delegation = delegate(
        &founder,
        &group_id,
        &invite.secret().invite_public_key(),
        now() + DAY,
        Some("seams"),
    );
    let hints = hints_for(&invite, &delegation, joiner.peer_id()).unwrap();
    let ad = peer_advertisement(&group_id, &joiner, ISSUED, Some(&hints));
    let (verified, issuer) = verify_signed_peer_ad(&signed_peer_ad(&ad, &joiner)).unwrap();
    assert_eq!(issuer, joiner.peer_id());
    let credential = map_field(&verified, "resourceHints")
        .get(HINT_KEY)
        .and_then(Value::as_str)
        .unwrap();
    let ad_issuer = map_field(&signed, "advertisement")
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap();
    assert_eq!(ad_issuer, founder.peer_id());
    let judge = |candidate: &str, at: i64| {
        judge_delegated_credential(credential, candidate, ad_issuer, &group_id, at)
    };
    assert_eq!(judge(joiner.peer_id(), now()), JoinVerdict::Valid);
    assert_eq!(judge(founder.peer_id(), now()), JoinVerdict::Invalid);
    assert_eq!(
        judge(joiner.peer_id(), now() + 2 * DAY),
        JoinVerdict::Expired
    );
}

#[test]
fn a_revoked_agents_write_still_verifies_and_the_registry_refuses_it() {
    let peer = Identity::from_seed(&[9; 32]);
    let (_, group) = founded(&peer);
    let mut agent = peer
        .renewing_subordinate("scout", "PT1H", None, now())
        .unwrap();
    assert!(!agent.renew_if_due(&peer, now()).unwrap());
    let space = ids::space_id_local("tasks");
    let issued = stamp(&peer, 0, 0);
    let signed_at = stamp(&peer, 0, 1);
    let write = EntryWrite {
        entry_id: "e-2",
        space_id: &space,
        type_name: "Task#v1",
        payload: Some(b"\xf6"),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: &issued,
        expires_at_millis: now() + MINUTE,
        counter: 1,
    };
    let state = entry_state(&write, &peer, "unused", Some((&agent, &signed_at))).unwrap();
    assert_eq!(
        map_field(&state, "record")
            .get("issuer")
            .and_then(Value::as_str),
        Some(agent.agent_id())
    );
    assert!(issuer_accepts(&state, now() + 5));

    // The agent's own peer retires the agent half an hour later.
    let mut registry = Registry::new(None, Some(group.clone()));
    assert!(!registry.refuses(agent.agent_id(), Some(agent.public_raw()), Some(now())));
    let ad = credential_revocation(
        peer.peer_id(),
        &group,
        "2026-11-08T12:30:00Z",
        "PT24H",
        &agent_target(agent.agent_id()),
        "retired",
        None,
    )
    .unwrap();
    let payload = cbor::encode(&Value::Map(sign_revocation(&ad, &peer)));
    assert!(registry.accept(CREDENTIAL_STREAM, &payload, now() + 30 * MINUTE));
    assert!(
        !registry.accept(CREDENTIAL_STREAM, &payload, now() + 30 * MINUTE),
        "the same record does not revoke twice"
    );

    // The freeze rule: the write signed before the revocation stands, a later signature does
    // not. The record check alone still passes; refusing is the fold's composition.
    assert!(issuer_accepts(&state, now() + 31 * MINUTE));
    let key = agent.public_raw();
    assert!(!registry.refuses(agent.agent_id(), Some(key), Some(now())));
    assert!(registry.refuses(agent.agent_id(), Some(key), Some(now() + 30 * MINUTE)));
    assert!(registry.refuses(agent.agent_id(), Some(key), None));
    assert!(!registry.refuses(&peer.agent("sibling"), None, Some(now() + 30 * MINUTE)));
}

#[test]
fn a_large_payload_travels_as_a_block_the_record_references() {
    let writer = Identity::from_seed(&[6; 32]);
    let data = vec![0xA5; INLINE_PAYLOAD_LIMIT + 1];
    let cid = bodies::block_cid(&data);
    assert_eq!(
        records::block_cid(&data),
        cid,
        "one block id across modules"
    );
    let space = ids::space_id_local("files");
    let issued = stamp(&writer, 0, 0);
    let write = EntryWrite {
        entry_id: "e-3",
        space_id: &space,
        type_name: "File#v1",
        payload: None,
        payload_ref: Some(&cid),
        tags: None,
        key_epoch: None,
        issued: &issued,
        expires_at_millis: now() + MINUTE,
        counter: 1,
    };
    let state = entry_state(&write, &writer, "uploader", None).unwrap();
    assert!(issuer_accepts(&state, now() + 5));
    let record = map_field(&state, "record");
    assert_eq!(payload_source(record), Some(PayloadSource::Block(&cid)));

    let block = parse_block(&block_body(&cid, &data)).unwrap();
    assert_eq!(block.cid, cid);
    assert!(block.verifies());
    let mut forged = block.clone();
    forged.bytes[0] ^= 1;
    assert!(!forged.verifies());
}
