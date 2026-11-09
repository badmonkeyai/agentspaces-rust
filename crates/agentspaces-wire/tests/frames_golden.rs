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

//! Envelopes, frames, and frame bodies against the golden vectors Java produced (`test_golden.py`,
//! `test_founding.py`'s bootstrap frames, `test_adversarial.py`'s frame tests, `test_content.py`'s
//! relay vectors, `test_robustness.py`'s frame filter), plus the attested and session paths of
//! `decode_frame_detailed` as the Ruby and TypeScript clients define them.

mod common;

use agentspaces_wire::bodies::{
    self, AGGREGATE_CAPABILITY, Aggregate, FRAME_KINDS, KIND_CHANNEL_HELLO, KIND_GROUP_AD,
    KIND_GROUP_AD_WANT, KIND_PING, KIND_SESSION_HELLO, LEARN_ACCEPT, LEARN_BUSY, LEARN_OFFER,
    RELAY_SIGNAL_CAPABILITY, RELAY_SIGNAL_UNREACHABLE, RUMOR_HOPS, aggregate_frame,
    aggregate_roster_token, block_body, block_cid, block_want_body, channel_hello_body,
    decode_model, digest_body, encode_model, group_ad_body, group_ad_want_envelope,
    learn_content_id, learn_exchange, parse_block, parse_block_want, parse_channel_hello,
    parse_digest, parse_ping, parse_pipe_data, parse_pull_resp, parse_relay_frame,
    parse_relay_signal, parse_rumor, ping_body, pipe_data_body, pull_resp_body, relay_frame_body,
    relay_signal_body, rumor_body,
};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::envelope::{
    Auth, FrameFilter, accepts, decode_frame, decode_frame_detailed, encode_bare_frame,
    encode_frame, envelope, stamp_physical,
};
use agentspaces_wire::founding::{found_group, verify_signed_group_ad};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::limits::{
    FRAME_FILTER_CAPACITY, MAX_FRAME_AGE_MILLIS, MAX_HLC_SKEW_MILLIS, WIRE_VERSION,
};
use agentspaces_wire::session::{self, HELLO_KINDS};
use common::{golden, hex, s};

fn identity() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn bytes_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

fn map_of(bytes: &[u8]) -> Map {
    cbor::decode(bytes).unwrap().into_map().unwrap()
}

/// The golden PING envelope: group, kind PING, sender, stamp, body nonce 42, addressed to itself.
fn ping_envelope() -> Map {
    envelope(
        s("group_id"),
        KIND_PING,
        s("peer_id"),
        s("hlc_encoded"),
        &hex("ping_body_cbor"),
        Some(s("peer_id")),
    )
}

fn golden_physical() -> i64 {
    s("hlc_encoded").split(':').next().unwrap().parse().unwrap()
}

fn session_key() -> [u8; 32] {
    <[u8; 32]>::try_from(hex("session_key").as_slice()).unwrap()
}

// ---------------------------------------------------------------------------------------------
// The PING frame

#[test]
fn ping_body_envelope_signature_and_frame_match_java() {
    let identity = identity();
    assert_eq!(ping_body(42), hex("ping_body_cbor"));
    let env = ping_envelope();
    let keys: Vec<&str> = env.keys().filter_map(Value::as_str).collect();
    assert_eq!(
        keys,
        ["ver", "group", "kind", "from", "to", "stamp", "body"]
    );
    assert_eq!(bytes_of(&env), hex("ping_envelope_cbor"));
    // RFC 8032 signing is deterministic: same key, same bytes, same signature.
    assert_eq!(
        identity.sign(&bytes_of(&env)).to_vec(),
        hex("ping_envelope_signature")
    );
    assert_eq!(encode_frame(&env, &identity), hex("ping_frame_cbor"));
}

#[test]
fn the_java_ping_frame_decodes_verifies_and_reencodes() {
    let env = decode_frame(&hex("ping_frame_cbor")).expect("the Java frame verifies");
    assert_eq!(env.get("kind").and_then(Value::as_str), Some("PING"));
    assert_eq!(env.get("from").and_then(Value::as_str), Some(s("peer_id")));
    assert_eq!(env.get("ver"), Some(&Value::from(WIRE_VERSION)));
    assert_eq!(bytes_of(&env), hex("ping_envelope_cbor"));
    let body = env.get("body").and_then(Value::as_bytes).unwrap();
    assert_eq!(parse_ping(body), Some(42));
    let (_, auth) = decode_frame_detailed(&hex("ping_frame_cbor"), None, None).unwrap();
    assert_eq!(auth, Auth::Signed);
    assert_eq!(auth.as_str(), "signed");
    assert_eq!(stamp_physical(&env), Some(golden_physical()));
}

#[test]
fn a_tampered_frame_is_refused() {
    let frame = hex("ping_frame_cbor");
    let mut tampered = frame.clone();
    let last = tampered.len() - 2; // the final signature byte, before the map's break
    tampered[last] ^= 0x01;
    assert_eq!(decode_frame(&tampered), None);
    let mut broken = frame.clone();
    let end = broken.len() - 1;
    broken[end] ^= 0x01; // the break byte itself: no longer CBOR
    assert_eq!(decode_frame(&broken), None);
    // Any single flipped bit in the envelope or the signature fails verification or decoding.
    for index in (0..frame.len()).step_by(7) {
        let mut flipped = frame.clone();
        flipped[index] ^= 0x20;
        if let Some(env) = decode_frame(&flipped) {
            panic!("byte {index} flipped still verified: {env:?}");
        }
    }
    assert_eq!(decode_frame(&frame[..frame.len() - 1]), None);
    assert_eq!(decode_frame(&[]), None);
    assert_eq!(decode_frame(&hex("adv_deep_nesting_cbor")), None);
}

#[test]
fn adv_frame_bad_signature_is_refused() {
    assert_eq!(decode_frame(&hex("adv_frame_bad_signature")), None);
    assert_eq!(
        decode_frame_detailed(&hex("adv_frame_bad_signature"), Some(s("peer_id")), None),
        None,
        "a broken signature is not rescued by an attested channel"
    );
}

#[test]
fn a_misaddressed_frame_verifies_but_fails_the_reader_filter() {
    let env = decode_frame(&hex("adv_frame_wrong_destination")).expect("the signature is valid");
    assert_eq!(
        env.get("to").and_then(Value::as_str),
        Some(s("adv_frame_wrong_destination_to"))
    );
    let ping = decode_frame(&hex("ping_frame_cbor")).unwrap();
    assert!(accepts(&ping, s("group_id"), s("peer_id")));
    assert!(!accepts(&env, s("group_id"), s("peer_id")));
    // The recipient it names accepts it.
    assert!(accepts(
        &env,
        s("group_id"),
        s("adv_frame_wrong_destination_to")
    ));
}

#[test]
fn a_frame_for_a_foreign_group_fails_the_reader_filter() {
    let env = decode_frame(&hex("ping_frame_cbor")).unwrap();
    assert!(accepts(&env, s("group_id"), s("peer_id")));
    assert!(!accepts(&env, "zSomeOtherGroup", s("peer_id")));
    // An unaddressed frame passes for every member of its group.
    let mut unaddressed = env.clone();
    unaddressed.insert("to", Value::Null);
    assert!(accepts(&unaddressed, s("group_id"), "zAnyone"));
    unaddressed.remove("to");
    assert!(accepts(&unaddressed, s("group_id"), "zAnyone"));
}

#[test]
fn a_frame_of_another_wire_version_is_dropped() {
    let identity = identity();
    let env = ping_envelope();
    assert!(decode_frame(&encode_frame(&env, &identity)).is_some());
    for bad in [
        Value::from(1),
        Value::from(2),
        Value::from(4),
        Value::from("3"),
        Value::Null,
        Value::from(true),
        Value::from(3.0),
    ] {
        let mut stale = env.clone();
        stale.insert("ver", bad.clone());
        let frame = encode_frame(&stale, &identity); // validly signed
        assert_eq!(
            map_of(&frame).get("envelope").unwrap().get("ver"),
            Some(&bad)
        );
        assert_eq!(decode_frame(&frame), None, "{bad:?}");
        assert_eq!(
            decode_frame_detailed(&encode_bare_frame(&stale), Some(s("peer_id")), None),
            None,
            "{bad:?} bare"
        );
    }
    let mut missing = env.clone();
    missing.remove("ver");
    assert_eq!(decode_frame(&encode_frame(&missing, &identity)), None);
}

#[test]
fn a_frame_whose_key_is_not_its_sender_is_refused() {
    let identity = identity();
    let mut env = ping_envelope();
    env.insert("from", "zSomebodyElse");
    assert_eq!(decode_frame(&encode_frame(&env, &identity)), None);
    // A 31-byte key, a text key, and a missing signature are refused too.
    let good = map_of(&hex("ping_frame_cbor"));
    for (field, value) in [
        ("senderPublicKey", Value::from(&[7u8; 31])),
        ("senderPublicKey", Value::from("key")),
        ("signature", Value::Null),
        ("signature", Value::from("sig")),
    ] {
        let mut frame = good.clone();
        frame.insert(field, value);
        assert_eq!(decode_frame(&bytes_of(&frame)), None, "{field}");
    }
    assert_eq!(decode_frame(&cbor::encode(&Value::from(3))), None);
    assert_eq!(
        decode_frame(&cbor::encode(&cbor_map! { "envelope" => 3 })),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// Bare and session frames

#[test]
fn a_bare_frame_is_accepted_only_from_the_attested_sender() {
    let env = ping_envelope();
    let bare = encode_bare_frame(&env);
    assert_eq!(
        map_of(&bare).len(),
        1,
        "a bare frame carries the envelope alone"
    );
    let (decoded, auth) =
        decode_frame_detailed(&bare, Some(s("peer_id")), None).expect("attested sender");
    assert_eq!(auth, Auth::Attested);
    assert_eq!(decoded, env);
    assert_eq!(
        decode_frame_detailed(&bare, Some("zSomeoneElse"), None),
        None
    );
    assert_eq!(decode_frame_detailed(&bare, None, None), None);
    assert_eq!(decode_frame(&bare), None);
    // A session does not admit a bare frame either: bare is the attested form.
    assert_eq!(
        decode_frame_detailed(&bare, None, Some((s("peer_id"), &session_key()))),
        None
    );
    // Explicit nulls read as absent, as Python's dict.get reads them.
    let nulls = cbor_map! {
        "envelope" => env.clone(), "senderPublicKey" => Value::Null, "signature" => Value::Null,
    };
    assert_eq!(
        decode_frame_detailed(&cbor::encode(&nulls), Some(s("peer_id")), None)
            .map(|(_, auth)| auth),
        Some(Auth::Attested)
    );
}

#[test]
fn a_hello_never_travels_bare_or_tagged_but_travels_signed() {
    let identity = identity();
    let key = session_key();
    for kind in HELLO_KINDS {
        let mut env = ping_envelope();
        env.insert("kind", kind);
        assert_eq!(
            decode_frame_detailed(&encode_bare_frame(&env), Some(s("peer_id")), None),
            None,
            "{kind} bare"
        );
        let tagged = session::encode_session_frame(&Value::Map(env.clone()), &key);
        assert_eq!(
            decode_frame_detailed(&tagged, None, Some((s("peer_id"), &key))),
            None,
            "{kind} tagged"
        );
        let (_, auth) = decode_frame_detailed(
            &encode_frame(&env, &identity),
            Some(s("peer_id")),
            Some((s("peer_id"), &key)),
        )
        .expect("a signed hello");
        assert_eq!(auth, Auth::Signed, "{kind}");
    }
    assert_eq!(HELLO_KINDS, [KIND_SESSION_HELLO, KIND_CHANNEL_HELLO]);
}

#[test]
fn the_java_session_frame_verifies_on_its_session_only() {
    let frame = hex("session_frame_cbor");
    let key = session_key();
    let (env, auth) =
        decode_frame_detailed(&frame, None, Some(("zA", &key))).expect("the Java session frame");
    assert_eq!(auth, Auth::Session);
    assert_eq!(auth.as_str(), "session");
    assert_eq!(bytes_of(&env), hex("session_envelope_cbor"));
    assert_eq!(
        session::encode_session_frame(&Value::Map(env.clone()), &key),
        frame
    );
    // Another peer's session, another key, no session, or an attested channel: refused.
    assert_eq!(
        decode_frame_detailed(&frame, None, Some(("zB", &key))),
        None
    );
    let mut other_key = key;
    other_key[0] ^= 1;
    assert_eq!(
        decode_frame_detailed(&frame, None, Some(("zA", &other_key))),
        None
    );
    assert_eq!(decode_frame_detailed(&frame, None, None), None);
    assert_eq!(decode_frame_detailed(&frame, Some("zA"), None), None);
    assert_eq!(decode_frame(&frame), None);
}

#[test]
fn a_session_frame_is_refused_when_tampered_or_mis_sized() {
    let key = session_key();
    let env = envelope(
        "zGroup",
        KIND_PING,
        "zA",
        "1735689600000:4:zA",
        &ping_body(1),
        Some("zB"),
    );
    let frame = session::encode_session_frame(&Value::Map(env.clone()), &key);
    assert!(decode_frame_detailed(&frame, None, Some(("zA", &key))).is_some());
    let mut tampered = map_of(&frame);
    tampered
        .get_mut("envelope")
        .and_then(Value::as_map_mut)
        .unwrap()
        .insert("stamp", "1735689600000:5:zA");
    assert_eq!(
        decode_frame_detailed(&bytes_of(&tampered), None, Some(("zA", &key))),
        None
    );
    let tag = map_of(&frame).get("signature").cloned().unwrap();
    let tag = tag.as_bytes().unwrap();
    let longer = [tag, &[0u8][..]].concat();
    for bad in [&tag[..31], &longer[..]] {
        let mut sized = map_of(&frame);
        sized.insert("signature", bad);
        assert_eq!(
            decode_frame_detailed(&bytes_of(&sized), None, Some(("zA", &key))),
            None,
            "{} bytes",
            bad.len()
        );
    }
    let mut text_tag = map_of(&frame);
    text_tag.insert("signature", "tag");
    assert_eq!(
        decode_frame_detailed(&bytes_of(&text_tag), None, Some(("zA", &key))),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// The frame filter

fn filtered(sender: &Identity, nonce: i64, stamp: &str) -> Map {
    let env = envelope(
        s("group_id"),
        KIND_PING,
        sender.peer_id(),
        stamp,
        &ping_body(nonce),
        Some(s("peer_id")),
    );
    decode_frame(&encode_frame(&env, sender)).unwrap()
}

#[test]
fn a_replayed_frame_is_dropped_and_counted() {
    let other = Identity::from_seed(&[9u8; 32]);
    let now = golden_physical();
    let mut filter = FrameFilter::new();
    assert_eq!(filter.capacity(), FRAME_FILTER_CAPACITY);
    let ping = filtered(&other, 7, &format!("{now}:1:other"));
    assert!(filter.admit(&ping, now));
    assert!(!filter.admit(&ping, now));
    assert!(!filter.admit(&ping, now));
    assert_eq!(filter.replayed(), 2);
    // A fresh stamp from the same sender is a new frame; the same stamp from another sender too.
    assert!(filter.admit(&filtered(&other, 8, &format!("{now}:2:other")), now));
    assert!(filter.admit(&filtered(&identity(), 7, &format!("{now}:1:other")), now));
    assert_eq!(filter.len(), 3);
    assert_eq!(
        (filter.stale(), filter.ahead(), filter.replayed()),
        (0, 0, 2)
    );
}

#[test]
fn stale_and_far_ahead_frames_are_dropped_quietly() {
    let other = Identity::from_seed(&[9u8; 32]);
    let now = golden_physical();
    let mut filter = FrameFilter::default();
    assert!(!filter.admit(
        &filtered(
            &other,
            1,
            &format!("{}:0:other", now - MAX_FRAME_AGE_MILLIS - 1000)
        ),
        now
    ));
    assert!(!filter.admit(
        &filtered(
            &other,
            2,
            &format!("{}:0:other", now + MAX_HLC_SKEW_MILLIS + 60_000)
        ),
        now
    ));
    assert_eq!(
        (filter.stale(), filter.ahead(), filter.replayed()),
        (1, 1, 0)
    );
    assert!(filter.is_empty(), "a dropped frame is not remembered");
    // Within the bounds either way, and exactly at them, admitted.
    for (nonce, physical) in [
        (3, now - MAX_FRAME_AGE_MILLIS / 2),
        (4, now + MAX_HLC_SKEW_MILLIS / 2),
        (5, now - MAX_FRAME_AGE_MILLIS),
        (6, now + MAX_HLC_SKEW_MILLIS),
    ] {
        assert!(
            filter.admit(
                &filtered(&other, nonce, &format!("{physical}:0:other")),
                now
            ),
            "{nonce}"
        );
    }
    assert_eq!((filter.stale(), filter.ahead()), (1, 1));
    // Hostile extremes neither overflow nor pass.
    let (stale, ahead) = (filter.stale(), filter.ahead());
    for (physical, clock) in [
        (i64::MIN, now),
        (i64::MIN, i64::MAX),
        (i64::MAX, now),
        (i64::MAX, i64::MIN),
    ] {
        let mut env = filtered(&other, 9, "1:0:other");
        env.insert("stamp", format!("{physical}:0:other"));
        assert!(!filter.admit(&env, clock), "{physical} at {clock}");
    }
    assert_eq!((filter.stale(), filter.ahead()), (stale + 2, ahead + 2));
}

#[test]
fn an_unreadable_stamp_is_refused_uncounted() {
    let mut filter = FrameFilter::new();
    let now = golden_physical();
    let mut env = filtered(&identity(), 1, &format!("{now}:0:x"));
    for stamp in [
        Value::from("abc:0:x"),
        Value::from(""),
        Value::from(" 1:0:x"),
        Value::from(now),
        Value::Null,
    ] {
        env.insert("stamp", stamp.clone());
        assert!(!filter.admit(&env, now), "{stamp:?}");
    }
    env.insert("stamp", format!("{now}:0:x"));
    env.insert("from", 5);
    assert!(!filter.admit(&env, now));
    assert_eq!(
        (filter.stale(), filter.ahead(), filter.replayed()),
        (0, 0, 0)
    );
    // A leading plus is a number, as Java's Long.parseLong reads it.
    env.insert("from", "zX");
    env.insert("stamp", format!("+{now}:0:x"));
    assert!(filter.admit(&env, now));
}

#[test]
fn the_filter_forgets_its_oldest_pair_beyond_capacity() {
    let other = Identity::from_seed(&[9u8; 32]);
    let now = golden_physical();
    let mut filter = FrameFilter::with_capacity(2);
    let frames: Vec<Map> = (0..3)
        .map(|logical| filtered(&other, logical, &format!("{now}:{logical}:other")))
        .collect();
    for frame in &frames {
        assert!(filter.admit(frame, now));
    }
    assert_eq!(filter.len(), 2);
    assert!(
        filter.admit(&frames[0], now),
        "the oldest pair was forgotten"
    );
    assert!(
        !filter.admit(&frames[2], now),
        "the newest is still remembered"
    );
    let mut none = FrameFilter::with_capacity(0);
    assert!(none.admit(&frames[0], now));
    assert!(
        none.admit(&frames[0], now),
        "a zero-capacity filter remembers nothing"
    );
}

// ---------------------------------------------------------------------------------------------
// Bodies

#[test]
fn digest_body_matches_java() {
    let digests: Map = [("peers", Value::from(b"x".as_slice()))]
        .into_iter()
        .collect();
    assert_eq!(digest_body(&digests), hex("digest_body_cbor"));
    assert_eq!(parse_digest(&hex("digest_body_cbor")), Some(digests));
    // A digest of several streams is written in canonical order, as Java writes a Map.
    let several: Map = [
        ("space:tasks", b"".as_slice()),
        ("ads", b"".as_slice()),
        ("peers", b"".as_slice()),
    ]
    .into_iter()
    .collect();
    let keys: Vec<String> = parse_digest(&digest_body(&several))
        .unwrap()
        .keys()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    assert_eq!(keys, ["ads", "peers", "space:tasks"]);
}

#[test]
fn small_bodies_round_trip_through_their_parsers() {
    let ack = cbor::decode(&bodies::ack_body(42)).unwrap();
    assert_eq!(ack, cbor_map! { "nonce" => 42, "onBehalf" => Value::Null });
    assert_eq!(parse_ping(&bodies::ack_body(-7)), Some(-7));
    assert_eq!(parse_ping(&cbor::encode(&cbor_map! {})), Some(0));
    assert_eq!(
        parse_ping(&cbor::encode(&cbor_map! { "nonce" => "x" })),
        None
    );
    assert_eq!(parse_ping(b"\xff"), None);

    let rumor = parse_rumor(&rumor_body("ads", "item", RUMOR_HOPS, b"payload")).unwrap();
    assert_eq!(
        (
            rumor.stream_id.as_str(),
            rumor.item_id.as_str(),
            rumor.hops_remaining
        ),
        ("ads", "item", 6)
    );
    assert_eq!(rumor.payload, b"payload");
    let bare = parse_rumor(&cbor::encode(
        &cbor_map! { "streamId" => "peers", "payload" => Value::Null },
    ))
    .unwrap();
    assert!(bare.payload.is_empty() && bare.item_id.is_empty() && bare.hops_remaining == 0);
    assert_eq!(
        parse_rumor(&cbor::encode(&cbor_map! { "itemId" => "x" })),
        None
    );
    assert_eq!(
        parse_rumor(&cbor::encode(
            &cbor_map! { "streamId" => "a", "payload" => "text" }
        )),
        None
    );

    let hello = parse_channel_hello(&channel_hello_body(true, "zRemote")).unwrap();
    assert!(hello.accepts_bare);
    assert_eq!(hello.attested_remote, "zRemote");
    assert_eq!(
        cbor::decode(&channel_hello_body(false, "zR")).unwrap(),
        cbor_map! { "acceptsBare" => false, "attestedRemote" => "zR" }
    );

    let pipe = parse_pipe_data(&pipe_data_body(AGGREGATE_CAPABILITY, b"\xf6")).unwrap();
    assert_eq!(pipe.capability, AGGREGATE_CAPABILITY);
    assert_eq!(pipe.payload, b"\xf6");

    let data = b"some block bytes";
    let cid = block_cid(data);
    assert!(cid.starts_with('z'));
    assert_eq!(parse_block_want(&block_want_body(&cid)), Some(cid.clone()));
    let block = parse_block(&block_body(&cid, data)).unwrap();
    assert!(block.verifies());
    assert_eq!(block.bytes, data);
    let forged = parse_block(&block_body(&cid, b"other bytes")).unwrap();
    assert!(!forged.verifies());

    let deltas: Map = [("peers", b"\x01".as_slice()), ("ads", b"\x02".as_slice())]
        .into_iter()
        .collect();
    let parsed = parse_pull_resp(&pull_resp_body(&deltas)).unwrap();
    assert_eq!(parsed, cbor::canonical_map(&deltas));
    assert_eq!(
        parse_pull_resp(&cbor::encode(&cbor_map! {})),
        Some(Map::new())
    );
    assert_eq!(
        parse_pull_resp(&cbor::encode(&cbor_map! { "deltas" => 1 })),
        None
    );

    assert_eq!(FRAME_KINDS.len(), 20);
    assert!(bodies::is_known_kind("PULL_RESP") && !bodies::is_known_kind("NOPE"));
}

#[test]
fn relay_bodies_match_java() {
    let inner = hex("ping_frame_cbor");
    assert_eq!(
        relay_frame_body("zB", &inner, None, None),
        hex("relay_frame_body_cbor")
    );
    assert_eq!(
        relay_frame_body("zB", &inner, None, Some(3)),
        hex("relay_frame_body_cbor"),
        "hop is ignored without a path"
    );
    assert_eq!(
        relay_frame_body("zB", &inner, Some(&["zR1", "zR2"]), Some(0)),
        hex("relay_frame_with_path_cbor")
    );
    assert_eq!(
        relay_frame_body("zB", &inner, Some(&["zR1", "zR2"]), None),
        hex("relay_frame_with_path_cbor"),
        "a path's hop defaults to 0"
    );
    assert_eq!(
        relay_signal_body("zB", "zR2", RELAY_SIGNAL_UNREACHABLE),
        hex("relay_signal_unreachable_cbor")
    );

    let one_hop = parse_relay_frame(&hex("relay_frame_body_cbor")).unwrap();
    assert_eq!(one_hop.target, "zB");
    assert_eq!(one_hop.frame, inner);
    assert_eq!((one_hop.path.clone(), one_hop.hop), (None, None));
    assert_eq!(one_hop.next_hop(), one_hop);
    assert_eq!(one_hop.body(), hex("relay_frame_body_cbor"));
    let pathed = parse_relay_frame(&hex("relay_frame_with_path_cbor")).unwrap();
    assert_eq!(
        pathed.path.as_deref(),
        Some(&["zR1".to_owned(), "zR2".to_owned()][..])
    );
    assert_eq!(pathed.hop, Some(0));
    assert_eq!(pathed.body(), hex("relay_frame_with_path_cbor"));
    assert_eq!(pathed.next_hop().hop, Some(1));
    // The carried frame is the origin's, verified as usual.
    assert_eq!(
        decode_frame(&pathed.frame),
        decode_frame(&hex("ping_frame_cbor"))
    );

    let pipe = parse_pipe_data(&hex("relay_signal_unreachable_cbor")).unwrap();
    assert_eq!(pipe.capability, RELAY_SIGNAL_CAPABILITY);
    let signal = parse_relay_signal(&pipe.payload).unwrap();
    assert_eq!(
        (
            signal.target.as_str(),
            signal.failed_hop.as_str(),
            signal.reason.as_str()
        ),
        ("zB", "zR2", "unreachable")
    );

    for hostile in [
        cbor_map! { "target" => "zB" },
        cbor_map! { "target" => 1, "frame" => b"x".as_slice() },
        cbor_map! { "target" => "zB", "frame" => b"x".as_slice(), "hop" => -1 },
        cbor_map! { "target" => "zB", "frame" => b"x".as_slice(), "path" => vec![Value::from(1)] },
        cbor_map! { "target" => "zB", "frame" => b"x".as_slice(), "path" => "zR1" },
    ] {
        assert_eq!(
            parse_relay_frame(&cbor::encode(&hostile)),
            None,
            "{hostile:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Join by GroupID

fn found() -> Map {
    found_group(
        &identity(),
        "golden-fleet",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
        "2026-01-01T00:00:00Z",
        "PT24H",
    )
    .unwrap()
}

#[test]
fn group_ad_want_frame_matches_java() {
    let identity = identity();
    let env = group_ad_want_envelope(
        s("founding_group_id"),
        s("peer_id"),
        s("hlc_encoded"),
        Some(s("peer_id")),
    );
    assert_eq!(env.get("body"), Some(&Value::Bytes(Vec::new())));
    assert_eq!(bytes_of(&env), hex("group_ad_want_envelope_cbor"));
    assert_eq!(
        encode_frame(&env, &identity),
        hex("group_ad_want_frame_cbor")
    );
    let decoded = decode_frame(&hex("group_ad_want_frame_cbor")).unwrap();
    assert_eq!(decoded.get("ver"), Some(&Value::from(3)));
    assert_eq!(
        decoded.get("kind").and_then(Value::as_str),
        Some(KIND_GROUP_AD_WANT)
    );
    assert_eq!(
        decoded.get("group").and_then(Value::as_str),
        Some(s("founding_group_id"))
    );
    assert_eq!(decoded.get("body"), Some(&Value::Bytes(Vec::new())));
    // The real request is unaddressed: the seed's PeerID is not yet known.
    assert_eq!(
        group_ad_want_envelope("g", "p", "1:0:p", None).get("to"),
        Some(&Value::Null)
    );
}

#[test]
fn group_ad_frame_matches_java() {
    let identity = identity();
    let body = group_ad_body(&found()).unwrap();
    assert_eq!(body, hex("signed_group_ad_cbor"));
    let env = envelope(
        s("founding_group_id"),
        KIND_GROUP_AD,
        s("peer_id"),
        s("hlc_encoded"),
        &body,
        Some(s("peer_id")),
    );
    assert_eq!(bytes_of(&env), hex("group_ad_envelope_cbor"));
    assert_eq!(encode_frame(&env, &identity), hex("group_ad_frame_cbor"));
    let decoded = decode_frame(&hex("group_ad_frame_cbor")).unwrap();
    assert_eq!(
        decoded.get("kind").and_then(Value::as_str),
        Some(KIND_GROUP_AD)
    );
    let carried = decoded.get("body").and_then(Value::as_bytes).unwrap();
    assert_eq!(carried, hex("signed_group_ad_cbor"));
    assert_eq!(
        verify_signed_group_ad(&cbor::decode(carried).unwrap()).as_deref(),
        Some(s("founding_group_id"))
    );
    // The reader filter keys on the wanted group alone, so the joiner accepts the answer while
    // not yet a member, and a member of another group does not.
    assert!(accepts(&decoded, s("founding_group_id"), s("peer_id")));
    assert!(!accepts(&decoded, s("group_id"), s("peer_id")));
    // A body missing a part is refused, not half-written.
    let mut partial = found();
    partial.remove("signature");
    assert_eq!(group_ad_body(&partial), None);
}

// ---------------------------------------------------------------------------------------------
// Capability payloads

#[test]
fn aggregate_frames_and_the_roster_token_match_java() {
    let share = Aggregate::Share {
        epoch_id: "golden".into(),
        value: 4.5,
        weight: 0.5,
    };
    assert_eq!(
        bytes_of(&aggregate_frame(&share)),
        hex("aggregate_share_frame_cbor")
    );
    let extremum = Aggregate::Extremum {
        epoch_id: "golden".into(),
        max: true,
        value: 4.5,
    };
    assert_eq!(
        bytes_of(&aggregate_frame(&extremum)),
        hex("aggregate_extremum_frame_cbor")
    );
    let histogram = Aggregate::Histogram {
        epoch_id: "golden".into(),
        lo: 0.0,
        hi: 10.0,
        buckets: vec![1.0, 0.0, 2.0, 0.5],
    };
    assert_eq!(
        bytes_of(&aggregate_frame(&histogram)),
        hex("aggregate_histogram_frame_cbor")
    );
    let token = aggregate_roster_token(s("peer_id"));
    assert_eq!(token, -7_559_124_713_570_419_099);
    assert_eq!(token.to_string(), s("aggregate_roster_token"));
    let roster = Aggregate::Roster {
        epoch_id: "golden".into(),
        members: vec![token],
    };
    let roster_bytes = bytes_of(&aggregate_frame(&roster));
    assert_eq!(roster_bytes, hex("aggregate_roster_frame_cbor"));
    // A negative int64 is CBOR major type 1 over 8 bytes, never an unsigned two's complement.
    let negative = [0x3b, 0x68, 0xe7, 0x67, 0xe0, 0x85, 0x3d, 0xc1, 0x9a];
    assert!(roster_bytes.windows(9).any(|w| w == negative));
    // Every Java vector parses back to its variant.
    for (name, variant) in [
        ("aggregate_share_frame_cbor", &share),
        ("aggregate_extremum_frame_cbor", &extremum),
        ("aggregate_histogram_frame_cbor", &histogram),
        ("aggregate_roster_frame_cbor", &roster),
    ] {
        let parsed = Aggregate::from_frame(&cbor::decode(&hex(name)).unwrap());
        assert_eq!(parsed.as_ref(), Some(variant), "{name}");
    }
    // Not exactly one variant: refused.
    let mut two = aggregate_frame(&share);
    two.insert(
        "roster",
        aggregate_frame(&roster).get("roster").unwrap().clone(),
    );
    assert_eq!(Aggregate::from_frame(&Value::Map(two)), None);
    let none = cbor_map! { "share" => Value::Null, "extremum" => Value::Null };
    assert_eq!(Aggregate::from_frame(&none), None);
    let wrong = cbor_map! { "share" => 5 };
    assert_eq!(Aggregate::from_frame(&wrong), None);
}

#[test]
fn gossip_learn_exchanges_match_java() {
    let encoding = hex("learn_model_encoding");
    assert_eq!(encode_model(&[1.0, 2.5, -3.0]), encoding);
    assert_eq!(decode_model(&encoding), Some(vec![1.0, 2.5, -3.0]));
    assert_eq!(decode_model(&encoding[..7]), None);
    assert_eq!(learn_content_id(&encoding), s("learn_content_id"));
    assert_eq!(
        learn_content_id(&encoding),
        "zJ4br3ZyuAyY2TZosJ1fKJurayY1eRqJdUAFacKQta9Dh"
    );
    assert_eq!(
        bytes_of(&learn_exchange(
            "golden-model",
            7,
            LEARN_OFFER,
            2,
            Some(&encoding),
            None
        )),
        hex("learn_exchange_offer_cbor")
    );
    assert_eq!(
        bytes_of(&learn_exchange(
            "golden-model",
            7,
            LEARN_ACCEPT,
            3,
            Some(&encoding),
            None
        )),
        hex("learn_exchange_accept_cbor")
    );
    assert_eq!(
        bytes_of(&learn_exchange(
            "golden-model",
            7,
            LEARN_BUSY,
            0,
            None,
            None
        )),
        hex("learn_exchange_busy_cbor")
    );
    let busy = map_of(&hex("learn_exchange_busy_cbor"));
    assert_eq!(busy.get("inline"), Some(&Value::Null));
    assert_eq!(busy.get("cid"), Some(&Value::Null));
    assert_eq!(busy.get("round"), Some(&Value::from(0)));
}

#[test]
fn the_wire_version_matches_java() {
    assert_eq!(
        golden()["wire_version"].as_u64(),
        Some(u64::from(WIRE_VERSION))
    );
    assert_eq!(
        envelope("g", KIND_PING, "p", "1:0:p", b"", None).get("ver"),
        Some(&Value::from(3))
    );
}
