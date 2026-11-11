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

//! Session attestation (SPEC §5.6) against the Java node's golden vectors (`session_*`), the
//! state machine's open, answer, confirm, tie, echo, retry, and age rules, and the session path
//! of the frame decoder (a hello only fully signed; a session frame only on its session, under
//! its key), as the Ruby gem's `session_test.rb` and the TypeScript client's `session.test.ts`
//! cover them.

mod common;

use agentspaces_wire::bodies::channel_hello_body;
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::crypto::{self, Zeroizing};
use agentspaces_wire::envelope::{
    self, Auth, decode_frame, decode_frame_detailed, encode_bare_frame, encode_frame,
};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::session::{
    self, HELLO_MAX_AGE_MILLIS, HELLO_RETRY_MILLIS, HINT, HelloOutcome, MAC_LENGTH, Session,
    SessionHello, Verdict, derive_key, encode_session_frame, hello_body, hello_is_fresh,
    parse_hello, session_tag, verify_session_tag,
};
use common::hex;

fn array32(name: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex(name).as_slice()).expect("a 32-byte golden value")
}

fn golden_key() -> [u8; 32] {
    array32("session_key")
}

/// The golden session of side A ("zA") or B ("zB"), with the golden scalar and nonce.
fn golden_session(side: char) -> Session {
    let (peer, scalar, nonce) = match side {
        'a' => ("zA", "session_a_scalar", "session_a_nonce"),
        _ => ("zB", "session_b_scalar", "session_b_nonce"),
    };
    Session::with_ephemeral(peer, Zeroizing::new(array32(scalar)), array32(nonce))
}

fn fresh(peer: &str) -> Session {
    Session::new(peer).expect("the random source works")
}

fn parsed(body: &[u8]) -> SessionHello {
    parse_hello(body).expect("a well-formed hello")
}

// ---------------------------------------------------------------------------------------------
// Golden vectors

#[test]
fn the_ephemeral_publics_match_the_java_nodes() {
    let port = crypto::port();
    assert_eq!(
        port.x25519_public_key(&array32("session_a_scalar")),
        array32("session_a_public")
    );
    assert_eq!(
        port.x25519_public_key(&array32("session_b_scalar")),
        array32("session_b_public")
    );
    assert_eq!(
        golden_session('a').ephemeral_public(),
        &array32("session_a_public")
    );
    assert_eq!(
        golden_session('b').ephemeral_public(),
        &array32("session_b_public")
    );
    assert_eq!(golden_session('a').nonce(), &array32("session_a_nonce"));
}

#[test]
fn both_sides_derive_the_java_nodes_key() {
    let a_nonce = hex("session_a_nonce");
    let b_nonce = hex("session_b_nonce");
    let from_a = derive_key(
        &array32("session_a_scalar"),
        "zA",
        &a_nonce,
        &array32("session_b_public"),
        "zB",
        &b_nonce,
    )
    .expect("a contributory agreement");
    let from_b = derive_key(
        &array32("session_b_scalar"),
        "zB",
        &b_nonce,
        &array32("session_a_public"),
        "zA",
        &a_nonce,
    )
    .expect("a contributory agreement");
    assert_eq!(*from_a, golden_key());
    assert_eq!(*from_b, golden_key());
}

#[test]
fn the_hello_and_answer_bodies_match_the_java_nodes() {
    let a_nonce = hex("session_a_nonce");
    let opening = hello_body(&array32("session_a_public"), &a_nonce, "zB", None);
    assert_eq!(opening, hex("session_hello_cbor"));
    let answer = hello_body(
        &array32("session_b_public"),
        &hex("session_b_nonce"),
        "zA",
        Some(&a_nonce),
    );
    assert_eq!(answer, hex("session_answer_cbor"));

    // The session methods build the same bodies from the injected halves.
    assert_eq!(
        golden_session('a').hello("zB", None),
        hex("session_hello_cbor")
    );
    assert_eq!(
        golden_session('b').hello("zA", Some(&a_nonce)),
        hex("session_answer_cbor")
    );

    // And they parse back to what was put in.
    let hello = parsed(&hex("session_hello_cbor"));
    assert_eq!(hello.ephemeral_key, array32("session_a_public"));
    assert_eq!(hello.nonce, a_nonce);
    assert_eq!(hello.remote, "zB");
    assert!(hello.is_opening());
    let answer = parsed(&hex("session_answer_cbor"));
    assert_eq!(answer.ephemeral_key, array32("session_b_public"));
    assert_eq!(answer.nonce, hex("session_b_nonce"));
    assert_eq!(answer.remote, "zA");
    assert_eq!(answer.echo.as_deref(), Some(a_nonce.as_slice()));
    assert!(!answer.is_opening());
}

#[test]
fn the_session_frame_matches_the_java_nodes() {
    let envelope_bytes = hex("session_envelope_cbor");
    let envelope = cbor::decode(&envelope_bytes).expect("the golden envelope decodes");
    assert_eq!(cbor::encode(&envelope), envelope_bytes);
    let frame = encode_session_frame(&envelope, &golden_key());
    assert_eq!(frame, hex("session_frame_cbor"));

    // The spliced encoding is exactly the frame map the codec writes.
    let tag = session_tag(&envelope_bytes, &golden_key());
    let built = cbor_map! {
        "envelope" => envelope.clone(),
        "senderPublicKey" => Value::Null,
        "signature" => tag,
    };
    assert_eq!(cbor::encode(&built), frame);
}

#[test]
fn a_hand_built_envelope_reproduces_the_golden_frame() {
    // The golden envelope built by hand: Java record order, body bytes inline.
    let body = cbor::encode(&cbor_map! { "nonce" => 42 });
    let envelope = cbor_map! {
        "ver" => 3,
        "group" => "zGroup",
        "kind" => "PING",
        "from" => "zA",
        "to" => "zB",
        "stamp" => "1735689600000:3:zA",
        "body" => body,
    };
    assert_eq!(cbor::encode(&envelope), hex("session_envelope_cbor"));
    assert_eq!(
        encode_session_frame(&envelope, &golden_key()),
        hex("session_frame_cbor")
    );
}

#[test]
fn the_golden_frames_tag_verifies_and_a_wrong_one_is_refused() {
    let frame = cbor::decode(&hex("session_frame_cbor")).expect("the golden frame decodes");
    let envelope = frame.get("envelope").expect("an envelope");
    assert_eq!(envelope.get("kind").and_then(Value::as_str), Some("PING"));
    assert_eq!(envelope.get("from").and_then(Value::as_str), Some("zA"));
    assert!(frame.get("senderPublicKey").is_some_and(Value::is_null));
    let tag = frame
        .get("signature")
        .and_then(Value::as_bytes)
        .expect("a tag");
    assert_eq!(tag.len(), MAC_LENGTH);
    let envelope_bytes = cbor::encode(envelope);
    let key = golden_key();
    assert!(verify_session_tag(&envelope_bytes, tag, &key));

    // A flipped bit anywhere in the tag, a wrong key, a changed envelope, and a tag of the wrong
    // length all fail.
    for index in 0..tag.len() {
        let mut wrong = tag.to_vec();
        wrong[index] ^= 0x01;
        assert!(
            !verify_session_tag(&envelope_bytes, &wrong, &key),
            "bit {index}"
        );
    }
    assert!(
        !verify_session_tag(&envelope_bytes, tag, &[b'x'; 32]),
        "a wrong key never verifies"
    );
    let mut changed = envelope_bytes.clone();
    let last = changed.len() - 2; // inside the body, before the closing breaks
    changed[last] ^= 0x01;
    assert!(!verify_session_tag(&changed, tag, &key));
    assert!(!verify_session_tag(&envelope_bytes, &tag[..31], &key));
    let mut long = tag.to_vec();
    long.push(0);
    assert!(!verify_session_tag(&envelope_bytes, &long, &key));
    assert!(!verify_session_tag(&envelope_bytes, &[], &key));
}

// ---------------------------------------------------------------------------------------------
// The state machine (session_test.rb)

#[test]
fn two_sessions_agree_and_the_lower_peer_id_opens_when_both_do() {
    let mut low = fresh("zA");
    let mut high = fresh("zB");
    low.sent(0, false);
    high.sent(0, false);
    let low_hello = parsed(&low.hello("zB", None));
    let high_hello = parsed(&high.hello("zA", None));
    assert_eq!(
        low.accept("zB", &high_hello),
        None,
        "the lower PeerID stays the opener and waits"
    );
    assert_eq!(high.accept("zA", &low_hello), Some(Verdict::Answer));
    let answer = parsed(&high.hello("zA", Some(low.nonce())));
    assert_eq!(low.accept("zB", &answer), Some(Verdict::Confirmed));
    assert_eq!(low.key(), high.key());
    assert!(low.key().is_some());
    assert!(low.is_confirmed());
    assert!(
        !high.is_confirmed(),
        "the answerer signs until the opener's first session frame verifies"
    );
    assert_eq!(
        low.accept("zC", &answer),
        None,
        "one session per connection, with one peer"
    );
    assert_eq!(
        low.key_for(Some("zB"), "SESSION_HELLO"),
        None,
        "hellos are always fully signed"
    );
    assert_eq!(low.key_for(Some("zB"), "CHANNEL_HELLO"), None);
    assert_eq!(low.key_for(Some("zB"), "PING"), low.key());
    assert_eq!(
        low.key_for(Some("zC"), "PING"),
        None,
        "only toward the session's peer"
    );
    assert_eq!(
        low.key_for(None, "PING"),
        None,
        "never for an unaddressed frame"
    );
    assert_eq!(low.remote(), Some("zB"));
    assert_eq!(high.remote(), Some("zA"));
}

#[test]
fn the_golden_sessions_run_the_whole_exchange_to_the_golden_key() {
    let mut a = golden_session('a');
    let mut b = golden_session('b');
    let now = 1_735_689_600_000;
    let opening = a.open("zB", now).expect("a may open");
    assert_eq!(opening, hex("session_hello_cbor"));
    assert!(a.open("zB", now).is_none(), "the opening stands");

    let HelloOutcome::Answer(answer) = b.on_hello("zA", &opening, now, now + 10) else {
        panic!("b answers the opening");
    };
    assert_eq!(answer, hex("session_answer_cbor"));
    assert!(b.answered());
    assert_eq!(b.key(), Some(&golden_key()));
    assert!(!b.is_confirmed());
    assert_eq!(b.key_for(Some("zA"), "PING"), None, "b keeps signing");
    assert_eq!(
        b.established(),
        Some(("zA", &golden_key())),
        "b can verify a's first frame"
    );

    assert_eq!(
        a.on_hello("zB", &answer, now + 10, now + 20),
        HelloOutcome::Confirmed
    );
    assert_eq!(a.key_for(Some("zB"), "PING"), Some(&golden_key()));
    assert_eq!(a.established(), Some(("zB", &golden_key())));

    // a's first tagged frame verifies at b under b's established key, which confirms b.
    let envelope = cbor::decode(&hex("session_envelope_cbor")).expect("the golden envelope");
    let key = a.key_for(Some("zB"), "PING").expect("a tags");
    let frame = cbor::decode(&encode_session_frame(&envelope, key)).expect("the frame decodes");
    let (peer, b_key) = b.established().expect("b holds the key");
    assert_eq!(
        frame
            .get("envelope")
            .and_then(|e| e.get("from"))
            .and_then(Value::as_str),
        Some(peer)
    );
    let tag = frame
        .get("signature")
        .and_then(Value::as_bytes)
        .expect("a tag");
    assert!(verify_session_tag(&cbor::encode(&envelope), tag, b_key));
    b.confirm();
    assert!(b.is_confirmed());
    assert_eq!(b.key_for(Some("zA"), "PING"), Some(&golden_key()));

    // Once a key stands, nothing more is accepted and nothing more opens.
    assert_eq!(
        b.on_hello("zA", &opening, now, now + 30),
        HelloOutcome::Ignored
    );
    assert_eq!(
        a.on_hello("zB", &answer, now, now + 30),
        HelloOutcome::Ignored
    );
    assert!(a.open("zB", now + 60_000).is_none());
    assert!(!a.may_open(now + 60_000));
}

#[test]
fn simultaneous_opens_resolve_to_one_key() {
    let now = 1_000;
    let mut low = fresh("zA");
    let mut high = fresh("zB");
    let low_opening = low.open("zB", now).expect("low opens");
    let high_opening = high.open("zA", now).expect("high opens");
    assert_eq!(
        low.on_hello("zB", &high_opening, now, now),
        HelloOutcome::Ignored
    );
    let HelloOutcome::Answer(answer) = high.on_hello("zA", &low_opening, now, now) else {
        panic!("the higher PeerID answers");
    };
    assert_eq!(
        low.on_hello("zB", &answer, now, now),
        HelloOutcome::Confirmed
    );
    assert_eq!(low.key(), high.key());
    assert!(low.is_confirmed());
    assert!(!high.is_confirmed());
}

#[test]
fn an_answer_that_echoes_another_nonce_is_refused() {
    let mut opener = fresh("zA");
    opener.sent(0, false);
    let forged = parsed(&fresh("zB").hello("zA", Some(&[b'n'; 32])));
    assert_eq!(opener.accept("zB", &forged), None);
    assert!(opener.key().is_none());
    assert!(opener.established().is_none());
}

#[test]
fn an_answer_to_a_hello_never_opened_is_refused() {
    let mut idle = fresh("zA");
    let answer = parsed(&fresh("zB").hello("zA", Some(idle.nonce())));
    assert_eq!(idle.accept("zB", &answer), None, "no opening was sent");

    // Nor is one taken by an end whose own hello was an answer.
    let mut answerer = fresh("zA");
    answerer.sent(0, true);
    let answer = parsed(&fresh("zB").hello("zA", Some(answerer.nonce())));
    assert_eq!(answerer.accept("zB", &answer), None);
}

#[test]
fn a_low_order_ephemeral_key_is_refused_without_a_trace() {
    let mut session = fresh("zB");
    let hostile = SessionHello {
        ephemeral_key: [0; 32],
        nonce: vec![7; 32],
        remote: "zB".into(),
        echo: None,
    };
    assert_eq!(session.accept("zA", &hostile), None);
    assert!(session.key().is_none());
    assert!(session.remote().is_none());
    // The connection can still be opened honestly afterwards.
    let opener = fresh("zA");
    assert_eq!(
        session.accept("zA", &parsed(&opener.hello("zB", None))),
        Some(Verdict::Answer)
    );
}

#[test]
fn an_opening_may_be_repeated_after_the_retry_interval() {
    let mut session = fresh("zA");
    assert!(session.may_open(0));
    assert!(
        session.open("zA", 0).is_none(),
        "never toward this node itself"
    );
    assert!(session.open("zB", 0).is_some());
    assert!(session.hello_sent());
    assert!(!session.may_open(HELLO_RETRY_MILLIS - 1));
    assert!(session.open("zB", HELLO_RETRY_MILLIS - 1).is_none());
    assert!(session.may_open(HELLO_RETRY_MILLIS));
    assert!(session.open("zB", HELLO_RETRY_MILLIS).is_some());

    // An end that answered never opens.
    let mut answerer = fresh("zB");
    answerer.sent(0, true);
    assert!(!answerer.may_open(i64::MAX));
}

#[test]
fn a_hello_is_answered_only_when_fresh_and_addressed_here() {
    let opener = fresh("zA");
    let body = opener.hello("zB", None);
    let now = 1_800_000_000_000;

    let mut session = fresh("zB");
    assert_eq!(
        session.on_hello("zA", &body, now - HELLO_MAX_AGE_MILLIS - 1, now),
        HelloOutcome::Stale
    );
    assert!(session.key().is_none(), "a stale hello creates no state");
    assert_eq!(
        session.on_hello("zA", &opener.hello("zC", None), now, now),
        HelloOutcome::Ignored,
        "a hello naming another peer"
    );
    assert_eq!(
        session.on_hello("zA", b"\xff", now, now),
        HelloOutcome::Ignored
    );
    assert!(session.key().is_none());
    assert!(matches!(
        session.on_hello("zA", &body, now - HELLO_MAX_AGE_MILLIS, now),
        HelloOutcome::Answer(_)
    ));

    assert!(hello_is_fresh(now, now));
    assert!(
        hello_is_fresh(now, now + 60_000),
        "skew is the stamp filter's business"
    );
    assert!(hello_is_fresh(now, now - HELLO_MAX_AGE_MILLIS));
    assert!(!hello_is_fresh(now, now - HELLO_MAX_AGE_MILLIS - 1));
    assert!(
        !hello_is_fresh(now, i64::MIN),
        "no overflow on a hostile stamp"
    );
    assert!(hello_is_fresh(i64::MIN, i64::MAX));
}

#[test]
fn a_lost_answer_is_undone_so_the_opener_opens_again() {
    let mut opener = fresh("zA");
    let mut answerer = fresh("zB");
    let opening = opener.open("zB", 0).expect("opens");
    let HelloOutcome::Answer(_) = answerer.on_hello("zA", &opening, 0, 0) else {
        panic!("answers");
    };
    answerer.send_failed();
    assert!(answerer.key().is_none());
    assert!(answerer.remote().is_none());
    assert!(!answerer.answered());
    assert!(!answerer.hello_sent());

    // The repeated opening (from a fresh session, as after a lost hello) is answered anew.
    let mut opener2 = fresh("zA");
    let opening = opener2.open("zB", HELLO_RETRY_MILLIS).expect("opens");
    let HelloOutcome::Answer(answer) = answerer.on_hello("zA", &opening, 5_000, 5_000) else {
        panic!("answers again");
    };
    assert_eq!(
        opener2.on_hello("zB", &answer, 5_000, 5_000),
        HelloOutcome::Confirmed
    );
    assert_eq!(opener2.key(), answerer.key());

    // A lost opening restores the marks, so the opening may go out again at once.
    opener.send_failed();
    assert!(!opener.hello_sent());
    assert!(opener.may_open(1));
    opener.send_failed(); // nothing outstanding: no change
    assert!(opener.may_open(1));
}

#[test]
fn confirmation_needs_a_key() {
    let mut session = fresh("zA");
    session.confirm();
    assert!(!session.is_confirmed());
    assert_eq!(session.key_for(Some("zB"), "PING"), None);
}

#[test]
fn malformed_hellos_are_refused() {
    let key = [9u8; 32];
    let good = hello_body(&key, &[1; 32], "zB", None);
    assert!(parse_hello(&good).is_some());

    let shaped = |ephemeral: Value, nonce: Value, remote: Value, echo: Value| {
        cbor::encode(&cbor_map! {
            "ephemeralKey" => ephemeral,
            "nonce" => nonce,
            "remote" => remote,
            "echo" => echo,
        })
    };
    let bytes = |n: usize| Value::Bytes(vec![1; n]);
    // Nonce bounds: 16 and 64 bytes pass, 15 and 65 do not.
    assert!(parse_hello(&shaped(bytes(32), bytes(16), "zB".into(), Value::Null)).is_some());
    assert!(parse_hello(&shaped(bytes(32), bytes(64), "zB".into(), Value::Null)).is_some());
    assert!(parse_hello(&shaped(bytes(32), bytes(15), "zB".into(), Value::Null)).is_none());
    assert!(parse_hello(&shaped(bytes(32), bytes(65), "zB".into(), Value::Null)).is_none());
    // The ephemeral key must be exactly 32 bytes.
    assert!(parse_hello(&shaped(bytes(31), bytes(32), "zB".into(), Value::Null)).is_none());
    assert!(parse_hello(&shaped(bytes(33), bytes(32), "zB".into(), Value::Null)).is_none());
    // Text where bytes belong, bytes where text belongs.
    assert!(
        parse_hello(&shaped(
            "k".repeat(32).into(),
            bytes(32),
            "zB".into(),
            Value::Null
        ))
        .is_none()
    );
    assert!(
        parse_hello(&shaped(
            bytes(32),
            "n".repeat(32).into(),
            "zB".into(),
            Value::Null
        ))
        .is_none()
    );
    assert!(parse_hello(&shaped(bytes(32), bytes(32), bytes(2), Value::Null)).is_none());
    assert!(parse_hello(&shaped(bytes(32), bytes(32), "zB".into(), "echo".into())).is_none());
    assert!(parse_hello(&shaped(bytes(32), bytes(32), "zB".into(), Value::Int(1))).is_none());
    // A null echo is an opening. Since v0.1.31 the record's fields are always written and no
    // other is (SPEC §9.1 P1): an absent echo or an extra key does not decode.
    let opening = cbor::encode(&cbor_map! {
        "ephemeralKey" => bytes(32), "nonce" => bytes(32), "remote" => "zB", "echo" => Value::Null,
    });
    assert!(parse_hello(&opening).is_some_and(|hello| hello.is_opening()));
    let absent = cbor::encode(&cbor_map! {
        "ephemeralKey" => bytes(32), "nonce" => bytes(32), "remote" => "zB",
    });
    assert!(parse_hello(&absent).is_none());
    let extra = cbor::encode(&cbor_map! {
        "ephemeralKey" => bytes(32), "nonce" => bytes(32), "remote" => "zB", "echo" => Value::Null,
        "later" => 1,
    });
    assert!(parse_hello(&extra).is_none());
    // Missing fields, other shapes, and garbage.
    let missing = cbor::encode(&cbor_map! { "ephemeralKey" => bytes(32), "nonce" => bytes(32) });
    assert!(parse_hello(&missing).is_none());
    assert!(parse_hello(&cbor::encode(&Value::Array(vec![]))).is_none());
    assert!(parse_hello(&cbor::encode(&Value::Bytes(good.clone()))).is_none());
    assert!(parse_hello(b"").is_none());
    assert!(parse_hello(&good[..good.len() - 1]).is_none(), "truncated");
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(parse_hello(&trailing).is_none(), "trailing bytes");
}

#[test]
fn constants_are_the_reference_values() {
    assert_eq!(HELLO_MAX_AGE_MILLIS, 30_000);
    assert_eq!(HELLO_RETRY_MILLIS, 5_000);
    assert_eq!(HINT, "wire.session");
    assert_eq!(MAC_LENGTH, 32);
    assert_eq!(session::NONCE_LENGTH, 32);
    assert_eq!(session::INFO, b"agentspaces session v1");
    assert_eq!(session::HELLO_KINDS, ["SESSION_HELLO", "CHANNEL_HELLO"]);
}

#[test]
fn debug_shows_no_secrets() {
    let session = golden_session('a');
    let shown = format!("{session:?}");
    assert_eq!(shown, "Session { remote: None, confirmed: false, .. }");
}

// ---------------------------------------------------------------------------------------------
// The decoder's session path (session_test.rb and session.test.ts, which need the envelope
// decoder)

/// A frame map's CBOR, as a hostile or hand-built frame arrives.
fn frame_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

#[test]
fn a_hello_is_accepted_only_fully_signed() {
    // session_test.rb's test_a_hello_is_accepted_only_fully_signed, for both hello kinds.
    let identity = Identity::generate().expect("the random source works");
    let peer = identity.peer_id();
    let key = [b'k'; 32];
    let bodies = [
        ("SESSION_HELLO", fresh(peer).hello("zB", None)),
        ("CHANNEL_HELLO", channel_hello_body(true, "zB")),
    ];
    for (kind, body) in bodies {
        let env = envelope::envelope("g", kind, peer, "1:0:x", &body, None);
        let bare = cbor::encode(&cbor_map! {
            "envelope" => env.clone(),
            "senderPublicKey" => Value::Null,
            "signature" => Value::Null,
        });
        let tagged = envelope::encode_session_frame(&env, &key);
        assert_eq!(
            decode_frame_detailed(&bare, Some(peer), None),
            None,
            "{kind} bare"
        );
        assert_eq!(
            decode_frame_detailed(&encode_bare_frame(&env), Some(peer), None),
            None,
            "{kind} bare, without the null fields"
        );
        assert_eq!(
            decode_frame_detailed(&tagged, None, Some((peer, &key))),
            None,
            "{kind} tagged"
        );
        assert_eq!(
            decode_frame_detailed(&tagged, Some(peer), Some((peer, &key))),
            None,
            "{kind} tagged on an attested channel"
        );
        let signed = encode_frame(&env, &identity);
        assert_eq!(decode_frame(&signed), Some(env.clone()), "{kind} signed");
        assert_eq!(
            decode_frame_detailed(&signed, Some(peer), Some((peer, &key))),
            Some((env, Auth::Signed)),
            "{kind} signed, whatever the connection offers"
        );
    }
}

#[test]
fn decode_frame_detailed_accepts_a_session_frame_on_its_session_only() {
    // session_test.rb's test_the_session_vectors_match_the_java_nodes, decoder half.
    let golden_frame = hex("session_frame_cbor");
    let key = golden_key();
    let (env, auth) = decode_frame_detailed(&golden_frame, None, Some(("zA", &key)))
        .expect("the Java session frame decodes on zA's session");
    assert_eq!(auth, Auth::Session);
    assert_eq!(env.get("kind").and_then(Value::as_str), Some("PING"));
    assert_eq!(frame_of(&env), hex("session_envelope_cbor"));
    // The envelope-level encoder writes the golden frame byte for byte, as the Value one does.
    assert_eq!(envelope::encode_session_frame(&env, &key), golden_frame);
    assert_eq!(
        encode_session_frame(&Value::Map(env.clone()), &key),
        golden_frame
    );
    assert_eq!(
        decode_frame_detailed(&golden_frame, None, Some(("zB", &key))),
        None,
        "a session names its sender"
    );
    assert_eq!(
        decode_frame_detailed(&golden_frame, None, Some(("zA", &[b'x'; 32]))),
        None,
        "a wrong key never verifies"
    );
    assert_eq!(
        decode_frame_detailed(&golden_frame, None, None),
        None,
        "no session, no frame"
    );
    assert_eq!(decode_frame(&golden_frame), None);

    // A wrong tag: every flipped byte, a short one, a long one, and none at all.
    let decoded = cbor::decode(&golden_frame).expect("the golden frame decodes");
    let frame = decoded.as_map().expect("a frame map");
    let tag = frame
        .get("signature")
        .and_then(Value::as_bytes)
        .expect("a tag")
        .to_vec();
    let with_tag = |tag: Value| {
        let mut wrong = frame.clone();
        wrong.insert("signature", tag);
        frame_of(&wrong)
    };
    assert_eq!(with_tag(Value::from(tag.clone())), golden_frame);
    for index in 0..tag.len() {
        let mut flipped = tag.clone();
        flipped[index] ^= 0x80;
        assert_eq!(
            decode_frame_detailed(&with_tag(Value::from(flipped)), None, Some(("zA", &key))),
            None,
            "byte {index}"
        );
    }
    for wrong in [
        Value::from(&tag[..MAC_LENGTH - 1]),
        Value::from([tag.as_slice(), &[0]].concat()),
        Value::from(""),
        Value::Int(1),
    ] {
        assert_eq!(
            decode_frame_detailed(&with_tag(wrong.clone()), None, Some(("zA", &key))),
            None,
            "{wrong:?}"
        );
    }
    let unsigned = with_tag(Value::Null);
    assert_eq!(
        decode_frame_detailed(&unsigned, None, Some(("zA", &key))),
        None,
        "a bare frame needs an attested channel, not a session"
    );
    assert_eq!(
        decode_frame_detailed(&unsigned, Some("zA"), Some(("zA", &key))).map(|(_, auth)| auth),
        Some(Auth::Attested)
    );

    // A hello kind is never accepted bare or session-tagged, even under the right key.
    for kind in session::HELLO_KINDS {
        let mut hello = env.clone();
        hello.insert("kind", kind);
        let tagged = envelope::encode_session_frame(&hello, &key);
        assert_eq!(
            decode_frame_detailed(&tagged, None, Some(("zA", &key))),
            None,
            "{kind} tagged"
        );
        assert_eq!(
            decode_frame_detailed(&encode_bare_frame(&hello), Some("zA"), Some(("zA", &key))),
            None,
            "{kind} bare"
        );
    }
}

#[test]
fn a_session_frame_under_derived_keys_round_trips() {
    // session.test.ts's deterministic case: fixed scalars and nonces, one key both ways.
    let port = crypto::port();
    let (a_scalar, b_scalar) = ([1u8; 32], [2u8; 32]);
    let (a_nonce, b_nonce) = ([0xaa; 32], [0xbb; 32]);
    let from_a = derive_key(
        &a_scalar,
        "zA",
        &a_nonce,
        &port.x25519_public_key(&b_scalar),
        "zB",
        &b_nonce,
    )
    .expect("a contributory agreement");
    let from_b = derive_key(
        &b_scalar,
        "zB",
        &b_nonce,
        &port.x25519_public_key(&a_scalar),
        "zA",
        &a_nonce,
    )
    .expect("a contributory agreement");
    assert_eq!(*from_a, *from_b, "both ends derive one key");
    let (from_a, from_b): (&[u8; 32], &[u8; 32]) = (&from_a, &from_b);
    let env = envelope::envelope(
        "zGroup",
        "PING",
        "zA",
        "1735689600000:3:zA",
        b"x",
        Some("zB"),
    );
    let frame = envelope::encode_session_frame(&env, from_a);
    assert_eq!(
        frame,
        encode_session_frame(&Value::Map(env.clone()), from_a)
    );
    assert_eq!(
        decode_frame_detailed(&frame, None, Some(("zA", from_b))),
        Some((env, Auth::Session))
    );
    assert_eq!(
        decode_frame_detailed(&frame, None, Some(("zB", from_b))),
        None
    );
    assert_eq!(
        decode_frame_detailed(&frame, None, None),
        None,
        "no session, no acceptance"
    );
}
