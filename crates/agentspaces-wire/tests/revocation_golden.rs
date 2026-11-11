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

//! Revocations against the golden vectors Java produced (`test_golden.py`'s credential
//! revocation tests): the builders reproduce Java's `CredentialRevocation` and
//! `SignedRevocation` bytes, an agent's own peer revokes its agent and key under the freeze
//! rule, only the founder revokes an X.509 leaf or a join credential, a cross-issuer revocation
//! is refused under either founder setting, and hostile or malformed records are refused
//! without panicking.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids::derive_id;
use agentspaces_wire::revocation::{
    Authority, CREDENTIAL_STREAM, KEY_COMPROMISE, KINDS, MAX_EVIDENCE, MAX_ISSUED_SKEW_MILLIS,
    PEER_STREAM, REASONS, Registry, STREAMS, UNSPECIFIED, agent_key_target, agent_target,
    canonical_target, credential_revocation, is_valid_target, join_credential_target,
    revocation_id, sign_revocation, x509_leaf_target,
};
use agentspaces_wire::time::parse_instant_millis;
use common::{hex, s};

const MINUTE: i64 = 60_000;
const ISSUED: &str = "2026-01-01T00:00:00Z";
const TTL: &str = "PT720H";

fn identity() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn forger() -> Identity {
    Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap()
}

fn at(iso: &str) -> i64 {
    parse_instant_millis(iso).unwrap()
}

fn now() -> i64 {
    at("2026-06-01T00:00:00Z")
}

fn decoded_map(bytes: &[u8]) -> Map {
    cbor::decode(bytes).unwrap().into_map().unwrap()
}

fn bytes_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    crypto::port().sha256(data)
}

fn group() -> Option<String> {
    Some(s("group_id").to_owned())
}

/// The four golden revocations as Java `GoldenVectors` built them.
fn golden_ad(kind: &str) -> Map {
    let agent = identity().agent("python");
    let (target, reason, effective) = match kind {
        "agent" => (
            agent_target(&agent),
            "retired",
            Some("2025-12-31T23:00:00Z"),
        ),
        "agent_key" => (
            agent_key_target(&agent, &sha256(&hex("agent_public_key_raw"))),
            KEY_COMPROMISE,
            None,
        ),
        "x509_leaf" => (
            x509_leaf_target(
                "CN=golden-leaf,O=Bad Monkey",
                "0a1b2c3d",
                &sha256(b"golden-leaf-der"),
            ),
            "superseded",
            None,
        ),
        _ => (
            join_credential_target(&sha256(b"golden-join-credential")),
            "privilege-withdrawn",
            None,
        ),
    };
    credential_revocation(
        s("peer_id"),
        s("group_id"),
        ISSUED,
        TTL,
        &target,
        reason,
        effective,
    )
    .unwrap()
}

const GOLDEN_KINDS: [&str; 4] = ["agent", "agent_key", "x509_leaf", "join_credential"];

#[test]
fn the_constants_are_javas() {
    assert_eq!(STREAMS, ["revocations", "credential-revocations"]);
    assert_eq!(
        KINDS,
        ["AGENT", "AGENT_KEY", "X509_LEAF", "JOIN_CREDENTIAL"]
    );
    assert_eq!(REASONS[0], "key-compromise");
    assert_eq!(REASONS.len(), 5);
}

#[test]
fn the_builders_reproduce_javas_revocations_byte_for_byte() {
    for kind in GOLDEN_KINDS {
        let ad = golden_ad(kind);
        assert_eq!(
            bytes_of(&ad),
            hex(&format!("credential_revocation_{kind}_cbor")),
            "{kind}"
        );
        // Ed25519 is deterministic: the signed record is Java's too.
        assert_eq!(
            bytes_of(&sign_revocation(&ad, &identity())),
            hex(&format!("signed_credential_revocation_{kind}_cbor")),
            "{kind}"
        );
        let target = ad.get("target").and_then(Value::as_map).unwrap();
        assert!(is_valid_target(target));
        assert_eq!(
            revocation_id(s("group_id"), target).as_deref(),
            ad.get("id").and_then(Value::as_str)
        );
    }
    // The cross-issuer record: the forger revoking an agent it does not host.
    let ad = credential_revocation(
        forger().peer_id(),
        s("group_id"),
        ISSUED,
        TTL,
        &agent_target(&identity().agent("python")),
        KEY_COMPROMISE,
        None,
    )
    .unwrap();
    assert_eq!(
        bytes_of(&sign_revocation(&ad, &forger())),
        hex("adv_credential_revocation_cross_issuer_cbor")
    );
}

#[test]
fn a_builder_refuses_an_invalid_target_or_reason() {
    let target = agent_target("p/a");
    let build = |target: &Map, reason: &str| {
        credential_revocation("p", "zG", ISSUED, TTL, target, reason, None)
    };
    assert!(build(&target, "because").is_none());
    let blank = build(&target, " ").unwrap();
    assert_eq!(
        blank.get("reason").and_then(Value::as_str),
        Some("unspecified")
    );
    let mut bad = target.clone();
    bad.remove("agent");
    assert!(build(&bad, "retired").is_none());
}

#[test]
fn credential_revocations_from_the_agents_own_peer_apply_the_freeze_rule() {
    // SPEC §5.6 v0.1.13: the golden peer revokes its own agent (retired, an hour before issue)
    // and the agent's key (key-compromise).
    let identity = identity();
    let mut registry = Registry::new(None, group());
    for kind in ["agent", "agent_key"] {
        let payload = hex(&format!("signed_credential_revocation_{kind}_cbor"));
        assert!(
            registry.accept(CREDENTIAL_STREAM, &payload, now()),
            "{kind}"
        );
        // The same record again revokes nothing new.
        assert!(
            !registry.accept(CREDENTIAL_STREAM, &payload, now()),
            "{kind}"
        );
    }
    let issued = at(ISSUED);
    let agent = identity.agent("python");
    assert!(!registry.refuses(&agent, None, Some(issued - 90 * MINUTE)));
    assert!(registry.refuses(&agent, None, Some(issued - 30 * MINUTE)));
    assert!(
        registry.refuses(&agent, None, Some(issued - 60 * MINUTE)),
        "at the instant"
    );
    assert!(!registry.refuses(&agent, None, Some(issued - 60 * MINUTE - 1)));
    assert!(registry.refuses(&agent, None, None));
    assert!(registry.refuses(&agent, Some(&hex("agent_public_key_raw")), Some(0)));
    assert!(!registry.refuses(&identity.agent("sibling"), None, Some(issued)));
    assert!(
        !registry.refuses(&agent, Some(&[7u8; 32]), Some(0)),
        "another key, before the agent-wide instant"
    );
    assert!(!registry.peer_revoked(identity.peer_id()));

    let held = &registry.credentials()[&format!("AGENT:{agent}")];
    assert_eq!(held.authority, Authority::OwnPeer);
    assert_eq!(held.issued_ms, issued);
    assert_eq!(held.effective_ms, issued - 60 * MINUTE);
    assert!(!held.compromise);
    assert_eq!(
        held.digest,
        sha256(&hex("credential_revocation_agent_cbor"))
    );
    let key = format!(
        "AGENT_KEY:{agent}#{}",
        hex_of(&sha256(&hex("agent_public_key_raw")))
    );
    assert!(registry.credentials()[&key].compromise);
    assert_eq!(registry.credentials().len(), 2);

    // A stranger cannot revoke the agent: the same bytes re-signed by another key fail.
    let stranger = Identity::generate().unwrap();
    let ad = hex("credential_revocation_agent_cbor");
    let mut fresh = Registry::new(None, group());
    let mut signed = Map::new();
    signed.insert("adBytes", ad.as_slice());
    signed.insert("publicKey", stranger.public_raw());
    signed.insert("signature", stranger.sign(&ad));
    assert!(!fresh.accept_signed(CREDENTIAL_STREAM, &Value::Map(signed), now()));
    assert!(fresh.credentials().is_empty());
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn leaf_and_join_credential_revocations_need_the_founder() {
    // SPEC §5.6 v0.1.13: only the founder revokes an X.509 leaf or a join credential.
    let mut founded = Registry::new(Some(s("peer_id").to_owned()), group());
    let stranger = Identity::generate().unwrap();
    let mut stranger_founded = Registry::new(Some(stranger.peer_id().to_owned()), group());
    let mut unfounded = Registry::new(None, group());
    let expected_targets = [
        (
            "x509_leaf",
            x509_leaf_target(
                "CN=golden-leaf,O=Bad Monkey",
                "0a1b2c3d",
                &sha256(b"golden-leaf-der"),
            ),
        ),
        (
            "join_credential",
            join_credential_target(&sha256(b"golden-join-credential")),
        ),
    ];
    for (kind, target) in &expected_targets {
        let ad = decoded_map(&hex(&format!("credential_revocation_{kind}_cbor")));
        assert_eq!(
            ad.get("target"),
            Some(&Value::Map(target.clone())),
            "{kind}"
        );
        assert_eq!(
            ad.get("id").and_then(Value::as_str),
            revocation_id(s("group_id"), target).as_deref()
        );
        assert_eq!(ad.get("issuer").and_then(Value::as_str), Some(s("peer_id")));
        let signed = hex(&format!("signed_credential_revocation_{kind}_cbor"));
        assert!(founded.accept(CREDENTIAL_STREAM, &signed, now()), "{kind}");
        assert!(
            !stranger_founded.accept(CREDENTIAL_STREAM, &signed, now()),
            "{kind}"
        );
        assert!(
            !unfounded.accept(CREDENTIAL_STREAM, &signed, now()),
            "{kind}"
        );
    }
    let keys: Vec<&String> = founded.credentials().keys().collect();
    let mut expected = [
        format!("X509_LEAF:{}", hex_of(&sha256(b"golden-leaf-der"))),
        format!(
            "JOIN_CREDENTIAL:{}",
            hex_of(&sha256(b"golden-join-credential"))
        ),
    ];
    expected.sort();
    assert_eq!(keys, expected.iter().collect::<Vec<_>>());
    assert!(
        founded
            .credentials()
            .values()
            .all(|held| held.authority == Authority::Founder)
    );
    assert!(stranger_founded.credentials().is_empty());
    assert!(unfounded.credentials().is_empty());
}

#[test]
fn a_cross_issuer_revocation_is_refused() {
    // adv_forger revokes peer_id/python, an agent it does not host.
    let payload = hex("adv_credential_revocation_cross_issuer_cbor");
    let signed = decoded_map(&payload);
    let ad_bytes = signed.get("adBytes").and_then(Value::as_bytes).unwrap();
    let ad = decoded_map(ad_bytes);
    assert_eq!(
        ad.get("issuer").and_then(Value::as_str),
        Some(derive_id(&hex("adv_forger_public_key_raw")).as_str())
    );
    assert_eq!(
        ad.get("target"),
        Some(&Value::Map(agent_target(&identity().agent("python"))))
    );
    assert!(Identity::verify(
        signed.get("publicKey").and_then(Value::as_bytes).unwrap(),
        ad_bytes,
        signed.get("signature").and_then(Value::as_bytes).unwrap()
    ));
    for founder in [Some(s("peer_id").to_owned()), None] {
        let mut registry = Registry::new(founder, group());
        assert!(!registry.accept(CREDENTIAL_STREAM, &payload, now()));
        assert!(!registry.refuses(
            &identity().agent("python"),
            Some(&hex("agent_public_key_raw")),
            Some(0)
        ));
    }
}

#[test]
fn the_founder_outranks_the_agents_own_peer_and_keeps_its_record() {
    // The golden peer is also the founder here: its record for the agent is rank FOUNDER.
    let mut founded = Registry::new(Some(s("peer_id").to_owned()), group());
    let payload = hex("signed_credential_revocation_agent_cbor");
    assert!(founded.accept(CREDENTIAL_STREAM, &payload, now()));
    let agent = identity().agent("python");
    assert_eq!(
        founded.credentials()[&format!("AGENT:{agent}")].authority,
        Authority::Founder
    );
    // A newer own-peer record cannot displace a founder's.
    let mut own = Registry::new(None, group());
    assert!(own.accept(CREDENTIAL_STREAM, &payload, now()));
    let newer = credential_revocation(
        s("peer_id"),
        s("group_id"),
        "2026-02-01T00:00:00Z",
        TTL,
        &agent_target(&agent),
        "retired",
        None,
    )
    .unwrap();
    let newer = bytes_of(&sign_revocation(&newer, &identity()));
    assert!(!own.accept(CREDENTIAL_STREAM, &newer, now()));
    assert_eq!(
        own.credentials()[&format!("AGENT:{agent}")].issued_ms,
        at("2026-02-01T00:00:00Z"),
        "the newer issued replaces at equal authority"
    );
    assert!(!own.refuses(&agent, None, Some(at("2026-01-15T00:00:00Z"))));
}

fn signed_payload(ad: &Map, by: &Identity) -> Vec<u8> {
    bytes_of(&sign_revocation(ad, by))
}

/// Java's `CredentialRevocation` constructor reads an absent, null, or blank reason
/// (`String.isBlank`, Java whitespace) as `unspecified` and `verify` enforces the record, so a
/// revocation signed without a reason must revoke here too. A reason that only Rust calls
/// whitespace (U+00A0) or a number is no known reason to Java, and stays refused.
#[test]
fn a_revocation_without_a_reason_is_unspecified_as_java_reads_it() {
    let identity = identity();
    let agent = identity.agent("python");
    let good = golden_ad("agent");
    let effective = at("2025-12-31T23:00:00Z");
    let unspecified: [(&str, Option<Value>); 5] = [
        ("absent", None),
        ("null", Some(Value::Null)),
        ("empty", Some(Value::from(""))),
        ("spaces", Some(Value::from("  "))),
        ("em space", Some(Value::from("\u{2003}"))),
    ];
    // Since v0.1.31 a record arrives as the bytes Java writes for it (SPEC §9.1 F3): Java reads
    // an absent, null, or blank reason as `unspecified` and re-encodes it so, which is not what
    // arrived, so each of these is refused; the record its issuer wrote as `unspecified` holds.
    for (name, reason) in unspecified {
        let mut ad = good.clone();
        match reason {
            None => {
                ad.remove("reason");
            }
            Some(reason) => {
                ad.insert("reason", reason);
            }
        }
        let mut registry = Registry::new(None, group());
        assert!(
            !registry.accept(CREDENTIAL_STREAM, &signed_payload(&ad, &identity), now()),
            "{name}"
        );
    }
    let mut written = good.clone();
    written.insert("reason", UNSPECIFIED);
    let mut registry = Registry::new(None, group());
    assert!(registry.accept(
        CREDENTIAL_STREAM,
        &signed_payload(&written, &identity),
        now()
    ));
    let held = &registry.credentials()[&format!("AGENT:{agent}")];
    assert!(!held.compromise);
    assert_eq!(held.effective_ms, effective);
    // The freeze rule of an unspecified reason: an unknown time is refused, a signature before
    // the effective instant is not, one at or after it is.
    assert!(registry.refuses(&agent, None, None));
    assert!(!registry.refuses(&agent, None, Some(effective - 1)));
    assert!(registry.refuses(&agent, None, Some(effective)));
    for (name, reason) in [
        ("no-break space", Value::from("\u{A0}")),
        ("figure space", Value::from("\u{2007}")),
        ("a number", Value::from(5)),
        ("an array", Value::Array(vec![Value::from("retired")])),
    ] {
        let mut ad = good.clone();
        ad.insert("reason", reason);
        assert!(
            !Registry::new(None, group()).accept(
                CREDENTIAL_STREAM,
                &signed_payload(&ad, &identity),
                now()
            ),
            "{name}"
        );
    }
    // The builder reads blank the same way: Java whitespace is blank, a no-break space is not.
    let build = |reason: &str| {
        credential_revocation(
            s("peer_id"),
            s("group_id"),
            ISSUED,
            TTL,
            &agent_target(&agent),
            reason,
            None,
        )
    };
    let built = build("\u{2003}\u{1C}").unwrap();
    assert_eq!(built.get("reason"), Some(&Value::from("unspecified")));
    assert_eq!(build("\u{A0}"), None);
}

/// What else Java's decode refuses in a credential revocation, refused here too: a target agent
/// that is not a Java `AgentId`, no lifetime, and evidence beyond `MAX_EVIDENCE`.
#[test]
fn a_revocation_java_cannot_decode_is_refused() {
    let identity = identity();
    let good = golden_ad("agent");
    let accepts = |ad: &Map| {
        Registry::new(None, group()).accept(
            CREDENTIAL_STREAM,
            &signed_payload(ad, &identity),
            now(),
        )
    };
    assert!(accepts(&good));
    for agent in [
        format!("{}/", s("peer_id")),
        format!("{}/python/extra", s("peer_id")),
    ] {
        let target = agent_target(&agent);
        assert!(!is_valid_target(&target), "{agent}");
        let mut ad = good.clone();
        ad.insert("id", revocation_id(s("group_id"), &target).unwrap());
        ad.insert("target", target);
        assert!(!accepts(&ad), "{agent}");
    }
    let mut lifeless = good.clone();
    lifeless.remove("ttl");
    assert!(!accepts(&lifeless));
    let mut null_life = good.clone();
    null_life.insert("ttl", Value::Null);
    assert!(!accepts(&null_life));
    let mut evidenced = good.clone();
    evidenced.insert("evidence", vec![7u8; MAX_EVIDENCE]);
    assert!(accepts(&evidenced));
    evidenced.insert("evidence", vec![7u8; MAX_EVIDENCE + 1]);
    assert!(!accepts(&evidenced));
}

#[test]
fn hostile_and_malformed_records_are_refused() {
    let identity = identity();
    let agent = identity.agent("python");
    let mut registry = Registry::new(None, group());
    let good = golden_ad("agent");

    // Another group, when the registry knows its group.
    let mut other_group = good.clone();
    other_group.insert("group", "zOther");
    other_group.insert(
        "id",
        revocation_id("zOther", &agent_target(&agent)).unwrap(),
    );
    let payload = signed_payload(&other_group, &identity);
    assert!(!registry.accept(CREDENTIAL_STREAM, &payload, now()));
    assert!(Registry::new(None, None).accept(CREDENTIAL_STREAM, &payload, now()));

    // Issued too far in the future.
    let issued = at(ISSUED);
    let payload = signed_payload(&good, &identity);
    assert!(!registry.accept(
        CREDENTIAL_STREAM,
        &payload,
        issued - MAX_ISSUED_SKEW_MILLIS - 1
    ));
    assert!(registry.accept(CREDENTIAL_STREAM, &payload, issued - MAX_ISSUED_SKEW_MILLIS));

    let mut registry = Registry::new(None, group());
    let mut cases: Vec<(&str, Map)> = Vec::new();
    let mut edited = |name: &'static str, edit: &dyn Fn(&mut Map)| {
        let mut ad = good.clone();
        edit(&mut ad);
        cases.push((name, ad));
    };
    edited("unknown reason", &|ad| {
        ad.insert("reason", "bored");
    });
    // "no reason" is not in this list: Java's constructor reads an absent reason
    // as `unspecified` and enforces the record, so it is accepted below and in
    // `a_revocation_without_a_reason_is_unspecified_as_java_reads_it`.
    edited("non-canonical id", &|ad| {
        ad.insert("id", "aspace://x/revocation/agent/y");
    });
    edited("effective after issued", &|ad| {
        ad.insert("effectiveFrom", "2026-01-01T00:00:00.001Z");
    });
    edited("effective not an instant", &|ad| {
        ad.insert("effectiveFrom", 5);
    });
    edited("issued not an instant", &|ad| {
        ad.insert("issued", "yesterday");
    });
    edited("no target", &|ad| {
        ad.remove("target");
    });
    edited("unknown kind", &|ad| {
        let mut target = agent_target("z/a");
        target.insert("kind", "PEER");
        ad.insert("target", target);
    });
    edited("someone else's agent", &|ad| {
        let target = agent_target("zSomeoneElse/a");
        ad.insert("id", revocation_id(s("group_id"), &target).unwrap());
        ad.insert("target", target);
    });
    edited("a prefix of the issuer is not its agent", &|ad| {
        let target = agent_target(&format!("{}x/a", s("peer_id")));
        ad.insert("id", revocation_id(s("group_id"), &target).unwrap());
        ad.insert("target", target);
    });
    edited("a short key fingerprint", &|ad| {
        let mut target = agent_key_target("z/a", &[0; 32]);
        target.insert("keyFingerprint", vec![0u8; 31]);
        ad.insert("target", target);
    });
    for (name, ad) in &cases {
        assert!(
            !registry.accept(CREDENTIAL_STREAM, &signed_payload(ad, &identity), now()),
            "{name}"
        );
    }
    // A record with no reason breaks P1 since v0.1.31 (SPEC §9.1): the field is always written.
    let mut reasonless = good.clone();
    reasonless.remove("reason");
    assert!(!Registry::new(None, group()).accept(
        CREDENTIAL_STREAM,
        &signed_payload(&reasonless, &identity),
        now()
    ));
    // An effectiveFrom written null breaks P1 too (it is omitted when null), and an absent one
    // is the issue instant.
    let mut null_effective = good.clone();
    null_effective.insert("effectiveFrom", Value::Null);
    assert!(!registry.accept(
        CREDENTIAL_STREAM,
        &signed_payload(&null_effective, &identity),
        now()
    ));
    null_effective.remove("effectiveFrom");
    assert!(registry.accept(
        CREDENTIAL_STREAM,
        &signed_payload(&null_effective, &identity),
        now()
    ));
    assert_eq!(
        registry.credentials()[&format!("AGENT:{agent}")].effective_ms,
        issued
    );

    // Signed-record shapes.
    let mut registry = Registry::new(None, group());
    let signed = sign_revocation(&good, &identity);
    let with = |key: &str, value: Value| {
        let mut copy = signed.clone();
        copy.insert(key, value);
        Value::Map(copy)
    };
    let mut tampered = bytes_of(&good);
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    for (name, bad) in [
        ("short key", with("publicKey", Value::Bytes(vec![0; 31]))),
        ("text key", with("publicKey", Value::Text("k".into()))),
        ("no signature", with("signature", Value::Null)),
        ("tampered ad", with("adBytes", Value::Bytes(tampered))),
        ("ad not CBOR", with("adBytes", Value::Bytes(vec![0xFF]))),
        (
            "ad not a map",
            with("adBytes", Value::Bytes(cbor::encode(&Value::Int(1)))),
        ),
        ("not a map", Value::Array(vec![])),
    ] {
        assert!(
            !registry.accept_signed(CREDENTIAL_STREAM, &bad, now()),
            "{name}"
        );
    }
    assert!(!registry.accept_signed("rumors", &Value::Map(signed.clone()), now()));
    assert!(!registry.accept(CREDENTIAL_STREAM, &bytes_of(&signed)[1..], now()));
    // A credential revocation on the peer stream names no revoked peer.
    let mut founded = Registry::new(Some(s("peer_id").to_owned()), group());
    assert!(!founded.accept_signed(PEER_STREAM, &Value::Map(signed.clone()), now()));
    assert!(registry.accept_signed(CREDENTIAL_STREAM, &Value::Map(signed), now()));
}

/// A `RevocationAdvertisement` as Java writes one.
fn peer_revocation(issuer: &Identity, revoked: &str, issued: &str) -> Map {
    let mut ad = Map::new();
    ad.insert(
        "id",
        format!("aspace://{}/revocation/{revoked}", s("group_id")),
    );
    ad.insert("issuer", issuer.peer_id());
    ad.insert("group", s("group_id"));
    ad.insert("issued", issued);
    ad.insert("ttl", TTL);
    ad.insert("revoked", revoked);
    ad.insert("reason", KEY_COMPROMISE);
    ad.insert("successor", Value::Null);
    ad
}

#[test]
fn only_the_founder_revokes_a_peer() {
    let founder = identity();
    let victim = Identity::generate().unwrap();
    let ad = peer_revocation(&founder, victim.peer_id(), ISSUED);
    let payload = signed_payload(&ad, &founder);

    let mut unfounded = Registry::new(None, group());
    assert!(!unfounded.accept(PEER_STREAM, &payload, now()));
    let mut wrong_founder = Registry::new(Some(victim.peer_id().to_owned()), group());
    assert!(!wrong_founder.accept(PEER_STREAM, &payload, now()));
    // A peer revoking another peer is not the founder.
    let stranger = Identity::generate().unwrap();
    let mut founded = Registry::new(None, group());
    founded.set_founder(Some(founder.peer_id().to_owned()));
    assert_eq!(founded.founder(), Some(founder.peer_id()));
    let forged = peer_revocation(&stranger, victim.peer_id(), ISSUED);
    assert!(!founded.accept(PEER_STREAM, &signed_payload(&forged, &stranger), now()));

    assert!(founded.accept(PEER_STREAM, &payload, now()));
    assert!(founded.peer_revoked(victim.peer_id()));
    assert!(!founded.peer_revoked(founder.peer_id()));
    let agent = format!("{}/worker", victim.peer_id());
    assert!(
        founded.refuses(&agent, None, Some(0)),
        "every agent of a revoked peer"
    );
    assert!(
        !founded.refuses(victim.peer_id(), None, None),
        "a bare PeerID is not an agent"
    );
    assert_eq!(founded.peers().len(), 1);
    assert_eq!(
        founded.peers()[victim.peer_id()].authority,
        Authority::Founder
    );

    // A peer revocation on the credential stream is not a credential revocation.
    let mut other = Registry::new(Some(founder.peer_id().to_owned()), group());
    assert!(!other.accept(CREDENTIAL_STREAM, &payload, now()));
    // Clearing the group admits any group; setting it again filters.
    other.set_group(None);
    assert_eq!(other.group(), None);
    other.set_group(Some("zOther".into()));
    assert!(!other.accept(PEER_STREAM, &payload, now()));
    other.set_group(group());
    assert!(other.accept(PEER_STREAM, &payload, now()));
}

#[test]
fn canonical_targets_match_the_golden_ids() {
    for kind in GOLDEN_KINDS {
        let ad = decoded_map(&hex(&format!("credential_revocation_{kind}_cbor")));
        let target = ad.get("target").and_then(Value::as_map).unwrap();
        let canonical = canonical_target(target).unwrap();
        let id = ad.get("id").and_then(Value::as_str).unwrap();
        assert!(id.ends_with(&format!("/{canonical}")), "{kind}");
        assert!(id.contains(&format!("/revocation/{kind}/")), "{kind}");
    }
}
