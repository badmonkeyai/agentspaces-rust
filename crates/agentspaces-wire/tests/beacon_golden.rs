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

//! The beacon document (`test_beacon.py` without the HTTP server): the canonical bytes are
//! Jackson's, a document Java signed verifies and its canonical bytes and JSON are reproduced
//! exactly, a signed document arrives as exactly its canonical JSON (SPEC §9.1), a tampered
//! signature, body, or issuer is refused, a pinned beacon is honoured, groups are selected and
//! their foundings verified, seeds of schemes the client cannot dial are skipped, and every
//! beacon vector of annex I gets its verdict.

mod common;

use agentspaces_wire::beacon::{
    BeaconDocument, BeaconError, DocumentSeed, FORBIDDEN_PARAMETERS, Group, MAX_DOCUMENT_BYTES,
    Seed, VERSION, WELL_KNOWN, canonical_bytes, document_group, document_signer, founding_of,
    group_from_document, seeds_of, sign_document, to_json, verified_group_id, verify_document,
};
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::founding::found_group;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::social::{base64_encode, delegation_group};

/// The transports the Python client dials (`agentspaces.seed.CLIENT_TRANSPORTS`).
const CLIENT_TRANSPORTS: [&str; 2] = ["tcp", "tls"];

/// A document Java's `BeaconDocument.signed` wrote for the issuer seeded 0x10..0x2f (the social
/// golden founder) at 2026-10-14T00:00:00Z, ttl 300: one full group (a non-ASCII, quoted,
/// control-character parameter included) and one bare group.
const JAVA_SIGNED_DOCUMENT: &str = r#"{"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \"q\" \u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}],"signature":"7gGY0YkDJfdrSzjbeVZTjkV+zr4o9H1MqVC8Ab7D4qoWMiuFt4qUEF99yidhtIJxzZAcvl3QbA23ST6zY02gAw=="}"#;
const JAVA_CANONICAL_BYTES: &str = r#"{"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \"q\" \u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}]}"#;

const ISSUED: &str = "2026-10-14T00:00:00Z";

fn founding(founder: &Identity) -> Map {
    found_group(
        founder,
        "research-fleet",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
        ISSUED,
        "PT8760H",
    )
    .unwrap()
}

fn group_id_of(signed: &Map) -> String {
    signed
        .get("advertisement")
        .and_then(|ad| ad.get("group"))
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

fn document(issuer: &Identity, founder: &Identity) -> BeaconDocument {
    let signed = founding(founder);
    let group = Group::new("research-fleet")
        .with_id(&group_id_of(&signed))
        .with_signed_founding(&signed)
        .with_seed("tls", "seed-a.corp.example:7500")
        .with_seed("tcp", "127.0.0.1:7500")
        .with_wire("session", 1)
        .with_wire("batch", 1)
        .with_parameter("region", "eu-west-1")
        .unwrap();
    let other = document_group("other", None, None, &[("tcp", "127.0.0.1:7600")]);
    sign_document(issuer, ISSUED, 300, vec![group, other]).unwrap()
}

fn endpoint(host: &str, port: u16, scheme: &str) -> Seed {
    Seed {
        host: host.into(),
        port,
        scheme: scheme.into(),
    }
}

#[test]
fn the_constants_are_javas() {
    assert_eq!(VERSION, 1);
    assert_eq!(WELL_KNOWN, "/.well-known/agentspaces/beacon.json");
    assert_eq!(MAX_DOCUMENT_BYTES, 65_536);
    assert!(FORBIDDEN_PARAMETERS.contains(&"content-key"));
    assert_eq!(FORBIDDEN_PARAMETERS.len(), 8);
}

#[test]
fn canonical_bytes_are_jacksons() {
    let issuer = Identity::generate().unwrap();
    let group = document_group("g", Some("zG"), Some("AA=="), &[("tcp", "h:1")])
        .with_wire("session", 1)
        .with_wire("batch", 1)
        .with_multicast("239.255.42.99:7787")
        .with_parameter("b", "2")
        .unwrap()
        .with_parameter("a", "1")
        .unwrap()
        .with_invite("QQ==");
    let doc = sign_document(&issuer, ISSUED, 300, vec![group]).unwrap();
    let key = base64_encode(issuer.public_raw());
    let expected = format!(
        concat!(
            r#"{{"v":1,"issuer":"{}","issuerKey":"{}","#,
            r#""issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{{"name":"g","id":"aspace://zG","#,
            r#""founding":"AA==","seeds":[{{"transport":"tcp","address":"h:1","priority":0}}],"#,
            r#""wire":{{"batch":1,"session":1}},"multicast":"239.255.42.99:7787","#,
            r#""parameters":{{"a":"1","b":"2"}},"invite":"QQ=="}}]}}"#
        ),
        issuer.peer_id(),
        key
    );
    assert_eq!(String::from_utf8(canonical_bytes(&doc)).unwrap(), expected);

    // A signed document arrives as exactly its canonical JSON (SPEC §9.1): unknown fields and
    // pretty whitespace refuse it rather than relabel it. Unsigned, the same form reads, and the
    // unknown fields and whitespace change nothing it would sign.
    let mut json: serde_json::Value = serde_json::from_slice(&to_json(&doc)).unwrap();
    json["extra"] = serde_json::json!(1);
    json["groups"][0]["unknown"] = serde_json::json!("x");
    json["groups"][0]["seeds"][0]["weight"] = serde_json::json!(5);
    assert_eq!(
        BeaconDocument::parse(&serde_json::to_vec_pretty(&json).unwrap()),
        Err(BeaconError::NotCanonical)
    );
    json.as_object_mut().unwrap().remove("signature");
    let reparsed = BeaconDocument::parse(&serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    assert_eq!(canonical_bytes(&reparsed), canonical_bytes(&doc));
    assert_eq!(verify_document(&reparsed, None), Ok(None));
    assert_eq!(BeaconDocument::parse(&to_json(&doc)), Ok(doc.clone()));
    assert_eq!(
        verify_document(&doc, Some(issuer.peer_id())),
        Ok(Some(issuer.peer_id().to_owned()))
    );

    // A document never carries a secret.
    for name in ["content-key", "Content-Key", "SECRET", "join-credential"] {
        assert_eq!(
            Group::new("g").with_parameter(name, "x"),
            Err(BeaconError::ForbiddenParameter(name.to_owned()))
        );
    }
    let mut smuggled = Group::new("g");
    smuggled.parameters = Some([("hints".to_owned(), Some("x".to_owned()))].into());
    assert_eq!(
        sign_document(&issuer, ISSUED, 300, vec![smuggled]),
        Err(BeaconError::ForbiddenParameter("hints".to_owned()))
    );
    let mut json: serde_json::Value = serde_json::from_slice(&to_json(&doc)).unwrap();
    json["groups"][0]["parameters"]["Membership"] = serde_json::json!("x");
    assert_eq!(
        BeaconDocument::parse(&serde_json::to_vec(&json).unwrap()),
        Err(BeaconError::ForbiddenParameter("Membership".to_owned()))
    );
}

#[test]
fn a_document_java_signed_verifies_and_its_canonical_bytes_are_reproduced() {
    let doc = BeaconDocument::parse(JAVA_SIGNED_DOCUMENT.as_bytes()).unwrap();
    let seed: [u8; 32] = std::array::from_fn(|i| 0x10 + i as u8);
    let issuer = Identity::from_seed(&seed);
    assert_eq!(doc.issuer.as_deref(), Some(issuer.peer_id()));
    assert_eq!(
        String::from_utf8(canonical_bytes(&doc)).unwrap(),
        JAVA_CANONICAL_BYTES
    );
    assert_eq!(
        verify_document(&doc, Some(issuer.peer_id())),
        Ok(Some(issuer.peer_id().to_owned()))
    );
    assert_eq!(document_signer(&doc).as_deref(), Some(issuer.peer_id()));
    assert_eq!(
        String::from_utf8(to_json(&doc)).unwrap(),
        JAVA_SIGNED_DOCUMENT
    );
    assert_eq!(
        doc.groups[0].parameters.as_ref().unwrap()["a"].as_deref(),
        Some("ü \"q\" \u{1}")
    );
    // The same document re-signed by this issuer carries Java's signature exactly.
    let resigned = sign_document(
        &issuer,
        doc.issued.as_deref().unwrap(),
        doc.ttl,
        doc.groups.clone(),
    )
    .unwrap();
    assert_eq!(resigned.signature, doc.signature);
    assert_eq!(resigned, doc);
    // A byte order mark before a signed document makes its bytes another form than its
    // canonical JSON, which refuses it (SPEC §9.1); before an unsigned one it is skipped, as
    // Jackson skips it.
    let with_bom = [b"\xEF\xBB\xBF".as_slice(), JAVA_SIGNED_DOCUMENT.as_bytes()].concat();
    assert_eq!(
        BeaconDocument::parse(&with_bom),
        Err(BeaconError::NotCanonical)
    );
    let mut unsigned = doc.clone();
    unsigned.signature = None;
    let unsigned_with_bom = [b"\xEF\xBB\xBF".as_slice(), &to_json(&unsigned)].concat();
    assert_eq!(BeaconDocument::parse(&unsigned_with_bom), Ok(unsigned));
}

#[test]
fn a_tampered_signature_or_body_is_refused() {
    let issuer = Identity::generate().unwrap();
    let founder = Identity::generate().unwrap();
    let doc = document(&issuer, &founder);
    assert_eq!(
        verify_document(&doc, None),
        Ok(Some(issuer.peer_id().to_owned()))
    );

    let mut bad_signature = doc.clone();
    bad_signature.signature = Some(base64_encode(&[0u8; 64]));
    let mut bad_body = doc.clone();
    bad_body.groups[0].seeds[1].address = Some("evil.example:7500".into());
    let mut wrong_issuer = doc.clone();
    wrong_issuer.issuer = Some(Identity::generate().unwrap().peer_id().to_owned());
    let mut not_base64 = doc.clone();
    not_base64.signature = Some("!!".into());
    let mut short_key = doc.clone();
    short_key.issuer_key = Some(base64_encode(&[1u8; 31]));
    let mut empty_signature = doc.clone();
    empty_signature.signature = Some(String::new());
    for (name, body) in [
        ("signature", bad_signature),
        ("body", bad_body),
        ("issuer", wrong_issuer),
        ("short key", short_key),
        ("empty signature", empty_signature),
    ] {
        // Through the wire form, as a fetched document arrives.
        let fetched = BeaconDocument::parse(&to_json(&body)).unwrap();
        assert_eq!(
            verify_document(&fetched, None),
            Err(BeaconError::BadSignature),
            "{name}"
        );
        assert_eq!(document_signer(&fetched), None, "{name}");
    }
    // A signature that is no base64 at all fails verification, and through the wire form it is
    // no padded standard base64 text, which refuses the document before any verification.
    assert_eq!(
        verify_document(&not_base64, None),
        Err(BeaconError::BadSignature)
    );
    assert_eq!(document_signer(&not_base64), None);
    assert_eq!(
        BeaconDocument::parse(&to_json(&not_base64)),
        Err(BeaconError::NotCanonical)
    );
}

#[test]
fn the_pinned_beacon_is_honoured() {
    let issuer = Identity::generate().unwrap();
    let founder = Identity::generate().unwrap();
    let doc = document(&issuer, &founder);
    assert_eq!(
        verify_document(&doc, Some(issuer.peer_id())),
        Ok(Some(issuer.peer_id().to_owned()))
    );
    let other = Identity::generate().unwrap();
    assert_eq!(
        verify_document(&doc, Some(other.peer_id())),
        Err(BeaconError::NotPinned(other.peer_id().to_owned()))
    );
    // An unsigned document passes unpinned (as the Java reader) and fails a pin.
    let mut unsigned = doc.clone();
    unsigned.signature = None;
    let unsigned = BeaconDocument::parse(&to_json(&unsigned)).unwrap();
    assert_eq!(unsigned.signature, None);
    assert_eq!(verify_document(&unsigned, None), Ok(None));
    assert!(verify_document(&unsigned, Some(issuer.peer_id())).is_err());
    // A version below 1 is not a document.
    let mut old = doc.clone();
    old.v = 0;
    assert_eq!(verify_document(&old, None), Err(BeaconError::Version(0)));
}

#[test]
fn a_signed_document_selects_and_verifies_its_groups() {
    let issuer = Identity::generate().unwrap();
    let founder = Identity::generate().unwrap();
    let doc = BeaconDocument::parse(&to_json(&document(&issuer, &founder))).unwrap();
    let group_id = group_id_of(&founding(&founder));
    let by_id = group_from_document(&doc, Some(&group_id), None).unwrap();
    assert_eq!(by_id.name, "research-fleet");
    assert!(std::ptr::eq(
        group_from_document(&doc, Some(&format!("aspace://{group_id}")), None).unwrap(),
        by_id
    ));
    assert_eq!(
        group_from_document(&doc, None, Some("other")).unwrap().name,
        "other"
    );
    assert_eq!(
        group_from_document(&doc, None, None),
        Err(BeaconError::Ambiguous(2)),
        "two groups: name one"
    );
    assert!(group_from_document(&doc, Some("zNope"), None).is_err());
    assert!(group_from_document(&doc, Some(""), None).is_err());
    assert!(group_from_document(&doc, None, Some("nope")).is_err());

    assert_eq!(verified_group_id(by_id, None), Ok(group_id.clone()));
    assert_eq!(
        verified_group_id(by_id, Some(&group_id)),
        Ok(group_id.clone())
    );
    assert!(matches!(
        verified_group_id(by_id, Some("zOther")),
        Err(BeaconError::FoundingMismatch { .. })
    ));
    let other = group_from_document(&doc, None, Some("other")).unwrap();
    assert_eq!(
        verified_group_id(other, None),
        Err(BeaconError::NoFounding("other".into()))
    );
    assert_eq!(founding_of(other), Ok(None));
    assert_eq!(founding_of(by_id), Ok(Some(founding(&founder))));

    // Both seeds are the Python client's since the tls binding landed, in priority order.
    assert_eq!(
        seeds_of(by_id, &CLIENT_TRANSPORTS),
        vec![
            endpoint("seed-a.corp.example", 7500, "tls"),
            endpoint("127.0.0.1", 7500, "tcp")
        ]
    );
    assert_eq!(
        seeds_of(by_id, &["tcp"]),
        vec![endpoint("127.0.0.1", 7500, "tcp")]
    );
    assert_eq!(
        seeds_of(by_id, &CLIENT_TRANSPORTS)[0].to_string(),
        "tls://seed-a.corp.example:7500"
    );
}

#[test]
fn a_founding_that_does_not_match_is_refused() {
    let founder = Identity::generate().unwrap();
    let signed = founding(&founder);
    // The id names another group than the founding derives to.
    let lying = Group::new("lying")
        .with_id("zSomethingElse")
        .with_signed_founding(&signed);
    assert!(matches!(
        verified_group_id(&lying, None),
        Err(BeaconError::FoundingMismatch { .. })
    ));
    // A founding whose advertisement was edited fails the four checks.
    let mut edited = signed.clone();
    if let Some(ad) = edited.get_mut("advertisement").and_then(Value::as_map_mut) {
        ad.insert("name", "renamed");
    }
    let forged = Group::new("forged").with_signed_founding(&edited);
    assert_eq!(
        verified_group_id(&forged, None),
        Err(BeaconError::FoundingInvalid("forged".into()))
    );
    // A founding that is not base64 CBOR, or not a map.
    let garbage = Group::new("garbage").with_founding("!!");
    assert_eq!(
        founding_of(&garbage),
        Err(BeaconError::FoundingNotCbor("garbage".into()))
    );
    let truncated = Group::new("truncated").with_founding("vw==");
    assert!(founding_of(&truncated).is_err());
    let scalar = Group::new("scalar").with_founding("AQ==");
    assert_eq!(founding_of(&scalar), Ok(None));
    assert_eq!(
        founding_of(&Group::new("empty").with_founding("")),
        Ok(None)
    );
}

#[test]
fn a_social_beacon_document_carries_the_golden_founding_and_delegation() {
    let golden = common::social_golden();
    let text = |name: &str| golden[name].as_str().unwrap();
    let group = Group::new("weekend-hack")
        .with_id(text("group_id"))
        .with_founding(text("founding_cbor_base64"))
        .with_seed("tcp", "127.0.0.1:7500")
        .with_invite(text("delegation_base64"));
    let beacon = Identity::generate().unwrap();
    let doc = sign_document(&beacon, ISSUED, 300, vec![group]).unwrap();
    let doc = BeaconDocument::parse(&to_json(&doc)).unwrap();
    let only = group_from_document(&doc, None, None).unwrap();
    let delegation = only.invite.as_deref().unwrap();
    assert_eq!(delegation_group(delegation).unwrap(), text("group_id"));
    assert_eq!(
        verified_group_id(only, Some(&delegation_group(delegation).unwrap())),
        Ok(text("group_id").to_owned())
    );
}

#[test]
fn seeds_skip_datagram_schemes_this_client_cannot_dial() {
    // A dtls or udp seed is skipped for the next one this client speaks.
    let group = Group::new("g")
        .with_seed("dtls", "10.0.0.5:7502")
        .with_seed("udp", "10.0.0.5:7503")
        .with_seed("tcp", "10.0.0.5:7500");
    assert_eq!(
        seeds_of(&group, &CLIENT_TRANSPORTS),
        vec![endpoint("10.0.0.5", 7500, "tcp")]
    );
}

#[test]
fn the_client_skips_the_schemes_it_cannot_dial() {
    // The client dials tcp and tls and skips every other scheme a beacon document may list, in
    // priority order, so a mixed fleet still reaches it.
    let group = Group::new("g")
        .with_seed("wss", "fleet.example.com:443/aspace")
        .with_seed("webrtc", "sig")
        .with_seed("https", "fleet.example.com:443/aspace/h")
        .with_seed("dtls", "10.0.0.5:7502")
        .with_seed("ws", "10.0.0.5:7503")
        .with_seed("http", "10.0.0.5:7503/aspace/h")
        .with_seed("tcp", "10.0.0.5:7500")
        .with_seed("tls", "10.0.0.5:7501");
    assert_eq!(
        seeds_of(&group, &CLIENT_TRANSPORTS),
        vec![
            endpoint("10.0.0.5", 7500, "tcp"),
            endpoint("10.0.0.5", 7501, "tls")
        ]
    );
    // A dialer that speaks wss is the caller's to declare; its path-bearing address is not a
    // host:port seed, so it is skipped here rather than misread.
    assert!(seeds_of(&group, &["wss"]).is_empty());
    assert_eq!(
        seeds_of(&group, &["dtls"]),
        vec![endpoint("10.0.0.5", 7502, "dtls")]
    );
}

#[test]
fn seeds_sort_by_priority_and_default_to_tcp() {
    let seed = |transport: Option<&str>, address: Option<&str>, priority: i32| DocumentSeed {
        transport: transport.map(str::to_owned),
        address: address.map(str::to_owned),
        priority,
    };
    let group = Group::new("g")
        .with_document_seed(seed(Some("TLS"), Some("b:2"), 5))
        .with_document_seed(seed(None, Some("a:1"), 5))
        .with_document_seed(seed(Some(""), Some("[::1]:3"), -1))
        .with_document_seed(seed(Some("tcp"), None, 0))
        .with_document_seed(seed(Some("tcp"), Some(""), 0))
        .with_document_seed(seed(Some("tcp"), Some("no-port"), 0))
        .with_document_seed(seed(Some("tcp"), Some("h:65536"), 0));
    assert_eq!(
        seeds_of(&group, &CLIENT_TRANSPORTS),
        vec![
            endpoint("::1", 3, "tcp"),
            endpoint("b", 2, "tls"),
            endpoint("a", 1, "tcp")
        ]
    );
    // A seed without a transport or address is written with nulls, as Java's Seed record.
    let doc = sign_document(&Identity::generate().unwrap(), ISSUED, 300, vec![group]).unwrap();
    let json = String::from_utf8(to_json(&doc)).unwrap();
    assert!(json.contains(r#"{"transport":null,"address":"a:1","priority":5}"#));
    assert!(json.contains(r#"{"transport":"tcp","address":null,"priority":0}"#));
    assert_eq!(BeaconDocument::parse(json.as_bytes()), Ok(doc));
}

#[test]
fn malformed_documents_are_refused_and_numbers_read_as_javas_reader_reads_them() {
    let parse = |text: &str| BeaconDocument::parse(text.as_bytes());
    let too_big = format!("[{}1]", "1,".repeat(MAX_DOCUMENT_BYTES / 2));
    assert_eq!(
        BeaconDocument::parse(too_big.as_bytes()),
        Err(BeaconError::TooLarge(too_big.len()))
    );
    assert!(matches!(parse("{"), Err(BeaconError::Json(_))));
    assert!(matches!(parse("not json"), Err(BeaconError::Json(_))));
    assert!(matches!(parse("[]"), Err(BeaconError::Malformed { .. })));
    assert_eq!(parse("{}"), Err(BeaconError::Version(0)));
    assert_eq!(parse(r#"{"v":0}"#), Err(BeaconError::Version(0)));
    for bad in [
        r#"{"v":1,"groups":{}}"#,
        r#"{"v":1,"groups":[1]}"#,
        r#"{"v":1,"groups":[{}]}"#,
        r#"{"v":1,"groups":[{"name":null}]}"#,
        r#"{"v":1,"groups":[{"name":5}]}"#,
        r#"{"v":1,"groups":[{"name":"g","seeds":[null]}]}"#,
        r#"{"v":1,"groups":[{"name":"g","seeds":[{"priority":true}]}]}"#,
        r#"{"v":1,"groups":[{"name":"g","seeds":[{"address":7500}]}]}"#,
        r#"{"v":1,"groups":[{"name":"g","wire":{"session":2147483648}}]}"#,
        r#"{"v":1,"groups":[{"name":"g","parameters":{"a":1}}]}"#,
        r#"{"v":1,"groups":[{"name":"g","parameters":[]}]}"#,
        r#"{"v":1,"issuer":5}"#,
        r#"{"v":2147483648}"#,
        r#"{"v":1,"ttl":"soon"}"#,
        r#"{"v":1,"ttl":1e300}"#,
        // Java's reader turns Jackson's coercions off (SPEC §9.1): a fraction, an exponent, or
        // numeric text fills no integer member, signed or not.
        r#"{"v":1.9}"#,
        r#"{"v":1.0}"#,
        r#"{"v":"1"}"#,
        r#"{"v":1,"ttl":"300"}"#,
        r#"{"v":1,"ttl":300.0}"#,
        r#"{"v":1,"ttl":3e2}"#,
        r#"{"v":1,"groups":[{"name":"g","wire":{"b":2.5}}]}"#,
        r#"{"v":1,"groups":[{"name":"g","wire":{"b":"2"}}]}"#,
        r#"{"v":1,"groups":[{"name":"g","seeds":[{"priority":"0"}]}]}"#,
        r#"{"v":1,"groups":[{"name":"g","seeds":[{"priority":1.0}]}]}"#,
    ] {
        assert!(
            matches!(parse(bad), Err(BeaconError::Malformed { .. })),
            "{bad}"
        );
    }
    // Absent and null numbers are 0, null lists are empty, and a null wire hint or parameter
    // stays null, as Java's reader reads them.
    let doc = parse(
        r#"{"v":1,"groups":[{"name":"g","seeds":null,"wire":{"b":2,"n":null},
            "parameters":{"k":null}},
            {"name":"h","seeds":[{"transport":"tcp","address":"h:1","priority":null}]}],
            "issuer":null,"signature":null}"#,
    )
    .unwrap();
    assert_eq!((doc.v, doc.ttl, doc.issuer.clone()), (1, 0, None));
    assert!(doc.groups[0].seeds.is_empty());
    assert_eq!(doc.groups[0].wire.as_ref().unwrap()["b"], Some(2));
    assert_eq!(doc.groups[0].wire.as_ref().unwrap()["n"], None);
    assert_eq!(doc.groups[0].parameters.as_ref().unwrap()["k"], None);
    assert_eq!(doc.groups[1].seeds[0].priority, 0);
    assert_eq!(parse(r#"{"v":1,"groups":null}"#).unwrap().groups, vec![]);
    let session = parse(r#"{"v":1,"groups":[{"name":"g","wire":{"session":null}}]}"#).unwrap();
    assert_eq!(session.groups[0].wire.as_ref().unwrap()["session"], None);
}

#[test]
fn a_signed_document_with_null_hints_and_supplementary_text_round_trips() {
    // A null wire hint and parameter are written null, and a character past U+FFFF is UTF-8 in
    // the served JSON and its surrogates' escapes in the signed bytes (SPEC §9.1).
    let issuer = Identity::generate().unwrap();
    let mut group = Group::new("g")
        .with_seed("tcp", "127.0.0.1:7500")
        .with_parameter("\u{1F600}", "smile \u{1F600}")
        .unwrap()
        .with_parameter("\u{FF01}", "x")
        .unwrap();
    group.wire = Some([("session".to_owned(), None)].into());
    group
        .parameters
        .get_or_insert_with(Default::default)
        .insert("k".to_owned(), None);
    let doc = sign_document(&issuer, ISSUED, 300, vec![group]).unwrap();
    let served = String::from_utf8(to_json(&doc)).unwrap();
    assert!(served.contains(r#""wire":{"session":null}"#), "{served}");
    assert!(
        served.contains(
            "\"parameters\":{\"k\":null,\"\u{1F600}\":\"smile \u{1F600}\",\"\u{FF01}\":\"x\"}"
        ),
        "{served}"
    );
    let signed = String::from_utf8(canonical_bytes(&doc)).unwrap();
    assert!(
        signed.contains(r#"{"k":null,"\uD83D\uDE00":"smile \uD83D\uDE00","#),
        "{signed}"
    );
    let fetched = BeaconDocument::parse(served.as_bytes()).unwrap();
    assert_eq!(fetched, doc);
    assert_eq!(
        verify_document(&fetched, Some(issuer.peer_id())),
        Ok(Some(issuer.peer_id().to_owned()))
    );
}

/// The beacon-document vectors of annex I (`tests/wire-encoding-vectors.json`): the JSON bytes,
/// the verdict, and the signer an accepted signed document names.
fn annex_i_beacon_vectors() -> Vec<(String, Vec<u8>, String, Option<String>)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/wire-encoding-vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("the annex I vectors");
    let vectors: serde_json::Value = serde_json::from_str(&text).expect("the vectors parse");
    vectors["vectors"]
        .as_array()
        .expect("a vector list")
        .iter()
        .filter(|vector| vector["carrier"] == "beacon-document")
        .map(|vector| {
            let field = |name: &str| vector[name].as_str().unwrap_or_default().to_owned();
            let bytes = hex::decode(field("hex")).expect("hex");
            (
                field("id"),
                bytes,
                field("verdict"),
                vector["signer"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

#[test]
fn every_annex_i_beacon_vector_gets_its_verdict() {
    let vectors = annex_i_beacon_vectors();
    assert_eq!(vectors.len(), 40, "beacon-01 to beacon-40");
    let mut agree = 0;
    for (id, bytes, verdict, signer) in &vectors {
        let read = BeaconDocument::parse(bytes).and_then(|doc| verify_document(&doc, None));
        match verdict.as_str() {
            "accept" => assert_eq!(read.as_ref(), Ok(signer), "{id}"),
            "refuse" => assert!(read.is_err(), "{id}: {read:?}"),
            other => panic!("{id}: an unknown verdict {other}"),
        }
        agree += 1;
    }
    assert_eq!(agree, 40);
}
