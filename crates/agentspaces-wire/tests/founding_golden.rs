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

//! Self-certifying groups against the golden vectors Java produced (`test_founding.py` without
//! the socket and Peer tests): the founder reproduces Java `GroupFounding.found` byte for byte,
//! the four receiver checks accept the genuine document and refuse both adversarial ones, and
//! malformed shapes are refused without panicking.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::founding::{
    CONFLICT_STRATEGIES, FoundingError, MEMBERSHIP_POLICIES, found_group, founding_document,
    founding_fields, founding_fields_of, group_advertisement, group_id_from_founding_document,
    verify_signed_group_ad,
};
use agentspaces_wire::identity::Identity;
use common::{hex, s};

fn identity() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn bytes_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

fn decoded(name: &str) -> Value {
    cbor::decode(&hex(name)).unwrap()
}

/// Java: `GroupFounding.found(identity, "golden-fleet", OPEN, LEASE_RACE,
/// GossipParameters(3, PT1S), issued 2026-01-01T00:00:00Z, ttl P1D)`.
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

fn golden_fields() -> Map {
    founding_fields(
        "golden-fleet",
        s("peer_id"),
        "2026-01-01T00:00:00Z",
        "PT24H",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
    )
}

/// The signed advertisement with one top-level field replaced.
fn with(signed: &Map, key: &str, value: impl Into<Value>) -> Value {
    let mut copy = signed.clone();
    copy.insert(key, value);
    Value::Map(copy)
}

/// The signed advertisement with its advertisement edited.
fn with_ad(signed: &Map, edit: impl FnOnce(&mut Map)) -> Value {
    let mut copy = signed.clone();
    if let Some(ad) = copy.get_mut("advertisement").and_then(Value::as_map_mut) {
        edit(ad);
    }
    Value::Map(copy)
}

#[test]
fn the_enum_names_are_javas() {
    assert_eq!(MEMBERSHIP_POLICIES, ["OPEN", "INVITE", "POLICY"]);
    assert_eq!(CONFLICT_STRATEGIES, ["LEASE_RACE", "AUCTION", "ORDERED"]);
}

#[test]
fn founding_fields_and_signature_match_java() {
    let fields = golden_fields();
    assert_eq!(bytes_of(&fields), hex("founding_fields_cbor"));
    let signature = identity().sign(&bytes_of(&fields));
    assert_eq!(signature.as_slice(), hex("founding_signature"));
    let document = founding_document(&fields, &signature);
    assert_eq!(bytes_of(&document), hex("founding_document_cbor"));
    assert_eq!(
        group_id_from_founding_document(&bytes_of(&document)),
        s("founding_group_id")
    );
    assert_eq!(
        bytes_of(&group_advertisement(s("founding_group_id"), &fields).unwrap()),
        hex("group_ad_cbor")
    );
}

#[test]
fn found_group_reproduces_the_java_advertisement() {
    let signed = found();
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    assert_eq!(
        ad.get("group").and_then(Value::as_str),
        Some(s("founding_group_id"))
    );
    assert_eq!(
        ad.get("id").and_then(Value::as_str),
        Some(s("founding_ad_id"))
    );
    assert_eq!(
        s("founding_ad_id"),
        format!("aspace://{}", s("founding_group_id"))
    );
    assert_eq!(bytes_of(ad), hex("group_ad_cbor"));
    assert_eq!(
        signed.get("signature").and_then(Value::as_bytes),
        Some(hex("founding_signature").as_slice())
    );
    assert_eq!(
        signed.get("founderPublicKey").and_then(Value::as_bytes),
        Some(hex("public_key_raw").as_slice())
    );
    assert_eq!(bytes_of(&signed), hex("signed_group_ad_cbor"));
    // The fields the advertisement carries are the founding fields, byte for byte.
    assert_eq!(
        bytes_of(&founding_fields_of(ad).unwrap()),
        hex("founding_fields_cbor")
    );
}

#[test]
fn the_four_checks_accept_the_genuine_founding_document() {
    assert_eq!(
        verify_signed_group_ad(&Value::Map(found())).as_deref(),
        Some(s("founding_group_id"))
    );
    // The same document decoded from Java's bytes verifies identically.
    assert_eq!(
        verify_signed_group_ad(&decoded("signed_group_ad_cbor")).as_deref(),
        Some(s("founding_group_id"))
    );
}

#[test]
fn the_wrong_id_document_still_derives_to_the_real_group() {
    // SPEC §4.4: the substitution is detected because the founding document the attacker was
    // forced to carry derives to the real GroupID, not the one the advertisement claims.
    let signed = decoded("adv_group_ad_wrong_id_cbor");
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    assert_eq!(ad.get("group").and_then(Value::as_str), Some(s("group_id")));
    assert_eq!(
        ad.get("id").and_then(Value::as_str),
        Some(format!("aspace://{}", s("group_id")).as_str())
    );
    let fields = founding_fields_of(ad).unwrap();
    assert_eq!(bytes_of(&fields), hex("founding_fields_cbor"));
    let key = signed
        .get("founderPublicKey")
        .and_then(Value::as_bytes)
        .unwrap();
    let signature = signed.get("signature").and_then(Value::as_bytes).unwrap();
    assert!(Identity::verify(key, &bytes_of(&fields), signature));
    let derived =
        group_id_from_founding_document(&bytes_of(&founding_document(&fields, signature)));
    assert_eq!(derived, s("founding_group_id"));
    assert_ne!(derived, s("group_id"));
    assert_eq!(verify_signed_group_ad(&signed), None);
}

#[test]
fn the_forged_signature_document_fails_only_the_signature_check() {
    let signed = decoded("adv_group_ad_forged_signature_cbor");
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    assert_eq!(
        ad.get("group").and_then(Value::as_str),
        Some(s("founding_group_id"))
    );
    let key = signed
        .get("founderPublicKey")
        .and_then(Value::as_bytes)
        .unwrap();
    let signature = signed.get("signature").and_then(Value::as_bytes).unwrap();
    assert_eq!(key, hex("public_key_raw").as_slice());
    assert_ne!(signature, hex("founding_signature").as_slice());
    assert!(!Identity::verify(
        key,
        &hex("founding_fields_cbor"),
        signature
    ));
    assert_eq!(verify_signed_group_ad(&signed), None);
    // A forger cannot repair it by claiming its own key either: the key would no longer hash to
    // the advertisement's issuer.
    let forged_key = hex("adv_forger_public_key_raw");
    assert!(Identity::verify(
        &forged_key,
        &hex("founding_fields_cbor"),
        signature
    ));
    let signed = signed.as_map().unwrap();
    assert_eq!(
        verify_signed_group_ad(&with(signed, "founderPublicKey", forged_key)),
        None
    );
}

#[test]
fn verification_tolerates_malformed_shapes() {
    let signed = found();
    let genuine = Value::Map(signed.clone());
    assert!(verify_signed_group_ad(&genuine).is_some());

    // The cases test_founding.py checks.
    assert_eq!(verify_signed_group_ad(&Value::Null), None);
    assert_eq!(verify_signed_group_ad(&Value::Map(Map::new())), None);
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "founderPublicKey", vec![0u8; 31])),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "signature", "not bytes")),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.remove("gossip");
        })),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.insert(
                "gossip",
                agentspaces_wire::cbor_map! { "fanout" => "3", "period" => "PT1S" },
            );
        })),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.insert("id", format!("aspace://{}", s("group_id")));
        })),
        None
    );

    // Further hostile shapes.
    for top in [
        Value::from("signed"),
        Value::from(7),
        Value::Array(vec![genuine.clone()]),
        Value::from(hex("signed_group_ad_cbor")),
    ] {
        assert_eq!(verify_signed_group_ad(&top), None);
    }
    for field in ["advertisement", "founderPublicKey", "signature"] {
        let mut copy = signed.clone();
        copy.remove(field);
        assert_eq!(verify_signed_group_ad(&Value::Map(copy)), None, "{field}");
        assert_eq!(
            verify_signed_group_ad(&with(&signed, field, Value::Null)),
            None,
            "{field}"
        );
    }
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "advertisement", "ad")),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "founderPublicKey", vec![0u8; 33])),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "signature", vec![0u8; 64])),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "signature", Vec::<u8>::new())),
        None
    );
    for field in [
        "id",
        "issuer",
        "group",
        "issued",
        "ttl",
        "name",
        "membershipPolicy",
        "defaultStrategy",
    ] {
        assert_eq!(
            verify_signed_group_ad(&with_ad(&signed, |ad| {
                ad.remove(field);
            })),
            None,
            "without {field}"
        );
        assert_eq!(
            verify_signed_group_ad(&with_ad(&signed, |ad| {
                ad.insert(field, 1);
            })),
            None,
            "int {field}"
        );
    }
    for gossip in [
        Value::Null,
        Value::from("gossip"),
        agentspaces_wire::cbor_array![3, "PT1S"],
        agentspaces_wire::cbor_map! { "period" => "PT1S" },
        agentspaces_wire::cbor_map! { "fanout" => 3 },
        agentspaces_wire::cbor_map! { "fanout" => true, "period" => "PT1S" },
        agentspaces_wire::cbor_map! { "fanout" => 3.0, "period" => "PT1S" },
        agentspaces_wire::cbor_map! { "fanout" => 3, "period" => 1 },
        agentspaces_wire::cbor_map! { "fanout" => 4, "period" => "PT1S" },
    ] {
        assert_eq!(
            verify_signed_group_ad(&with_ad(&signed, |ad| {
                ad.insert("gossip", gossip.clone());
            })),
            None,
            "gossip {gossip:?}"
        );
    }
    // Any change to a signed field breaks the signature.
    for (field, value) in [
        ("name", "golden-fleet2"),
        ("issued", "2026-01-01T00:00:00.000Z"),
        ("ttl", "PT48H"),
        ("membershipPolicy", "INVITE"),
        ("defaultStrategy", "AUCTION"),
    ] {
        assert_eq!(
            verify_signed_group_ad(&with_ad(&signed, |ad| {
                ad.insert(field, value);
            })),
            None,
            "{field}"
        );
    }
    // The group and the id must both name the derived group.
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    assert!(founding_fields_of(ad).is_ok());
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.insert("id", s("founding_group_id"));
        })),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.insert("id", format!("ASPACE://{}", s("founding_group_id")));
        })),
        None
    );
    assert_eq!(
        verify_signed_group_ad(&with_ad(&signed, |ad| {
            ad.insert("group", s("group_id"));
        })),
        None
    );
    // Fields outside the founding document are not covered and do not matter.
    assert_eq!(
        verify_signed_group_ad(&with(&signed, "extra", 1)).as_deref(),
        Some(s("founding_group_id"))
    );
}

#[test]
fn founding_fields_of_refuses_what_cannot_be_a_founding_document() {
    let signed = found();
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    let mut no_gossip = ad.clone();
    no_gossip.remove("gossip");
    assert_eq!(
        founding_fields_of(&no_gossip),
        Err(FoundingError::Malformed { field: "gossip" })
    );
    let mut text_fanout = ad.clone();
    text_fanout.insert(
        "gossip",
        agentspaces_wire::cbor_map! { "fanout" => "3", "period" => "PT1S" },
    );
    assert_eq!(
        founding_fields_of(&text_fanout),
        Err(FoundingError::Malformed {
            field: "gossip.fanout"
        })
    );
    let mut no_issuer = ad.clone();
    no_issuer.remove("issuer");
    assert_eq!(
        founding_fields_of(&no_issuer),
        Err(FoundingError::Malformed { field: "issuer" })
    );
    // An integer fanout of any size is carried as it is, as identity.py carries it.
    let mut wide = ad.clone();
    wide.insert(
        "gossip",
        agentspaces_wire::cbor_map! { "fanout" => u64::MAX, "period" => "PT1S" },
    );
    let fields = founding_fields_of(&wide).unwrap();
    assert_eq!(
        fields
            .get("gossip")
            .and_then(|gossip| gossip.get("fanout"))
            .and_then(Value::as_u64),
        Some(u64::MAX)
    );
}

#[test]
fn a_genuine_document_for_another_group_verifies_to_that_group() {
    // A seed answering with a valid founding document for a different group verifies, to its own
    // id: the joiner compares the result against the GroupID it holds.
    let other = found_group(
        &identity(),
        "other-fleet",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
        "2026-01-01T00:00:00Z",
        "PT24H",
    )
    .unwrap();
    let verified = verify_signed_group_ad(&Value::Map(other)).unwrap();
    assert_ne!(verified, s("founding_group_id"));
    assert!(verified.starts_with('z'));
    // Founding is deterministic.
    assert_eq!(bytes_of(&found()), bytes_of(&found()));
}

#[test]
fn every_single_bit_flip_of_the_signed_advertisement_is_refused_or_harmless() {
    let bytes = hex("signed_group_ad_cbor");
    let genuine = decoded("signed_group_ad_cbor");
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[index] ^= 1 << bit;
            let Ok(value) = cbor::decode(&flipped) else {
                continue;
            };
            if let Some(group) = verify_signed_group_ad(&value) {
                assert_eq!(group, s("founding_group_id"), "byte {index} bit {bit}");
                assert_eq!(value, genuine, "byte {index} bit {bit} verified");
            }
        }
    }
    for length in 0..bytes.len() {
        if let Ok(value) = cbor::decode(&bytes[..length]) {
            assert_eq!(verify_signed_group_ad(&value), None);
        }
    }
}
