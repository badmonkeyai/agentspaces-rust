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

//! The codec, crypto, and id modules against the golden vectors Java produced: the codec
//! reproduces every wire CBOR vector byte for byte, the crypto port reproduces the keys and the
//! deterministic signatures, the derived ids match, and the adversarial nesting vector is
//! refused.

mod common;

use agentspaces_wire::cbor::{self, CborError, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::{base58, ids, time};
use common::{golden, hex, s};

/// Every golden entry that is wire CBOR in the Jackson shape: `*_cbor` and the frames and
/// deltas, without the `pdt_*` content-tree vectors (DAG-CBOR, a different codec) and the
/// nesting vector, which must be refused.
fn wire_cbor_names() -> Vec<&'static str> {
    golden()
        .as_object()
        .expect("golden.json is an object")
        .keys()
        .map(String::as_str)
        .filter(|name| {
            (name.ends_with("_cbor")
                || name.contains("_delta")
                || name.ends_with("_frame_wrong_destination"))
                && !name.starts_with("pdt_")
                && *name != "adv_deep_nesting_cbor"
        })
        .collect()
}

/// Re-encodes every embedded byte string that is itself a Jackson map (signed `adBytes`,
/// relayed frames) and checks it reproduces too.
fn embedded_round_trips(value: &Value, name: &str) {
    match value {
        Value::Bytes(bytes) if bytes.first() == Some(&0xBF) => {
            if let Ok(inner) = cbor::decode(bytes) {
                assert_eq!(&cbor::encode(&inner), bytes, "{name}: embedded item");
                embedded_round_trips(&inner, name);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| embedded_round_trips(item, name)),
        Value::Map(map) => map.iter().for_each(|(key, item)| {
            embedded_round_trips(key, name);
            embedded_round_trips(item, name);
        }),
        _ => {}
    }
}

#[test]
fn every_wire_cbor_vector_round_trips_byte_for_byte() {
    let names = wire_cbor_names();
    assert!(names.len() >= 151, "only {} wire CBOR vectors", names.len());
    for name in names {
        let bytes = hex(name);
        let value = cbor::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(cbor::encode(&value), bytes, "{name}");
        assert_eq!(cbor::try_encode(&value).as_ref(), Ok(&bytes), "{name}");
        embedded_round_trips(&value, name);
    }
}

#[test]
fn the_deep_nesting_vector_is_refused() {
    assert!(matches!(
        cbor::decode(&hex("adv_deep_nesting_cbor")),
        Err(CborError::TooDeep { limit: 64, .. })
    ));
}

#[test]
fn a_frame_whose_tampering_breaks_the_cbor_is_refused() {
    // Python's cbor.loads refuses it the same way (unsupported simple value 0xfe).
    assert!(matches!(
        cbor::decode(&hex("adv_frame_bad_signature")),
        Err(CborError::UnsupportedSimple { byte: 0xFE, .. })
    ));
}

#[test]
fn keys_and_ids_match_java() {
    let port = crypto::port();
    let seed = crypto::ed25519_seed_from_pkcs8(&hex("private_key_pkcs8")).unwrap();
    let public = port.ed25519_public_key(&seed);
    assert_eq!(public.to_vec(), hex("public_key_raw"));
    assert_eq!(
        crypto::ed25519_pkcs8(&seed).to_vec(),
        hex("private_key_pkcs8")
    );
    assert_eq!(ids::derive_id(&public), s("peer_id"));
    assert_eq!(
        base58::multibase_decode(s("peer_id")).unwrap(),
        port.sha256(&public).to_vec()
    );
    assert_eq!(
        ids::group_id_from_founding(b"research-fleet-demo-v1"),
        s("group_id")
    );
    assert_eq!(
        ids::space_id_local(&format!("{}/tasks", s("group_id"))),
        s("space_id")
    );
    assert_eq!(
        ids::group_id_from_founding(&hex("founding_document_cbor")),
        s("founding_group_id")
    );
    assert_eq!(
        format!("{}{}", ids::URI_PREFIX, s("founding_group_id")),
        s("founding_ad_id")
    );
    assert_eq!(
        ids::derive_id(&hex("space_ad_cbor")),
        s("space_ad_space_id")
    );

    let agent = crypto::ed25519_seed_from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap();
    assert_eq!(
        port.ed25519_public_key(&agent).to_vec(),
        hex("agent_public_key_raw")
    );
    let forger = crypto::ed25519_seed_from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    assert_eq!(
        port.ed25519_public_key(&forger).to_vec(),
        hex("adv_forger_public_key_raw")
    );

    let scalar =
        crypto::x25519_scalar_from_pkcs8(&hex("agent_encryption_private_key_pkcs8")).unwrap();
    assert_eq!(
        port.x25519_public_key(&scalar).to_vec(),
        hex("agent_encryption_public_key_raw")
    );
    assert_eq!(
        crypto::x25519_pkcs8(&scalar).to_vec(),
        hex("agent_encryption_private_key_pkcs8")
    );
    // The two PKCS#8 forms are not interchangeable.
    assert!(crypto::x25519_scalar_from_pkcs8(&hex("private_key_pkcs8")).is_err());
    assert!(crypto::ed25519_seed_from_pkcs8(&hex("agent_encryption_private_key_pkcs8")).is_err());

    for (scalar, public) in [
        ("session_a_scalar", "session_a_public"),
        ("session_b_scalar", "session_b_public"),
    ] {
        let scalar: [u8; 32] = hex(scalar).try_into().unwrap();
        assert_eq!(port.x25519_public_key(&scalar).to_vec(), hex(public));
    }
}

#[test]
fn deterministic_signatures_reproduce_and_verify() {
    let port = crypto::port();
    let peer = crypto::ed25519_seed_from_pkcs8(&hex("private_key_pkcs8")).unwrap();
    let agent = crypto::ed25519_seed_from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap();
    for (seed, message, signature) in [
        (&peer, "sign_view_cbor", "record_signature"),
        (&peer, "state_sign_view_cbor", "state_signature"),
        (&peer, "take_claim_cbor", "take_claim_signature"),
        (&peer, "founding_fields_cbor", "founding_signature"),
        (&peer, "agent_card_cbor", "agent_card_signature"),
        (
            &peer,
            "agent_certificate_unsigned_cbor",
            "agent_certificate_signature",
        ),
        (
            &agent,
            "state_sign_view_agent_cbor",
            "state_signature_agent_key",
        ),
    ] {
        let public = port.ed25519_public_key(seed);
        let message = hex(message);
        let expected = hex(signature);
        assert_eq!(
            port.ed25519_sign(seed, &message).to_vec(),
            expected,
            "{signature}"
        );
        assert!(
            port.ed25519_verify(&public, &message, &expected),
            "{signature}"
        );
        let mut tampered = expected.clone();
        tampered[10] ^= 0x01;
        assert!(!port.ed25519_verify(&public, &message, &tampered));
        assert!(!port.ed25519_verify(&public, &message, &expected[..63]));
    }
}

#[test]
fn golden_instants_parse() {
    assert_eq!(
        time::parse_instant_millis(s("certificate_verify_at")),
        Ok(1_735_689_600_000)
    );
    assert_eq!(
        time::parse_instant_millis(s("renewed_certificate_signed_at")),
        Ok(1_735_777_800_000)
    );
    assert_eq!(
        time::instant_iso(1_735_689_600_000),
        s("certificate_verify_at")
    );
}
