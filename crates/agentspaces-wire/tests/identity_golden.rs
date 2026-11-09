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

//! Identities and agent certificates against the golden vectors Java produced (`test_golden.py`'s
//! identity, subordinate certificate, encryption key, and renewed certificate tests): the keys,
//! PeerID, certificate bodies, and deterministic peer signatures match byte for byte, expiry and
//! signing-time judgment draw their lines where Java does, and hostile certificates are refused
//! without panicking.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto;
use agentspaces_wire::identity::{
    AgentIdentity, Identity, IdentityError, agent_certificate, certificate_body,
    certificate_covers, sign_agent_certificate, verify_agent_certificate,
    verify_agent_certificate_at,
};
use agentspaces_wire::limits::MAX_DRIFT_MILLIS;
use agentspaces_wire::time::{parse_duration_millis, parse_instant_millis};
use common::{hex, s};

const HOUR: i64 = 3_600_000;

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn agent_key() -> Identity {
    Identity::from_pkcs8(&hex("agent_private_key_pkcs8")).unwrap()
}

fn decoded(name: &str) -> Value {
    cbor::decode(&hex(name)).unwrap()
}

fn bytes_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

fn verify_at() -> i64 {
    parse_instant_millis(s("certificate_verify_at")).unwrap()
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

/// A certificate value with one field replaced.
fn with(certificate: &Value, key: &str, value: impl Into<Value>) -> Value {
    let mut map = certificate.as_map().unwrap().clone();
    map.insert(key, value);
    Value::Map(map)
}

/// A certificate value with one field removed.
fn without(certificate: &Value, key: &str) -> Value {
    let mut map = certificate.as_map().unwrap().clone();
    map.remove(key);
    Value::Map(map)
}

// ------------------------------------------------------------------------- Identity

#[test]
fn identity_and_peer_id_match_java() {
    let identity = peer();
    assert_eq!(identity.public_raw().as_slice(), hex("public_key_raw"));
    assert_eq!(identity.peer_id(), s("peer_id"));
    assert_eq!(identity.pkcs8().as_slice(), hex("private_key_pkcs8"));
    assert_eq!(identity.agent("python"), format!("{}/python", s("peer_id")));

    // The seed is the last 32 bytes of the 48-byte PKCS#8 form.
    let der = hex("private_key_pkcs8");
    let seed: [u8; 32] = der[16..].try_into().unwrap();
    let from_seed = Identity::from_seed(&seed);
    assert_eq!(from_seed.public_raw(), identity.public_raw());
    assert_eq!(from_seed.peer_id(), identity.peer_id());

    let agent = agent_key();
    assert_eq!(agent.public_raw().as_slice(), hex("agent_public_key_raw"));
    assert_eq!(agent.pkcs8().as_slice(), hex("agent_private_key_pkcs8"));
    let forger = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    assert_eq!(
        forger.public_raw().as_slice(),
        hex("adv_forger_public_key_raw")
    );
}

#[test]
fn identity_signs_deterministically_and_verifies_strictly() {
    let identity = peer();
    let signature = identity.sign(b"message");
    assert_eq!(signature, identity.sign(b"message"));
    assert!(Identity::verify(
        identity.public_raw(),
        b"message",
        &signature
    ));
    assert!(!Identity::verify(
        identity.public_raw(),
        b"messagf",
        &signature
    ));
    assert!(!Identity::verify(
        &identity.public_raw()[..31],
        b"message",
        &signature
    ));
    assert!(!Identity::verify(
        identity.public_raw(),
        b"message",
        &signature[..63]
    ));
    assert!(!Identity::verify(b"", b"", b""));
}

#[test]
fn identity_refuses_other_key_forms_and_generates_fresh_keys() {
    let der = hex("private_key_pkcs8");
    assert!(Identity::from_pkcs8(&der[..47]).is_err());
    assert!(Identity::from_pkcs8(b"").is_err());
    assert!(Identity::from_pkcs8(&hex("agent_encryption_private_key_pkcs8")).is_err());
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    assert_ne!(a.peer_id(), b.peer_id());
    assert!(a.peer_id().starts_with('z'));
    let restored = Identity::from_pkcs8(&a.pkcs8()).unwrap();
    assert_eq!(restored.public_raw(), a.public_raw());
}

#[test]
fn identity_debug_hides_the_seed() {
    let identity = peer();
    let shown = format!("{identity:?}");
    assert!(shown.contains(s("peer_id")));
    let seed_hex = &common::golden()["private_key_pkcs8"].as_str().unwrap()[32..];
    assert!(!shown.contains(seed_hex));
    assert!(!format!("{:?}", subordinate()).contains(seed_hex));
}

// ---------------------------------------------------------------- agent certificates

#[test]
fn subordinate_agent_certificate_matches_java() {
    let identity = peer();
    let agent = subordinate();
    assert_eq!(agent.agent_id(), identity.agent("python"));
    assert_eq!(agent.local_name(), "python");
    assert_eq!(agent.public_raw().as_slice(), hex("agent_public_key_raw"));
    assert!(!agent.is_renewing());
    assert_eq!(agent.encryption_public_raw(), None);

    let certificate = agent.certificate();
    assert_eq!(
        bytes_of(&certificate_body(certificate).unwrap()),
        hex("agent_certificate_unsigned_cbor")
    );
    assert_eq!(
        certificate.get("peerSignature").and_then(Value::as_bytes),
        Some(hex("agent_certificate_signature").as_slice())
    );
    assert_eq!(bytes_of(certificate), hex("agent_certificate_cbor"));
    assert_eq!(
        certificate.get("issued").and_then(Value::as_str),
        Some(s("certificate_verify_at"))
    );

    // The builder and the signer reproduce it step by step.
    let body = agent_certificate(
        &identity.agent("python"),
        agent.public_raw(),
        s("certificate_verify_at"),
        "PT24H",
        None,
        None,
    );
    assert_eq!(bytes_of(&body), hex("agent_certificate_unsigned_cbor"));
    let signed = sign_agent_certificate(&body, &identity).unwrap();
    assert_eq!(bytes_of(&signed), hex("agent_certificate_cbor"));
    let signature: [u8; 64] = hex("agent_certificate_signature").try_into().unwrap();
    let rebuilt = agent_certificate(
        &identity.agent("python"),
        agent.public_raw(),
        s("certificate_verify_at"),
        "PT24H",
        Some(&signature),
        None,
    );
    assert_eq!(bytes_of(&rebuilt), hex("agent_certificate_cbor"));
}

#[test]
fn agent_certificate_expiry_is_inclusive() {
    let identity = peer();
    let python = identity.agent("python");
    let now = verify_at();
    let day = parse_duration_millis("PT24H").unwrap();
    let decoded = decoded("agent_certificate_cbor");
    assert!(verify_agent_certificate(
        &decoded,
        identity.public_raw(),
        &python,
        now
    ));
    let built = Value::Map(subordinate().certificate().clone());
    assert!(verify_agent_certificate(
        &built,
        identity.public_raw(),
        &python,
        now + day - 1
    ));
    // issued + ttl is the first refused instant.
    assert!(!verify_agent_certificate(
        &built,
        identity.public_raw(),
        &python,
        now + day
    ));
    // Expiry alone is judged here; the window's start is verify_agent_certificate_at's.
    assert!(verify_agent_certificate(
        &built,
        identity.public_raw(),
        &python,
        now - 1
    ));
    let map = built.as_map().unwrap();
    assert!(certificate_covers(map, now));
    assert!(certificate_covers(map, now + day - 1));
    assert!(!certificate_covers(map, now + day));
    assert!(!certificate_covers(map, now - 1));
}

#[test]
fn the_agent_key_signs_records_not_the_peer_key() {
    let agent = subordinate();
    let view = hex("sign_view_cbor");
    let signature = agent.sign(&view);
    assert_eq!(signature.as_slice(), hex("record_signature_agent_key"));
    assert!(Identity::verify(agent.public_raw(), &view, &signature));
    assert!(!Identity::verify(peer().public_raw(), &view, &signature));
}

#[test]
fn a_certificate_can_certify_the_agents_encryption_key() {
    let identity = peer();
    let python = identity.agent("python");
    let certificate = decoded("agent_certificate_with_encryption_cbor");
    let encryption_key = hex("agent_encryption_public_key_raw");
    assert_eq!(
        certificate
            .get("encryptionPublicKey")
            .and_then(Value::as_bytes),
        Some(encryption_key.as_slice())
    );
    assert_eq!(
        bytes_of(&certificate_body(certificate.as_map().unwrap()).unwrap()),
        hex("agent_certificate_with_encryption_unsigned_cbor")
    );
    assert!(verify_agent_certificate(
        &certificate,
        identity.public_raw(),
        &python,
        verify_at()
    ));
    assert_eq!(
        bytes_of(&certificate_body(decoded("agent_certificate_cbor").as_map().unwrap()).unwrap()),
        hex("agent_certificate_unsigned_cbor")
    );

    // The X25519 key is the one the agent's encryption private key derives.
    let scalar =
        crypto::x25519_scalar_from_pkcs8(&hex("agent_encryption_private_key_pkcs8")).unwrap();
    let derived = crypto::port().x25519_public_key(&scalar);
    assert_eq!(derived.as_slice(), encryption_key);

    // Built and signed here, it is Java's certificate byte for byte.
    let body = agent_certificate(
        &python,
        agent_key().public_raw(),
        s("certificate_verify_at"),
        "PT24H",
        None,
        Some(&derived),
    );
    assert_eq!(
        bytes_of(&body),
        hex("agent_certificate_with_encryption_unsigned_cbor")
    );
    let signed = sign_agent_certificate(&body, &identity).unwrap();
    assert_eq!(
        signed.get("peerSignature").and_then(Value::as_bytes),
        Some(hex("agent_certificate_with_encryption_signature").as_slice())
    );
    assert_eq!(
        bytes_of(&signed),
        hex("agent_certificate_with_encryption_cbor")
    );

    // So is the first certificate of a renewing identity that certifies the key.
    let agent = identity
        .renewing_subordinate_with_encryption(
            "python",
            "PT24H",
            Some(agent_key()),
            &derived,
            verify_at(),
        )
        .unwrap();
    assert_eq!(agent.encryption_public_raw(), Some(&derived));
    assert_eq!(
        bytes_of(agent.certificate()),
        hex("agent_certificate_with_encryption_cbor")
    );

    // A null encryptionPublicKey is an absent one; a malformed one is refused.
    let plain = decoded("agent_certificate_cbor");
    let key = identity.public_raw();
    let at = verify_at();
    assert!(verify_agent_certificate(
        &with(&plain, "encryptionPublicKey", Value::Null),
        key,
        &python,
        at
    ));
    for bad in [
        Value::from(&encryption_key[..31]),
        Value::from("not bytes"),
        Value::from(7),
    ] {
        assert!(!verify_agent_certificate(
            &with(&certificate, "encryptionPublicKey", bad),
            key,
            &python,
            at
        ));
    }
    // Stripping the certified key breaks the signature rather than downgrading the certificate.
    assert!(!verify_agent_certificate(
        &without(&certificate, "encryptionPublicKey"),
        key,
        &python,
        at
    ));
}

#[test]
fn renewed_agent_certificate_matches_java_and_is_judged_at_signing_time() {
    let identity = peer();
    let python = identity.agent("python");
    let verify_at = verify_at();
    let signed_at = parse_instant_millis(s("renewed_certificate_signed_at")).unwrap();

    let mut agent = identity
        .renewing_subordinate("python", "PT24H", Some(agent_key()), verify_at)
        .unwrap();
    assert!(agent.is_renewing());
    assert_eq!(bytes_of(agent.certificate()), hex("agent_certificate_cbor"));

    // Half-life is the first instant a renewal is due.
    assert!(!agent.renew_if_due(&identity, verify_at).unwrap());
    assert!(
        !agent
            .renew_if_due(&identity, verify_at + 12 * HOUR - 1)
            .unwrap()
    );
    let mut at_half_life = agent.clone();
    assert!(
        at_half_life
            .renew_if_due(&identity, verify_at + 12 * HOUR)
            .unwrap()
    );

    assert!(
        agent
            .renew_if_due(&identity, verify_at + 13 * HOUR)
            .unwrap()
    );
    assert!(!agent.renew_if_due(&identity, signed_at).unwrap());
    assert_eq!(agent.certificates().count(), 2);
    let renewed = agent.certificate_covering(signed_at).unwrap();
    assert_eq!(bytes_of(renewed), hex("renewed_agent_certificate_cbor"));
    assert_eq!(agent.certificate(), renewed);
    // An earlier stamp is still covered by the first certificate, the newest that covers it.
    assert_eq!(
        bytes_of(agent.certificate_covering(verify_at).unwrap()),
        hex("agent_certificate_cbor")
    );
    assert_eq!(
        bytes_of(agent.certificate_covering(verify_at + 13 * HOUR).unwrap()),
        hex("renewed_agent_certificate_cbor")
    );
    assert!(agent.certificate_covering(verify_at - 1).is_none());
    assert!(agent.certificate_covering(verify_at + 37 * HOUR).is_none());

    let renewed = decoded("renewed_agent_certificate_cbor");
    let first = decoded("agent_certificate_cbor");
    let key = identity.public_raw();
    let long_after = signed_at + 30 * HOUR;
    assert!(verify_agent_certificate_at(
        &renewed, key, &python, signed_at, long_after
    ));
    assert!(!verify_agent_certificate(
        &renewed, key, &python, long_after
    ));
    // The first certificate does not cover the renewed signing time.
    assert!(!verify_agent_certificate_at(
        &first, key, &python, signed_at, signed_at
    ));
    // A signing time that leads the receiver beyond the drift ceiling is refused.
    assert!(verify_agent_certificate_at(
        &renewed,
        key,
        &python,
        signed_at,
        signed_at - MAX_DRIFT_MILLIS
    ));
    assert!(!verify_agent_certificate_at(
        &renewed,
        key,
        &python,
        signed_at,
        signed_at - MAX_DRIFT_MILLIS - 1
    ));
    assert!(!verify_agent_certificate_at(
        &renewed, key, &python, signed_at, verify_at
    ));
    // Outside the window, before or after.
    let window_start = verify_at + 13 * HOUR;
    assert!(verify_agent_certificate_at(
        &renewed,
        key,
        &python,
        window_start,
        long_after
    ));
    assert!(!verify_agent_certificate_at(
        &renewed,
        key,
        &python,
        window_start - 1,
        long_after
    ));
    assert!(!verify_agent_certificate_at(
        &renewed,
        key,
        &python,
        window_start + 24 * HOUR,
        long_after
    ));
    // Every other check of verify_agent_certificate still applies at the signing time.
    let other = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    assert!(!verify_agent_certificate_at(
        &renewed,
        other.public_raw(),
        &python,
        signed_at,
        signed_at
    ));
    assert!(!verify_agent_certificate_at(
        &renewed,
        key,
        &identity.agent("other"),
        signed_at,
        signed_at
    ));
    assert!(!verify_agent_certificate_at(
        &Value::Null,
        key,
        &python,
        signed_at,
        signed_at
    ));
}

#[test]
fn renewal_is_refused_for_another_peer_and_skipped_without_renewal() {
    let identity = peer();
    let other = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    let mut renewing = identity
        .renewing_subordinate("python", "PT24H", Some(agent_key()), verify_at())
        .unwrap();
    assert!(matches!(
        renewing.renew_if_due(&other, verify_at() + 13 * HOUR),
        Err(IdentityError::ForeignAgent { .. })
    ));
    assert_eq!(renewing.certificates().count(), 1);
    assert_eq!(
        bytes_of(renewing.certificate()),
        hex("agent_certificate_cbor")
    );

    let mut fixed = subordinate();
    assert!(
        !fixed
            .renew_if_due(&identity, verify_at() + 100 * HOUR)
            .unwrap()
    );
    assert_eq!(fixed.certificates().count(), 1);

    // A renewal time that cannot print as a four-digit-year instant is refused.
    assert!(matches!(
        renewing.renew_if_due(&identity, i64::MAX),
        Err(IdentityError::Time(_))
    ));
}

#[test]
fn subordinate_refuses_what_java_cannot_express() {
    let identity = peer();
    for name in ["", "a/b", "/"] {
        assert_eq!(
            identity
                .subordinate(name, s("certificate_verify_at"), "PT1H", None)
                .unwrap_err(),
            IdentityError::InvalidLocalName(name.to_owned())
        );
    }
    assert!(matches!(
        identity.subordinate("a", "2025-01-01", "PT1H", None),
        Err(IdentityError::Time(_))
    ));
    assert!(matches!(
        identity.subordinate("a", s("certificate_verify_at"), "P1D", None),
        Err(IdentityError::Time(_))
    ));
    assert!(matches!(
        identity.renewing_subordinate("a", "1 day", None, verify_at()),
        Err(IdentityError::Time(_))
    ));
    assert!(matches!(
        identity.renewing_subordinate("a", "PT1H", None, i64::MAX),
        Err(IdentityError::Time(_))
    ));
    // A fresh key when none is given.
    let fresh = identity
        .subordinate("a", s("certificate_verify_at"), "PT1H", None)
        .unwrap();
    assert_ne!(fresh.public_raw(), agent_key().public_raw());
    assert!(verify_agent_certificate(
        &Value::Map(fresh.certificate().clone()),
        identity.public_raw(),
        &identity.agent("a"),
        verify_at()
    ));
}

#[test]
fn only_the_agents_own_peer_may_sign_its_certificate() {
    let identity = peer();
    let other = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    let body = agent_certificate(
        &identity.agent("python"),
        agent_key().public_raw(),
        s("certificate_verify_at"),
        "PT24H",
        None,
        None,
    );
    assert_eq!(
        sign_agent_certificate(&body, &other),
        Err(IdentityError::ForeignAgent {
            agent: identity.agent("python"),
            peer: other.peer_id().to_owned(),
        })
    );
    // A name that merely starts with the PeerID is not the peer's.
    let mut prefixed = body.clone();
    prefixed.insert("agent", format!("{}x/python", identity.peer_id()));
    assert!(matches!(
        sign_agent_certificate(&prefixed, &identity),
        Err(IdentityError::ForeignAgent { .. })
    ));
    let mut nameless = body.clone();
    nameless.insert("agent", 7);
    assert_eq!(
        sign_agent_certificate(&nameless, &identity),
        Err(IdentityError::MalformedCertificate { field: "agent" })
    );
    let mut keyless = body.clone();
    keyless.remove("agentPublicKey");
    assert!(matches!(
        sign_agent_certificate(&keyless, &identity),
        Err(IdentityError::MalformedCertificate { .. })
    ));
    // Signing an already-signed certificate re-signs its canonical body.
    let signed = sign_agent_certificate(&body, &identity).unwrap();
    assert_eq!(sign_agent_certificate(&signed, &identity).unwrap(), signed);
}

#[test]
fn hostile_certificates_are_refused() {
    let identity = peer();
    let python = identity.agent("python");
    let key = identity.public_raw();
    let at = verify_at();
    let genuine = decoded("agent_certificate_cbor");
    assert!(verify_agent_certificate(&genuine, key, &python, at));

    let refused = |certificate: &Value| !verify_agent_certificate(certificate, key, &python, at);
    assert!(refused(&Value::Null));
    assert!(refused(&Value::from("certificate")));
    assert!(refused(&Value::Array(vec![genuine.clone()])));
    assert!(refused(&Value::Map(Map::new())));
    for field in ["agent", "agentPublicKey", "issued", "ttl", "peerSignature"] {
        assert!(refused(&without(&genuine, field)), "without {field}");
        assert!(refused(&with(&genuine, field, Value::Null)), "null {field}");
        assert!(refused(&with(&genuine, field, 1)), "int {field}");
    }
    assert!(refused(&with(&genuine, "peerSignature", "signature")));
    assert!(refused(&with(&genuine, "peerSignature", vec![0u8; 64])));
    assert!(refused(&with(
        &genuine,
        "agentPublicKey",
        &hex("agent_public_key_raw")[..31]
    )));
    assert!(refused(&with(
        &genuine,
        "agentPublicKey",
        hex("public_key_raw")
    )));
    assert!(refused(&with(&genuine, "ttl", "PT48H")));
    assert!(refused(&with(&genuine, "ttl", "P1D")));
    assert!(refused(&with(
        &genuine,
        "issued",
        "2025-01-01T00:00:00.000Z"
    )));
    assert!(refused(&with(&genuine, "issued", "not an instant")));
    assert!(refused(&with(&genuine, "agent", identity.agent("other"))));

    // The wrong peer key, a malformed one, or the wrong expected agent.
    let other = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    assert!(!verify_agent_certificate(
        &genuine,
        other.public_raw(),
        &python,
        at
    ));
    assert!(!verify_agent_certificate(&genuine, &key[..31], &python, at));
    assert!(!verify_agent_certificate(&genuine, &[], &python, at));
    assert!(!verify_agent_certificate(
        &genuine,
        key,
        &identity.agent("other"),
        at
    ));
    assert!(!verify_agent_certificate(
        &genuine,
        key,
        identity.peer_id(),
        at
    ));

    // The body is rebuilt in canonical order: a reordered or extended certificate still
    // verifies, as Java decodes it into its record.
    let map = genuine.as_map().unwrap();
    let reversed: Map = map
        .iter()
        .rev()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert!(verify_agent_certificate(
        &Value::Map(reversed),
        key,
        &python,
        at
    ));
    assert!(verify_agent_certificate(
        &with(&genuine, "extra", "ignored"),
        key,
        &python,
        at
    ));
}

#[test]
fn every_single_bit_flip_of_a_certificate_is_refused_or_harmless() {
    let identity = peer();
    let python = identity.agent("python");
    let bytes = hex("agent_certificate_cbor");
    let genuine = decoded("agent_certificate_cbor");
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[index] ^= 1 << bit;
            let Ok(value) = cbor::decode(&flipped) else {
                continue;
            };
            let at = verify_at();
            let accepted = verify_agent_certificate(&value, identity.public_raw(), &python, at);
            let accepted_at =
                verify_agent_certificate_at(&value, identity.public_raw(), &python, at, at);
            assert_eq!(accepted, accepted_at, "byte {index} bit {bit}");
            if accepted {
                assert_eq!(value, genuine, "byte {index} bit {bit} verified");
            }
        }
    }
    for length in 0..bytes.len() {
        if let Ok(value) = cbor::decode(&bytes[..length]) {
            assert!(!verify_agent_certificate(
                &value,
                identity.public_raw(),
                &python,
                verify_at()
            ));
        }
    }
}
