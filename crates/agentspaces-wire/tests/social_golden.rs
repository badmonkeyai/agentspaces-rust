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

//! The invite key and the delegated credential against the social golden vector
//! (`test_social.py`): every derivation from the secret, the founder's delegation,
//! the candidate's credential, both hashes, the signed view, and both key renderings match the
//! Java bytes exactly; the admission window, forgeries, and malformed keys are judged as Java
//! judges them.

mod common;

use agentspaces_wire::cbor::{self, Value};
use agentspaces_wire::founding::found_group;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::revocation::{
    CREDENTIAL_STREAM, Registry, credential_revocation, join_credential_target, sign_revocation,
};
use agentspaces_wire::social::{
    self, DEFAULT_HOST, DELEGATED_PREFIX, EXPIRY_SKEW_MILLIS, GroupSecret, HINT_KEY, InviteKey,
    JoinVerdict, SALT, SocialError, base32_decode, base32_encode, base64_decode, base64_encode,
    credential_hash, credential_view, decode_delegated, decode_delegation, delegate,
    delegated_credential_admits, delegation_group, delegation_hash, delegation_info,
    delegation_verifies, hints_for, issue_delegated, judge_delegated_credential,
};
use agentspaces_wire::time::parse_instant_millis;

fn sg(name: &str) -> &'static str {
    common::social_golden()[name]
        .as_str()
        .unwrap_or_else(|| panic!("social golden {name} is not a string"))
}

fn sg_hex(name: &str) -> Vec<u8> {
    hex::decode(sg(name)).unwrap()
}

fn seed(name: &str) -> [u8; 32] {
    sg_hex(name).try_into().unwrap()
}

fn secret() -> GroupSecret {
    GroupSecret::from_slice(&sg_hex("secret_hex")).unwrap()
}

fn founder() -> Identity {
    Identity::from_seed(&seed("founder_seed_hex"))
}

fn millis(name: &str) -> i64 {
    parse_instant_millis(sg(name)).unwrap()
}

#[test]
fn secret_derivations_match_java() {
    let secret = secret();
    assert_eq!(SALT, sg("hkdf_salt").as_bytes());
    assert_eq!(secret.code(), sg("code"));
    assert_eq!(secret.code().len(), 16);
    assert_eq!(
        secret.invite_private_seed().as_slice(),
        sg_hex("invite_private_seed_hex").as_slice()
    );
    assert_eq!(
        secret.invite_public_key().as_slice(),
        sg_hex("invite_public_key_hex").as_slice()
    );
    assert_eq!(
        secret.invite_key().public_raw().as_slice(),
        sg_hex("invite_public_key_hex").as_slice()
    );
    assert_eq!(
        secret.content_key().as_slice(),
        sg_hex("content_key_hex").as_slice()
    );
    assert_eq!(
        secret.content_key_base64().as_str(),
        base64_encode(&sg_hex("content_key_hex"))
    );
    assert_eq!(GroupSecret::new(*secret.as_bytes()).unwrap(), secret);
    assert_ne!(GroupSecret::random().unwrap(), secret);
    assert_eq!(
        GroupSecret::from_slice(&[0; 15]),
        Err(SocialError::SecretLength(15))
    );
    assert_eq!(
        GroupSecret::from_slice(&[0; 17]),
        Err(SocialError::SecretLength(17))
    );
}

#[test]
fn identities_from_seeds_match_java() {
    assert_eq!(founder().peer_id(), sg("founder_peer_id"));
    assert_eq!(
        Identity::from_seed(&seed("candidate_seed_hex")).peer_id(),
        sg("candidate_peer_id")
    );
}

#[test]
fn the_founder_reproduces_the_golden_founding() {
    // Java: GroupFounding.found(founder, "weekend-hack", INVITE, LEASE_RACE,
    // GossipParameters.defaults(), issued, Duration.ofDays(365)).
    let signed = found_group(
        &founder(),
        "weekend-hack",
        "INVITE",
        "LEASE_RACE",
        3,
        "PT1S",
        sg("founding_issued"),
        "PT8760H",
    )
    .unwrap();
    assert_eq!(
        cbor::encode(&Value::Map(signed.clone())),
        base64_decode(sg("founding_cbor_base64")).unwrap()
    );
    let ad = signed.get("advertisement").and_then(Value::as_map).unwrap();
    assert_eq!(
        ad.get("group").and_then(Value::as_str),
        Some(sg("group_id"))
    );
}

#[test]
fn the_delegation_decodes_and_hashes() {
    let delegation = sg("delegation_base64");
    let info = delegation_info(delegation).unwrap();
    assert_eq!(info.founder, sg("founder_peer_id"));
    assert_eq!(info.invite_key, sg_hex("invite_public_key_hex"));
    assert_eq!(info.group, sg("group_id"));
    assert_eq!(info.not_after_millis, millis("delegation_not_after"));
    assert_eq!(info.label, sg("delegation_label"));
    assert_eq!(delegation_group(delegation).unwrap(), sg("group_id"));
    assert_eq!(
        delegation_hash(delegation).unwrap().as_slice(),
        sg_hex("delegation_hash_hex").as_slice()
    );
    // The decoded record re-encodes to the same bytes: the field order is Java's.
    let decoded = decode_delegation(delegation).unwrap();
    assert_eq!(decoded.to_cbor(), base64_decode(delegation).unwrap());
    assert_eq!(decoded.to_base64(), delegation);
    // Surrounding whitespace is forgiven; garbage is not a delegation.
    assert_eq!(
        decode_delegation(&format!("  {delegation}\n")).unwrap(),
        decoded
    );
    for bad in ["", "not base64!", "AAAA", &base64_encode(b"\xa0")] {
        assert_eq!(
            decode_delegation(bad),
            Err(SocialError::NotDelegation),
            "{bad:?}"
        );
    }
}

#[test]
fn the_founder_signs_the_same_delegation() {
    let delegation = delegate(
        &founder(),
        sg("group_id"),
        &secret().invite_public_key(),
        millis("delegation_not_after"),
        Some(sg("delegation_label")),
    );
    assert_eq!(delegation, sg("delegation_base64"));
}

#[test]
fn the_delegated_credential_is_reproduced_byte_for_byte() {
    let secret = secret();
    let delegation = sg("delegation_base64");
    let candidate = sg("candidate_peer_id");
    let from_seed = Identity::from_seed(&secret.invite_private_seed());
    let credential = issue_delegated(delegation, &from_seed, candidate).unwrap();
    assert_eq!(credential, sg("credential"));
    assert!(credential.starts_with(DELEGATED_PREFIX));
    // The invite Identity signs the same bytes as its seed.
    assert_eq!(
        issue_delegated(delegation, &secret.invite_key(), candidate).unwrap(),
        credential
    );
    assert_eq!(
        credential_hash(&credential).unwrap().as_slice(),
        sg_hex("credential_hash_hex").as_slice()
    );
    assert_eq!(
        delegation_hash(&credential).unwrap().as_slice(),
        sg_hex("delegation_hash_hex").as_slice()
    );
    assert_eq!(
        cbor::encode(&Value::Map(credential_view(candidate, sg("group_id")))),
        sg_hex("credential_view_cbor_hex")
    );
    let decoded = decode_delegated(&credential).unwrap();
    assert_eq!(decoded.delegation, decode_delegation(delegation).unwrap());
    assert_eq!(decoded.to_credential_string(), credential);
    assert!(issue_delegated("nope", &from_seed, candidate).is_err());
    assert_eq!(credential_hash("d1:!"), Err(SocialError::Base64));
}

#[test]
fn the_credential_admits_exactly_the_candidate_in_the_window() {
    let credential = sg("credential");
    let issued = millis("founding_issued");
    let not_after = millis("delegation_not_after");
    let (issuer, group) = (sg("founder_peer_id"), sg("group_id"));
    let candidate = sg("candidate_peer_id");
    let admits = |credential: &str, candidate: &str, issuer: &str, group: &str, now: i64| {
        delegated_credential_admits(credential, candidate, issuer, group, now)
    };
    assert!(admits(credential, candidate, issuer, group, issued));
    assert!(admits(
        credential,
        candidate,
        issuer,
        group,
        not_after + EXPIRY_SKEW_MILLIS
    ));
    assert!(!admits(
        credential,
        candidate,
        issuer,
        group,
        not_after + EXPIRY_SKEW_MILLIS + 1
    ));
    assert!(
        !admits(credential, sg("founder_peer_id"), issuer, group, issued),
        "another candidate"
    );
    assert!(
        !admits(credential, candidate, candidate, group, issued),
        "not the founder's group"
    );
    assert!(
        !admits(credential, candidate, issuer, "zOther", issued),
        "another group"
    );
    assert!(!admits(
        "not a credential",
        candidate,
        issuer,
        group,
        issued
    ));
    let tampered = format!("{}AAAAAAA=", &credential[..credential.len() - 8]);
    assert!(
        !admits(&tampered, candidate, issuer, group, issued),
        "tampered"
    );
    assert!(!admits(credential, candidate, issuer, group, i64::MAX));
    assert!(admits(credential, candidate, issuer, group, i64::MIN));
    // The delegation half alone.
    let delegation = decode_delegation(sg("delegation_base64")).unwrap();
    assert!(delegation_verifies(&delegation, issuer, group, issued));
    let mut short = delegation.clone();
    short.founder_key.pop();
    assert!(!delegation_verifies(&short, issuer, group, issued));
    let mut relabelled = delegation.clone();
    relabelled.label.push('!');
    assert!(!delegation_verifies(&relabelled, issuer, group, issued));
}

#[test]
fn a_credential_under_another_invite_key_is_refused() {
    let other = GroupSecret::random().unwrap();
    let forged = issue_delegated(
        sg("delegation_base64"),
        &other.invite_key(),
        sg("candidate_peer_id"),
    )
    .unwrap();
    assert!(!delegated_credential_admits(
        &forged,
        sg("candidate_peer_id"),
        sg("founder_peer_id"),
        sg("group_id"),
        millis("founding_issued"),
    ));
}

#[test]
fn both_renderings_parse_to_the_secret_and_render_back() {
    for (name, url) in [
        ("invite_key_compact", false),
        ("invite_key_url", true),
        ("invite_key_compact_with_host_and_delegation", false),
        ("invite_key_url_with_delegation", true),
    ] {
        let key = InviteKey::parse(sg(name)).unwrap();
        assert_eq!(key.secret(), &secret(), "{name}");
        assert_eq!(key.code(), sg("code"), "{name}");
        let rendered = if url { key.url() } else { key.compact() };
        assert_eq!(rendered.as_str(), sg(name), "{name}");
        if name.contains("delegation") {
            assert_eq!(key.host(), "beacon.example.org");
            assert_eq!(key.delegation().as_deref(), Some(sg("delegation_base64")));
            assert_eq!(
                key.document_url("https"),
                format!("https://beacon.example.org/j/{}", sg("code"))
            );
            assert_eq!(key.beacon("https"), "https://beacon.example.org");
        } else {
            assert_eq!(key.host(), DEFAULT_HOST);
            assert_eq!(key.delegation(), None);
        }
        // The two renderings of one key are each other's.
        assert_eq!(
            InviteKey::parse(&key.compact()).unwrap().url().as_str(),
            key.url().as_str()
        );
        assert_eq!(
            InviteKey::parse(&key.url()).unwrap().compact().as_str(),
            key.compact().as_str()
        );
        assert_eq!(InviteKey::parse(&key.url()).unwrap(), key);
    }
}

#[test]
fn a_key_is_built_from_its_secret() {
    let key = InviteKey::of(secret());
    assert!(key.compact().starts_with(social::PREFIX));
    assert_eq!(key.compact().as_str(), sg("invite_key_compact"));
    assert_eq!(key.url().as_str(), sg("invite_key_url"));
    let full = key
        .with_host("Beacon.Example.Org ")
        .with_delegation(Some(sg("delegation_base64")))
        .unwrap();
    assert_eq!(
        full.compact().as_str(),
        sg("invite_key_compact_with_host_and_delegation")
    );
    assert_eq!(full.url().as_str(), sg("invite_key_url_with_delegation"));
    assert_eq!(
        full.delegation_bytes(),
        base64_decode(sg("delegation_base64")).as_deref()
    );
    assert_eq!(
        full.with_delegation(None).unwrap().with_host(DEFAULT_HOST),
        key
    );
    assert_eq!(
        key.with_delegation(Some("not base64!")),
        Err(SocialError::Base64)
    );
    // Debug never shows the secret.
    let shown = format!("{full:?} {:?}", full.secret());
    assert!(shown.contains(sg("code")));
    assert!(shown.contains("@beacon.example.org"));
    assert!(!shown.contains("000G40R40M30E209185GR38E1W"));
}

#[test]
fn a_key_read_aloud_survives() {
    let compact = sg("invite_key_compact");
    let lower = compact.to_lowercase();
    let spaced = compact.replace("-000G", "- 000G").replace("G40R", "G40R ");
    let wrapped = format!("  {compact}\n");
    for text in [lower.as_str(), spaced.as_str(), wrapped.as_str()] {
        assert_eq!(
            InviteKey::parse(text).unwrap().compact().as_str(),
            compact,
            "{text:?}"
        );
    }
    // Crockford: O reads as 0, I and L as 1, dashes and case are ignored.
    assert_eq!(
        base32_decode("o-i-l").unwrap(),
        base32_decode("011").unwrap()
    );
    assert_eq!(
        base32_decode(&base32_encode(b"\x00\x01\xff").to_lowercase()).unwrap(),
        b"\x00\x01\xff"
    );
    assert_eq!(base32_decode("U"), Err(SocialError::Base32('U')));
    assert!(base32_decode("é").is_err());
}

#[test]
fn a_code_that_does_not_belong_to_the_secret_is_refused() {
    let code = sg("code");
    let compact = sg("invite_key_compact");
    let wrong_code = format!("{}0", &code[..code.len() - 1]);
    let wrong = compact.replace(&format!("-{code}-"), &format!("-{wrong_code}-"));
    assert_ne!(wrong, compact);
    assert!(InviteKey::parse(&wrong).is_err());
    let url = sg("invite_key_url").replace(&format!("/j/{code}"), &format!("/j/{wrong_code}"));
    assert!(InviteKey::parse(&url).is_err());
    for bad in [
        String::new(),
        "aspace-inv2-x-y".to_owned(),
        "https://host/x#y".to_owned(),
        format!("https://host/j/{code}"),
        format!("aspace-inv1-{code}"),
        format!("aspace-inv1-{code}-000G-X-Y"),
        format!("aspace-inv1-{code}-000G40R40M30E209185GR38E1W-U"),
        format!("https://host/j/{code}#000G40R40M30E209185GR38E"),
        format!("https://host:99999/j/{code}#000G40R40M30E209185GR38E1W"),
        format!("https:///j/{code}#000G40R40M30E209185GR38E1W"),
        "aspace-inv1-é".to_owned(),
        "https://é".to_owned(),
    ] {
        assert!(InviteKey::parse(&bad).is_err(), "{bad:?}");
    }
    // A trailing dash carries no delegation, as Java's split reads it.
    let trailing = InviteKey::parse(&format!("{compact}-")).unwrap();
    assert_eq!(trailing.delegation(), None);
}

#[test]
fn a_url_key_keeps_a_non_default_port() {
    let url =
        sg("invite_key_url").replace("https://s.agentspaces.dev/", "https://beacon.test:8443/");
    let key = InviteKey::parse(&url).unwrap();
    assert_eq!(key.host(), "beacon.test:8443");
    assert_eq!(key.url().as_str(), url);
    assert_eq!(
        key.compact().as_str(),
        format!("{}@beacon.test:8443", sg("invite_key_compact"))
    );
    assert_eq!(
        InviteKey::parse(&key.compact()).unwrap().host(),
        "beacon.test:8443"
    );
    // The default port is dropped; an IPv6 host keeps its brackets.
    let default_port = sg("invite_key_url").replace("s.agentspaces.dev/", "s.agentspaces.dev:443/");
    assert_eq!(
        InviteKey::parse(&default_port).unwrap().host(),
        DEFAULT_HOST
    );
    let v6 = sg("invite_key_url").replace("s.agentspaces.dev/", "[::1]:8443/");
    assert_eq!(InviteKey::parse(&v6).unwrap().host(), "[::1]:8443");
}

#[test]
fn hints_for_carries_the_credential_under_the_join_key() {
    let key = InviteKey::parse(sg("invite_key_url_with_delegation")).unwrap();
    let delegation = key.delegation().unwrap();
    let hints = hints_for(&key, &delegation, sg("candidate_peer_id")).unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(
        hints.get(HINT_KEY).and_then(Value::as_str),
        Some(sg("credential"))
    );
    assert_eq!(HINT_KEY, "aspace:join");
}

#[test]
fn judge_tells_expiry_from_forgery() {
    // Past the window the golden credential is "expired", not "invalid", so a peer the members
    // may re-admit from their admission memory is not refused (SPEC §5.1, v0.1.20).
    let credential = sg("credential");
    let issued = millis("founding_issued");
    let not_after = millis("delegation_not_after");
    let (issuer, group) = (sg("founder_peer_id"), sg("group_id"));
    let candidate = sg("candidate_peer_id");
    let judge = |credential: &str, candidate: &str, issuer: &str, now: i64| {
        judge_delegated_credential(credential, candidate, issuer, group, now)
    };
    assert_eq!(
        judge(credential, candidate, issuer, issued),
        JoinVerdict::Valid
    );
    assert_eq!(
        judge(
            credential,
            candidate,
            issuer,
            not_after + EXPIRY_SKEW_MILLIS
        ),
        JoinVerdict::Valid
    );
    assert_eq!(
        judge(
            credential,
            candidate,
            issuer,
            not_after + EXPIRY_SKEW_MILLIS + 1
        ),
        JoinVerdict::Expired
    );
    assert_eq!(
        judge(credential, sg("founder_peer_id"), issuer, issued),
        JoinVerdict::Invalid,
        "another candidate"
    );
    assert_eq!(
        judge(credential, candidate, candidate, issued),
        JoinVerdict::Invalid,
        "not the founder's group"
    );
    assert_eq!(
        judge("d1:AAAA", candidate, issuer, issued),
        JoinVerdict::Invalid
    );
    assert_eq!(JoinVerdict::Valid.as_str(), "valid");
    assert_eq!(JoinVerdict::Expired.as_str(), "expired");
    assert_eq!(JoinVerdict::Invalid.as_str(), "invalid");
    // A forgery past the window is invalid, never merely expired.
    let forged = issue_delegated(
        sg("delegation_base64"),
        &GroupSecret::random().unwrap().invite_key(),
        candidate,
    )
    .unwrap();
    assert_eq!(
        judge(
            &forged,
            candidate,
            issuer,
            not_after + EXPIRY_SKEW_MILLIS + 1
        ),
        JoinVerdict::Invalid
    );
}

#[test]
fn the_founder_revokes_one_holder_by_its_credential_hash() {
    // The JOIN_CREDENTIAL target names credential_hash; the founder's registry keeps it.
    let founder = founder();
    let hash = credential_hash(sg("credential")).unwrap();
    let ad = credential_revocation(
        founder.peer_id(),
        sg("group_id"),
        "2026-10-15T00:00:00Z",
        "PT720H",
        &join_credential_target(&hash),
        "privilege-withdrawn",
        None,
    )
    .unwrap();
    let payload = cbor::encode(&Value::Map(sign_revocation(&ad, &founder)));
    let mut registry = Registry::new(
        Some(sg("founder_peer_id").to_owned()),
        Some(sg("group_id").to_owned()),
    );
    let now = parse_instant_millis("2026-10-16T00:00:00Z").unwrap();
    assert!(registry.accept(CREDENTIAL_STREAM, &payload, now));
    assert!(
        registry
            .credentials()
            .contains_key(&format!("JOIN_CREDENTIAL:{}", sg("credential_hash_hex")))
    );
}
