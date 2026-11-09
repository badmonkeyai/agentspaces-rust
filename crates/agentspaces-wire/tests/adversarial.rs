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

//! Adversarial conformance (a port of `test_adversarial.py`): every `adv_*` vector in
//! `golden.json` is a hostile input this crate must reject, by a failed decode, a failed
//! verification, or a bound, without panicking. The same vectors gate the Java, TypeScript,
//! Python, and Ruby implementations, so all reject alike.
//! Hostile states and claims go through the real fold ([`SpaceStore`]); the receivers' clocks
//! are pinned, and a vector refused for its own reason is refused at every clock tried.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::crypto::{self, x25519_scalar_from_pkcs8};
use agentspaces_wire::envelope::{accepts, decode_frame, decode_frame_detailed, encode_frame};
use agentspaces_wire::fold::{FoldContext, FoldOutcome, Refusal, SpaceStore};
use agentspaces_wire::founding::verify_signed_group_ad;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids::derive_id;
use agentspaces_wire::limits::{MAX_CBOR_DEPTH, MAX_FRAME_BYTES, WIRE_VERSION};
use agentspaces_wire::records::{sign_view_of, state_sign_view_of};
use agentspaces_wire::revocation::{CREDENTIAL_STREAM, Registry};
use agentspaces_wire::time::parse_instant_millis;
use common::{golden, hex, s};

const ENTRY: &str = "11111111-2222-3333-4444-555555555555";

/// Every `adv_*` key this suite and `fold_golden.rs` assert (`founding_test.rb`'s list).
const COVERED: [&str; 39] = [
    "adv_claim_bad_signature_delta",
    "adv_claim_transplanted_delta",
    "adv_claim_nan_bid_delta",
    "adv_claim_epoch_zero_delta",
    "adv_claim_epoch_jump_delta",
    "adv_claim_eternal_delta",
    "adv_deep_nesting_cbor",
    "adv_frame_bad_signature",
    "adv_frame_wrong_destination",
    "adv_frame_wrong_destination_to",
    "adv_group_ad_wrong_id_cbor",
    "adv_group_ad_forged_signature_cbor",
    "adv_forger_private_key_pkcs8",
    "adv_forger_public_key_raw",
    "adv_cert_wrong_peer_delta",
    "adv_cert_wrong_agent_delta",
    "adv_cert_expired_delta",
    "adv_cert_uncertified_key_delta",
    "adv_cert_peer_signed_record_delta",
    "adv_claim_cert_peer_signed_delta",
    "adv_claim_cert_expired_delta",
    "adv_claim_cert_wrong_holder_delta",
    "adv_legacy_state_on_attested_entry_dto_cbor",
    "adv_legacy_state_on_attested_entry_delta_cbor",
    "adv_agent_state_peer_key_delta",
    "adv_agent_state_wrong_signer_delta",
    "adv_agent_state_out_of_window_delta",
    "adv_agent_state_drift_delta",
    "adv_claim_cert_out_of_window_delta",
    "adv_claim_predates_issue_delta",
    "adv_key_epoch_relabelled_record_cbor",
    "adv_key_epoch_relabelled_delta",
    "adv_key_wrap_wrong_group_cbor",
    "adv_key_wrap_wrong_group_binding_cbor",
    "adv_key_wrap_wrong_epoch_cbor",
    "adv_key_wrap_wrong_epoch_binding_cbor",
    "adv_key_wrap_wrong_rotator_cbor",
    "adv_key_wrap_wrong_rotator_binding_cbor",
    "adv_credential_revocation_cross_issuer_cbor",
];

// ------------------------------------------------------------------------- helpers

fn peer() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn instant(iso: &str) -> i64 {
    parse_instant_millis(iso).unwrap()
}

fn verify_at() -> i64 {
    instant(s("certificate_verify_at"))
}

/// The physical milliseconds of the golden stamp `hlc_encoded`.
fn t0() -> i64 {
    s("hlc_encoded").split(':').next().unwrap().parse().unwrap()
}

/// Receiver clocks: the vectors' own instant, the golden stamp a minute on, and this suite's
/// wall-clock era (`test_adversarial.py`'s `_peer()` reads wall time).
fn clocks() -> [i64; 3] {
    [verify_at(), t0() + 60_000, instant("2026-11-08T00:00:00Z")]
}

fn decoded(name: &str) -> Value {
    cbor::decode(&hex(name)).unwrap()
}

fn map_of(name: &str) -> Map {
    decoded(name).into_map().unwrap()
}

fn state_of(name: &str) -> Map {
    map_of(name).get("state").unwrap().as_map().unwrap().clone()
}

fn claim_of(name: &str) -> (String, Map) {
    let delta = map_of(name);
    let entry = delta
        .get("claimEntry")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    (entry, delta.get("claim").unwrap().as_map().unwrap().clone())
}

/// A fresh replica at `now` folding one state.
fn fold_state(state: &Map, now: i64) -> (SpaceStore, FoldOutcome) {
    let registry = Registry::default();
    let mut store = SpaceStore::new();
    let outcome = store.fold_state(state, &FoldContext::new(now, &registry));
    (store, outcome)
}

/// A fresh replica at `now` folding one claim.
fn fold_claim(entry_id: &str, signed: &Map, now: i64) -> (SpaceStore, FoldOutcome) {
    let registry = Registry::default();
    let mut store = SpaceStore::new();
    let outcome = store.fold_claim(entry_id, signed, &FoldContext::new(now, &registry));
    (store, outcome)
}

fn refused(refusal: Refusal) -> FoldOutcome {
    FoldOutcome::Refused(refusal)
}

// ------------------------------------------------------------------------- claims

#[test]
fn hostile_claims_never_enter_the_lattice() {
    for (name, refusal) in [
        ("adv_claim_bad_signature_delta", Refusal::UnverifiedClaim),
        ("adv_claim_transplanted_delta", Refusal::ClaimMismatch),
        ("adv_claim_nan_bid_delta", Refusal::Malformed),
        ("adv_claim_epoch_zero_delta", Refusal::Malformed),
        ("adv_claim_epoch_jump_delta", Refusal::OutOfBounds),
        ("adv_claim_eternal_delta", Refusal::UnverifiedClaim),
    ] {
        let (entry, signed) = claim_of(name);
        for now in clocks() {
            let (store, outcome) = fold_claim(&entry, &signed, now);
            assert_eq!(outcome, refused(refusal), "{name} at {now}");
            assert_eq!(store.claim_count(), 0, "{name} at {now}");
        }
    }
    // The control merges at every clock.
    let (entry, control) = claim_of("claim_delta_cbor");
    for now in clocks() {
        assert_eq!(fold_claim(&entry, &control, now).1, FoldOutcome::Applied);
    }
}

#[test]
fn hostile_certified_claims_never_enter_the_lattice() {
    // TECH-SPEC §7.6's two-key rule for claims: the control (agent-signed,
    // certificate attached) merges; each hostile proof is dropped.
    let (entry, good) = claim_of("claim_delta_with_certificate_cbor");
    let (control, outcome) = fold_claim(&entry, &good, verify_at());
    assert_eq!(outcome, FoldOutcome::Applied);
    assert_eq!(control.claim_proof(ENTRY), Some(&good));
    for name in [
        "adv_claim_cert_peer_signed_delta",
        "adv_claim_cert_expired_delta",
        "adv_claim_cert_wrong_holder_delta",
        "adv_claim_cert_out_of_window_delta",
    ] {
        let (entry, signed) = claim_of(name);
        assert!(signed.get("holderCertificate").unwrap().as_map().is_some());
        for now in clocks() {
            let (store, outcome) = fold_claim(&entry, &signed, now);
            assert_eq!(
                outcome,
                refused(Refusal::UnverifiedClaim),
                "{name} at {now}"
            );
            assert_eq!(store.claim_count(), 0);
        }
    }
    // A receiver holding the entry refuses a claim that predates its issue stamp
    // (`founding_test.rb`; Java `mergeClaim`).
    let registry = Registry::default();
    let ctx = FoldContext::new(verify_at(), &registry);
    let mut holding = SpaceStore::new();
    assert_eq!(
        holding.fold_state(&state_of("delta_cbor"), &ctx),
        FoldOutcome::Applied
    );
    let (entry, early) = claim_of("adv_claim_predates_issue_delta");
    assert_eq!(
        holding.fold_claim(&entry, &early, &ctx),
        refused(Refusal::PredatesIssue)
    );
    assert_eq!(holding.claim_count(), 0);
}

// ------------------------------------------------------------------------- records and states

#[test]
fn hostile_certificates_never_authenticate_a_record() {
    // TECH-SPEC §7.2's two-key rule: each delta decodes and differs from the
    // certified golden delta in exactly one respect, and each is dropped before it reaches the
    // joined view. The control (the agent-signed state, since an attested entry's state must be
    // agent-signed) folds.
    let (control, outcome) = fold_state(&state_of("delta_agent_signed_cbor"), verify_at());
    assert_eq!(outcome, FoldOutcome::Applied);
    assert_eq!(control.len(), 1);
    for name in [
        "adv_cert_wrong_peer_delta",
        "adv_cert_wrong_agent_delta",
        "adv_cert_expired_delta",
        "adv_cert_uncertified_key_delta",
        "adv_cert_peer_signed_record_delta",
    ] {
        let state = state_of(name);
        assert!(state.get("agentCertificate").unwrap().as_map().is_some());
        let (store, outcome) = fold_state(&state, verify_at());
        assert_eq!(outcome, refused(Refusal::UnverifiedRecord), "{name}");
        assert!(store.is_empty(), "{name}");
    }
}

#[test]
fn an_expired_certificate_is_refused_whatever_the_receivers_clock() {
    // SPEC §4.2 v0.1.13: a certificate is judged at the record's signing time, not at receipt.
    // adv_cert_expired_delta's certificate lapsed before the record's stamp, so no receiver
    // clock, even one inside the certificate's own window, makes it authenticate.
    let state = state_of("adv_cert_expired_delta");
    for at in ["2024-12-31T00:30:00Z", s("certificate_verify_at")] {
        let (store, outcome) = fold_state(&state, instant(at));
        assert!(outcome.is_refused(), "{at}");
        assert!(store.is_empty(), "{at}");
    }
}

#[test]
fn an_attested_entrys_state_must_be_signed_by_its_agent() {
    // SPEC §11a.4 v0.1.13: a peer-signed state on an agent-attested entry, agent-signer
    // fields under a peer-key signature, and a signer other than the issuer are each refused;
    // the agent-signed control folds.
    assert_eq!(
        fold_state(&state_of("delta_agent_signed_cbor"), verify_at()).1,
        FoldOutcome::Applied
    );
    for name in [
        "adv_legacy_state_on_attested_entry_delta_cbor",
        "delta_with_certificate_cbor",
        "adv_agent_state_peer_key_delta",
        "adv_agent_state_wrong_signer_delta",
    ] {
        for now in clocks() {
            let (store, outcome) = fold_state(&state_of(name), now);
            assert_eq!(
                outcome,
                refused(Refusal::UnverifiedState),
                "{name} at {now}"
            );
            assert!(store.is_empty(), "{name}");
        }
    }
    let legacy = map_of("adv_legacy_state_on_attested_entry_dto_cbor");
    assert_eq!(
        legacy,
        state_of("adv_legacy_state_on_attested_entry_delta_cbor")
    );
    assert_eq!(
        fold_state(&legacy, verify_at()).1,
        refused(Refusal::UnverifiedState)
    );
}

#[test]
fn a_bit_flip_never_changes_what_the_signatures_cover() {
    // Flip one bit at a stride through the agent-signed state: whatever still decodes either is
    // refused or folds with every signed field exactly as the author signed it.
    let original = state_of("delta_agent_signed_cbor");
    let bytes = cbor::encode(&Value::Map(original.clone()));
    let record = |state: &Map| state.get("record").and_then(Value::as_map).cloned();
    let signed_view = |state: &Map| {
        (
            record(state).as_ref().and_then(sign_view_of),
            state_sign_view_of(state),
            state.get("issuerPublicKey").cloned(),
            state.get("agentCertificate").cloned(),
            state.get("stateCertificate").cloned(),
        )
    };
    let expected = signed_view(&original);
    let (mut folded, mut refusals) = (0, 0);
    for index in (0..bytes.len()).step_by(7) {
        for bit in [0, 5] {
            let mut flipped = bytes.clone();
            flipped[index] ^= 1 << bit;
            let Some(state) = cbor::decode(&flipped).ok().and_then(Value::into_map) else {
                continue;
            };
            if state == original {
                continue;
            }
            match fold_state(&state, verify_at()).1 {
                FoldOutcome::Refused(_) => refusals += 1,
                _ => {
                    assert_eq!(signed_view(&state), expected, "byte {index} bit {bit}");
                    folded += 1;
                }
            }
        }
    }
    assert!(refusals > 100, "{refusals} refused, {folded} folded");
}

// ------------------------------------------------------------------------- frames

#[test]
fn deep_nesting_is_refused_bounded() {
    assert!(cbor::decode(&hex("adv_deep_nesting_cbor")).is_err());
    assert_eq!(decode_frame(&hex("adv_deep_nesting_cbor")), None);
    assert_eq!(MAX_CBOR_DEPTH, 64);
}

#[test]
fn a_tampered_frame_signature_never_verifies() {
    let frame = hex("adv_frame_bad_signature");
    assert_eq!(decode_frame(&frame), None);
    assert_eq!(
        decode_frame_detailed(&frame, Some(s("peer_id")), None),
        None
    );
}

#[test]
fn a_misaddressed_frame_fails_the_reader_filter() {
    let env = decode_frame(&hex("adv_frame_wrong_destination")).expect("the signature is valid");
    assert_eq!(
        env.get("to").and_then(Value::as_str),
        Some(s("adv_frame_wrong_destination_to"))
    );
    // The reader honors an addressed frame only when it is the recipient: the same signed PING
    // addressed to nobody passes, the misaddressed one fails.
    let ping = decode_frame(&hex("ping_frame_cbor")).unwrap();
    assert!(accepts(&ping, s("group_id"), s("peer_id")));
    assert!(!accepts(&env, s("group_id"), s("peer_id")));
    assert!(accepts(
        &env,
        s("group_id"),
        s("adv_frame_wrong_destination_to")
    ));
}

#[test]
fn a_frame_for_a_foreign_group_fails_the_reader_filter() {
    // SPEC §9: receivers reject envelopes whose group they do not belong to.
    let env = decode_frame(&hex("ping_frame_cbor")).unwrap();
    assert!(accepts(&env, s("group_id"), s("peer_id")));
    assert!(!accepts(&env, "zSomeOtherGroup", s("peer_id")));
    // An unverifiable frame never reaches a handler: it does not decode to an envelope.
    assert_eq!(decode_frame(b"\xf6"), None);
    assert_eq!(decode_frame(&[]), None);
}

#[test]
fn frame_cap_matches_the_shared_constant() {
    assert_eq!(
        golden()["max_frame_bytes"].as_u64(),
        Some(MAX_FRAME_BYTES as u64)
    );
}

#[test]
fn a_frame_of_another_wire_version_is_dropped() {
    // SPEC §9: ver != 3 is dropped before signature verification. Re-sign the golden PING
    // envelope under ver 2 so the signature itself is valid.
    let mut env = decode_frame(&hex("ping_frame_cbor")).unwrap();
    assert_eq!(env.get("ver"), Some(&Value::from(WIRE_VERSION)));
    assert_eq!(golden()["wire_version"].as_u64(), Some(3));
    env.insert("ver", 2);
    let stale = encode_frame(&env, &peer());
    assert_eq!(
        cbor::decode(&stale)
            .unwrap()
            .get("envelope")
            .and_then(|env| env.get("ver")),
        Some(&Value::from(2))
    );
    assert_eq!(decode_frame(&stale), None);
    assert_eq!(decode_frame_detailed(&stale, None, None), None);
}

// ------------------------------------------------------------------------- founding documents

#[test]
fn hostile_founding_documents_never_verify() {
    // SPEC §5.1's four checks: a genuine signature under the wrong GroupID, and the right GroupID
    // under a forged signature, are both refused. The bytes decode cleanly, so the refusal is
    // verification, not a parse failure, and a join waiting for the founding group never
    // completes on either.
    assert_eq!(
        verify_signed_group_ad(&decoded("signed_group_ad_cbor")).as_deref(),
        Some(s("founding_group_id"))
    );
    for name in [
        "adv_group_ad_wrong_id_cbor",
        "adv_group_ad_forged_signature_cbor",
    ] {
        let signed = decoded(name);
        assert!(signed.as_map().is_some(), "{name}");
        assert_eq!(verify_signed_group_ad(&signed), None, "{name}");
    }
}

// ------------------------------------------------------------------------- revocations

#[test]
fn a_cross_issuer_revocation_refuses_nothing() {
    // adv_forger revokes peer_id/python, an agent it does not host: refused by every registry,
    // so the agent's entries and claims still fold.
    let forger = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    assert_eq!(
        forger.public_raw(),
        hex("adv_forger_public_key_raw").as_slice()
    );
    let signed = map_of("adv_credential_revocation_cross_issuer_cbor");
    let ad_bytes = signed.get("adBytes").and_then(Value::as_bytes).unwrap();
    let ad = cbor::decode(ad_bytes).unwrap();
    assert_eq!(
        ad.get("issuer").and_then(Value::as_str),
        Some(derive_id(&hex("adv_forger_public_key_raw")).as_str())
    );
    assert_eq!(
        ad.get("target")
            .and_then(|target| target.get("agent"))
            .and_then(Value::as_str),
        Some(peer().agent("python").as_str())
    );
    let now = instant("2026-06-01T00:00:00Z");
    for founder in [Some(s("peer_id").to_owned()), None] {
        let mut registry = Registry::new(founder, Some(s("group_id").to_owned()));
        assert!(!registry.accept(
            CREDENTIAL_STREAM,
            &hex("adv_credential_revocation_cross_issuer_cbor"),
            now
        ));
        let ctx = FoldContext::new(verify_at(), &registry);
        let mut store = SpaceStore::new();
        let (entry, claim) = claim_of("claim_delta_with_certificate_cbor");
        assert_eq!(store.fold_claim(&entry, &claim, &ctx), FoldOutcome::Applied);
        assert_eq!(
            store.fold_state(&state_of("delta_agent_signed_cbor"), &ctx),
            FoldOutcome::Applied
        );
    }
}

// ------------------------------------------------------------------------- key wraps

/// Java `GroupKeyDistributor.WrapBinding` (key-wrap v2, SPEC §11a.2) in record order.
fn wrap_binding(group: &str, requester: &str, epoch: i64, rotator: &str) -> Map {
    let mut binding = Map::with_capacity(7);
    binding.insert("group", group);
    binding.insert("holder", s("peer_id"));
    binding.insert("requester", requester);
    binding.insert("nonce", 7);
    binding.insert("epoch", epoch);
    binding.insert("rotator", rotator);
    binding.insert("agent", peer().agent("python"));
    binding
}

/// The key-encryption key a requester derives for a wrap under `binding` (Java
/// `GroupKeyWrap.kekFor`): HKDF-SHA-256 over the X25519 agreement, salted with the ephemeral and
/// recipient public keys and the binding's digest.
fn kek(shared: &[u8], ephemeral: &[u8], recipient: &[u8], binding: &Map) -> Vec<u8> {
    let port = crypto::port();
    let digest = port.sha256(&cbor::encode(&Value::Map(binding.clone())));
    let salt = [ephemeral, recipient, &digest].concat();
    port.hkdf_sha256(shared, &salt, b"aspace-group-key-wrap-v2", 32)
        .unwrap()
        .to_vec()
}

#[test]
fn a_key_wrap_for_another_exchange_is_bound_to_that_exchange() {
    // SPEC §11a.2: each hostile wrap is a genuine wrap of the epoch key sealed under
    // a binding that names another exchange (another group, epoch, or rotator). The requester
    // opens under the binding it expects, wrap_binding_v2_cbor, so its key-encryption key and the
    // AES-256-GCM associated data (the binding digest) both differ from the sealer's, and the
    // seal does not open. (Opening needs AES-256-GCM, which this crate does not carry; Java's
    // GoldenVectorsV0113ConformanceTest opens each wrap.)
    let forger = derive_id(&hex("adv_forger_public_key_raw"));
    let expected = wrap_binding(s("group_id"), &forger, 2, s("peer_id"));
    assert_eq!(
        cbor::encode(&Value::Map(expected.clone())),
        hex("wrap_binding_v2_cbor")
    );
    let scalar = x25519_scalar_from_pkcs8(&hex("agent_encryption_private_key_pkcs8")).unwrap();
    let recipient = hex("agent_encryption_public_key_raw");
    assert_eq!(
        crypto::port().x25519_public_key(&scalar).as_slice(),
        recipient
    );
    let hostile = [
        (
            "adv_key_wrap_wrong_group",
            "group",
            wrap_binding(s("founding_group_id"), &forger, 2, s("peer_id")),
        ),
        (
            "adv_key_wrap_wrong_epoch",
            "epoch",
            wrap_binding(s("group_id"), &forger, 3, s("peer_id")),
        ),
        (
            "adv_key_wrap_wrong_rotator",
            "rotator",
            wrap_binding(s("group_id"), &forger, 2, &forger),
        ),
    ];
    for (name, field, binding) in hostile {
        // The binding is the expected one with exactly the named field changed.
        assert_eq!(
            cbor::encode(&Value::Map(binding.clone())),
            hex(&format!("{name}_binding_cbor")),
            "{name}"
        );
        let differing: Vec<_> = expected
            .iter()
            .zip(binding.iter())
            .filter(|(a, b)| a != b)
            .filter_map(|((key, _), _)| key.as_str())
            .collect();
        assert_eq!(differing, [field], "{name}");
        // The wrap: an X25519 ephemeral key and the sealed key (12-byte nonce, 32-byte key,
        // 16-byte tag), re-encoding byte for byte.
        for wrap_name in [format!("{name}_cbor"), "key_wrap_v2_cbor".to_owned()] {
            let wrap = map_of(&wrap_name);
            let keys: Vec<_> = wrap.keys().filter_map(Value::as_str).collect();
            assert_eq!(keys, ["ephemeralPublicKey", "sealed"], "{wrap_name}");
            assert_eq!(cbor::encode(&Value::Map(wrap.clone())), hex(&wrap_name));
            let ephemeral: [u8; 32] = wrap
                .get("ephemeralPublicKey")
                .and_then(Value::as_bytes)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                wrap.get("sealed")
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::len),
                Some(12 + 32 + 16)
            );
            let shared = crypto::port().x25519(&scalar, &ephemeral).unwrap();
            assert_ne!(
                kek(shared.as_slice(), &ephemeral, &recipient, &expected),
                kek(shared.as_slice(), &ephemeral, &recipient, &binding),
                "{wrap_name}"
            );
        }
    }
}

// ------------------------------------------------------------------------- coverage

#[test]
fn every_hostile_adv_input_is_covered() {
    let all: Vec<&str> = golden()
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|key| key.starts_with("adv_"))
        .collect();
    let missing: Vec<_> = all.iter().filter(|key| !COVERED.contains(key)).collect();
    assert!(missing.is_empty(), "uncovered adv vectors: {missing:?}");
    for key in COVERED {
        assert!(all.contains(&key), "{key} is not a golden vector");
    }
}
