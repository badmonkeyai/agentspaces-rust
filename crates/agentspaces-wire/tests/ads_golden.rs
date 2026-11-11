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

//! Advertisements against the golden vectors Java produced (`test_golden.py`'s membership intro,
//! agent cards, stored ads, and space advertisement; `test_content.py`'s via hint;
//! `test_ui_declaration.py`; `test_app_card_host.py`), the AppCard revision of SPEC v0.1.32
//! (origin and formats, the card spill and its parts documents, the AppCard level, the content
//! store's asset card), plus the receiver checks of `Peer.accept_ad` and `Peer._accept_peer_ad`.

mod common;

use agentspaces_wire::ads::{
    ACTION_TAKE, AD_TYPE_AGENT_CARD, AD_TYPE_APP_CARD, AD_TYPE_ASSET_CARD, AD_TYPE_SPACE, AdError,
    AppCard, HINT_APP_CARD, MAX_AD_ISSUED_SKEW_MILLIS, MAX_AD_TTL_MILLIS, PEER_AD_TTL,
    SPILL_MAX_FETCH_BYTES, SpillError, UI_PROTOCOL, UI_VERSION, ad_expires_at_millis, agent_card,
    app_card_at_level, app_card_host, app_card_level, app_card_origin, app_card_ui, card_action,
    card_parts, card_spill, content_root, content_store_of, endpoint, peer_advertisement,
    peer_advertisement_with_ttl, resolve_spill, signed_peer_ad, space_advertisement, space_id_of,
    spill_card, spill_of, stored_ad, ui_component, ui_declaration, verify_signed_peer_ad,
    verify_stored_ad,
};
use agentspaces_wire::bodies::{STREAM_PEERS, parse_rumor, rumor_body};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::founding::group_id_from_founding_document;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids::derive_id;
use agentspaces_wire::limits::{CARD_SPILL_THRESHOLD_BYTES, CARD_SPILL_WARN_BYTES};
use agentspaces_wire::schema;
use agentspaces_wire::time::parse_instant_millis;
use common::{hex, s};

const TASK: &str = "GoldenVectors$ResearchTask#v1";
const FINDING: &str = "GoldenVectors$Finding#v1";
const DESCRIPTION: &str = "Researches a topic and writes a finding";
// The neutral values of the regenerated vectors (SPEC annex I.3, v0.1.32).
const SHARED_ITEM: &str = "https://example.org/ns/demo/v1/SharedItem";
const MESSAGE: &str = "https://example.org/ns/demo/v1/Message";

fn identity() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).unwrap()
}

fn bytes_of(map: &Map) -> Vec<u8> {
    cbor::encode(&Value::Map(map.clone()))
}

fn map_of(bytes: &[u8]) -> Map {
    cbor::decode(bytes).unwrap().into_map().unwrap()
}

fn text_map(entries: &[(&str, &str)]) -> Map {
    entries.iter().map(|(k, v)| (*k, *v)).collect()
}

fn agent_key() -> [u8; 32] {
    <[u8; 32]>::try_from(hex("agent_public_key_raw").as_slice()).unwrap()
}

fn millis(iso: &str) -> i64 {
    parse_instant_millis(iso).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Peer advertisements

fn golden_peer_ad() -> Map {
    let mut ad = peer_advertisement(s("group_id"), &identity(), "2026-01-01T00:00:00Z", None);
    let replaced = ad.insert(
        "endpoints",
        vec![Value::Map(endpoint("tcp", "127.0.0.1:7460", 0))],
    );
    assert_eq!(replaced, Some(Value::Array(Vec::new())));
    ad
}

#[test]
fn the_membership_intro_matches_java() {
    let identity = identity();
    let ad = golden_peer_ad();
    assert_eq!(ad.get("ttl").and_then(Value::as_str), Some(PEER_AD_TTL));
    assert_eq!(bytes_of(&ad), hex("peer_ad_cbor"));
    let signed = signed_peer_ad(&ad, &identity);
    assert_eq!(signed, hex("signed_peer_ad_cbor"));
    let item_id = format!("peer:{}:1767225600000", identity.peer_id());
    let rumor = rumor_body(STREAM_PEERS, &item_id, 6, &signed);
    assert_eq!(rumor, hex("intro_rumor_body_cbor"));
    assert_eq!(parse_rumor(&rumor).unwrap().payload, signed);
    assert_eq!(
        bytes_of(&peer_advertisement_with_ttl(
            s("group_id"),
            &identity,
            "2026-01-01T00:00:00Z",
            PEER_AD_TTL,
            None
        )),
        bytes_of(&peer_advertisement(
            s("group_id"),
            &identity,
            "2026-01-01T00:00:00Z",
            None
        ))
    );
}

#[test]
fn the_via_hint_matches_java() {
    let hints = text_map(&[("relay.via", "zR1,zR2")]);
    let ad = peer_advertisement(
        s("group_id"),
        &identity(),
        "2026-01-01T00:00:00Z",
        Some(&hints),
    );
    assert_eq!(bytes_of(&ad), hex("peer_ad_with_via_hint_cbor"));
}

#[test]
fn resource_hints_are_canonical_and_text_only() {
    let mut hints = text_map(&[("wire.session", "1"), ("aspace:join", "ticket"), ("a", "b")]);
    hints.insert("skipped", 5);
    hints.insert(7, "skipped too");
    let ad = peer_advertisement("zG", &identity(), "2026-01-01T00:00:00Z", Some(&hints));
    let carried = ad.get("resourceHints").and_then(Value::as_map).unwrap();
    let keys: Vec<&str> = carried.keys().filter_map(Value::as_str).collect();
    assert_eq!(keys, ["a", "aspace:join", "wire.session"]);
}

#[test]
fn a_signed_peer_ad_verifies_and_a_forged_one_does_not() {
    let (ad, issuer) = verify_signed_peer_ad(&hex("signed_peer_ad_cbor")).expect("genuine");
    assert_eq!(issuer, s("peer_id"));
    assert_eq!(bytes_of(&ad), hex("peer_ad_cbor"));

    let genuine = map_of(&hex("signed_peer_ad_cbor"));
    let forger = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    let ad_bytes = genuine.get("adBytes").and_then(Value::as_bytes).unwrap();
    // The forger's own key and signature over the genuine bytes: the issuer is not the forger.
    let mut stolen = genuine.clone();
    stolen.insert("publicKey", forger.public_raw());
    stolen.insert("signature", forger.sign(ad_bytes));
    assert_eq!(verify_signed_peer_ad(&bytes_of(&stolen)), None);
    // The genuine key under a forged signature.
    let mut forged = genuine.clone();
    forged.insert("signature", forger.sign(ad_bytes));
    assert_eq!(verify_signed_peer_ad(&bytes_of(&forged)), None);
    // Tampered bytes, a short key, missing parts, and garbage.
    let mut tampered = genuine.clone();
    let mut bytes = ad_bytes.to_vec();
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    tampered.insert("adBytes", bytes);
    assert_eq!(verify_signed_peer_ad(&bytes_of(&tampered)), None);
    let mut short = genuine.clone();
    short.insert("publicKey", [1u8; 31]);
    assert_eq!(verify_signed_peer_ad(&bytes_of(&short)), None);
    let mut missing = genuine;
    missing.remove("signature");
    assert_eq!(verify_signed_peer_ad(&bytes_of(&missing)), None);
    assert_eq!(verify_signed_peer_ad(b"\xff"), None);
    assert_eq!(verify_signed_peer_ad(&[]), None);
}

// ---------------------------------------------------------------------------------------------
// Agent cards

fn golden_card(
    issued: &str,
    key: Option<&[u8; 32]>,
    actions: &[Map],
    certificate: Option<&Map>,
    ui: Option<&Map>,
) -> Result<Map, AdError> {
    agent_card(
        s("group_id"),
        &identity(),
        "python",
        issued,
        "PT15M",
        DESCRIPTION,
        &["research"],
        &[TASK],
        &[FINDING],
        &text_map(&[("tokens", "low")]),
        &text_map(&[(TASK, "tasks")]),
        key,
        actions,
        certificate,
        ui,
    )
}

fn golden_certificate() -> Map {
    map_of(&hex("agent_certificate_cbor"))
}

fn golden_actions() -> Vec<Map> {
    vec![card_action(
        "research",
        DESCRIPTION,
        &[TASK],
        &[FINDING],
        ACTION_TAKE,
        Some("tasks"),
    )]
}

#[test]
fn the_agent_card_and_its_stored_form_match_java() {
    let identity = identity();
    let card = golden_card("2026-01-01T00:00:00Z", None, &[], None, None).unwrap();
    assert_eq!(
        card.get("id").and_then(Value::as_str),
        Some(format!("aspace://{}/agent/{}/python", s("group_id"), s("peer_id")).as_str())
    );
    assert_eq!(bytes_of(&card), hex("agent_card_cbor"));
    let signature = identity.sign(&bytes_of(&card));
    assert_eq!(signature.to_vec(), hex("agent_card_signature"));
    let stored = stored_ad(AD_TYPE_AGENT_CARD, &card, &identity);
    assert_eq!(bytes_of(&stored), hex("signed_agent_card_cbor"));
    assert_eq!(
        derive_id(stored.get("publicKey").and_then(Value::as_bytes).unwrap()),
        s("peer_id")
    );
}

#[test]
fn the_agent_card_with_its_key_matches_java() {
    let card = golden_card("2026-01-01T00:00:00Z", Some(&agent_key()), &[], None, None).unwrap();
    assert_eq!(bytes_of(&card), hex("agent_card_with_key_cbor"));
    assert_eq!(
        identity().sign(&bytes_of(&card)).to_vec(),
        hex("agent_card_with_key_signature")
    );
}

#[test]
fn a_card_declares_its_actions_and_carries_its_certificate() {
    let certificate = golden_certificate();
    let card = golden_card(
        s("certificate_verify_at"),
        Some(&agent_key()),
        &golden_actions(),
        Some(&certificate),
        None,
    )
    .unwrap();
    assert_eq!(bytes_of(&card), hex("agent_card_with_actions_cbor"));
    assert_eq!(
        identity().sign(&bytes_of(&card)).to_vec(),
        hex("agent_card_with_actions_signature")
    );
    let action = &card.get("actions").and_then(Value::as_array).unwrap()[0];
    let keys: Vec<&str> = action
        .as_map()
        .unwrap()
        .keys()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "description",
            "consumes",
            "produces",
            "space",
            "kind"
        ]
    );
    let unbound = card_action("a", "", &[], &[], ACTION_TAKE, None);
    assert!(!unbound.contains_key("space"));
}

#[test]
fn a_card_whose_certificate_certifies_another_key_or_agent_is_refused() {
    let certificate = golden_certificate();
    let actions = golden_actions();
    let issued = s("certificate_verify_at");
    assert_eq!(
        golden_card(issued, None, &actions, Some(&certificate), None),
        Err(AdError::CertificateMismatch)
    );
    assert_eq!(
        golden_card(issued, Some(&[7u8; 32]), &actions, Some(&certificate), None),
        Err(AdError::CertificateMismatch)
    );
    let mut other_agent = certificate.clone();
    other_agent.insert("agent", format!("{}/someone-else", s("peer_id")));
    assert_eq!(
        golden_card(
            issued,
            Some(&agent_key()),
            &actions,
            Some(&other_agent),
            None
        ),
        Err(AdError::CertificateMismatch)
    );
}

fn golden_ui() -> Map {
    let components = [
        ui_component(
            "share",
            "example-widgets",
            "ItemPanel",
            SHARED_ITEM,
            &["research"],
            "panel",
        )
        .unwrap(),
        ui_component(
            "ask",
            "example-widgets",
            "MessageInput",
            MESSAGE,
            &[],
            "control",
        )
        .unwrap(),
    ];
    ui_declaration(
        &components,
        &[SHARED_ITEM],
        &[MESSAGE],
        UI_PROTOCOL,
        UI_VERSION,
    )
}

#[test]
fn the_card_with_a_ui_declaration_matches_java() {
    let ui = golden_ui();
    let keys: Vec<&str> = ui.keys().filter_map(Value::as_str).collect();
    assert_eq!(
        keys,
        ["protocol", "version", "components", "entries", "catalogIds"]
    );
    assert_eq!(
        ui.get("catalogIds"),
        Some(&Value::Array(vec![Value::from("example-widgets")]))
    );
    let card = golden_card(
        s("certificate_verify_at"),
        Some(&agent_key()),
        &golden_actions(),
        Some(&golden_certificate()),
        Some(&ui),
    )
    .unwrap();
    assert_eq!(bytes_of(&card), hex("agent_card_ui_cbor"));
    // ui is the last key, and a card without it keeps the actions card's bytes.
    let mut without = card.clone();
    without.remove("ui");
    assert_eq!(bytes_of(&without), hex("agent_card_with_actions_cbor"));
    // The Java declaration rebuilds byte for byte from its own parts.
    let java = map_of(&hex("agent_card_ui_cbor"));
    assert_eq!(java.get("ui"), Some(&Value::Map(ui)));
}

#[test]
fn a_ui_component_role_outside_the_three_is_refused() {
    assert_eq!(
        ui_component("x", "c", "C", "", &[], "popup"),
        Err(AdError::InvalidRole("popup".into()))
    );
    for role in ["panel", "control", "row"] {
        assert!(ui_component("x", "c", "C", "", &[], role).is_ok());
    }
    let catalogs = ui_declaration(
        &[
            ui_component("a", "one", "A", "", &[], "row").unwrap(),
            ui_component("b", "two", "B", "", &[], "row").unwrap(),
            ui_component("c", "one", "C", "", &[], "row").unwrap(),
        ],
        &[],
        &[],
        UI_PROTOCOL,
        UI_VERSION,
    );
    assert_eq!(
        catalogs.get("catalogIds"),
        Some(&Value::Array(vec![Value::from("one"), Value::from("two")]))
    );
}

// ---------------------------------------------------------------------------------------------
// App cards

#[test]
fn the_app_card_with_a_host_matches_java() {
    let ui = app_card_ui(
        "a2ui",
        "v0.9.1",
        &["example-widgets", "agentspaces-viz"],
        "summariser",
        "views",
        &["chat-1"],
        &[],
    )
    .unwrap();
    let host = app_card_host(
        "https://chat.example.org",
        7801,
        "zHostPeer",
        "/",
        "idp",
        "summariser",
        "2026-11-06T09:00:00Z",
        "serving",
    )
    .unwrap();
    let card = AppCard {
        id: "aspace://zApps/app/zPeerA/support-chat",
        issuer: "zPeerA",
        group: "zApps",
        issued: "2026-11-06T09:00:00Z",
        ttl: "PT15M",
        name: "Support chat",
        kind: "fed",
        shape: "a2ui",
        owner: "support",
        reads: &["zApps/conversations"],
        actions: &["ask"],
        version: "1",
        views: &["conversations"],
        ui: Some(&ui),
        host: Some(&host),
        ..AppCard::default()
    }
    .to_map()
    .unwrap();
    assert_eq!(bytes_of(&card), hex("app_card_host_cbor"));
    // host is the last key; the Java host rebuilds byte for byte from its own parts.
    assert_eq!(
        card.keys().next_back().and_then(Value::as_str),
        Some("host")
    );
    let java = map_of(&hex("app_card_host_cbor"));
    let java_host = java.get("host").and_then(Value::as_map).unwrap();
    let field = |name: &str| java_host.get(name).and_then(Value::as_str).unwrap();
    let port = java_host.get("port").and_then(Value::as_u64).unwrap();
    let rebuilt = app_card_host(
        field("url"),
        u16::try_from(port).unwrap(),
        field("hostAgent"),
        field("path"),
        field("signOn"),
        field("publishedBy"),
        field("publishedAt"),
        field("status"),
    )
    .unwrap();
    assert_eq!(&rebuilt, java_host);
    // A card without the host keeps the v0.1.27 shape.
    let mut without = card;
    without.remove("host");
    assert!(!map_of(&bytes_of(&without)).contains_key("host"));
}

#[test]
fn the_host_builder_refuses_what_the_record_refuses() {
    let host = |url, sign_on, status| {
        app_card_host(url, 0, "", "", sign_on, "", "2026-11-06T09:00:00Z", status)
    };
    assert_eq!(host("", "idp", "serving"), Err(AdError::EmptyUrl));
    assert_eq!(
        host("http://x", "password", "serving"),
        Err(AdError::InvalidSignOn("password".into()))
    );
    // v0.1.28 to v0.1.31 wrote `tenant`; v0.1.32 refuses it (SPEC §6.1a.4).
    assert_eq!(
        host("http://x", "tenant", "serving"),
        Err(AdError::InvalidSignOn("tenant".into()))
    );
    assert_eq!(
        host("http://x", "idp", "gone"),
        Err(AdError::InvalidStatus("gone".into()))
    );
    // An empty sign-on reads as the default, `idp`, as Java's Host does.
    let default_sign_on = host("http://x", "", "serving").unwrap();
    assert_eq!(
        default_sign_on.get("signOn").and_then(Value::as_str),
        Some("idp")
    );
    let defaulted = host("http://127.0.0.1:7801", "none", "stopped").unwrap();
    assert_eq!(defaulted.get("path").and_then(Value::as_str), Some("/"));
}

#[test]
fn the_app_card_refuses_what_the_record_refuses() {
    let base = AppCard {
        id: "aspace://zApps/app/zPeerA/x",
        issuer: "zPeerA",
        group: "zApps",
        issued: "2026-11-06T09:00:00Z",
        ttl: "PT15M",
        name: "X",
        ..AppCard::default()
    };
    let card = base.to_map().unwrap();
    assert_eq!(card.get("kind").and_then(Value::as_str), Some("fed"));
    assert_eq!(card.get("shape").and_then(Value::as_str), Some("web"));
    assert_eq!(card.get("version").and_then(Value::as_str), Some("1"));
    assert!(!card.contains_key("ui") && !card.contains_key("host"));
    assert_eq!(
        AppCard { name: " ", ..base }.to_map(),
        Err(AdError::EmptyName)
    );
    assert_eq!(
        AppCard {
            kind: "robot",
            ..base
        }
        .to_map(),
        Err(AdError::InvalidAppKind("robot".into()))
    );
    assert_eq!(
        AppCard {
            shape: "hologram",
            ..base
        }
        .to_map(),
        Err(AdError::InvalidAppShape("hologram".into()))
    );
    assert_eq!(
        AppCard {
            shape: "a2ui",
            ..base
        }
        .to_map(),
        Err(AdError::MissingUi)
    );
    let many = vec!["v"; 65];
    assert!(matches!(
        AppCard {
            views: &many,
            ..base
        }
        .to_map(),
        Err(AdError::TooManyTerms {
            field: "views",
            limit: 64
        })
    ));
    assert_eq!(
        app_card_ui("", "", &[], "", "carrier-pigeon", &[], &[]),
        Err(AdError::InvalidTransport("carrier-pigeon".into()))
    );
    let defaulted = app_card_ui("", "", &[], "", "", &[], &[]).unwrap();
    assert_eq!(
        defaulted,
        cbor_map! {
            "protocol" => "a2ui", "version" => "v0.9.1", "catalogIds" => Vec::<Value>::new(),
            "agent" => "", "transport" => "views", "surfaces" => Vec::<Value>::new(),
        }
        .into_map()
        .unwrap()
    );
    let component = ui_component("a", "c", "C", "", &[], "panel").unwrap();
    let with = app_card_ui("", "", &[], "", "a2a", &[], &[component]).unwrap();
    assert_eq!(
        with.keys().next_back().and_then(Value::as_str),
        Some("components")
    );
}

// ---------------------------------------------------------------------------------------------
// Space advertisements

#[test]
fn the_space_advertisement_and_its_space_id_match_java() {
    let ad = space_advertisement(
        s("group_id"),
        s("peer_id"),
        "tasks",
        "2026-01-01T00:00:00Z",
        "PT15M",
        &[TASK],
        "LEASE_RACE",
        "ALLOWLIST",
        "TAG_SHARDED",
    );
    assert_eq!(bytes_of(&ad), hex("space_ad_cbor"));
    assert_eq!(space_id_of(&ad), s("space_ad_space_id"));
    assert_eq!(derive_id(&hex("space_ad_cbor")), s("space_ad_space_id"));
    assert_eq!(
        group_id_from_founding_document(&hex("space_ad_cbor")),
        s("space_ad_space_id")
    );
}

// ---------------------------------------------------------------------------------------------
// Stored advertisements (AdCache.accept)

#[test]
fn the_java_stored_card_is_admitted_while_live() {
    let stored = cbor::decode(&hex("signed_agent_card_cbor")).unwrap();
    let issued = millis("2026-01-01T00:00:00Z");
    let (ad_type, ad, issuer) = verify_stored_ad(&stored, issued + 60_000).expect("live");
    assert_eq!(ad_type, AD_TYPE_AGENT_CARD);
    assert_eq!(issuer, s("peer_id"));
    assert_eq!(bytes_of(&ad), hex("agent_card_cbor"));
    assert_eq!(ad_expires_at_millis(&ad), Some(issued + 15 * 60_000));
    // Admitted from its issue instant to the last millisecond before expiry, and no further.
    assert!(verify_stored_ad(&stored, issued).is_some());
    assert!(verify_stored_ad(&stored, issued + 15 * 60_000 - 1).is_some());
    assert_eq!(verify_stored_ad(&stored, issued + 15 * 60_000), None);
    // An issue instant more than the skew ahead of the receiver's clock is refused.
    assert!(verify_stored_ad(&stored, issued - MAX_AD_ISSUED_SKEW_MILLIS).is_some());
    assert_eq!(
        verify_stored_ad(&stored, issued - MAX_AD_ISSUED_SKEW_MILLIS - 1),
        None
    );
}

#[test]
fn a_tampered_retyped_or_reissued_stored_ad_is_refused() {
    let identity = identity();
    let now = millis("2026-01-01T00:01:00Z");
    let genuine = map_of(&hex("signed_agent_card_cbor"));
    let check = |stored: &Map| verify_stored_ad(&Value::Map(stored.clone()), now);
    assert!(check(&genuine).is_some());

    let mut retyped = genuine.clone();
    retyped.insert("adType", "Unknown");
    assert_eq!(check(&retyped), None);
    let mut untyped = genuine.clone();
    untyped.remove("adType");
    assert_eq!(check(&untyped), None);

    let mut tampered = genuine.clone();
    let mut bytes = genuine
        .get("adBytes")
        .and_then(Value::as_bytes)
        .unwrap()
        .to_vec();
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    tampered.insert("adBytes", bytes);
    assert_eq!(check(&tampered), None);

    // Signed by another key: the issuer is not the key's PeerID.
    let forger = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    let card = map_of(genuine.get("adBytes").and_then(Value::as_bytes).unwrap());
    assert_eq!(check(&stored_ad(AD_TYPE_AGENT_CARD, &card, &forger)), None);

    // An advertisement claiming a TTL beyond the cap is refused.
    let mut eternal = card.clone();
    eternal.insert("ttl", "PT720H0M0.001S");
    assert_eq!(
        check(&stored_ad(AD_TYPE_AGENT_CARD, &eternal, &identity)),
        None
    );
    let mut month = card.clone();
    month.insert("ttl", "PT720H");
    assert!(check(&stored_ad(AD_TYPE_AGENT_CARD, &month, &identity)).is_some());
    assert_eq!(MAX_AD_TTL_MILLIS, 30 * 86_400_000);

    // Unparseable times, a missing issuer, and non-maps are refused.
    let mut garbled = card.clone();
    garbled.insert("issued", "yesterday");
    assert_eq!(
        check(&stored_ad(AD_TYPE_AGENT_CARD, &garbled, &identity)),
        None
    );
    let mut anonymous = card;
    anonymous.remove("issuer");
    assert_eq!(
        check(&stored_ad(AD_TYPE_AGENT_CARD, &anonymous, &identity)),
        None
    );
    assert_eq!(verify_stored_ad(&Value::from(3), now), None);
    assert_eq!(verify_stored_ad(&Value::Null, now), None);
}

#[test]
fn a_card_carrying_a_certificate_must_prove_it_at_its_issue_time() {
    let identity = identity();
    let certificate = golden_certificate();
    let verify_at = millis(s("certificate_verify_at"));
    let card = golden_card(
        s("certificate_verify_at"),
        Some(&agent_key()),
        &golden_actions(),
        Some(&certificate),
        None,
    )
    .unwrap();
    let stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &card, &identity));
    let (_, ad, _) = verify_stored_ad(&stored, verify_at + 60_000).expect("certified");
    assert_eq!(bytes_of(&ad), hex("agent_card_with_actions_cbor"));

    // The same certificate on a card issued after its 24-hour window: refused.
    let late = golden_card(
        "2026-01-01T00:00:00Z",
        Some(&agent_key()),
        &golden_actions(),
        Some(&certificate),
        None,
    )
    .unwrap();
    let late_stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &late, &identity));
    assert_eq!(
        verify_stored_ad(&late_stored, millis("2026-01-01T00:01:00Z")),
        None
    );

    // A certificate another peer signed: refused under this issuer's key.
    let forger = Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap();
    let mut forged = certificate.clone();
    forged.insert("peerSignature", forger.sign(b"anything"));
    let mut forged_card = card.clone();
    forged_card.insert("agentCertificate", forged);
    let forged_stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &forged_card, &identity));
    assert_eq!(verify_stored_ad(&forged_stored, verify_at + 60_000), None);

    // A certificate written as null is no certificate, and since v0.1.31 no card either: the
    // field is omitted when null, so an F6 in its place makes the card undecodable (SPEC §9.1,
    // P1). Without the field the same card verifies.
    let mut null_card =
        golden_card("2026-01-01T00:00:00Z", Some(&agent_key()), &[], None, None).unwrap();
    let plain_stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &null_card, &identity));
    assert!(verify_stored_ad(&plain_stored, millis("2026-01-01T00:01:00Z")).is_some());
    null_card.insert("agentCertificate", Value::Null);
    let null_stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &null_card, &identity));
    assert_eq!(
        verify_stored_ad(&null_stored, millis("2026-01-01T00:01:00Z")),
        None
    );
}

/// Java's `AgentCard` constructor refuses a card whose `agentCertificate` does not certify exactly
/// its `agentPublicKey`, so `AdCache.accept` drops it. A card the issuing peer re-signs with the
/// golden certificate but another, a missing, a null, or a non-byte key must be refused here too,
/// or a consumer would take an uncertified key for the certified one.
#[test]
fn a_card_whose_key_its_certificate_does_not_certify_is_refused() {
    let identity = identity();
    let certificate = golden_certificate();
    let verify_at = millis(s("certificate_verify_at"));
    let card = golden_card(
        s("certificate_verify_at"),
        Some(&agent_key()),
        &golden_actions(),
        Some(&certificate),
        None,
    )
    .unwrap();
    let verify = |card: &Map| {
        verify_stored_ad(
            &Value::Map(stored_ad(AD_TYPE_AGENT_CARD, card, &identity)),
            verify_at + 60_000,
        )
    };
    assert!(verify(&card).is_some(), "the honest card");
    let mut other_key = card.clone();
    other_key.insert("agentPublicKey", vec![9u8; 32]);
    assert_eq!(verify(&other_key), None, "another key");
    let mut keyless = card.clone();
    keyless.remove("agentPublicKey");
    assert_eq!(verify(&keyless), None, "no key");
    let mut null_key = card.clone();
    null_key.insert("agentPublicKey", Value::Null);
    assert_eq!(verify(&null_key), None, "a null key");
    let mut text_key = card.clone();
    text_key.insert("agentPublicKey", "key");
    assert_eq!(verify(&text_key), None, "a text key");
    // The certificate is unchanged and still proves the honest card at its issue time.
    assert!(verify(&card).is_some());
}

/// The forger's own card for an agent it hosts, built and signed by the forger.
fn forger_card(issued: &str, local_name: &str) -> Map {
    agent_card(
        s("group_id"),
        &forger(),
        local_name,
        issued,
        "PT15M",
        "Trust me",
        &["research"],
        &[TASK],
        &[FINDING],
        &Map::new(),
        &text_map(&[(TASK, "evil")]),
        None,
        &golden_actions(),
        None,
        None,
    )
    .unwrap()
}

fn forger() -> Identity {
    Identity::from_pkcs8(&hex("adv_forger_private_key_pkcs8")).unwrap()
}

/// A stored card names one of its issuer's own agents, `<issuer>/<local name>`. Java binds only
/// a certified card to its issuer (through the certificate); a peer-signed card naming another
/// peer's agent is admitted by Java's `AdCache` and refused here. Every card below is built and
/// signed in the test by the key its `issuer` derives from, so only the agent binding refuses.
#[test]
fn a_card_naming_another_peers_agent_is_refused() {
    let honest = identity();
    let forger = forger();
    assert_ne!(honest.peer_id(), forger.peer_id());
    let now = millis("2026-01-01T00:01:00Z");
    let verify = |card: &Map, signer: &Identity| {
        verify_stored_ad(
            &Value::Map(stored_ad(AD_TYPE_AGENT_CARD, card, signer)),
            now,
        )
    };

    // The honest golden card (Java's bytes) names the golden peer's own `python`.
    let honest_card = golden_card("2026-01-01T00:00:00Z", None, &golden_actions(), None, None)
        .expect("the honest card");
    assert_eq!(
        honest_card.get("agent").and_then(Value::as_str),
        Some(honest.agent("python").as_str())
    );
    let (_, admitted, issuer) = verify(&honest_card, &honest).expect("the honest card");
    assert_eq!(issuer, honest.peer_id());
    assert_eq!(admitted, honest_card);
    assert!(
        verify_stored_ad(&cbor::decode(&hex("signed_agent_card_cbor")).unwrap(), now).is_some(),
        "Java's stored card"
    );

    // The forger's card for its own `python` (same local name, its own PeerID) is admitted.
    let own = forger_card("2026-01-01T00:00:30Z", "python");
    assert_eq!(
        own.get("agent").and_then(Value::as_str),
        Some(forger.agent("python").as_str())
    );
    assert!(verify(&own, &forger).is_some(), "the forger's own agent");

    // The forger's card naming the honest peer's agent, under the honest card's id and issued
    // later: refused, whatever else it carries.
    let mut impostor = own.clone();
    impostor.insert("agent", honest.agent("python"));
    assert_eq!(verify(&impostor, &forger), None, "another peer's agent");
    impostor.insert("id", honest_card.get("id").cloned().unwrap());
    assert_eq!(verify(&impostor, &forger), None, "and the honest id");

    // The honest certified card's agent, key, and certificate, re-issued under the forger's
    // PeerID and signed by it: refused (the binding, and the certificate under the wrong key).
    let certified = golden_card(
        s("certificate_verify_at"),
        Some(&agent_key()),
        &golden_actions(),
        Some(&golden_certificate()),
        None,
    )
    .unwrap();
    let verify_at = millis(s("certificate_verify_at"));
    assert!(
        verify_stored_ad(
            &Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &certified, &honest)),
            verify_at + 60_000,
        )
        .is_some()
    );
    let mut lifted = certified;
    lifted.insert("issuer", forger.peer_id());
    assert_eq!(
        verify_stored_ad(
            &Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &lifted, &forger)),
            verify_at + 60_000,
        ),
        None,
        "a lifted certified card"
    );

    // Agents that are not `<issuer>/<local name>`, on cards the honest issuer signs itself.
    let peer = honest.peer_id();
    let forged_peer = forger.peer_id();
    let refused: [(&str, Value); 12] = [
        (
            "an agent under a PeerID it prefixes",
            Value::from(format!("{peer}x/python")),
        ),
        ("an agent under a prefix of its PeerID", {
            let short = &peer[..peer.len() - 1];
            Value::from(format!("{short}/python"))
        }),
        (
            "another peer's agent",
            Value::from(format!("{forged_peer}/python")),
        ),
        ("an empty local name", Value::from(format!("{peer}/"))),
        ("a nested local name", Value::from(format!("{peer}/a/b"))),
        ("a doubled slash", Value::from(format!("{peer}//python"))),
        ("no peer", Value::from("/python")),
        ("no slash", Value::from(peer)),
        ("the empty agent", Value::from("")),
        ("a number", Value::from(7)),
        ("null", Value::Null),
        ("bytes", Value::from(peer.as_bytes().to_vec())),
    ];
    for (why, agent) in refused {
        let mut card = honest_card.clone();
        card.insert("agent", agent);
        assert_eq!(verify(&card, &honest), None, "{why}");
    }
    let mut agentless = honest_card.clone();
    agentless.remove("agent");
    assert_eq!(verify(&agentless, &honest), None, "no agent");

    // Any local name Java's AgentId admits, under the issuer's own PeerID, is admitted.
    for local in ["a", "a.b-c_d", "é", "worker 1"] {
        let mut card = honest_card.clone();
        card.insert("agent", honest.agent(local));
        assert!(verify(&card, &honest).is_some(), "{local}");
    }

    // The binding applies to agent cards only: other advertisements carry no agent.
    let space = space_advertisement(
        s("group_id"),
        peer,
        "tasks",
        "2026-01-01T00:00:00Z",
        "PT15M",
        &[TASK],
        "LEASE_RACE",
        "GROUP",
        "TAG_SHARDED",
    );
    assert!(
        verify_stored_ad(&Value::Map(stored_ad(AD_TYPE_SPACE, &space, &honest)), now).is_some()
    );
}

// ---------------------------------------------------------------------------------------------
// The AppCard revision (SPEC v0.1.32, §6.1a.2 to §6.1a.6)

/// The text list a card field holds.
fn texts_of(card: &Map, field: &str) -> Vec<String> {
    card.get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_app_card_with_an_origin_and_formats_matches_java() {
    let golden = map_of(&hex("app_card_origin_formats_cbor"));
    let java_origin = golden.get("origin").and_then(Value::as_map).unwrap();
    let attrs = java_origin.get("attrs").and_then(Value::as_map).unwrap();
    // Built in another order, the attributes are written in canonical order.
    let mut shuffled = Map::new();
    for (key, value) in attrs.iter().rev() {
        shuffled.insert(key.clone(), value.clone());
    }
    let origin = app_card_origin(
        "realm",
        "example-realm/example-app",
        "1.0.0",
        Some(&shuffled),
    )
    .unwrap();
    assert_eq!(&origin, java_origin);
    let card = AppCard {
        id: "aspace://zApps/app/zPeerA/example-app",
        issuer: "zPeerA",
        group: "zApps",
        issued: "2026-11-09T09:00:00Z",
        ttl: "PT15M",
        name: "example-app",
        kind: "fed",
        shape: "static",
        owner: "example-realm",
        url: "app://example-realm/example-app",
        origin: Some(&origin),
        // A media type is lower-cased and a repeat dropped, as Java's withFormats does.
        formats: &[
            "text/html",
            "Application/Geo+JSON",
            "urn:realm:example-realm#",
            "text/html",
        ],
        ..AppCard::default()
    }
    .to_map()
    .unwrap();
    assert_eq!(bytes_of(&card), hex("app_card_origin_formats_cbor"));
    assert!(schema::decode(&hex("app_card_origin_formats_cbor"), AD_TYPE_APP_CARD).is_some());
    // An origin without attributes omits them, and an empty map is no attributes.
    let bare = app_card_origin("console", "c/b", "", Some(&Map::new())).unwrap();
    assert!(!bare.contains_key("attrs"));
    // The grammar and the bounds of SPEC §6.1a.2.
    for (system, reference, version) in [
        ("Realm", "r", ""),
        ("realm.", "r", ""),
        ("realm", "", ""),
        ("realm", "a\u{1}b", ""),
        ("realm", &"r".repeat(257), ""),
        ("realm", "r", &"v".repeat(65)),
    ] {
        assert!(
            matches!(
                app_card_origin(system, reference, version, None),
                Err(AdError::InvalidOrigin(_))
            ),
            "{system} {reference:?} {version:?}"
        );
    }
    let mut foreign = Map::new();
    foreign.insert("console.x", "y");
    assert!(app_card_origin("realm", "r", "", Some(&foreign)).is_err());
    // Formats outside their grammar are refused when the card is built.
    for bad in [&["text/html;charset=utf-8"][..], &["x y:z"], &["1x:y"]] {
        let built = AppCard {
            name: "x",
            formats: bad,
            ..AppCard::default()
        }
        .to_map();
        assert!(matches!(built, Err(AdError::InvalidFormats(_))), "{bad:?}");
    }
}

#[test]
fn the_app_card_kind_is_closed_to_four_values() {
    for kind in ["peer", "fed", "gateway", "assembled"] {
        let card = AppCard {
            name: "x",
            kind,
            ..AppCard::default()
        };
        assert!(card.to_map().is_ok(), "{kind}");
    }
    let realm = AppCard {
        name: "x",
        kind: "realm",
        ..AppCard::default()
    };
    assert_eq!(realm.to_map(), Err(AdError::InvalidAppKind("realm".into())));
}

/// The stub and its parts document of a card kind, decoded.
fn stub_and_parts(stub: &str, parts: &str) -> (Map, Vec<u8>) {
    (map_of(&hex(stub)), hex(parts))
}

#[test]
fn the_spilled_cards_and_their_parts_documents_match_java() {
    assert_eq!(
        common::golden()["card_spill_threshold_bytes"].as_u64(),
        u64::try_from(CARD_SPILL_THRESHOLD_BYTES).ok()
    );
    assert_eq!(
        common::golden()["card_spill_warn_bytes"].as_u64(),
        u64::try_from(CARD_SPILL_WARN_BYTES).ok()
    );
    for (ad_type, stub_name, parts_name, parts_record) in [
        (
            AD_TYPE_APP_CARD,
            "app_card_spill_cbor",
            "app_card_parts_cbor",
            "AppCard.Parts",
        ),
        (
            AD_TYPE_AGENT_CARD,
            "agent_card_spill_cbor",
            "agent_card_parts_cbor",
            "AgentCard.Parts",
        ),
    ] {
        let (stub, document) = stub_and_parts(stub_name, parts_name);
        assert!(
            schema::decode(&hex(stub_name), ad_type).is_some(),
            "{stub_name}"
        );
        assert!(
            schema::decode(&document, parts_record).is_some(),
            "{parts_name}"
        );
        // The reference names exactly the document: its content root over 65,536-byte pieces
        // and its length.
        let (root, size, parts) = spill_of(ad_type, &stub).unwrap();
        assert_eq!(content_root(&document), root, "{stub_name}");
        assert_eq!(size, u64::try_from(document.len()).unwrap());
        let spill = card_spill(root, size, &parts).unwrap();
        assert_eq!(stub.get("spill"), Some(&Value::Map(spill)));
        // The reader completes the stub; spilling the full card gives back both vectors.
        let full = resolve_spill(ad_type, &stub, &document, SPILL_MAX_FETCH_BYTES).unwrap();
        assert!(!full.contains_key("spill"));
        assert!(schema::conforms(&Value::Map(full.clone()), ad_type));
        let (parts_map, names) = card_parts(ad_type, &full).unwrap();
        assert_eq!(names, parts);
        assert_eq!(bytes_of(&parts_map), document);
        let (respilled, redocument) = spill_card(ad_type, &full).unwrap();
        assert_eq!(bytes_of(&respilled), hex(stub_name), "{stub_name}");
        assert_eq!(redocument, document);
        // A document that fails a check fails the resolution, and the stub stays as it is.
        let mut longer = document.clone();
        longer.push(0);
        assert!(matches!(
            resolve_spill(ad_type, &stub, &longer, SPILL_MAX_FETCH_BYTES),
            Err(SpillError::Size { .. })
        ));
        let mut flipped = document.clone();
        let last = flipped.len() - 2;
        flipped[last] ^= 1;
        assert_eq!(
            resolve_spill(ad_type, &stub, &flipped, SPILL_MAX_FETCH_BYTES),
            Err(SpillError::Root)
        );
        assert!(matches!(
            resolve_spill(ad_type, &stub, &document, size - 1),
            Err(SpillError::OverLimit { .. })
        ));
        assert_eq!(
            resolve_spill(ad_type, &full, &document, SPILL_MAX_FETCH_BYTES),
            Err(SpillError::NotAStub)
        );
    }
    // The app card's parts: its lists and its ui, its actions empty and so not named.
    let parts = map_of(&hex("app_card_parts_cbor"));
    assert_eq!(texts_of(&parts, "views"), ["board", "items", "orders"]);
    let stub = map_of(&hex("app_card_spill_cbor"));
    assert_eq!(texts_of(&stub, "reads"), Vec::<String>::new());
    assert!(!stub.contains_key("ui"));
    // The agent card's stub keeps every field but its actions and ui.
    let agent_stub = map_of(&hex("agent_card_spill_cbor"));
    assert!(!agent_stub.contains_key("actions") && !agent_stub.contains_key("ui"));
    assert!(schema::decode(&hex("agent_card_parts_cbor"), "AgentCard.Parts").is_some());
}

#[test]
fn a_content_root_is_the_cid_of_its_piece_table() {
    // Java's GoldenVectors: three pieces, 65,536 bytes of 0x01, 65,536 of 0x02, 100 of 0x03.
    let mut artifact = vec![1u8; 65_536];
    artifact.extend(vec![2u8; 65_536]);
    artifact.extend(vec![3u8; 100]);
    assert_eq!(content_root(&artifact), s("content_root_cidv1"));
    assert!(schema::is_content_root(s("content_root_cidv1")));
    assert!(!schema::is_content_root(&s("content_root_cidv1")[..58]));
    // A dag-cbor root is no content root of a card spill.
    assert!(!schema::is_content_root(
        "bafyreibhxghlalnhvgu4tpiiqpiwfew7jddr5jr6rtfqga6cp6772wnzsm"
    ));
}

#[test]
fn the_app_card_level_gates_the_new_fields() {
    assert_eq!(HINT_APP_CARD, "wire.appcard");
    for (hint, level) in [
        (None, 1),
        (Some(""), 1),
        (Some("0"), 1),
        (Some("1"), 1),
        (Some("2"), 2),
        (Some("02"), 1),
        (Some("10"), 10),
        (Some("2.0"), 1),
        (Some("+2"), 1),
        (Some("99999999999"), i32::MAX),
    ] {
        assert_eq!(app_card_level(hint), level, "{hint:?}");
    }
    // Below the level, an issuer drops origin, formats, an idp host, and spill.
    let full = map_of(&hex("app_card_origin_formats_cbor"));
    let (plain, downgraded) = app_card_at_level(AD_TYPE_APP_CARD, &full);
    assert!(downgraded);
    assert!(!plain.contains_key("origin") && !plain.contains_key("formats"));
    assert!(schema::conforms(&Value::Map(plain), AD_TYPE_APP_CARD));
    let hosted = map_of(&hex("app_card_host_cbor"));
    let (unhosted, downgraded) = app_card_at_level(AD_TYPE_APP_CARD, &hosted);
    assert!(downgraded && !unhosted.contains_key("host"));
    let mut open_host = hosted.clone();
    open_host
        .get_mut("host")
        .and_then(Value::as_map_mut)
        .unwrap()
        .insert("signOn", "none");
    let (kept, downgraded) = app_card_at_level(AD_TYPE_APP_CARD, &open_host);
    assert!(
        !downgraded && kept == open_host,
        "a host with no sign-on passes the gate"
    );
    let card = map_of(&hex("agent_card_cbor"));
    assert_eq!(app_card_at_level(AD_TYPE_AGENT_CARD, &card), (card, false));
}

#[test]
fn a_content_store_advertises_itself_by_an_asset_card() {
    let bytes = hex("asset_card_content_store_cbor");
    let card = schema::decode_map(&bytes, AD_TYPE_ASSET_CARD).expect("an AssetCard");
    let store = content_store_of(&card).expect("a content store");
    assert_eq!(store.name, "site-a");
    assert_eq!(store.uri, "aspace://zGolden/store/site-a");
    assert_eq!(store.holding_interval, "PT10S");
    assert_eq!(store.capacity, Some(2_199_023_255_552));
    assert_eq!(store.free, Some(2_145_336_164_352));
    assert_eq!(store.max_object, Some(68_719_476_736));
    assert_eq!(store.codecs, ["dag-cbor", "raw"]);
    assert_eq!(store.sealing, ["none", "sealed-nodes"]);
    assert!(!store.blind && store.challenge);
    assert_eq!(
        (store.policy.as_str(), store.tier.as_str()),
        ("grant", "hot")
    );
    assert_eq!(store.waiting, None);
    assert_eq!(store.price_per_gib_month.as_deref(), Some("2"));
    // Any other asset card is no content store.
    let mut other = card.clone();
    other
        .get_mut("access")
        .and_then(Value::as_map_mut)
        .unwrap()
        .insert("kind", "content-collection");
    assert_eq!(content_store_of(&other), None);
}

#[test]
fn a_stored_card_meets_its_value_rules_at_the_cache() {
    // A peer-signed AppCard is held only when it decodes under SPEC §6.1a.2 to §6.1a.5.
    let identity = identity();
    let now = millis("2026-11-09T09:01:00Z");
    let mut card = map_of(&hex("app_card_origin_formats_cbor"));
    card.insert("issuer", identity.peer_id());
    let stored = |card: &Map| Value::Map(stored_ad(AD_TYPE_APP_CARD, card, &identity));
    assert!(verify_stored_ad(&stored(&card), now).is_some());
    let mut realm = card.clone();
    realm.insert("kind", "realm");
    assert_eq!(verify_stored_ad(&stored(&realm), now), None);
    let mut extra = card.clone();
    extra.insert("future", "field");
    assert_eq!(
        verify_stored_ad(&stored(&extra), now),
        None,
        "P1: an unknown field"
    );
}
