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

//! Advertisements (SPEC §5.1, §5.2, §6.1, §6.2), a port of `wire.py`'s `peer_advertisement`,
//! `stored_ad`, `signed_peer_ad`, `agent_card`, `card_action`, `ui_declaration`, `ui_component`,
//! and `app_card_host`, the TypeScript client's `spaceAdvertisement`, the checks of
//! `Peer.accept_ad` and `Peer._accept_peer_ad`, and the Java `AppCard` record. Java's records
//! are the authority on bytes: every builder writes its map in the record's field order, a field
//! the record omits when absent is omitted here too (so older cards keep their bytes), and a
//! map-valued field a signature covers (`resourceHints`, `costHints`, `spaceBindings`) is put in
//! canonical order.
//!
//! An advertisement travels signed in one of two wrappers:
//!
//! - on the `peers` stream, `PeerNode.SignedPeerAd` `{adBytes, publicKey, signature}`
//!   ([`signed_peer_ad`], judged by [`verify_signed_peer_ad`]);
//! - on the `ads` stream and in query answers, `AdCache.StoredAd`
//!   `{adType, adBytes, publicKey, signature}` ([`stored_ad`], judged by [`verify_stored_ad`]).
//!
//! In both the signature covers `adBytes`, the advertisement's CBOR, and the advertisement's
//! `issuer` must be the PeerID the carried key hashes to. A stored `AgentCard` must also name
//! one of its issuer's own agents, `<issuer>/<local name>` (stricter than Java; see
//! [`verify_stored_ad`]).
#![warn(missing_docs)]

use crate::cbor::{self, Map, Value};
use crate::crypto::KEY_LENGTH;
use crate::identity::{Identity, verify_agent_certificate_at};
use crate::ids;
use crate::time;
use crate::util::{encode_map, present};

// ---------------------------------------------------------------------------------------------
// Types and bounds

/// The type tag of a `PeerAdvertisement`.
pub const AD_TYPE_PEER: &str = "PeerAdvertisement";
/// The type tag of a `GroupAdvertisement`.
pub const AD_TYPE_GROUP: &str = "GroupAdvertisement";
/// The type tag of a `SpaceAdvertisement` ([`space_advertisement`]).
pub const AD_TYPE_SPACE: &str = "SpaceAdvertisement";
/// The type tag of a `CapabilityAdvertisement`.
pub const AD_TYPE_CAPABILITY: &str = "CapabilityAdvertisement";
/// The type tag of an `AgentCard` ([`agent_card`]).
pub const AD_TYPE_AGENT_CARD: &str = "AgentCard";
/// The type tag of an `AssetCard`.
pub const AD_TYPE_ASSET_CARD: &str = "AssetCard";
/// The type tag of a `ModelCard`.
pub const AD_TYPE_MODEL_CARD: &str = "ModelCard";
/// The type tag of an `AppCard` ([`AppCard`]).
pub const AD_TYPE_APP_CARD: &str = "AppCard";

/// The type tags a stored advertisement may carry (`AdCache.AD_TYPES`); [`verify_stored_ad`]
/// refuses any other.
pub const AD_TYPES: [&str; 8] = [
    AD_TYPE_PEER,
    AD_TYPE_GROUP,
    AD_TYPE_SPACE,
    AD_TYPE_CAPABILITY,
    AD_TYPE_AGENT_CARD,
    AD_TYPE_ASSET_CARD,
    AD_TYPE_MODEL_CARD,
    AD_TYPE_APP_CARD,
];

/// How far ahead of the receiver's clock a stored advertisement's `issued` may run (Java
/// `AdCache.MAX_ISSUED_SKEW`): 10 minutes.
pub const MAX_AD_ISSUED_SKEW_MILLIS: i64 = 10 * 60 * 1000;

/// The longest TTL a stored advertisement may claim (Java `AdCache.MAX_TTL`): 30 days.
pub const MAX_AD_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

/// The TTL of a peer's self-advertisement ([`peer_advertisement`]): 10 minutes.
pub const PEER_AD_TTL: &str = "PT10M";

/// Why an advertisement could not be built: the refusals of `wire.py`'s builders, and of the
/// Java `AppCard` record where `wire.py` has no builder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdError {
    /// A card's certificate does not certify the card's agent and `agentPublicKey` (or the card
    /// carries a certificate but no `agentPublicKey`).
    #[error("a card's certificate must certify its agent and agentPublicKey")]
    CertificateMismatch,
    /// A host names no url.
    #[error("a host has a url")]
    EmptyUrl,
    /// A host's `signOn` is not one of [`HOST_SIGN_ONS`].
    #[error("a host's signOn is tenant or none: {0:?}")]
    InvalidSignOn(String),
    /// A host's `status` is not one of [`HOST_STATUSES`].
    #[error("a host's status is serving or stopped: {0:?}")]
    InvalidStatus(String),
    /// A ui component's `role` is not one of [`UI_ROLES`].
    #[error("a ui component's role is one of panel, control, row: {0:?}")]
    InvalidRole(String),
    /// An app card names no app.
    #[error("an AppCard needs a name")]
    EmptyName,
    /// An app card's `kind` is not one of [`APP_KINDS`].
    #[error("an AppCard's kind must be one of {APP_KINDS:?}: {0:?}")]
    InvalidAppKind(String),
    /// An app card's `shape` is not one of [`APP_SHAPES`].
    #[error("an AppCard's shape must be one of {APP_SHAPES:?}: {0:?}")]
    InvalidAppShape(String),
    /// An app card's ui `transport` is not one of [`APP_TRANSPORTS`].
    #[error("an AppCard's ui transport must be one of {APP_TRANSPORTS:?}: {0:?}")]
    InvalidTransport(String),
    /// An `a2ui` app card names no surfaces.
    #[error("an a2ui app names its surfaces in ui")]
    MissingUi,
    /// A list carries more terms than its record allows.
    #[error("{field} carries at most {limit} terms")]
    TooManyTerms {
        /// The list.
        field: &'static str,
        /// Its bound.
        limit: usize,
    },
}

// ---------------------------------------------------------------------------------------------
// Peer advertisements

/// A `PeerAdvertisement` with no endpoints and no roles, the dial-only NAT posture, living
/// [`PEER_AD_TTL`]: `id` (`aspace://<group>/peer/<peerId>`), `issuer`, `group`, `issued`, `ttl`,
/// `endpoints`, `roles`, `resourceHints`.
///
/// `resource_hints` (text to text) is where a join credential (`aspace:join`), a relay path
/// (`relay.via`), or a wire mode (`wire.session`) travels; it is written in canonical order, and
/// an entry whose key or value is not text is skipped (Java's `Map<String, String>` cannot carry
/// it). Set endpoints with `Map::insert("endpoints", ...)` and [`endpoint`]: the key keeps its
/// position.
pub fn peer_advertisement(
    group: &str,
    identity: &Identity,
    issued_iso: &str,
    resource_hints: Option<&Map>,
) -> Map {
    peer_advertisement_with_ttl(group, identity, issued_iso, PEER_AD_TTL, resource_hints)
}

/// [`peer_advertisement`] with an explicit TTL (`wire.py`'s `ttl_iso`).
pub fn peer_advertisement_with_ttl(
    group: &str,
    identity: &Identity,
    issued_iso: &str,
    ttl_iso: &str,
    resource_hints: Option<&Map>,
) -> Map {
    let hints: Map = resource_hints
        .into_iter()
        .flatten()
        .filter(|(key, value)| key.as_str().is_some() && value.as_str().is_some())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let peer_id = identity.peer_id();
    let mut ad = Map::with_capacity(8);
    ad.insert("id", format!("{}{group}/peer/{peer_id}", ids::URI_PREFIX));
    ad.insert("issuer", peer_id);
    ad.insert("group", group);
    ad.insert("issued", issued_iso);
    ad.insert("ttl", ttl_iso);
    ad.insert("endpoints", Vec::<Value>::new());
    ad.insert("roles", Vec::<Value>::new());
    ad.insert("resourceHints", cbor::canonical_map(&hints));
    ad
}

/// One `PeerAdvertisement.Endpoint` `{transport, address, priority}`: a way of reaching a peer,
/// lower priorities dialed first.
pub fn endpoint(transport: &str, address: &str, priority: i32) -> Map {
    let mut endpoint = Map::with_capacity(3);
    endpoint.insert("transport", transport);
    endpoint.insert("address", address);
    endpoint.insert("priority", priority);
    endpoint
}

/// The `peers` stream payload, `PeerNode.SignedPeerAd` `{adBytes, publicKey, signature}`: the
/// advertisement's CBOR, the issuer's raw key, and its signature over those bytes.
pub fn signed_peer_ad(ad: &Map, identity: &Identity) -> Vec<u8> {
    encode_map(&signed_wrapper(None, ad, identity))
}

/// `Peer._accept_peer_ad`: the advertisement a `peers` stream payload carries and its issuer,
/// when the payload is a map whose 32-byte `publicKey` verifies the `signature` over `adBytes`,
/// and those bytes decode to a map whose `issuer` is the PeerID the key hashes to. `None`
/// otherwise; never panics. The advertisement's lifetime is not judged (the caller keeps it
/// under its issuer until a newer one replaces it).
pub fn verify_signed_peer_ad(payload: &[u8]) -> Option<(Map, String)> {
    let signed = cbor::decode(payload).ok()?;
    let (ad, issuer) = verified_ad(signed.as_map()?)?;
    Some((ad, issuer))
}

// ---------------------------------------------------------------------------------------------
// Stored advertisements

/// `AdCache.StoredAd`, the `ads` stream payload (SPEC §6.2): `{adType, adBytes, publicKey,
/// signature}`, the type tag ([`AD_TYPES`]), the advertisement's CBOR, the issuer's raw key,
/// and the issuer's signature over those bytes.
pub fn stored_ad(ad_type: &str, ad: &Map, identity: &Identity) -> Map {
    signed_wrapper(Some(ad_type), ad, identity)
}

/// `AdCache.accept`: the type tag, advertisement, and issuer of a stored advertisement admitted
/// at `now_ms` on the receiver's clock, or `None`. The checks, every one of which must pass:
///
/// - `stored` is a map with a text `adType` among [`AD_TYPES`], byte `adBytes`, a 32-byte
///   `publicKey`, and a byte `signature` that verifies over `adBytes` under that key;
/// - `adBytes` decode to a map whose `issuer` is the PeerID the key hashes to;
/// - its `issued` and `ttl` parse, it has not expired (`now_ms < issued + ttl`), its `issued`
///   leads `now_ms` by at most [`MAX_AD_ISSUED_SKEW_MILLIS`], and its `ttl` is at most
///   [`MAX_AD_TTL_MILLIS`];
/// - an `AgentCard` names one of its issuer's own agents: its `agent` is text of the form
///   `<issuer PeerID>/<local name>`, a non-empty local name without `/`, as
///   [`ids::parse_agent_id`] (Java `AgentId.parse`) accepts it, with the peer part equal to the
///   issuer. A peer-signed card is otherwise bound to nothing, and any admitted member could
///   publish a card naming another peer's agent (its actions, its key, its bindings);
/// - an `AgentCard` carrying an `agentCertificate` proves it: the certificate verifies under the
///   card issuer's key for the card's `agent`, judged at the card's `issued`
///   ([`verify_agent_certificate_at`]), and certifies the card's own `agentPublicKey`, which
///   must be present and byte-equal to the certificate's (Java's `AgentCard` constructor refuses
///   a card whose key the certificate never certified, so a consumer may treat the card's key as
///   the certified one, as Java's revocation check of a card does).
///
/// The agent binding is stricter than Java: `AdCache.accept` refuses a card whose `agent` does
/// not parse as an `AgentId` (Jackson's decode throws) but admits a peer-signed card naming an
/// agent under another PeerID. Every Java publisher names its own agents (`AgentBinder`,
/// `EmbabelBinder`, and the examples build `identity.agent(name)` under the signing peer), so
/// nothing Java sends is refused here.
///
/// What needs state stays with the caller: the revocation registry, the cache bound, and
/// last-writer-wins by `issued` per issuer and advertisement `id`. Never panics.
pub fn verify_stored_ad(stored: &Value, now_ms: i64) -> Option<(String, Map, String)> {
    let stored = stored.as_map()?;
    let ad_type = stored.get("adType")?.as_str()?;
    if !AD_TYPES.contains(&ad_type) {
        return None;
    }
    let (ad, issuer) = verified_ad(stored)?;
    let issued_ms = time::parse_instant_millis(ad.get("issued")?.as_str()?).ok()?;
    let ttl_ms = time::parse_duration_millis(ad.get("ttl")?.as_str()?).ok()?;
    let (now, issued, ttl) = (
        i128::from(now_ms),
        i128::from(issued_ms),
        i128::from(ttl_ms),
    );
    if now >= issued + ttl
        || issued > now + i128::from(MAX_AD_ISSUED_SKEW_MILLIS)
        || ttl > i128::from(MAX_AD_TTL_MILLIS)
    {
        return None;
    }
    if ad_type == AD_TYPE_AGENT_CARD && !names_own_agent(&ad, &issuer) {
        return None;
    }
    if ad_type == AD_TYPE_AGENT_CARD
        && let Some(certificate) = present(&ad, "agentCertificate")
    {
        let agent = ad.get("agent")?.as_str()?;
        let key = stored.get("publicKey")?.as_bytes()?;
        // Java's AgentCard constructor: a card's certificate certifies exactly its agent and its
        // agentPublicKey, which must therefore be present. The agent binding is
        // verify_agent_certificate's.
        let card_key = present(&ad, "agentPublicKey")?.as_bytes()?;
        let certified = certificate.get("agentPublicKey")?.as_bytes()?;
        if card_key != certified
            || !verify_agent_certificate_at(certificate, key, agent, issued_ms, now_ms)
        {
            return None;
        }
    }
    Some((ad_type.to_owned(), ad, issuer))
}

/// When an advertisement expires, `issued + ttl` in epoch milliseconds (the first instant it is
/// expired), or `None` when either does not parse or the sum leaves the `i64` range.
pub fn ad_expires_at_millis(ad: &Map) -> Option<i64> {
    let issued = time::parse_instant_millis(ad.get("issued")?.as_str()?).ok()?;
    let ttl = time::parse_duration_millis(ad.get("ttl")?.as_str()?).ok()?;
    issued.checked_add(ttl)
}

/// `{adType?, adBytes, publicKey, signature}` over the advertisement's CBOR.
fn signed_wrapper(ad_type: Option<&str>, ad: &Map, identity: &Identity) -> Map {
    let ad_bytes = encode_map(ad);
    let signature = identity.sign(&ad_bytes);
    let mut signed = Map::with_capacity(4);
    if let Some(ad_type) = ad_type {
        signed.insert("adType", ad_type);
    }
    signed.insert("adBytes", ad_bytes);
    signed.insert("publicKey", identity.public_raw());
    signed.insert("signature", signature);
    signed
}

/// The shared signature and issuer checks of both wrappers.
fn verified_ad(signed: &Map) -> Option<(Map, String)> {
    let ad_bytes = signed.get("adBytes")?.as_bytes()?;
    let key = signed
        .get("publicKey")?
        .as_bytes()
        .filter(|key| key.len() == KEY_LENGTH)?;
    let signature = signed.get("signature")?.as_bytes()?;
    if !Identity::verify(key, ad_bytes, signature) {
        return None;
    }
    let ad = cbor::decode(ad_bytes).ok()?.into_map()?;
    let issuer = ids::derive_id(key);
    (ad.get("issuer").and_then(Value::as_str) == Some(issuer.as_str())).then_some((ad, issuer))
}

/// Whether a card's `agent` is one of `issuer`'s own: `<issuer>/<local name>` as
/// [`ids::parse_agent_id`] accepts it. False for a missing or non-text `agent`, an agent id
/// Java's `AgentId.parse` refuses, and an agent under another PeerID.
fn names_own_agent(card: &Map, issuer: &str) -> bool {
    card.get("agent")
        .and_then(Value::as_str)
        .and_then(ids::parse_agent_id)
        .is_some_and(|(peer, _)| peer == issuer)
}

// ---------------------------------------------------------------------------------------------
// Agent cards

/// An `AgentCard` (SPEC §6.1) in Java field order: `id` (`aspace://<group>/agent/<agentId>`),
/// `issuer`, `group`, `issued`, `ttl`, `agent` (`<peerId>/<local_name>`), `description`,
/// `goals`, `consumes`, `produces`, `costHints`, `spaceBindings` (both canonical), then the
/// appended `agentPublicKey` (v0.1.11), `actions` (v0.1.13, [`card_action`]),
/// `agentCertificate` (v0.1.13), and `ui` (v0.1.26, [`ui_declaration`]), each omitted when absent
/// (`actions` when empty) so earlier cards keep their bytes.
///
/// A certificate must certify `agent_public_raw` for this card's agent
/// ([`AdError::CertificateMismatch`]).
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors wire.py's agent_card and the Java AgentCard record field for field"
)]
pub fn agent_card(
    group: &str,
    identity: &Identity,
    local_name: &str,
    issued_iso: &str,
    ttl_iso: &str,
    description: &str,
    goals: &[&str],
    consumes: &[&str],
    produces: &[&str],
    cost_hints: &Map,
    space_bindings: &Map,
    agent_public_raw: Option<&[u8; KEY_LENGTH]>,
    actions: &[Map],
    agent_certificate: Option<&Map>,
    ui: Option<&Map>,
) -> Result<Map, AdError> {
    let agent = identity.agent(local_name);
    if let Some(certificate) = agent_certificate {
        let certifies_key = agent_public_raw.is_some_and(|key| {
            certificate.get("agentPublicKey").and_then(Value::as_bytes) == Some(key.as_slice())
        });
        let certifies_agent =
            certificate.get("agent").and_then(Value::as_str) == Some(agent.as_str());
        if !certifies_key || !certifies_agent {
            return Err(AdError::CertificateMismatch);
        }
    }
    let mut card = Map::with_capacity(16);
    card.insert("id", format!("{}{group}/agent/{agent}", ids::URI_PREFIX));
    card.insert("issuer", identity.peer_id());
    card.insert("group", group);
    card.insert("issued", issued_iso);
    card.insert("ttl", ttl_iso);
    card.insert("agent", agent);
    card.insert("description", description);
    card.insert("goals", text_list(goals));
    card.insert("consumes", text_list(consumes));
    card.insert("produces", text_list(produces));
    card.insert("costHints", cbor::canonical_map(cost_hints));
    card.insert("spaceBindings", cbor::canonical_map(space_bindings));
    if let Some(key) = agent_public_raw {
        card.insert("agentPublicKey", key);
    }
    if !actions.is_empty() {
        card.insert("actions", maps(actions));
    }
    if let Some(certificate) = agent_certificate {
        card.insert("agentCertificate", certificate.clone());
    }
    if let Some(ui) = ui {
        card.insert("ui", ui.clone());
    }
    Ok(card)
}

/// A `@SpaceTake` worker action.
pub const ACTION_TAKE: &str = "take";
/// A `@SpaceNotify` reaction.
pub const ACTION_NOTIFY: &str = "notify";
/// An `@OrderedTake` exactly-once worker.
pub const ACTION_ORDERED_TAKE: &str = "ordered-take";
/// A `@Ballot` voter.
pub const ACTION_BALLOT: &str = "ballot";
/// An `@OnDecision` reaction to a closed vote.
pub const ACTION_ON_DECISION: &str = "on-decision";
/// An Embabel `@Action`.
pub const ACTION_EMBABEL: &str = "embabel-action";
/// A `@SpaceJoin` fan-in, never invocable by one entry.
pub const ACTION_JOIN: &str = "join";
/// A `@Propose` lead, never invocable.
pub const ACTION_PROPOSE: &str = "propose";
/// An `@OnEstimate` reaction, never invocable.
pub const ACTION_ON_ESTIMATE: &str = "on-estimate";
/// A `@SpaceReduce` fold, never invocable.
pub const ACTION_REDUCE: &str = "reduce";
/// The action kinds a remote caller invokes by writing the consumed entry
/// (`CardAction.INVOCABLE`).
pub const INVOCABLE_ACTIONS: [&str; 4] = [
    ACTION_TAKE,
    ACTION_NOTIFY,
    ACTION_ORDERED_TAKE,
    ACTION_EMBABEL,
];

/// A `CardAction` (SPEC §6.1, v0.1.13) in Java field order: `name`, `description`, `consumes`,
/// `produces`, `space` (omitted when `None`), `kind` (one of the `ACTION_*` kinds; an unknown
/// kind is carried, and reads as not invocable).
pub fn card_action(
    name: &str,
    description: &str,
    consumes: &[&str],
    produces: &[&str],
    kind: &str,
    space: Option<&str>,
) -> Map {
    let mut action = Map::with_capacity(6);
    action.insert("name", name);
    action.insert("description", description);
    action.insert("consumes", text_list(consumes));
    action.insert("produces", text_list(produces));
    if let Some(space) = space {
        action.insert("space", space);
    }
    action.insert("kind", kind);
    action
}

// ---------------------------------------------------------------------------------------------
// UI declarations

/// The UI protocol a declaration names by default.
pub const UI_PROTOCOL: &str = "a2ui";
/// The A2UI version a declaration names by default.
pub const UI_VERSION: &str = "v0.9.1";
/// The roles a ui component may have: a self-standing block, an input, one line in a list.
pub const UI_ROLES: [&str; 3] = ["panel", "control", "row"];

/// One component of a `UiDeclaration` (SPEC §6.1a.3) in Java field order: `id`, `catalogId`,
/// `component`, `entry` (the standard entry type IRI behind it, empty when none), `controls`
/// (the action names a person may trigger on it), `role` (one of [`UI_ROLES`], `"panel"` by
/// default in `wire.py`).
pub fn ui_component(
    id: &str,
    catalog_id: &str,
    component: &str,
    entry: &str,
    controls: &[&str],
    role: &str,
) -> Result<Map, AdError> {
    if !UI_ROLES.contains(&role) {
        return Err(AdError::InvalidRole(role.to_owned()));
    }
    let mut map = Map::with_capacity(6);
    map.insert("id", id);
    map.insert("catalogId", catalog_id);
    map.insert("component", component);
    map.insert("entry", entry);
    map.insert("controls", text_list(controls));
    map.insert("role", role);
    Ok(map)
}

/// A `UiDeclaration` (SPEC §6.1a.3) in Java field order: `protocol` ([`UI_PROTOCOL`] by
/// default), `version` ([`UI_VERSION`] by default), `components` ([`ui_component`]), `entries`
/// `{reads, writes}` (the entry type IRIs read and written through the components), and
/// `catalogIds`, the distinct text `catalogId`s of the components in first-seen order. Appended
/// to a card as `ui`.
pub fn ui_declaration(
    components: &[Map],
    reads: &[&str],
    writes: &[&str],
    protocol: &str,
    version: &str,
) -> Map {
    let mut catalog_ids: Vec<&str> = Vec::new();
    for catalog_id in components
        .iter()
        .filter_map(|c| c.get("catalogId").and_then(Value::as_str))
    {
        if !catalog_ids.contains(&catalog_id) {
            catalog_ids.push(catalog_id);
        }
    }
    let mut entries = Map::with_capacity(2);
    entries.insert("reads", text_list(reads));
    entries.insert("writes", text_list(writes));
    let mut declaration = Map::with_capacity(5);
    declaration.insert("protocol", protocol);
    declaration.insert("version", version);
    declaration.insert("components", maps(components));
    declaration.insert("entries", entries);
    declaration.insert("catalogIds", text_list(&catalog_ids));
    declaration
}

// ---------------------------------------------------------------------------------------------
// App cards

/// The kinds of app an `AppCard` advertises (`AppCard.KINDS`).
pub const APP_KINDS: [&str; 5] = ["peer", "fed", "gateway", "realm", "assembled"];
/// The shapes of app an `AppCard` advertises (`AppCard.SHAPES`).
pub const APP_SHAPES: [&str; 4] = ["web", "desktop", "static", "a2ui"];
/// The transports of an app card's surfaces (`AppCard.TRANSPORTS`).
pub const APP_TRANSPORTS: [&str; 2] = ["views", "a2a"];
/// The most terms an app card's lists carry (`AppCard.MAX_TERMS`).
pub const APP_MAX_TERMS: usize = 64;
/// The most components a ui carries (`UiDeclaration.MAX_COMPONENTS`).
pub const UI_MAX_COMPONENTS: usize = 32;
/// How a published app's host lets end users in: the tenant's identity provider, or no sign-on.
pub const HOST_SIGN_ONS: [&str; 2] = ["tenant", "none"];
/// Whether a published app's host serves it.
pub const HOST_STATUSES: [&str; 2] = ["serving", "stopped"];

/// The host group of a published `AppCard` (SPEC §6.1a.4, v0.1.28) in Java field order: `url`,
/// `port` (0 when the url says it all), `hostAgent`, `path` (`"/"` when empty), `signOn` (one of
/// [`HOST_SIGN_ONS`]), `publishedBy`, `publishedAt` (an ISO instant), `status` (one of
/// [`HOST_STATUSES`]). Appended last on the card ([`AppCard::host`]); a card without it keeps its
/// bytes. Refuses an empty url, an unknown sign-on, and an unknown status, as `wire.py` does.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors wire.py's app_card_host and the Java AppCard.Host record field for field"
)]
pub fn app_card_host(
    url: &str,
    port: u16,
    host_agent: &str,
    path: &str,
    sign_on: &str,
    published_by: &str,
    published_at_iso: &str,
    status: &str,
) -> Result<Map, AdError> {
    if url.is_empty() {
        return Err(AdError::EmptyUrl);
    }
    if !HOST_SIGN_ONS.contains(&sign_on) {
        return Err(AdError::InvalidSignOn(sign_on.to_owned()));
    }
    if !HOST_STATUSES.contains(&status) {
        return Err(AdError::InvalidStatus(status.to_owned()));
    }
    let mut host = Map::with_capacity(8);
    host.insert("url", url);
    host.insert("port", port);
    host.insert("hostAgent", host_agent);
    host.insert("path", if path.is_empty() { "/" } else { path });
    host.insert("signOn", sign_on);
    host.insert("publishedBy", published_by);
    host.insert("publishedAt", published_at_iso);
    host.insert("status", status);
    Ok(host)
}

/// The surfaces an app draws, `AppCard.Ui` in Java field order: `protocol` and `version` (blank
/// reads as [`UI_PROTOCOL`] and [`UI_VERSION`]), `catalogIds`, `agent` (the surface agent's
/// instance), `transport` (one of [`APP_TRANSPORTS`], blank reads as `"views"`), `surfaces`, and
/// `components` ([`ui_component`], omitted when empty, so a v0.1.25 ui keeps its bytes).
/// Refuses what the Java record refuses: an unknown transport, more than [`APP_MAX_TERMS`]
/// catalogs or surfaces, more than [`UI_MAX_COMPONENTS`] components.
pub fn app_card_ui(
    protocol: &str,
    version: &str,
    catalog_ids: &[&str],
    agent: &str,
    transport: &str,
    surfaces: &[&str],
    components: &[Map],
) -> Result<Map, AdError> {
    let transport = or_default(transport, "views");
    if !APP_TRANSPORTS.contains(&transport) {
        return Err(AdError::InvalidTransport(transport.to_owned()));
    }
    bounded("ui.catalogIds", catalog_ids.len(), APP_MAX_TERMS)?;
    bounded("ui.surfaces", surfaces.len(), APP_MAX_TERMS)?;
    bounded("ui.components", components.len(), UI_MAX_COMPONENTS)?;
    let mut ui = Map::with_capacity(7);
    ui.insert("protocol", or_default(protocol, UI_PROTOCOL));
    ui.insert("version", or_default(version, UI_VERSION));
    ui.insert("catalogIds", text_list(catalog_ids));
    ui.insert("agent", agent);
    ui.insert("transport", transport);
    ui.insert("surfaces", text_list(surfaces));
    if !components.is_empty() {
        ui.insert("components", maps(components));
    }
    Ok(ui)
}

/// An `AppCard` (SPEC §6.1a.2, v0.1.25): an application advertised in a fleet. Fill the fields
/// (`..Default::default()` leaves the rest empty) and build the card with [`AppCard::to_map`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AppCard<'a> {
    /// The advertisement id, e.g. `aspace://<group>/app/<issuer>/<slug>`.
    pub id: &'a str,
    /// The issuing peer's PeerID.
    pub issuer: &'a str,
    /// The group.
    pub group: &'a str,
    /// When it was issued (an ISO instant).
    pub issued: &'a str,
    /// How long it lives (an ISO duration).
    pub ttl: &'a str,
    /// The app's name; must not be blank.
    pub name: &'a str,
    /// One of [`APP_KINDS`]; blank reads as `"fed"`.
    pub kind: &'a str,
    /// One of [`APP_SHAPES`]; blank reads as `"web"`.
    pub shape: &'a str,
    /// Who owns the app.
    pub owner: &'a str,
    /// The `group/space` pairs it reads.
    pub reads: &'a [&'a str],
    /// The action names it may request.
    pub actions: &'a [&'a str],
    /// Its identity-provider client, empty when none.
    pub idp_client: &'a str,
    /// Where it is reached, empty when none.
    pub url: &'a str,
    /// The package it is deployed from, empty when none.
    pub pkg: &'a str,
    /// Its version; blank reads as `"1"`.
    pub version: &'a str,
    /// The view names it asks of its feed.
    pub views: &'a [&'a str],
    /// The surfaces it draws ([`app_card_ui`]); required for an `a2ui` app, omitted when `None`.
    pub ui: Option<&'a Map>,
    /// Where it is served ([`app_card_host`]), appended last and omitted when `None`.
    pub host: Option<&'a Map>,
}

impl AppCard<'_> {
    /// The card in Java field order: `id`, `issuer`, `group`, `issued`, `ttl`, `name`, `kind`,
    /// `shape`, `owner`, `reads`, `actions`, `idpClient`, `url`, `pkg`, `version`, `views`, then
    /// `ui` and `host` when present. Refuses what the Java record refuses: a blank name, an
    /// unknown kind or shape, more than [`APP_MAX_TERMS`] reads, actions, or views, and an
    /// `a2ui` app without a ui.
    pub fn to_map(&self) -> Result<Map, AdError> {
        if self.name.trim().is_empty() {
            return Err(AdError::EmptyName);
        }
        let kind = or_default(self.kind, "fed");
        if !APP_KINDS.contains(&kind) {
            return Err(AdError::InvalidAppKind(kind.to_owned()));
        }
        let shape = or_default(self.shape, "web");
        if !APP_SHAPES.contains(&shape) {
            return Err(AdError::InvalidAppShape(shape.to_owned()));
        }
        bounded("reads", self.reads.len(), APP_MAX_TERMS)?;
        bounded("actions", self.actions.len(), APP_MAX_TERMS)?;
        bounded("views", self.views.len(), APP_MAX_TERMS)?;
        if shape == "a2ui" && self.ui.is_none() {
            return Err(AdError::MissingUi);
        }
        let mut card = Map::with_capacity(18);
        card.insert("id", self.id);
        card.insert("issuer", self.issuer);
        card.insert("group", self.group);
        card.insert("issued", self.issued);
        card.insert("ttl", self.ttl);
        card.insert("name", self.name);
        card.insert("kind", kind);
        card.insert("shape", shape);
        card.insert("owner", self.owner);
        card.insert("reads", text_list(self.reads));
        card.insert("actions", text_list(self.actions));
        card.insert("idpClient", self.idp_client);
        card.insert("url", self.url);
        card.insert("pkg", self.pkg);
        card.insert("version", or_default(self.version, "1"));
        card.insert("views", text_list(self.views));
        if let Some(ui) = self.ui {
            card.insert("ui", ui.clone());
        }
        if let Some(host) = self.host {
            card.insert("host", host.clone());
        }
        Ok(card)
    }
}

// ---------------------------------------------------------------------------------------------
// Space advertisements

/// A `SpaceAdvertisement` (SPEC §4.4, §7.5) in Java field order: `id`
/// (`aspace://<group>/<space_name>`), `issuer`, `group`, `issued`, `ttl`, `spaceName`,
/// `schemaHints`, `strategy` (e.g. `LEASE_RACE`), `admission` (e.g. `GROUP`, `ALLOWLIST`),
/// `replication` (e.g. `TAG_SHARDED`). Its CBOR is the space's founding document: the SpaceID
/// is [`ids::derive_id`] over it (`SpaceId.fromFounding`).
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the Java SpaceAdvertisement record field for field"
)]
pub fn space_advertisement(
    group: &str,
    issuer: &str,
    space_name: &str,
    issued_iso: &str,
    ttl_iso: &str,
    schema_hints: &[&str],
    strategy: &str,
    admission: &str,
    replication: &str,
) -> Map {
    let mut ad = Map::with_capacity(10);
    ad.insert("id", format!("{}{group}/{space_name}", ids::URI_PREFIX));
    ad.insert("issuer", issuer);
    ad.insert("group", group);
    ad.insert("issued", issued_iso);
    ad.insert("ttl", ttl_iso);
    ad.insert("spaceName", space_name);
    ad.insert("schemaHints", text_list(schema_hints));
    ad.insert("strategy", strategy);
    ad.insert("admission", admission);
    ad.insert("replication", replication);
    ad
}

/// The SpaceID a space advertisement founds: [`ids::derive_id`] over its CBOR.
pub fn space_id_of(space_ad: &Map) -> String {
    ids::derive_id(&encode_map(space_ad))
}

// ---------------------------------------------------------------------------------------------
// Helpers

/// A CBOR array of text.
fn text_list(items: &[&str]) -> Vec<Value> {
    items.iter().map(|item| Value::from(*item)).collect()
}

/// A CBOR array of maps.
fn maps(items: &[Map]) -> Vec<Value> {
    items.iter().cloned().map(Value::Map).collect()
}

/// `value`, or `default` when it is blank (Java's `isBlank`).
fn or_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

/// Refuses a list longer than its bound.
fn bounded(field: &'static str, len: usize, limit: usize) -> Result<(), AdError> {
    if len > limit {
        Err(AdError::TooManyTerms { field, limit })
    } else {
        Ok(())
    }
}
