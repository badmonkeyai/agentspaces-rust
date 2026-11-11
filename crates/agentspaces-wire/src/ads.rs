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

//! Advertisements (SPEC §5.1, §5.2, §6.1 to §6.3), a port of `wire.py`'s `peer_advertisement`,
//! `stored_ad`, `signed_peer_ad`, `agent_card`, `card_action`, `ui_declaration`, `ui_component`,
//! and `app_card_host`, the TypeScript client's `spaceAdvertisement`, the checks of
//! `Peer.accept_ad` and `Peer._accept_peer_ad`, and the Java `AppCard`, `AgentCard`, and
//! `CardSpill` records. Java's records are the authority on bytes: every builder writes its map
//! in the record's field order, a field the record omits when absent is omitted here too (so
//! older cards keep their bytes), and a map-valued field a signature covers (`resourceHints`,
//! `costHints`, `spaceBindings`, `origin.attrs`) is put in canonical order.
//!
//! # The AppCard revision (SPEC v0.1.32, §6.1a.2 to §6.1a.6)
//!
//! - An `AppCard`'s `kind` says how the app connects and is closed to `peer`, `fed`, `gateway`,
//!   and `assembled` ([`APP_KINDS`]); `host.signOn` is `idp` or `none` ([`HOST_SIGN_ONS`]). A
//!   reader treats a card with any other closed value as undecodable (SPEC §6.1b).
//! - `origin` ([`app_card_origin`]) and `formats` ([`formats_hold`]) are open values under a
//!   grammar and bounds; a reader never refuses a value the registry lacks.
//! - No card kind has a size cap: a card whose encoding passes 65,536 bytes travels as a stub
//!   whose large parts sit in a content-swarm document it references (`spill`, [`card_spill`],
//!   [`spill_card`]). A reader verifies the reference and its placeholders when it decodes the
//!   card, and [`resolve_spill`] checks a fetched document against it. Fetching the document
//!   needs the content swarm, which this peer does not run yet, so it keeps stubs as they are.
//! - The member hint `wire.appcard=2` ([`HINT_APP_CARD`], [`app_card_level`]) gates `origin`,
//!   `formats`, a `host` whose `signOn` is `idp`, and `spill` on the whole view
//!   ([`app_card_at_level`]).
//! - A content store advertises itself by an `AssetCard` ([`content_store_of`]).
//! - Every advertisement cache holds a byte budget instead of the old 4 KiB card sentence
//!   (SPEC §6.3; [`crate::limits::AD_CACHE_MAX_BYTES`]).
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
    /// A card's agent local name is empty or holds `/` or `:` (Java `AgentId`, SPEC §9.2 R5).
    #[error("an agent's local name is non-empty and holds no '/' and no ':': {0:?}")]
    InvalidLocalName(String),
    /// A host's `signOn` is not one of [`HOST_SIGN_ONS`].
    #[error("a host's signOn is idp or none: {0:?}")]
    InvalidSignOn(String),
    /// An app card's `origin` breaks a bound or a grammar of SPEC §6.1a.2.
    #[error("an AppCard's origin breaks a bound or a grammar: {0}")]
    InvalidOrigin(&'static str),
    /// An app card's `formats` is not 1 to 16 distinct lower-case media types without a parameter
    /// or vocabulary IRIs (SPEC §6.1a.2).
    #[error("an AppCard's formats are 1 to 16 distinct media types or vocabulary IRIs: {0:?}")]
    InvalidFormats(Vec<String>),
    /// A card spill reference breaks a rule of SPEC §6.1a.5, or a stub holds a spill-set field
    /// beyond its placeholder.
    #[error("a card's spill reference or its placeholders break SPEC 6.1a.5: {0}")]
    InvalidSpill(&'static str),
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
    let signed = crate::schema::decode(payload, "PeerNode.SignedPeerAd")?;
    let (ad, issuer) = verified_ad(signed.as_map()?, AD_TYPE_PEER)?;
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
/// - `stored` is an `AdCache.StoredAd` record (SPEC §9.1, annex I) whose `adType` is one of
///   [`AD_TYPES`], with a 32-byte `publicKey` and a `signature` that verifies over `adBytes`
///   under that key;
/// - `adBytes` decode as the record its `adType` names, under the wire encoding with the
///   canonical-bytes check (`CborCodec.fromWire`), and that record's value rules hold: for an
///   `AppCard` the closed `kind`, `shape`, `ui.transport`, component roles, `host.signOn`
///   (`idp` or `none`) and `host.status`, the grammars and bounds of `origin` and `formats`, and
///   the spill reference with its placeholders (SPEC §6.1a.2 to §6.1a.5, §6.1b); for an
///   `AgentCard` its actions, ui controls, certificate binding, and spill reference;
/// - the record's `issuer` is the PeerID the key hashes to;
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
/// What needs state stays with the caller: the revocation registry, the cache's entry bound and
/// byte budget (SPEC §6.3), and last-writer-wins by `issued` per issuer and advertisement `id`.
/// A stub (a card with `spill`) is admitted as it is: resolving its parts needs the content
/// swarm ([`resolve_spill`]). Never panics.
pub fn verify_stored_ad(stored: &Value, now_ms: i64) -> Option<(String, Map, String)> {
    if !crate::schema::conforms(stored, "AdCache.StoredAd") {
        return None;
    }
    let stored = stored.as_map()?;
    let ad_type = stored.get("adType")?.as_str()?;
    let ad_type = AD_TYPES.into_iter().find(|known| *known == ad_type)?;
    let (ad, issuer) = verified_ad(stored, ad_type)?;
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

/// The shared signature and issuer checks of both wrappers: the `adBytes` decode as the record
/// `record` under the wire encoding (SPEC §9.1, annex I), with its value rules (SPEC §6.1a.2 to
/// §6.1a.5 for the cards), and the signature over them verifies under a key that hashes to the
/// record's `issuer`.
fn verified_ad(signed: &Map, record: &str) -> Option<(Map, String)> {
    let ad_bytes = signed.get("adBytes")?.as_bytes()?;
    let key = signed
        .get("publicKey")?
        .as_bytes()
        .filter(|key| key.len() == KEY_LENGTH)?;
    let signature = signed.get("signature")?.as_bytes()?;
    if !Identity::verify(key, ad_bytes, signature) {
        return None;
    }
    let ad = crate::schema::decode_map(ad_bytes, record)?;
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
/// ([`AdError::CertificateMismatch`]), and the local name must be one Java's `AgentId` holds
/// ([`AdError::InvalidLocalName`]).
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
    if !ids::is_local_name(local_name) {
        return Err(AdError::InvalidLocalName(local_name.to_owned()));
    }
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
pub use crate::schema::UI_ROLES;

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

pub use crate::schema::{
    AGENT_CARD_SPILL_SET, APP_CARD_SPILL_SET, APP_KINDS, APP_MAX_FORMAT_UNITS, APP_MAX_FORMATS,
    APP_MAX_TERMS, APP_SHAPES, APP_TRANSPORTS, CARD_MAX_ACTIONS, CONTENT_ROOT_LENGTH,
    HOST_SIGN_ONS, HOST_STATUSES, SPILL_MAX_SIZE, UI_MAX_COMPONENTS, formats_hold, is_content_root,
};

/// The host group of a published `AppCard` (SPEC §6.1a.4, v0.1.28; v0.1.32 sign-on values) in
/// Java field order: `url`, `port` (0 when the url says it all), `hostAgent`, `path` (`"/"` when
/// empty), `signOn` (one of [`HOST_SIGN_ONS`]: `idp`, the identity provider of whoever runs the
/// host, or `none`; empty reads as `idp`), `publishedBy`, `publishedAt` (an ISO instant),
/// `status` (one of [`HOST_STATUSES`]). Appended after `ui` on the card ([`AppCard::host`]); a
/// card without it keeps its bytes. Refuses an empty url, an unknown sign-on (`tenant`, the value
/// of v0.1.28 to v0.1.31, included), and an unknown status, as Java's `AppCard.Host` does. A
/// host whose `signOn` is `idp` travels only under the AppCard level ([`app_card_at_level`]).
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
    let sign_on = or_default(sign_on, "idp");
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

/// The origin of an `AppCard` (SPEC §6.1a.2, v0.1.32), `AppCard.Origin` in Java field order:
/// `system` (1 to 64 of `[a-z0-9.-]`, starting and ending with a letter or digit), `ref` (the
/// app's identifier in that system, 1 to 256 UTF-16 code units with no control character),
/// `version` (0 to 64 code units with no control character), and `attrs`, omitted when `None` or
/// empty (Java's builder), else 1 to 8 entries keyed `<system>.<[a-z0-9.-]+>` (at most 128 code
/// units) with values of 0 to 256 code units and no control character, written in canonical
/// order. The values are open: a system, key, or value the registry lacks is fine when it meets
/// the grammar.
pub fn app_card_origin(
    system: &str,
    reference: &str,
    version: &str,
    attrs: Option<&Map>,
) -> Result<Map, AdError> {
    let mut origin = Map::with_capacity(4);
    origin.insert("system", system);
    origin.insert("ref", reference);
    origin.insert("version", version);
    if let Some(attrs) = attrs.filter(|attrs| !attrs.is_empty()) {
        origin.insert("attrs", cbor::canonical_map(attrs));
    }
    if !crate::schema::conforms(&Value::Map(origin.clone()), "AppCard.Origin") {
        return Err(AdError::InvalidOrigin(
            "system, ref, version, or attrs outside SPEC 6.1a.2",
        ));
    }
    Ok(origin)
}

/// A card's spill reference, `CardSpill {root, size, parts}` (SPEC §6.1a.5, v0.1.32): the
/// parts document's content root ([`is_content_root`], [`content_root`]), its length in bytes
/// (1 to [`SPILL_MAX_SIZE`]), and the spill-set fields whose full value is non-empty, distinct
/// and in the card's field order.
pub fn card_spill(root: &str, size: u64, parts: &[&str]) -> Result<Map, AdError> {
    if !is_content_root(root) {
        return Err(AdError::InvalidSpill(
            "root is no content root of codec raw over sha2-256",
        ));
    }
    let size = i64::try_from(size)
        .ok()
        .filter(|size| (1..=SPILL_MAX_SIZE).contains(size))
        .ok_or(AdError::InvalidSpill("size lies outside 1 to 2^53 - 1"))?;
    let mut spill = Map::with_capacity(3);
    spill.insert("root", root);
    spill.insert("size", size);
    spill.insert("parts", text_list(parts));
    if !crate::schema::conforms(&Value::Map(spill.clone()), "CardSpill") {
        return Err(AdError::InvalidSpill("parts are empty or repeat a name"));
    }
    Ok(spill)
}

/// An `AppCard` (SPEC §6.1a.2, v0.1.25; revised in v0.1.32): an application advertised in a
/// fleet. Fill the fields (`..Default::default()` leaves the rest empty) and build the card with
/// [`AppCard::to_map`].
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
    /// How the app connects, one of [`APP_KINDS`] (`peer`, `fed`, `gateway`, `assembled`); blank
    /// reads as `"fed"`.
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
    /// Where it is served ([`app_card_host`]), appended after `ui` and omitted when `None`.
    pub host: Option<&'a Map>,
    /// The external system it came from ([`app_card_origin`], v0.1.32), omitted when `None`.
    pub origin: Option<&'a Map>,
    /// The media types and vocabulary IRIs it reads or renders (v0.1.32), in the issuer's order;
    /// omitted when empty. A media type is lower-cased and a repeated entry dropped after its
    /// first occurrence, as Java's `withFormats` does, then the list must meet
    /// [`formats_hold`].
    pub formats: &'a [&'a str],
    /// The reference to its parts document when the card is a stub ([`card_spill`], v0.1.32),
    /// appended last and omitted when `None`. A stub holds `[]` in `reads`, `actions`, and
    /// `views` and no `ui`.
    pub spill: Option<&'a Map>,
}

impl AppCard<'_> {
    /// The card in Java field order: `id`, `issuer`, `group`, `issued`, `ttl`, `name`, `kind`,
    /// `shape`, `owner`, `reads`, `actions`, `idpClient`, `url`, `pkg`, `version`, `views`, then
    /// `ui`, `host`, `origin`, `formats`, and `spill` when present. Refuses what the Java record
    /// refuses: a blank name, a kind or shape outside its closed set, more than
    /// [`APP_MAX_TERMS`] reads, actions, or views, an `a2ui` app without a ui (unless its ui
    /// spilled), formats outside their grammar, and a stub whose spill-set fields hold more than
    /// their placeholders.
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
        let ui_spilled = self.spill.is_some_and(|spill| {
            spill
                .get("parts")
                .and_then(Value::as_array)
                .is_some_and(|parts| parts.contains(&Value::from("ui")))
        });
        if shape == "a2ui" && self.ui.is_none() && !ui_spilled {
            return Err(AdError::MissingUi);
        }
        let formats = normalized_formats(self.formats);
        if !formats.is_empty()
            && !formats_hold(&formats.iter().map(String::as_str).collect::<Vec<_>>())
        {
            return Err(AdError::InvalidFormats(formats));
        }
        if let Some(spill) = self.spill {
            let placeholders = self.reads.is_empty()
                && self.actions.is_empty()
                && self.views.is_empty()
                && self.ui.is_none();
            if !placeholders {
                return Err(AdError::InvalidSpill(
                    "a stub holds [] in reads, actions, and views and no ui",
                ));
            }
            if !crate::schema::conforms(&Value::Map(spill.clone()), "CardSpill") {
                return Err(AdError::InvalidSpill("not a CardSpill"));
            }
        }
        let mut card = Map::with_capacity(21);
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
        if let Some(origin) = self.origin {
            card.insert("origin", origin.clone());
        }
        if !formats.is_empty() {
            card.insert(
                "formats",
                formats.into_iter().map(Value::from).collect::<Vec<_>>(),
            );
        }
        if let Some(spill) = self.spill {
            card.insert("spill", spill.clone());
        }
        Ok(card)
    }
}

/// Java's `AppCard.withFormats`: a media type (an entry without `:`) lower-cased, a repeated entry
/// dropped after its first occurrence, the issuer's order kept.
fn normalized_formats(formats: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(formats.len());
    for format in formats {
        let format = if format.contains(':') {
            (*format).to_owned()
        } else {
            format.to_lowercase()
        };
        if !out.contains(&format) {
            out.push(format);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The card spill (SPEC §6.1a.5)

/// The piece size of a parts document (Java `CardSpill.PIECE_SIZE`), so every implementation
/// computes the same root for the same bytes.
pub const SPILL_PIECE_SIZE: usize = 65_536;

/// The default bound on a parts document a reader fetches (Java
/// `CardSpill.DEFAULT_MAX_FETCH_BYTES`), 16 MiB.
pub const SPILL_MAX_FETCH_BYTES: u64 = 16_777_216;

/// The content root of `bytes` cut into [`SPILL_PIECE_SIZE`] pieces (SPEC §7.1): `b` and the
/// lower-case unpadded base32 of the CIDv1 (codec raw 0x55, multihash sha2-256) of the
/// concatenated sha2-256 hashes of the pieces. The root of a card's parts document.
pub fn content_root(bytes: &[u8]) -> String {
    let crypto = crate::crypto::port();
    let mut table = Vec::with_capacity(bytes.len().div_ceil(SPILL_PIECE_SIZE).max(1) * 32);
    for piece in bytes.chunks(SPILL_PIECE_SIZE) {
        table.extend_from_slice(&crypto.sha256(piece));
    }
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend_from_slice(&crypto.sha256(&table));
    format!("b{}", crate::schema::base32_encode(&cid))
}

/// The spill set of a card kind ([`APP_CARD_SPILL_SET`], [`AGENT_CARD_SPILL_SET`]), and the name
/// of its parts record; `None` for a kind that never spills.
fn spill_kind(ad_type: &str) -> Option<(&'static [&'static str], &'static str)> {
    match ad_type {
        AD_TYPE_APP_CARD => Some((&APP_CARD_SPILL_SET, "AppCard.Parts")),
        AD_TYPE_AGENT_CARD => Some((&AGENT_CARD_SPILL_SET, "AgentCard.Parts")),
        _ => None,
    }
}

/// Whether a spill-set field holds a full value: neither absent, null, nor an empty list.
fn non_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Array(items)) => !items.is_empty(),
        Some(_) => true,
    }
}

/// The parts document of a full card (SPEC §6.1a.5): the kind's parts record
/// (`AppCard.Parts {reads, actions, views, ui}` or `AgentCard.Parts {actions, ui}`) holding the
/// card's values of the spill set, its optional fields omitted when absent, and the names of the
/// non-empty ones, in field order. `None` for a kind that never spills and for a stub.
pub fn card_parts(ad_type: &str, card: &Map) -> Option<(Map, Vec<&'static str>)> {
    let (spill_set, _) = spill_kind(ad_type)?;
    if card.contains_key("spill") {
        return None;
    }
    let mut parts = Map::with_capacity(spill_set.len());
    let mut names = Vec::new();
    for &name in spill_set {
        let value = card.get(name).filter(|value| !value.is_null());
        let always = ad_type == AD_TYPE_APP_CARD && name != "ui";
        match value {
            Some(value) => {
                parts.insert(name, value.clone());
            }
            None if always => {
                parts.insert(name, Vec::<Value>::new());
            }
            None => {}
        }
        if non_empty(value) {
            names.push(name);
        }
    }
    Some((parts, names))
}

/// A full card split into its stub and its parts document (SPEC §6.1a.5): the canonical bytes of
/// the parts document ([`card_parts`]) and the stub, which holds each spill-set field at its
/// placeholder (`[]` for an `AppCard`'s `reads`, `actions`, and `views`; absence for its `ui`
/// and for an `AgentCard`'s `actions` and `ui`) and appends `spill` with the document's
/// [`content_root`], length, and non-empty part names. A publisher spills only a card whose
/// encoding passes [`crate::limits::CARD_SPILL_THRESHOLD_BYTES`], only under the AppCard level
/// ([`app_card_at_level`]), and only where a content swarm serves the group: this peer runs no
/// content swarm, so it never spills its own cards. `Err` for a kind that never spills, a stub,
/// and a card whose spill set is empty.
pub fn spill_card(ad_type: &str, card: &Map) -> Result<(Map, Vec<u8>), AdError> {
    let (spill_set, _) =
        spill_kind(ad_type).ok_or(AdError::InvalidSpill("only an AppCard or AgentCard spills"))?;
    let (parts, names) =
        card_parts(ad_type, card).ok_or(AdError::InvalidSpill("a stub spills nothing more"))?;
    if names.is_empty() {
        return Err(AdError::InvalidSpill("the spill set holds nothing to move"));
    }
    let document = encode_map(&parts);
    let size = u64::try_from(document.len()).unwrap_or(u64::MAX);
    let spill = card_spill(&content_root(&document), size, &names)?;
    let mut stub = Map::with_capacity(card.len() + 1);
    for (key, value) in card {
        match key.as_str() {
            // An AppCard's lists stay as []; its ui and an AgentCard's parts leave.
            Some(name) if spill_set.contains(&name) => {
                if ad_type == AD_TYPE_APP_CARD && name != "ui" {
                    stub.insert(name, Vec::<Value>::new());
                }
            }
            _ => {
                stub.insert(key.clone(), value.clone());
            }
        }
    }
    stub.insert("spill", spill);
    Ok((stub, document))
}

/// Why a spilled card could not be resolved from a fetched parts document (SPEC §6.1a.5). Each
/// fails the resolution; the reader keeps the stub, counts the case (`spillsRefused`, or
/// `spillsOverLimit` for [`SpillError::OverLimit`]), and strikes nobody.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpillError {
    /// The card carries no `spill`, or its kind never spills.
    #[error("the card is no stub")]
    NotAStub,
    /// The stub's `size` passes the reader's fetch bound.
    #[error("the parts document of {size} bytes passes the fetch bound of {limit}")]
    OverLimit {
        /// The stub's `size`.
        size: u64,
        /// The bound.
        limit: u64,
    },
    /// The document's length is not the stub's `size`.
    #[error("the parts document holds {got} bytes where the stub names {size}")]
    Size {
        /// The stub's `size`.
        size: u64,
        /// The fetched length.
        got: usize,
    },
    /// The document's content root is not the stub's `root`.
    #[error("the parts document's content root is not the stub's root")]
    Root,
    /// The document does not decode as the kind's parts record (SPEC §9.1).
    #[error("the parts document is not the kind's parts record")]
    Undecodable,
    /// The document's non-empty fields are not exactly those `spill.parts` names.
    #[error("the parts document's fields are not the ones spill.parts names")]
    Parts,
}

/// A stub's spill reference, when `card` is an `AppCard` or `AgentCard` stub: its `root`, `size`,
/// and `parts`.
pub fn spill_of<'c>(ad_type: &str, card: &'c Map) -> Option<(&'c str, u64, Vec<&'c str>)> {
    spill_kind(ad_type)?;
    let spill = card.get("spill")?.as_map()?;
    let root = spill.get("root")?.as_str()?;
    let size = spill.get("size")?.as_u64()?;
    let parts = spill
        .get("parts")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    Some((root, size, parts))
}

/// `discovery.resolve(card)`'s checks on a fetched parts document (SPEC §6.1a.5): the full card
/// of a stub, the stub with the document's values in its spill-set fields and no `spill`. The
/// document's length must be `size` (and `size` at most `max_fetch_bytes`, which a reader checks
/// before it fetches), its content root `root` ([`content_root`]), it must decode as the kind's
/// parts record under the wire encoding, and its non-empty fields must be exactly those
/// `spill.parts` names. The full card must then be the kind's record again.
///
/// Fetching the document needs the content swarm (`aspace:cap/content-swarm`), which this peer
/// does not run yet: a reader without a content swarm keeps the stub, and discovery by every
/// field that never spills reads the stub alone.
pub fn resolve_spill(
    ad_type: &str,
    stub: &Map,
    document: &[u8],
    max_fetch_bytes: u64,
) -> Result<Map, SpillError> {
    let (spill_set, parts_record) = spill_kind(ad_type).ok_or(SpillError::NotAStub)?;
    let (root, size, names) = spill_of(ad_type, stub).ok_or(SpillError::NotAStub)?;
    if size > max_fetch_bytes {
        return Err(SpillError::OverLimit {
            size,
            limit: max_fetch_bytes,
        });
    }
    if u64::try_from(document.len()).ok() != Some(size) {
        return Err(SpillError::Size {
            size,
            got: document.len(),
        });
    }
    if content_root(document) != root {
        return Err(SpillError::Root);
    }
    let parts = crate::schema::decode_map(document, parts_record).ok_or(SpillError::Undecodable)?;
    let present: Vec<&str> = spill_set
        .iter()
        .copied()
        .filter(|name| non_empty(parts.get(name)))
        .collect();
    if present != names {
        return Err(SpillError::Parts);
    }
    let mut full = Map::with_capacity(stub.len() + parts.len());
    for (key, value) in stub {
        let Some(name) = key.as_str() else {
            continue;
        };
        match name {
            "spill" => {}
            // A full AgentCard places actions after agentPublicKey and ui after
            // agentCertificate, which the field order below restores.
            _ => {
                full.insert(name, value.clone());
            }
        }
    }
    for (key, value) in &parts {
        if let Some(name) = key.as_str() {
            full.insert(name, value.clone());
        }
    }
    let ordered = in_record_order(ad_type, full);
    if !crate::schema::conforms(&Value::Map(ordered.clone()), ad_type) {
        return Err(SpillError::Undecodable);
    }
    Ok(ordered)
}

/// `card`'s fields in the field order of its record, an optional field omitted when absent or
/// null; fields the record does not name are dropped.
fn in_record_order(ad_type: &str, card: Map) -> Map {
    let order: &[&str] = match ad_type {
        AD_TYPE_APP_CARD => &[
            "id",
            "issuer",
            "group",
            "issued",
            "ttl",
            "name",
            "kind",
            "shape",
            "owner",
            "reads",
            "actions",
            "idpClient",
            "url",
            "pkg",
            "version",
            "views",
            "ui",
            "host",
            "origin",
            "formats",
            "spill",
        ],
        _ => &[
            "id",
            "issuer",
            "group",
            "issued",
            "ttl",
            "agent",
            "description",
            "goals",
            "consumes",
            "produces",
            "costHints",
            "spaceBindings",
            "agentPublicKey",
            "actions",
            "agentCertificate",
            "ui",
            "spill",
        ],
    };
    let mut ordered = Map::with_capacity(card.len());
    for name in order {
        if let Some(value) = card.get(name) {
            ordered.insert(*name, value.clone());
        }
    }
    ordered
}

// ---------------------------------------------------------------------------------------------
// The AppCard level (SPEC §6.1a.2, §9)

/// The resource hint a member advertises once it reads the v0.1.32 schemas of the `AppCard` and
/// the `AgentCard` with their value rules (SPEC §6.1a.2, §9).
pub const HINT_APP_CARD: &str = "wire.appcard";

/// The AppCard level this crate reads, the value of [`HINT_APP_CARD`] it advertises.
pub const APP_CARD_LEVEL: i32 = 2;

/// The AppCard level a hint's text states, as Java's `PeerNode.appCardLevelOf` reads it:
/// canonical decimal text, so `2`, `10`, or a value past every `int` reads as at least that
/// level; no hint, any other text, a leading zero, and `0` read as level 1.
pub fn app_card_level(hint: Option<&str>) -> i32 {
    let Some(text) = hint.filter(|text| {
        !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0'))
    }) else {
        return 1;
    };
    if text.len() > 9 {
        return i32::MAX;
    }
    text.parse::<i32>().map_or(1, |level| level.max(1))
}

/// The card an issuer writes into a view whose members are not all at the AppCard level
/// (SPEC §6.1a.2): a full `AppCard` without `origin`, `formats`, a `host` whose `signOn` is
/// `idp`, and `spill`; a full `AgentCard` without `spill`. Returns the card and whether the gate
/// removed anything (what an issuer counts in `appCardsDowngraded`). A stub cannot be downgraded
/// (its parts are elsewhere): issue the full card instead. A dial-only member cannot see every
/// member's hints, so it issues every card this way; other kinds pass unchanged.
pub fn app_card_at_level(ad_type: &str, card: &Map) -> (Map, bool) {
    let gated = |name: &str, value: &Value| match ad_type {
        AD_TYPE_APP_CARD => match name {
            "origin" | "formats" | "spill" => true,
            "host" => value.get("signOn").and_then(Value::as_str) == Some("idp"),
            _ => false,
        },
        AD_TYPE_AGENT_CARD => name == "spill",
        _ => false,
    };
    let mut out = Map::with_capacity(card.len());
    let mut downgraded = false;
    for (key, value) in card {
        if key.as_str().is_some_and(|name| gated(name, value)) {
            downgraded = true;
        } else {
            out.insert(key.clone(), value.clone());
        }
    }
    (out, downgraded)
}

// ---------------------------------------------------------------------------------------------
// Content stores (SPEC §6.1a.6)

/// The `access.kind` of an `AssetCard` that advertises a content store.
pub const CONTENT_STORE_KIND: &str = "content-store";

/// What a content store's `AssetCard` states (SPEC §6.1a.6, v0.1.32), read from its `access`
/// map, whose values are all text. A reader ignores a key it does not know; this peer pins
/// nothing in a store yet (the content swarm's `pdt` level is not built here), so it reads the
/// card to list stores.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentStore {
    /// The store's name, from `asset` = `content-store:<name>`.
    pub name: String,
    /// The store's URI, `aspace://<group>/store/<name>`.
    pub uri: String,
    /// The holding interval, the card's `freshness` (an ISO-8601 duration).
    pub holding_interval: String,
    /// Capacity in bytes, when stated as canonical decimal.
    pub capacity: Option<u64>,
    /// Free bytes, when stated; `0` on the last card of a closing store.
    pub free: Option<u64>,
    /// The largest object it takes, in bytes, when stated.
    pub max_object: Option<u64>,
    /// The codecs it holds (`dag-cbor`, `raw`).
    pub codecs: Vec<String>,
    /// The sealing modes it holds.
    pub sealing: Vec<String>,
    /// Whether it holds what it cannot read (`blind`).
    pub blind: bool,
    /// Whether it answers possession challenges.
    pub challenge: bool,
    /// `open` or `grant`.
    pub policy: String,
    /// `hot` or `cold`.
    pub tier: String,
    /// Present (`authorizer`) while a `grant` store waits for an authorizer and takes no pins.
    pub waiting: Option<String>,
    /// The price per GiB-month from `costHints`, when its owner sets one.
    pub price_per_gib_month: Option<String>,
}

/// The content store an `AssetCard` advertises (SPEC §6.1a.6): `access.kind` is
/// [`CONTENT_STORE_KIND`] and `asset` is `content-store:<name>`. `None` for any other card. The
/// values are read as text (integers as canonical decimal, booleans as `true`); an unreadable
/// number reads as absent.
pub fn content_store_of(card: &Map) -> Option<ContentStore> {
    let access = card.get("access")?.as_map()?;
    let text = |key: &str| access.get(key).and_then(Value::as_str);
    if text("kind") != Some(CONTENT_STORE_KIND) {
        return None;
    }
    let name = card
        .get("asset")?
        .as_str()?
        .strip_prefix("content-store:")?
        .to_owned();
    let number = |key: &str| {
        text(key)
            .filter(|digits| digits == &"0" || !digits.starts_with('0'))
            .and_then(|digits| digits.parse().ok())
    };
    let list = |key: &str| {
        text(key)
            .filter(|list| !list.is_empty())
            .map(|list| list.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    };
    Some(ContentStore {
        name,
        uri: card
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        holding_interval: card
            .get("freshness")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        capacity: number("capacity"),
        free: number("free"),
        max_object: number("maxObject"),
        codecs: list("codecs"),
        sealing: list("sealing"),
        blind: text("blind") == Some("true"),
        challenge: text("challenge") == Some("true"),
        policy: text("policy").unwrap_or_default().to_owned(),
        tier: text("tier").unwrap_or_default().to_owned(),
        waiting: text("waiting").map(str::to_owned),
        price_per_gib_month: card
            .get("costHints")
            .and_then(|hints| hints.get("pricePerGibMonth"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
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
