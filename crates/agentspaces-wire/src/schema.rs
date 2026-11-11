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

//! The protocol records this peer reads from the network and the record rules P1 to P4 of the
//! wire encoding (SPEC §9.1, §9.2, annex I), a port of `agentspaces-python`'s `records.py`, with
//! Java's `CborCodec.fromWire` as the authority.
//!
//! A protocol record is a map whose keys are exactly the fields its schema names, in the schema's
//! declared order (P1). A field is present always (its null written as null), omitted when null
//! (`?null`), or omitted when null or empty (`?empty`). Each field holds the kind its schema
//! names and no other (P2): no tag, no float where an integer belongs, no integer where text or a
//! double belongs, no text where bytes belong (P3, rule F1), and a primitive (`int`, `long`,
//! `double`, `boolean`) is never null (P4). A typed text field holds the exact text Java prints
//! for its value: a canonical stamp ([`crate::hlc::Stamp::parse`]), an `Instant` as
//! `ISO_INSTANT` prints it, a `Duration` as `Duration.toString` prints it, an agent id under
//! Java's `AgentId` grammar (R5). A map field lists its keys in the RFC 8949 order and a set field
//! its elements in the order of their encodings.
//!
//! Beyond the kinds, a record must be one Java's constructor holds: Java decodes the record and
//! re-encodes it, and a value its constructor refuses, or replaces with a default, is refused
//! there (the canonical-bytes check of rule F3 compares the re-encoding with the bytes received).
//! The checks of the AppCard and the card spill (SPEC §6.1a.2 to §6.1a.5, §6.1b) are among them.
//!
//! [`decode`] runs the receiver's procedure on one carrier (SPEC §9.1): the item rules of
//! [`cbor::decode`] (S1 to S12), the record rules here, then the canonical-bytes rule, so
//! re-encoding what was decoded gives back exactly the bytes received (F3). A carrier that fails
//! any step is undecodable; the caller drops it, counts it where it counts an undecodable carrier
//! of its kind, and strikes nobody.
//!
//! The schemas are annex I.1's, which Java's own serializers generated. `PRef.attrs` follows rule
//! R1: a value under `pdt.issued` or `pdt.issuer` is any item (the head falls back when it is no
//! text), and every other value is text. The content swarm's messages (annex I.1a) are not read
//! here: this peer runs no content swarm.
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::cbor::{self, Map, Value};
use crate::hlc::Stamp;
use crate::ids;
use crate::limits::INLINE_PAYLOAD_LIMIT;
use crate::time;

/// The record schemas of annex I.1, as Java's serializers wrote them: one record per line,
/// `Name { field: kind, ... }`, with `?null` for a field omitted when null and `?empty` for one
/// omitted when null or empty.
pub const SCHEMAS: &str = "\
WireCodec.Signed { envelope: Envelope, senderPublicKey: bytes, signature: bytes }
Envelope { ver: int, group: GroupId, kind: enum Kind[PING,PING_REQ,ACK,RUMOR,DIGEST,PULL_RESP,QUERY,QUERY_HIT,BLOCK_WANT,BLOCK,PIPE_DATA,BATCH,HAVE,GRAFT,PRUNE,RELAY_FRAME,CHANNEL_HELLO,SESSION_HELLO,GROUP_AD_WANT,GROUP_AD], from: PeerId, to: PeerId, stamp: HlcTimestamp, body: bytes }
Bodies.Ping { nonce: long, root: bytes ?null, hashes: map<String,bytes> ?null, have: list<Bodies.HaveItem> ?null }
Bodies.PingReq { target: PeerId, nonce: long }
Bodies.Ack { nonce: long, onBehalf: PeerId, root: bytes ?null, hashes: map<String,bytes> ?null, have: list<Bodies.HaveItem> ?null }
Bodies.Rumor { streamId: String, itemId: String, hopsRemaining: int, payload: bytes }
Bodies.Digest { digests: map<String,bytes>, hashes: map<String,bytes> ?null, want: list<String> ?null }
Bodies.PullResp { deltas: map<String,bytes> }
Bodies.RelayFrame { target: PeerId, frame: bytes, path: list<PeerId> ?null, hop: Integer ?null }
Bodies.Batch { frames: list<bytes> }
Bodies.Have { items: list<Bodies.HaveItem> }
Bodies.HaveItem { streamId: String, hash: bytes }
Bodies.Graft { streamId: String, hash: bytes }
Bodies.Prune { streamId: String, hash: bytes }
Bodies.SessionHello { ephemeralKey: bytes, nonce: bytes, remote: PeerId, echo: bytes }
Bodies.ChannelHello { acceptsBare: boolean, attestedRemote: PeerId }
BlockExchange.Want { cid: String }
BlockExchange.Block { cid: String, bytes: bytes }
PeerNode.SignedPeerAd { adBytes: bytes, publicKey: bytes, signature: bytes }
PeerNode.RelayPipeFrame { capability: String, payload: bytes }
PeerNode.RelaySignal { target: PeerId, failedHop: PeerId, reason: String }
SignedGroupAdvertisement { advertisement: GroupAdvertisement, founderPublicKey: bytes, signature: bytes }
GroupFounding.FoundingFields { name: String, founder: PeerId, issued: Instant, ttl: Duration, membershipPolicy: enum MembershipPolicy[OPEN,INVITE,POLICY], defaultStrategy: enum ConflictStrategyType[LEASE_RACE,AUCTION,ORDERED], gossip: GroupAdvertisement.GossipParameters }
GroupFounding.FoundingDocument { fields: GroupFounding.FoundingFields, signature: bytes }
JoinCredentials.CredentialView { candidate: PeerId, group: GroupId }
JoinCredentials.Credential { founderKey: bytes, signature: bytes }
JoinCredentials.DelegationView { inviteKey: bytes, group: GroupId, notAfterMillis: long, label: String }
JoinCredentials.Delegation { founderKey: bytes, inviteKey: bytes, group: GroupId, notAfterMillis: long, label: String, signature: bytes }
JoinCredentials.DelegatedCredential { delegation: JoinCredentials.Delegation, signature: bytes }
RevocationRegistry.SignedRevocation { adBytes: bytes, publicKey: bytes, signature: bytes }
AdCache.StoredAd { adType: String, adBytes: bytes, publicKey: bytes, signature: bytes }
AdCache.Delta { ads: list<AdCache.StoredAd> }
DiscoveryService.AdQuery { queryId: String, asker: PeerId, adType: String, fieldEquals: map<String,String> }
DiscoveryService.QueryHits { queryId: String, hits: list<AdCache.StoredAd> }
AgentCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, agent: AgentId, description: String, goals: list<String>, consumes: list<String>, produces: list<String>, costHints: map<String,String>, spaceBindings: map<String,String>, agentPublicKey: bytes ?null, actions: list<CardAction> ?null, agentCertificate: AgentCertificate ?null, ui: UiDeclaration ?null, spill: CardSpill ?null }
AgentCard.Parts { actions: list<CardAction> ?null, ui: UiDeclaration ?null }
AppCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, kind: String, shape: String, owner: String, reads: list<String>, actions: list<String>, idpClient: String, url: String, pkg: String, version: String, views: list<String>, ui: AppCard.Ui ?null, host: AppCard.Host ?null, origin: AppCard.Origin ?null, formats: list<String> ?null, spill: CardSpill ?null }
AppCard.Ui { protocol: String, version: String, catalogIds: list<String>, agent: String, transport: String, surfaces: list<String>, components: list<UiDeclaration.Component> ?empty }
AppCard.Host { url: String, port: int, hostAgent: String, path: String, signOn: String, publishedBy: String, publishedAt: Instant, status: String }
AppCard.Origin { system: String, ref: String, version: String, attrs: map<String,String> ?null }
AppCard.Parts { reads: list<String>, actions: list<String>, views: list<String>, ui: AppCard.Ui ?null }
CardSpill { root: String, size: long, parts: list<String> }
AssetCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, asset: String, uri: String, description: String, shape: String, freshness: String, costHints: map<String,String>, access: map<String,String> }
CapabilityAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, capabilityType: String, version: String, binding: String, parameters: map<String,String>, costHints: map<String,String> }
CredentialRevocation { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, target: CredentialRevocation.Target, reason: String, effectiveFrom: Instant ?null, evidence: bytes ?null }
CredentialRevocation.Target { kind: String, agent: AgentId ?null, keyFingerprint: bytes ?null, x509Issuer: String ?null, x509Serial: String ?null, certificateFingerprint: bytes ?null, credentialHash: bytes ?null }
GroupAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, membershipPolicy: enum MembershipPolicy[OPEN,INVITE,POLICY], defaultStrategy: enum ConflictStrategyType[LEASE_RACE,AUCTION,ORDERED], gossip: GroupAdvertisement.GossipParameters }
GroupAdvertisement.GossipParameters { fanout: int, period: Duration }
ModelCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, version: String, tasks: list<String>, modality: String, limits: map<String,String>, licence: String, provenance: map<String,String>, evals: map<String,String>, costHints: map<String,String>, residency: map<String,String>, engine: String, servers: list<PeerId> }
PeerAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, endpoints: list<PeerAdvertisement.Endpoint>, roles: set<enum PeerRole[RENDEZVOUS,RELAY]>, resourceHints: map<String,String> }
PeerAdvertisement.Endpoint { transport: String, address: String, priority: int }
RevocationAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, revoked: PeerId, reason: String, successor: PeerId, evidence: bytes ?null }
SpaceAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, spaceName: String, schemaHints: list<String>, strategy: enum ConflictStrategyType[LEASE_RACE,AUCTION,ORDERED], admission: enum Admission[GROUP,ALLOWLIST,CREDENTIAL,AUTHORIZER], replication: enum Replication[FULL,TAG_SHARDED] }
CardAction { name: String, description: String, consumes: list<String>, produces: list<String>, space: String ?null, kind: String, contract: CardAction.Contract ?null }
CardAction.Contract { pre: list<String>, post: list<String>, cost: String, methods: list<String> }
UiDeclaration { protocol: String, version: String, components: list<UiDeclaration.Component>, entries: UiDeclaration.Entries, catalogIds: list<String> }
UiDeclaration.Component { id: String, catalogId: String, component: String, entry: String, controls: list<String>, role: String }
UiDeclaration.Entries { reads: list<String>, writes: list<String> }
AgentCertificate { agent: AgentId, agentPublicKey: bytes, issued: Instant, ttl: Duration, peerSignature: bytes, encryptionPublicKey: bytes ?null }
SpaceWire.Delta { state: SpaceWire.EntryStateDto, claimEntry: EntryId, claim: SpaceWire.SignedClaim }
SpaceWire.SyncDelta { states: list<SpaceWire.EntryStateDto>, claims: map<String,SpaceWire.SignedClaim> }
SpaceWire.EntryStateDto { record: EntryRecord ?null, issuerPublicKey: bytes, adds: list<Dot>, removes: list<Dot>, leaseStamp: HlcTimestamp, leaseValue: LeaseInfo, completed: boolean, stateSig: bytes, agentCertificate: AgentCertificate ?null, stateCertificate: AgentCertificate ?null, signer: String ?null, signedAt: HlcTimestamp ?null, entryId: EntryId ?null }
SpaceWire.SignedClaim { claim: TakeClaim, holderKey: bytes, signature: bytes, holderCertificate: AgentCertificate ?null }
TakeClaim { entryId: EntryId, spaceId: SpaceId, epoch: long, stamp: HlcTimestamp, holder: AgentId, bid: double, expiresAtMillis: long }
EntryRecord { entryId: EntryId, spaceId: SpaceId, type: String, payload: bytes, payloadRef: String, issuer: AgentId, issued: HlcTimestamp, lease: LeaseInfo, tags: map<String,String>, sig: bytes, keyEpoch: Long ?null }
Dot { replica: String, counter: long }
LeaseInfo { holder: AgentId, expiresAtMillis: long, kind: enum LeaseKind[WRITE,TAKE] }
PRef { v: int, name: String, kind: String, root: String, base: list<String>, seq: long, size: long, nodes: list<bytes> ?null, mode: String, sealing: String, keyEpoch: Long ?null, attrs: map<String,String> ?null }
OrderedTakes.ClaimCommand { entryId: EntryId, claim: TakeClaim, holderKey: bytes, signature: bytes, holderCertificate: AgentCertificate ?null }
CapabilityPipes.PipeFrame { capability: String, payload: bytes }
VoteCapability.Proposal { proposalId: String, question: String, options: list<String>, quorum: int }
VoteCapability.Ballot { proposalId: String, option: String, voter: String }
VoteCapability.Decision { proposalId: String, winner: String, tally: map<String,Integer>, granularity: enum Granularity[PEER,AGENT] }
PushSumAggregate.Frame { share: PushSumAggregate.Share, extremum: PushSumAggregate.Extremum, histogram: PushSumAggregate.Histogram, roster: PushSumAggregate.Roster }
PushSumAggregate.Share { epochId: String, value: double, weight: double }
PushSumAggregate.Extremum { epochId: String, max: boolean, value: double }
PushSumAggregate.Histogram { epochId: String, lo: double, hi: double, buckets: list<double> }
PushSumAggregate.Roster { epochId: String, members: list<long> }
";

/// The advertisement type tags of a stored advertisement, each the name of its record schema
/// (Java `AdCache.AD_TYPES`).
pub const AD_RECORDS: [&str; 8] = [
    "PeerAdvertisement",
    "GroupAdvertisement",
    "SpaceAdvertisement",
    "CapabilityAdvertisement",
    "AgentCard",
    "AssetCard",
    "ModelCard",
    "AppCard",
];

/// The kinds an `AppCard` connects as (SPEC §6.1a.2, v0.1.32), a closed set.
pub const APP_KINDS: [&str; 4] = ["peer", "fed", "gateway", "assembled"];
/// The shapes of an `AppCard`, a closed set.
pub const APP_SHAPES: [&str; 4] = ["web", "desktop", "static", "a2ui"];
/// The transports of an `AppCard.Ui`, a closed set.
pub const APP_TRANSPORTS: [&str; 2] = ["views", "a2a"];
/// The sign-on values of an `AppCard.Host` (SPEC §6.1a.4, v0.1.32), a closed set.
pub const HOST_SIGN_ONS: [&str; 2] = ["idp", "none"];
/// The status values of an `AppCard.Host`, a closed set.
pub const HOST_STATUSES: [&str; 2] = ["serving", "stopped"];
/// The roles of a ui component (SPEC §6.1a.3), a closed set.
pub const UI_ROLES: [&str; 3] = ["panel", "control", "row"];
/// The spill set of an `AppCard`, in field order (SPEC §6.1a.5).
pub const APP_CARD_SPILL_SET: [&str; 4] = ["reads", "actions", "views", "ui"];
/// The spill set of an `AgentCard`, in field order (SPEC §6.1a.5).
pub const AGENT_CARD_SPILL_SET: [&str; 2] = ["actions", "ui"];

/// The most terms an `AppCard`'s lists carry (`AppCard.MAX_TERMS`).
pub const APP_MAX_TERMS: usize = 64;
/// The most entries an `AppCard`'s `formats` holds.
pub const APP_MAX_FORMATS: usize = 16;
/// The longest `formats` entry, in UTF-16 code units.
pub const APP_MAX_FORMAT_UNITS: usize = 256;
/// The most components a ui declaration carries (`UiDeclaration.MAX_COMPONENTS`).
pub const UI_MAX_COMPONENTS: usize = 32;
/// The most controls a ui component names (`UiDeclaration.MAX_CONTROLS`).
pub const UI_MAX_CONTROLS: usize = 16;
/// The most entry types a ui declaration names per list (`UiDeclaration.MAX_ENTRIES`).
pub const UI_MAX_ENTRIES: usize = 64;
/// The most actions an `AgentCard` declares (`AgentCard.MAX_ACTIONS`).
pub const CARD_MAX_ACTIONS: usize = 64;
/// The longest action description, in UTF-16 code units (`CardAction.MAX_DESCRIPTION_LENGTH`).
pub const ACTION_MAX_DESCRIPTION_UNITS: usize = 512;
/// The most terms per list of an action contract (`CardAction.MAX_CONTRACT_TERMS`).
pub const CONTRACT_MAX_TERMS: usize = 32;
/// The longest cost hint of an action contract, in UTF-16 code units.
pub const CONTRACT_MAX_COST_UNITS: usize = 64;
/// The most evaluations a `ModelCard` carries (`ModelCard.MAX_EVALS`).
pub const MODEL_MAX_EVALS: usize = 64;
/// The largest `CardSpill.size`, 2^53 - 1 (SPEC §6.1a.5).
pub const SPILL_MAX_SIZE: i64 = (1 << 53) - 1;

// ---------------------------------------------------------------------------------------------
// The schema table

/// What a field holds (rule P2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// `int` (primitive) or `Integer` (boxed): a plain integer within a Java `int`.
    Int { primitive: bool },
    /// `long` or `Long`: a plain integer within a Java `long`.
    Long { primitive: bool },
    /// `double`: a float64, never null.
    Double,
    /// `boolean`: `F4` or `F5`, never null.
    Boolean,
    /// `String`: text.
    Text,
    /// `bytes`: a byte string.
    Bytes,
    /// `PeerId`, `GroupId`, `SpaceId`, `EntryId`: non-empty text.
    Id,
    /// `AgentId`: text under Java's `AgentId` grammar (R5).
    AgentId,
    /// `HlcTimestamp`: a canonical stamp.
    Stamp,
    /// `Instant`: text as `ISO_INSTANT` prints it.
    Instant,
    /// `Duration`: text as `Duration.toString` prints it.
    Duration,
    /// An enum: text holding one of the names.
    Enum(Vec<String>),
    /// `list<X>`.
    List(Box<Kind>),
    /// `set<X>`: distinct elements in the order of their encodings.
    Set(Box<Kind>),
    /// `map<String,X>`: text keys in the RFC 8949 order, values never null.
    Map(Box<Kind>),
    /// `PRef.attrs` under rule R1: text values, any item under `pdt.issued` and `pdt.issuer`.
    RefAttrs,
    /// A nested record.
    Record(String),
}

impl Kind {
    fn primitive(&self) -> bool {
        matches!(
            self,
            Kind::Int { primitive: true }
                | Kind::Long { primitive: true }
                | Kind::Double
                | Kind::Boolean
        )
    }
}

/// When a field appears (rule P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// Always present, a null written `F6`.
    Always,
    /// Omitted when null (`?null`).
    OmitNull,
    /// Omitted when null or empty (`?empty`).
    OmitEmpty,
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    kind: Kind,
    presence: Presence,
}

/// The parsed [`SCHEMAS`], by record name.
fn schemas() -> &'static HashMap<String, Vec<Field>> {
    static TABLE: OnceLock<HashMap<String, Vec<Field>>> = OnceLock::new();
    TABLE.get_or_init(|| parse_schemas(SCHEMAS))
}

/// Parses schema lines (see [`SCHEMAS`]). The text is this module's own constant, so a line that
/// does not parse is skipped rather than reported; the tests prove every line parses.
fn parse_schemas(text: &str) -> HashMap<String, Vec<Field>> {
    let mut table = HashMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((name, body)) = line.split_once(" { ") else {
            continue;
        };
        let Some(body) = body.strip_suffix(" }") else {
            continue;
        };
        let fields = split_top(body)
            .into_iter()
            .filter_map(|part| {
                let (field, kind) = part.split_once(": ")?;
                let (kind, presence) = if let Some(kind) = kind.strip_suffix(" ?null") {
                    (kind, Presence::OmitNull)
                } else if let Some(kind) = kind.strip_suffix(" ?empty") {
                    (kind, Presence::OmitEmpty)
                } else {
                    (kind, Presence::Always)
                };
                let kind = if name == "PRef" && field == "attrs" {
                    Kind::RefAttrs
                } else {
                    parse_kind(kind)
                };
                Some(Field {
                    name: field.to_owned(),
                    kind,
                    presence,
                })
            })
            .collect();
        table.insert(name.to_owned(), fields);
    }
    table
}

/// `text` split at each `,` outside angle and square brackets, each part trimmed.
fn split_top(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (index, char) in text.char_indices() {
        match char {
            '<' | '[' => depth += 1,
            '>' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

fn parse_kind(text: &str) -> Kind {
    if let Some(rest) = text.strip_prefix("enum ") {
        let names = rest
            .split_once('[')
            .and_then(|(_, names)| names.strip_suffix(']'))
            .unwrap_or_default();
        return Kind::Enum(names.split(',').map(str::to_owned).collect());
    }
    if let Some(inner) = text.strip_prefix("list<").and_then(|t| t.strip_suffix('>')) {
        return Kind::List(Box::new(parse_kind(inner)));
    }
    if let Some(inner) = text.strip_prefix("set<").and_then(|t| t.strip_suffix('>')) {
        return Kind::Set(Box::new(parse_kind(inner)));
    }
    if let Some(inner) = text
        .strip_prefix("map<String,")
        .and_then(|t| t.strip_suffix('>'))
    {
        return Kind::Map(Box::new(parse_kind(inner)));
    }
    match text {
        "int" => Kind::Int { primitive: true },
        "Integer" => Kind::Int { primitive: false },
        "long" => Kind::Long { primitive: true },
        "Long" => Kind::Long { primitive: false },
        "double" => Kind::Double,
        "boolean" => Kind::Boolean,
        "String" => Kind::Text,
        "bytes" => Kind::Bytes,
        "PeerId" | "GroupId" | "SpaceId" | "EntryId" => Kind::Id,
        "AgentId" => Kind::AgentId,
        "HlcTimestamp" => Kind::Stamp,
        "Instant" => Kind::Instant,
        "Duration" => Kind::Duration,
        record => Kind::Record(record.to_owned()),
    }
}

/// Whether `name` is a record this module knows.
pub fn is_record(name: &str) -> bool {
    schemas().contains_key(name)
}

/// The record names this module knows, in no particular order.
pub fn record_names() -> impl Iterator<Item = &'static str> {
    schemas().keys().map(String::as_str)
}

// ---------------------------------------------------------------------------------------------
// The receiver's procedure

/// The value `bytes` hold when they are one item in the wire encoding ([`cbor::decode`], S1 to
/// S12) that re-encodes to exactly those bytes (rule F3), else `None`. A float32 is refused here,
/// since the encoder writes every float as a float64: no protocol field holds one.
pub fn load_canonical(bytes: &[u8]) -> Option<Value> {
    let value = cbor::decode(bytes).ok()?;
    (cbor::encode(&value) == bytes).then_some(value)
}

/// The protocol record `record` that `bytes` hold, or `None` when they hold no such record in the
/// wire encoding: an item rule, a record rule, a rule of the record's Java constructor, or the
/// canonical-bytes rule fails (SPEC §9.1, rules F1 and F3). An unknown record name is `None`.
pub fn decode(bytes: &[u8], record: &str) -> Option<Value> {
    let value = load_canonical(bytes)?;
    conforms(&value, record).then_some(value)
}

/// [`decode`], as the record's map.
pub fn decode_map(bytes: &[u8], record: &str) -> Option<Map> {
    decode(bytes, record)?.into_map()
}

/// Whether a decoded `value` is the protocol record `record` under rules P1 to P4: exactly the
/// schema's fields in its order, each present as its presence rule says and of its kind, and a
/// record Java's constructor holds. An unknown record name conforms to nothing.
pub fn conforms(value: &Value, record: &str) -> bool {
    let (Some(map), Some(fields)) = (value.as_map(), schemas().get(record)) else {
        return false;
    };
    let mut entries = map.iter().peekable();
    for field in fields {
        let next = entries
            .peek()
            .filter(|(key, _)| key.as_str() == Some(field.name.as_str()));
        let Some((_, item)) = next else {
            if field.presence == Presence::Always {
                return false;
            }
            continue;
        };
        if item.is_null() {
            if field.presence != Presence::Always || field.kind.primitive() {
                return false;
            }
        } else if !holds(&field.kind, item)
            || (field.presence == Presence::OmitEmpty
                && item.as_array().is_some_and(<[Value]>::is_empty))
        {
            return false;
        }
        entries.next();
    }
    entries.next().is_none() && invariant(record, map)
}

/// Whether a present, non-null `value` holds `kind`.
fn holds(kind: &Kind, value: &Value) -> bool {
    match kind {
        Kind::Int { .. } => matches!(value, Value::Int(v) if i32::try_from(*v).is_ok()),
        Kind::Long { .. } => matches!(value, Value::Int(v) if i64::try_from(*v).is_ok()),
        Kind::Double => matches!(value, Value::Float(_)),
        Kind::Boolean => matches!(value, Value::Bool(_)),
        Kind::Text => matches!(value, Value::Text(_)),
        Kind::Bytes => matches!(value, Value::Bytes(_)),
        Kind::Id => value.as_str().is_some_and(|text| !text.is_empty()),
        Kind::AgentId => value
            .as_str()
            .is_some_and(|text| ids::parse_agent_id(text).is_some()),
        Kind::Stamp => value.as_str().and_then(Stamp::parse).is_some(),
        Kind::Instant => value.as_str().is_some_and(time::is_canonical_instant),
        Kind::Duration => value.as_str().is_some_and(time::is_canonical_duration),
        Kind::Enum(names) => value
            .as_str()
            .is_some_and(|text| names.iter().any(|name| name == text)),
        Kind::List(inner) => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| element(inner, item))),
        Kind::Set(inner) => value.as_array().is_some_and(|items| {
            items.iter().all(|item| element(inner, item)) && {
                let encoded: Vec<Vec<u8>> = items.iter().map(cbor::encode).collect();
                encoded
                    .windows(2)
                    .all(|pair| (pair[0].len(), &pair[0]) < (pair[1].len(), &pair[1]))
            }
        }),
        Kind::Map(inner) => value.as_map().is_some_and(|map| {
            in_canonical_order(map) && map.values().all(|item| element(inner, item))
        }),
        Kind::RefAttrs => value.as_map().is_some_and(|map| {
            in_canonical_order(map)
                && map.iter().all(|(key, item)| {
                    matches!(key.as_str(), Some("pdt.issued" | "pdt.issuer"))
                        || matches!(item, Value::Text(_))
                })
        }),
        Kind::Record(name) => conforms(value, name),
    }
}

/// A list, set, or map element: never null, and of its kind.
fn element(kind: &Kind, item: &Value) -> bool {
    !item.is_null() && holds(kind, item)
}

/// Whether a map's keys are text in the RFC 8949 order of wire version 3: the shorter UTF-8 key
/// first, then bytewise, each key once.
fn in_canonical_order(map: &Map) -> bool {
    let keys: Option<Vec<&str>> = map.keys().map(Value::as_str).collect();
    keys.is_some_and(|keys| {
        keys.windows(2)
            .all(|pair| (pair[0].len(), pair[0].as_bytes()) < (pair[1].len(), pair[1].as_bytes()))
    })
}

// ---------------------------------------------------------------------------------------------
// What the Java constructors refuse

/// The records whose Java constructor refuses, or replaces with a default, a null in any field
/// that is always present: either way Java refuses the carrier (a thrown constructor, or a
/// re-encoding that differs from the bytes received).
const NO_NULL_RECORDS: [&str; 26] = [
    "AgentCard",
    "AppCard",
    "AppCard.Ui",
    "AppCard.Host",
    "AppCard.Origin",
    "AppCard.Parts",
    "CardSpill",
    "AssetCard",
    "CapabilityAdvertisement",
    "GroupAdvertisement",
    "GroupAdvertisement.GossipParameters",
    "ModelCard",
    "PeerAdvertisement",
    "PeerAdvertisement.Endpoint",
    "SpaceAdvertisement",
    "CardAction",
    "CardAction.Contract",
    "UiDeclaration",
    "UiDeclaration.Component",
    "UiDeclaration.Entries",
    "AgentCertificate",
    "TakeClaim",
    "LeaseInfo",
    "Dot",
    "CredentialRevocation",
    "RevocationAdvertisement",
];

/// The fields of a record in [`NO_NULL_RECORDS`] that Java keeps null.
const NULLABLE_FIELDS: [(&str, &str); 1] = [("RevocationAdvertisement", "successor")];

/// Whether `map`, which holds the fields of `record` with their kinds, is a record Java's
/// constructor holds.
fn invariant(record: &str, map: &Map) -> bool {
    if NO_NULL_RECORDS.contains(&record)
        && map.iter().any(|(key, value)| {
            value.is_null()
                && !key
                    .as_str()
                    .is_some_and(|key| NULLABLE_FIELDS.contains(&(record, key)))
        })
    {
        return false;
    }
    match record {
        "Envelope" => ["group", "kind", "from", "stamp", "body"]
            .iter()
            .all(|field| present(map, field)),
        "EntryRecord" => entry_record_holds(map),
        "LeaseInfo" => long(map, "expiresAtMillis").is_some_and(|expires| expires > 0),
        "Dot" => long(map, "counter").is_some_and(|counter| counter > 0),
        "TakeClaim" => {
            long(map, "epoch").is_some_and(|epoch| epoch >= 1)
                && map
                    .get("bid")
                    .and_then(Value::as_f64)
                    .is_some_and(f64::is_finite)
        }
        "AgentCertificate" => {
            map.get("ttl").and_then(Value::as_str) != Some("PT0S")
                && map
                    .get("encryptionPublicKey")
                    .and_then(Value::as_bytes)
                    .is_none_or(|key| key.len() == 32)
        }
        "AgentCard" => agent_card_holds(map),
        "AgentCard.Parts" => list(map, "actions").len() <= CARD_MAX_ACTIONS,
        "CardAction" => card_action_holds(map),
        "CardAction.Contract" => {
            ["pre", "post", "methods"]
                .iter()
                .all(|field| list(map, field).len() <= CONTRACT_MAX_TERMS)
                && units(text(map, "cost")) <= CONTRACT_MAX_COST_UNITS
        }
        "UiDeclaration" => ui_declaration_holds(map),
        "UiDeclaration.Component" => component_holds(map),
        "UiDeclaration.Entries" => {
            list(map, "reads").len() <= UI_MAX_ENTRIES
                && list(map, "writes").len() <= UI_MAX_ENTRIES
        }
        "AppCard" => app_card_holds(map),
        "AppCard.Ui" => app_ui_holds(map),
        "AppCard.Host" => host_holds(map),
        "AppCard.Origin" => origin_holds(map),
        "AppCard.Parts" => ["reads", "actions", "views"]
            .iter()
            .all(|field| list(map, field).len() <= APP_MAX_TERMS),
        "CardSpill" => spill_holds(map),
        // Java reads a null or blank reason as `unspecified`, so only a known reason re-encodes
        // to the bytes received.
        "CredentialRevocation" => {
            crate::revocation::REASONS.contains(&text(map, "reason"))
                && ["id", "issuer", "group", "issued", "ttl"]
                    .iter()
                    .all(|field| present(map, field))
        }
        "ModelCard" => {
            map.get("evals").and_then(Value::as_map).map_or(0, Map::len) <= MODEL_MAX_EVALS
        }
        name if AD_RECORDS.contains(&name) || name == "RevocationAdvertisement" => {
            ["id", "issuer", "group", "issued", "ttl"]
                .iter()
                .all(|field| present(map, field))
        }
        _ => true,
    }
}

fn present(map: &Map, field: &str) -> bool {
    map.get(field).is_some_and(|value| !value.is_null())
}

fn long(map: &Map, field: &str) -> Option<i64> {
    map.get(field).and_then(Value::as_i64)
}

fn text<'a>(map: &'a Map, field: &str) -> &'a str {
    map.get(field).and_then(Value::as_str).unwrap_or_default()
}

fn list<'a>(map: &'a Map, field: &str) -> &'a [Value] {
    map.get(field).and_then(Value::as_array).unwrap_or_default()
}

/// The texts of a list field (its non-text items skipped; the kinds were checked already).
fn texts<'a>(map: &'a Map, field: &str) -> Vec<&'a str> {
    list(map, field).iter().filter_map(Value::as_str).collect()
}

/// The length of `text` in UTF-16 code units, as Java's `String.length()` counts it.
pub(crate) fn units(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Java's `String.isBlank`: empty, or only characters `Character.isWhitespace` names.
pub(crate) fn java_blank(text: &str) -> bool {
    text.chars().all(|c| {
        matches!(
            c,
            '\t' | '\n'
                | '\u{B}'
                | '\u{C}'
                | '\r'
                | '\u{1C}'..='\u{1F}'
                | ' '
                | '\u{1680}'
                | '\u{2000}'..='\u{2006}'
                | '\u{2008}'..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{205F}'
                | '\u{3000}'
        )
    })
}

/// A control character: U+0000 to U+001F, or U+007F.
fn has_control(text: &str) -> bool {
    text.chars().any(|c| c <= '\u{1F}' || c == '\u{7F}')
}

/// A control character or a code unit of the Unicode White_Space property, as Java's
/// `AppCard.hasWhitespaceOrControl` lists them.
fn has_whitespace_or_control(text: &str) -> bool {
    text.chars().any(|c| {
        c <= ' '
            || matches!(
                c,
                '\u{7F}' | '\u{85}' | '\u{A0}' | '\u{1680}' | '\u{2000}'
                    ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
            )
    })
}

/// Whether no text repeats in `items`.
fn distinct(items: &[&str]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    items.iter().all(|item| seen.insert(*item))
}

fn entry_record_holds(map: &Map) -> bool {
    let payload = map.get("payload").filter(|value| !value.is_null());
    let reference = map.get("payloadRef").filter(|value| !value.is_null());
    [
        "entryId", "spaceId", "type", "issuer", "issued", "lease", "tags",
    ]
    .iter()
    .all(|field| present(map, field))
        && (payload.is_some() != reference.is_some())
        && payload
            .and_then(Value::as_bytes)
            .is_none_or(|payload| payload.len() <= INLINE_PAYLOAD_LIMIT)
        && long(map, "keyEpoch").is_none_or(|epoch| epoch >= 1)
}

fn card_action_holds(map: &Map) -> bool {
    !text(map, "name").is_empty() && units(text(map, "description")) <= ACTION_MAX_DESCRIPTION_UNITS
}

fn agent_card_holds(map: &Map) -> bool {
    let actions = map.get("actions").and_then(Value::as_array);
    if let Some(actions) = actions {
        let names: Vec<&str> = actions
            .iter()
            .filter_map(|action| action.get("name").and_then(Value::as_str))
            .collect();
        if actions.len() > CARD_MAX_ACTIONS || !distinct(&names) {
            return false;
        }
    }
    // A certificate certifies exactly the card's agent and agentPublicKey.
    if let Some(certificate) = map.get("agentCertificate").and_then(Value::as_map) {
        let key = map.get("agentPublicKey").and_then(Value::as_bytes);
        if key.is_none()
            || key != certificate.get("agentPublicKey").and_then(Value::as_bytes)
            || certificate.get("agent") != map.get("agent")
        {
            return false;
        }
    }
    if let Some(spill) = map.get("spill").and_then(Value::as_map)
        && (!parts_within(&texts(spill, "parts"), &AGENT_CARD_SPILL_SET)
            || map.contains_key("actions")
            || map.contains_key("ui"))
    {
        return false;
    }
    // Every control of the ui names an action of the card.
    if let Some(ui) = map.get("ui").and_then(Value::as_map) {
        let names: Vec<&str> = actions
            .into_iter()
            .flatten()
            .filter_map(|action| action.get("name").and_then(Value::as_str))
            .collect();
        let controls_known = list(ui, "components").iter().all(|component| {
            component
                .get("controls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .all(|control| names.contains(&control))
        });
        if !controls_known {
            return false;
        }
    }
    true
}

fn ui_declaration_holds(map: &Map) -> bool {
    let components = list(map, "components");
    let ids: Vec<&str> = components
        .iter()
        .filter_map(|component| component.get("id").and_then(Value::as_str))
        .collect();
    // Java derives empty catalogIds from the components, so an empty list beside components
    // re-encodes otherwise.
    let derived_empty = components.is_empty() || !list(map, "catalogIds").is_empty();
    !java_blank(text(map, "protocol"))
        && !java_blank(text(map, "version"))
        && components.len() <= UI_MAX_COMPONENTS
        && distinct(&ids)
        && derived_empty
}

fn component_holds(map: &Map) -> bool {
    ["id", "catalogId", "component"]
        .iter()
        .all(|field| !java_blank(text(map, field)))
        && UI_ROLES.contains(&text(map, "role"))
        && list(map, "controls").len() <= UI_MAX_CONTROLS
}

fn app_card_holds(map: &Map) -> bool {
    if java_blank(text(map, "name")) || java_blank(text(map, "version")) {
        return false;
    }
    if !APP_KINDS.contains(&text(map, "kind")) || !APP_SHAPES.contains(&text(map, "shape")) {
        return false;
    }
    if ["reads", "actions", "views"]
        .iter()
        .any(|field| list(map, field).len() > APP_MAX_TERMS)
    {
        return false;
    }
    if let Some(formats) = map.get("formats").and_then(Value::as_array) {
        let formats: Vec<&str> = formats.iter().filter_map(Value::as_str).collect();
        if !formats_hold(&formats) {
            return false;
        }
    }
    let spill = map.get("spill").and_then(Value::as_map);
    let has_ui = map.contains_key("ui");
    if let Some(spill) = spill {
        let placeholders = ["reads", "actions", "views"]
            .iter()
            .all(|field| list(map, field).is_empty())
            && !has_ui;
        if !parts_within(&texts(spill, "parts"), &APP_CARD_SPILL_SET) || !placeholders {
            return false;
        }
    }
    let ui_spilled = spill.is_some_and(|spill| texts(spill, "parts").contains(&"ui"));
    !(text(map, "shape") == "a2ui" && !has_ui && !ui_spilled)
}

fn app_ui_holds(map: &Map) -> bool {
    !java_blank(text(map, "protocol"))
        && !java_blank(text(map, "version"))
        && APP_TRANSPORTS.contains(&text(map, "transport"))
        && list(map, "catalogIds").len() <= APP_MAX_TERMS
        && list(map, "surfaces").len() <= APP_MAX_TERMS
        && list(map, "components").len() <= UI_MAX_COMPONENTS
}

fn host_holds(map: &Map) -> bool {
    !java_blank(text(map, "url"))
        && long(map, "port").is_some_and(|port| (0..=65_535).contains(&port))
        && !java_blank(text(map, "path"))
        && HOST_SIGN_ONS.contains(&text(map, "signOn"))
        && HOST_STATUSES.contains(&text(map, "status"))
}

/// `AppCard.Origin` (SPEC §6.1a.2): the system's grammar, the ref's and version's bounds, and 1
/// to 8 attributes keyed under the system.
fn origin_holds(map: &Map) -> bool {
    let (system, reference, version) =
        (text(map, "system"), text(map, "ref"), text(map, "version"));
    if !origin_system(system)
        || !(1..=256).contains(&units(reference))
        || has_control(reference)
        || units(version) > 64
        || has_control(version)
    {
        return false;
    }
    let Some(attrs) = map.get("attrs") else {
        return true;
    };
    let Some(attrs) = attrs.as_map() else {
        return false;
    };
    let prefix = format!("{system}.");
    (1..=8).contains(&attrs.len())
        && attrs.iter().all(|(key, value)| {
            let (Some(key), Some(value)) = (key.as_str(), value.as_str()) else {
                return false;
            };
            units(key) <= 128
                && key.strip_prefix(&prefix).is_some_and(|tail| {
                    !tail.is_empty()
                        && tail.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                        })
                })
                && units(value) <= 256
                && !has_control(value)
        })
}

/// `[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?`: 1 to 64 of `[a-z0-9.-]`, starting and ending with a
/// letter or digit.
fn origin_system(system: &str) -> bool {
    let bytes = system.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes.iter().all(|b| edge(b) || *b == b'.' || *b == b'-')
}

/// `formats` (SPEC §6.1a.2): 1 to 16 distinct entries, each a lower-case media type without a
/// parameter or a vocabulary IRI with a scheme and no whitespace or control character.
pub fn formats_hold(formats: &[&str]) -> bool {
    (1..=APP_MAX_FORMATS).contains(&formats.len())
        && distinct(formats)
        && formats.iter().all(|entry| {
            (1..=APP_MAX_FORMAT_UNITS).contains(&units(entry))
                && match entry.split_once(':') {
                    None => media_type(entry),
                    Some((scheme, _)) => iri_scheme(scheme) && !has_whitespace_or_control(entry),
                }
        })
}

/// `[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}`: a media type under the
/// restricted names of RFC 6838 §4.2, lower-case, with no parameter.
fn media_type(entry: &str) -> bool {
    let name = |part: &str| {
        let bytes = part.as_bytes();
        (1..=127).contains(&bytes.len())
            && bytes
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(b))
    };
    entry
        .split_once('/')
        .is_some_and(|(kind, subtype)| name(kind) && name(subtype))
}

/// `[a-z][a-z0-9+.-]*`: the scheme of an IRI (RFC 3987 §2.2).
fn iri_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
}

/// `CardSpill` (SPEC §6.1a.5): a content root, a size from 1 to 2^53 - 1, and one or more
/// distinct parts.
fn spill_holds(map: &Map) -> bool {
    let parts = texts(map, "parts");
    is_content_root(text(map, "root"))
        && long(map, "size").is_some_and(|size| (1..=SPILL_MAX_SIZE).contains(&size))
        && !parts.is_empty()
        && distinct(&parts)
}

/// Every name in the kind's spill set, in the set's field order.
fn parts_within(parts: &[&str], spill_set: &[&str]) -> bool {
    let at: Option<Vec<usize>> = parts
        .iter()
        .map(|part| spill_set.iter().position(|name| name == part))
        .collect();
    at.is_some_and(|at| at.windows(2).all(|pair| pair[0] < pair[1]))
}

/// The length of a content root's text: `b` and the base32 of a 36-byte CIDv1.
pub const CONTENT_ROOT_LENGTH: usize = 59;

/// The CIDv1 prefix of a content root: version 1, codec raw (0x55), multihash sha2-256 (0x12),
/// 32 bytes (0x20).
const CONTENT_ROOT_PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

/// Whether `text` is a content root as `CardSpill.root` holds it (SPEC §6.1a.5, Java
/// `CardSpill.isRoot`): `b`, then the lower-case base32 (RFC 4648, no padding, zero pad bits) of
/// a CIDv1 with codec raw (0x55) and a sha2-256 multihash, [`CONTENT_ROOT_LENGTH`] characters in
/// all.
pub fn is_content_root(text: &str) -> bool {
    let Some(body) = text.strip_prefix('b') else {
        return false;
    };
    if text.len() != CONTENT_ROOT_LENGTH {
        return false;
    }
    base32_decode(body).is_some_and(|cid| {
        cid.len() == CONTENT_ROOT_PREFIX.len() + 32 && cid.starts_with(&CONTENT_ROOT_PREFIX)
    })
}

/// The bytes of lower-case unpadded base32 (RFC 4648 alphabet `a-z2-7`), or `None` when a
/// character lies outside the alphabet or the pad bits are not zero.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    // The leftover bits are padding: fewer than five, and all zero.
    (bits < 5 && buffer & ((1 << bits) - 1) == 0).then_some(out)
}

/// The lower-case unpadded base32 text of `bytes` (RFC 4648 alphabet `a-z2-7`).
pub(crate) fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_schema_line_parses() {
        let lines = SCHEMAS
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(schemas().len(), lines);
        for (name, fields) in schemas() {
            assert!(!fields.is_empty(), "{name}");
            for field in fields {
                if let Kind::Record(inner) = &field.kind {
                    assert!(is_record(inner), "{name}.{}: {inner}", field.name);
                }
                if let Kind::List(inner) | Kind::Set(inner) | Kind::Map(inner) = &field.kind
                    && let Kind::Record(inner) = inner.as_ref()
                {
                    assert!(is_record(inner), "{name}.{}: {inner}", field.name);
                }
            }
        }
        for record in AD_RECORDS {
            assert!(is_record(record), "{record}");
        }
    }

    #[test]
    fn base32_round_trips_and_refuses_pad_bits() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let text = base32_encode(bytes);
            assert_eq!(base32_decode(&text).as_deref(), Some(bytes), "{text}");
        }
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        // "mzxw6ytbop" sets a pad bit of the last character.
        assert_eq!(base32_decode("mzxw6ytbop"), None);
        assert_eq!(base32_decode("MZXW6YTBOI"), None);
    }

    #[test]
    fn a_record_holds_exactly_its_fields_in_order() {
        let mut ping = Map::new();
        ping.insert("nonce", 7);
        assert!(conforms(&Value::Map(ping.clone()), "Bodies.Ping"));
        ping.insert("root", Value::Null);
        assert!(
            !conforms(&Value::Map(ping), "Bodies.Ping"),
            "root is omitted when null"
        );
        let mut ack = Map::new();
        ack.insert("nonce", 7);
        ack.insert("onBehalf", Value::Null);
        assert!(conforms(&Value::Map(ack.clone()), "Bodies.Ack"));
        let mut swapped = Map::new();
        swapped.insert("onBehalf", Value::Null);
        swapped.insert("nonce", 7);
        assert!(!conforms(&Value::Map(swapped), "Bodies.Ack"));
        let mut float = Map::new();
        float.insert("nonce", 7.0);
        assert!(!conforms(&Value::Map(float), "Bodies.Ping"));
        assert!(!conforms(&Value::Map(ack), "No.Such.Record"));
    }

    #[test]
    fn formats_follow_their_grammar() {
        assert!(formats_hold(&["text/html", "https://schema.org/"]));
        assert!(formats_hold(&["application/ld+json"]));
        for bad in [
            &["Text/html"][..],
            &["text/html; charset=utf-8"],
            &["text/html", "text/html"],
            &[],
            &["text"],
            &["1http://x"],
            &["http://a b"],
        ] {
            assert!(!formats_hold(bad), "{bad:?}");
        }
        let many: Vec<String> = (0..17).map(|i| format!("text/x{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(!formats_hold(&many));
        assert!(formats_hold(&many[..16]));
    }

    #[test]
    fn origin_systems_follow_their_grammar() {
        for good in ["console", "realm", "org.example.apps", "a", "a-1"] {
            assert!(origin_system(good), "{good}");
        }
        for bad in ["", "-a", "a-", "A", "a_b", &"a".repeat(65)] {
            assert!(!origin_system(bad), "{bad}");
        }
    }

    #[test]
    fn java_blank_is_javas() {
        assert!(java_blank(""));
        assert!(java_blank(" \t\u{1C}\u{2028}"));
        assert!(!java_blank("\u{A0}"));
        assert!(!java_blank("\u{2007}"));
        assert!(!java_blank(" a "));
    }
}
