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

//! Space records, their state transitions, and take claims (SPEC §7, §11a; TECH-SPEC §7.2, §7.4,
//! §7.6), a port of the space-write and take-claim half of `wire.py`, with Java
//! `ReplicatedSpace`, `SpaceWire`, and `TakeClaim` as the authority on bytes and order.
//!
//! - A *record* (`EntryRecord`) is an entry's immutable identity: id, space, type, payload (or a
//!   payload reference), issuer, issue stamp, write lease, tags, signature, and, for a record
//!   sealed under a content-key epoch from 1, `keyEpoch`. The issuer signs its *sign view*
//!   ([`sign_view`], [`sign_view_of`]); [`verify_record`] is TECH-SPEC §7.2's two-key rule.
//! - A *state* (`EntryStateDto`) carries a record with its mutable CRDT fields (dots, lease,
//!   completion). The actor signs the *state sign view* ([`state_sign_view`], [`sign_state`]),
//!   and [`verify_state_signature`] judges that signature for the party a transition needs.
//! - A *delta* is the rumor payload `{state, claimEntry, claim}` ([`delta`], [`entry_delta`],
//!   [`claim_delta`]).
//! - A *take claim* (`TakeClaim`) is a holder's signed bid for an entry ([`take_claim`],
//!   [`signed_claim`], [`verify_claim_proof`]); claims merge by the lattice order of SPEC §7.4
//!   ([`claim_sort_key`], [`merge_claims`]).
//! - A record's payload is inline, or a block (`z...`) or content root (`b...`) it references
//!   ([`payload_source`], [`block_cid`]).
//!
//! Every map lists its keys in the Java record's field order, because the signatures cover the
//! CBOR and byte order is meaning; tags, the one map-valued field, are written in canonical order.
//!
//! # Canonical forms
//!
//! Java decodes every signed object into its typed record and verifies the signature over its
//! *own re-encoding* (`verifyClaim`'s `codec.toBytes(claim)`, `signableBytes`, `stateSignBytes`).
//! The verifiers here judge the decoded map they are given, so they accept an object only when
//! it already is the form Java writes back, and both sides then verify the same bytes:
//!
//! - a claim: exactly the seven `TakeClaim` fields in order, the bid a CBOR double
//!   ([`claim_is_canonical`]);
//! - every signed stamp (`issued`, a claim's `stamp`, `leaseStamp`, `signedAt`) in canonical
//!   form ([`crate::hlc::Stamp::parse_canonical`]: no `+`, no leading zeros);
//! - every agent id (a record's `issuer`, a claim's `holder`, a lease's `holder`) a Java `AgentId`
//!   ([`crate::ids::parse_agent_id`]: `<peerId>/<localName>`, the local name non-empty and free
//!   of `/`);
//! - a state's `leaseValue` exactly `{holder, expiresAtMillis, kind}` and each dot exactly
//!   `{replica, counter}`; a record's tags text to text ([`sign_view_of`],
//!   [`state_sign_view_of`]);
//! - a record Java can decode at all ([`record_is_well_formed`]: tags present, exactly one of
//!   `payload` and `payloadRef`, a `LeaseInfo` lease).
//!
//! A hostile member could otherwise sign a non-canonical object that these verifiers admit and
//! every Java replica refuses (an integer bid that wins the claim lattice here only), splitting a
//! mixed group for good. Honest builders here and in Java, Python, and Ruby emit only canonical
//! forms, so nothing honest is refused; a Java replica forwards the canonical form of anything it
//! accepted, so a replica here still converges. The Python and Ruby verifiers share the old
//! leniency and need the same fix.
//!
//! The module is sans-IO and has no clock: every hybrid logical clock stamp
//! (`physical:logical:node`) and every time is an argument, drawn by the caller from its own HLC.
//! Stamps are parsed as Java `HlcTimestamp.parse` parses them ([`crate::hlc::Stamp::parse`]: a
//! non-negative `long`, a non-negative `int`, and a non-empty node without `:`), so a stamp Java
//! could not decode never verifies. Every judgment of untrusted input returns `bool` or `Option`
//! and never panics.
#![warn(missing_docs)]

use std::cmp::Ordering;

use crate::cbor::{self, Map, Value};
use crate::crypto::KEY_LENGTH;
use crate::hlc::Stamp;
use crate::identity::{AgentIdentity, Identity, verify_agent_certificate_covering};
use crate::ids;
use crate::limits::{
    INLINE_PAYLOAD_LIMIT, MAX_CLAIM_EPOCH_JUMP, MAX_CLAIM_HOLD_MILLIS, MAX_DRIFT_MILLIS,
};
use crate::util::{encode_map, field, java_order, non_null, present, text};

/// How far before its entry's issue stamp a claim's stamp may lie (SPEC §7.4, §11; Java
/// `ReplicatedSpace.MAX_CLAIM_PREDATES_ISSUE_MILLIS`): the drift ceiling, since an honest
/// claimant's clock has absorbed the record's stamp unless the writer's clock ran ahead.
pub const MAX_CLAIM_PREDATES_ISSUE_MILLIS: i64 = MAX_DRIFT_MILLIS;

/// The `kind` of the lease a write carries (Java `LeaseKind.WRITE`).
pub const WRITE_LEASE_KIND: &str = "WRITE";

/// The CBOR null (`0xF6`): the payload bytes of a record with neither a payload nor a reference.
pub const NULL_PAYLOAD: [u8; 1] = [0xF6];

/// Why a record, state, or claim could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// A field the signature covers is missing or has the wrong type (`record`, `adds`,
    /// `removes`, `completed`).
    #[error("{field} is missing or has the wrong type")]
    Malformed {
        /// The field.
        field: &'static str,
    },
    /// A stamp is not a hybrid logical clock stamp `physical:logical:node` (`issued`,
    /// `signedAt`, or a claim's `stamp`).
    #[error("{field} is not a hybrid logical clock stamp physical:logical:node")]
    MalformedStamp {
        /// The field the stamp was meant for.
        field: &'static str,
    },
    /// The agent holds no certificate whose window covers the signing stamp, so receivers
    /// everywhere would refuse the signature (Java fails the write the same way).
    #[error("{agent} holds no certificate covering {stamp}")]
    NoCoveringCertificate {
        /// The agent.
        agent: String,
        /// The signing stamp.
        stamp: String,
    },
}

// ---------------------------------------------------------------------------------------------
// Small helpers

/// Whether `agent` is a Java `AgentId` ([`ids::parse_agent_id`]: a non-empty local name free of
/// `/`) of the PeerID `public_key` hashes to. `peer/` and `peer/a/b` are not agents of `peer`:
/// Java cannot decode either, so nothing it signed can name one.
fn issued_by(agent: &str, public_key: &[u8]) -> bool {
    ids::parse_agent_id(agent).is_some_and(|(peer, _)| peer == ids::derive_id(public_key))
}

/// The certificate's agent key, when it carries one as bytes.
fn agent_key(certificate: &Value) -> Option<&[u8]> {
    certificate.get("agentPublicKey").and_then(Value::as_bytes)
}

/// A non-empty text field (Java `EntryId`, `SpaceId`).
fn id_text<'a>(map: &'a Map, name: &str) -> Option<&'a str> {
    text(map, name).filter(|id| !id.is_empty())
}

/// An integer field that fits a positive Java `long`.
fn positive_long(map: &Map, name: &str) -> Option<i64> {
    map.get(name)
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
}

/// The kinds of lease Java `LeaseKind` names.
const LEASE_KINDS: [&str; 2] = [WRITE_LEASE_KIND, "TAKE"];

/// The `(holder, expiresAtMillis, kind)` of a lease Java can decode as a `LeaseInfo`: a map whose
/// holder is an agent id ([`ids::parse_agent_id`]), whose expiry is a positive `long`, and whose
/// kind is `WRITE` or `TAKE`. Other fields are ignored, as Jackson ignores them.
fn lease_fields(lease: &Value) -> Option<(&str, i64, &str)> {
    let map = lease.as_map()?;
    Some((
        text(map, "holder").filter(|holder| ids::parse_agent_id(holder).is_some())?,
        positive_long(map, "expiresAtMillis")?,
        text(map, "kind").filter(|kind| LEASE_KINDS.contains(kind))?,
    ))
}

/// Whether `lease` is a Java `LeaseInfo` written exactly as Java writes one back
/// ([`lease_fields`], and the map is `{holder, expiresAtMillis, kind}` in that order and nothing
/// else): the form a signed `leaseValue` must have.
fn is_canonical_lease(lease: &Value) -> bool {
    lease_fields(lease).is_some_and(|(holder, expires, kind)| {
        *lease
            == crate::cbor_map! {
                "holder" => holder,
                "expiresAtMillis" => expires,
                "kind" => kind,
            }
    })
}

/// Whether `dot` is a Java `Dot` written exactly as Java writes one back: `{replica, counter}` in
/// that order and nothing else, a text replica and a positive `long` counter.
fn is_canonical_dot(dot: &Value) -> bool {
    let Some(map) = dot.as_map() else {
        return false;
    };
    let (Some(replica), Some(counter)) = (text(map, "replica"), positive_long(map, "counter"))
    else {
        return false;
    };
    *dot == crate::cbor_map! { "replica" => replica, "counter" => counter }
}

/// Whether `tags` is a Java `Map<String, String>`: text keys to text values (Java writes them
/// back in canonical order, as [`sign_view`] does, so their order does not matter).
fn is_text_map(tags: &Map) -> bool {
    tags.iter()
        .all(|(key, value)| key.as_str().is_some() && value.as_str().is_some())
}

// ---------------------------------------------------------------------------------------------
// Records

/// Java `ReplicatedSpace.SignView`: the record identity the issuer signs, in field order
/// `entryId, spaceId, type, payload, payloadRef, issuer, issued, tags`, then `keyEpoch` only when
/// given (SPEC §11a.1, v0.1.13: only a record sealed under a content-key epoch from 1 names one,
/// so every other record signs the v0.1.12 bytes).
///
/// `tags` are part of the signed record (SPEC §7.1) and are written in canonical order; `None` is
/// the empty map. `payload_ref` names a block (`z...`) or a content root (`b...`) when the payload
/// travels outside the record, whose `payload` is then `None` (SPEC §7.1).
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per field of the Java SignView record, in its order"
)]
pub fn sign_view(
    entry_id: &str,
    space_id: &str,
    type_name: &str,
    payload: Option<&[u8]>,
    issuer: &str,
    issued: &str,
    key_epoch: Option<i64>,
    tags: Option<&Map>,
    payload_ref: Option<&str>,
) -> Map {
    let mut view = Map::with_capacity(9);
    view.insert("entryId", entry_id);
    view.insert("spaceId", space_id);
    view.insert("type", type_name);
    view.insert("payload", payload);
    view.insert("payloadRef", payload_ref);
    view.insert("issuer", issuer);
    view.insert("issued", issued);
    view.insert("tags", tags.map(cbor::canonical_map).unwrap_or_default());
    if let Some(epoch) = key_epoch {
        view.insert("keyEpoch", epoch);
    }
    view
}

/// The [`sign_view`] of an already-built (or received) record, from its own fields, exactly as
/// Java re-encodes the view of the record it decoded (`ReplicatedSpace.signableBytes`): tags in
/// canonical order (absent or null tags are the empty map), the payload or reference null when
/// absent, and `keyEpoch` appended only when present and not null.
///
/// `None` unless every field has the one form Java writes back, since Java verifies the
/// signature over its typed re-encoding and a verifier here over this view: a non-empty text
/// `entryId` and `spaceId`, a text `type`, a byte-string `payload` and a text `payloadRef` (each
/// may be absent or null), an `issuer` that is a Java `AgentId` ([`ids::parse_agent_id`]), an
/// `issued` stamp in canonical form ([`Stamp::parse_canonical`]: no `+`, no leading zeros), tags
/// of text to text, and a `keyEpoch` that is an integer from 1 that fits a `long`. A record of any
/// other form is one Java cannot decode, or re-encodes to other bytes than it carries, so nothing
/// it signed can match.
pub fn sign_view_of(record: &Map) -> Option<Map> {
    let tags = match present(record, "tags") {
        None => Map::new(),
        Some(tags) => {
            let tags = tags.as_map().filter(|tags| is_text_map(tags))?;
            cbor::canonical_map(tags)
        }
    };
    let optional = |name: &str, kind: fn(&Value) -> bool| match present(record, name) {
        None => Some(Value::Null),
        Some(value) => kind(value).then(|| value.clone()),
    };
    let key_epoch = match present(record, "keyEpoch") {
        None => None,
        Some(epoch) => Some(epoch.as_i64().filter(|epoch| *epoch >= 1)?),
    };
    let mut view = Map::with_capacity(9);
    view.insert("entryId", id_text(record, "entryId")?);
    view.insert("spaceId", id_text(record, "spaceId")?);
    view.insert("type", text(record, "type")?);
    view.insert(
        "payload",
        optional("payload", |value| value.as_bytes().is_some())?,
    );
    view.insert(
        "payloadRef",
        optional("payloadRef", |value| value.as_str().is_some())?,
    );
    view.insert(
        "issuer",
        text(record, "issuer").filter(|issuer| ids::parse_agent_id(issuer).is_some())?,
    );
    view.insert(
        "issued",
        text(record, "issued").filter(|issued| Stamp::parse_canonical(issued).is_some())?,
    );
    view.insert("tags", tags);
    if let Some(epoch) = key_epoch {
        view.insert("keyEpoch", epoch);
    }
    Some(view)
}

/// Whether a received record has the shape Java `EntryRecord` decodes, beyond what
/// [`sign_view_of`] reads (which it also requires): present `tags` (Java requires the map, even
/// an empty one), exactly one of an inline `payload` of at most [`INLINE_PAYLOAD_LIMIT`] bytes and
/// a `payloadRef`, and a `lease` Java decodes as a `LeaseInfo` (an agent holder, a positive
/// expiry, kind `WRITE` or `TAKE`; the lease is not signed, so its field order is free). Java
/// refuses any other record at decode, so [`verify_record`] refuses it too. A record built by
/// [`entry_state`] always has this shape.
pub fn record_is_well_formed(record: &Map) -> bool {
    let payload = present(record, "payload");
    let payload_ref = present(record, "payloadRef");
    let one_payload = match (payload, payload_ref) {
        (Some(payload), None) => payload
            .as_bytes()
            .is_some_and(|bytes| bytes.len() <= INLINE_PAYLOAD_LIMIT),
        (None, Some(reference)) => reference.as_str().is_some(),
        _ => false,
    };
    one_payload
        && present(record, "tags").is_some()
        && record
            .get("lease")
            .is_some_and(|lease| lease_fields(lease).is_some())
        && sign_view_of(record).is_some()
}

/// TECH-SPEC §7.2's record rule, as Java `ReplicatedSpace.verifyRecord` applies it.
///
/// `issuer_public` must be the 32-byte key of the record's issuing peer, and the record's
/// `issuer` must be an agent of the PeerID that key hashes to. Without a certificate (`None` or
/// null) the signature `sig` must verify over [`sign_view_of`] under that peer key. With one, the
/// certificate must verify under the peer key for exactly this issuer, judged at the record's own
/// issue stamp (v0.1.13: signing time, not receipt) with no bound of its own on how far that
/// stamp leads the receiver (v0.1.30: the fold's far-future rule judges it,
/// [`verify_agent_certificate_covering`]), and the signature must then verify under the
/// certificate's agent key: a record that arrives with a certificate but a peer-key signature is
/// refused. `_now_ms`, the receiver's time, bounds nothing here since v0.1.30.
///
/// The record must be one Java decodes ([`record_is_well_formed`]) and whose view Java re-encodes
/// to the bytes this function verifies ([`sign_view_of`]): Java verifies over its own typed
/// re-encoding, so a record whose `issued` reads `+5:0:n`, whose issuer is `peer/` or
/// `peer/a/b`, or whose tags hold a non-text value is refused here as it is there.
pub fn verify_record(
    record: &Map,
    issuer_public: &[u8],
    certificate: Option<&Value>,
    _now_ms: i64,
) -> bool {
    if issuer_public.len() != KEY_LENGTH || !record_is_well_formed(record) {
        return false;
    }
    let Some(issuer) = record.get("issuer").and_then(Value::as_str) else {
        return false;
    };
    if !issued_by(issuer, issuer_public) {
        return false;
    }
    let Some(signature) = record.get("sig").and_then(Value::as_bytes) else {
        return false;
    };
    let Some(view) = sign_view_of(record) else {
        return false;
    };
    let view = encode_map(&view);
    match non_null(certificate) {
        None => Identity::verify(issuer_public, &view, signature),
        Some(certificate) => {
            let Some(issued) = Stamp::of(record.get("issued")) else {
                return false;
            };
            verify_agent_certificate_covering(certificate, issuer_public, issuer, issued.physical)
                && agent_key(certificate).is_some_and(|key| Identity::verify(key, &view, signature))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// States

/// Java `ReplicatedSpace.sortedDots`: by `replica` (Java string order), then `counter`; stable.
/// A dot that is not a well-formed map sorts as `("", 0)`, `wire.py`'s defaults.
fn sorted_dots(dots: &[Value]) -> Vec<Value> {
    fn key(dot: &Value) -> (&str, i128) {
        (
            dot.get("replica").and_then(Value::as_str).unwrap_or(""),
            dot.get("counter").and_then(Value::as_i128).unwrap_or(0),
        )
    }
    let mut sorted = dots.to_vec();
    sorted.sort_by(|a, b| {
        let ((replica_a, counter_a), (replica_b, counter_b)) = (key(a), key(b));
        java_order(replica_a, replica_b).then(counter_a.cmp(&counter_b))
    });
    sorted
}

/// The state sign view from its parts; [`state_sign_view`] and [`state_sign_view_of`] share it.
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per field of the Java StateSignView record, in its order"
)]
fn state_view(
    space_id: Value,
    entry_id: Value,
    adds: &[Value],
    removes: &[Value],
    lease_stamp: Value,
    lease_value: Value,
    completed: bool,
    signer: Option<Value>,
    signed_at: Option<Value>,
) -> Map {
    let mut view = Map::with_capacity(9);
    view.insert("spaceId", space_id);
    view.insert("entryId", entry_id);
    view.insert("adds", sorted_dots(adds));
    view.insert("removes", sorted_dots(removes));
    view.insert("leaseStamp", lease_stamp);
    view.insert("leaseValue", lease_value);
    view.insert("completed", completed);
    if let Some(signer) = signer {
        view.insert("signer", signer);
    }
    if let Some(signed_at) = signed_at {
        view.insert("signedAt", signed_at);
    }
    view
}

/// Java `ReplicatedSpace.StateSignView` (SPEC §11a): the mutable state an actor signs so a
/// receiver can authenticate a write, renewal, cancellation, or completion. Field order
/// `spaceId, entryId, adds, removes, leaseStamp, leaseValue, completed`, the dot lists sorted by
/// `(replica, counter)`; an agent-signed state (SPEC §11a.4, v0.1.13) appends `signer` and
/// `signedAt`, and a peer-signed one omits them and keeps its v0.1.12 bytes.
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per field of the Java StateSignView record, in its order"
)]
pub fn state_sign_view(
    space_id: &str,
    entry_id: &str,
    adds: &[Value],
    removes: &[Value],
    lease_stamp: &str,
    lease_value: &Value,
    completed: bool,
    signer: Option<&str>,
    signed_at: Option<&str>,
) -> Map {
    state_view(
        space_id.into(),
        entry_id.into(),
        adds,
        removes,
        lease_stamp.into(),
        lease_value.clone(),
        completed,
        signer.map(Value::from),
        signed_at.map(Value::from),
    )
}

/// A dot list of a state: absent or null is empty; otherwise an array of `{replica, counter}`
/// maps with text replicas and integer counters (the Java `Dot` shape).
fn dots_of<'a>(dto: &'a Map, name: &'static str) -> Result<&'a [Value], &'static str> {
    let Some(dots) = present(dto, name) else {
        return Ok(&[]);
    };
    let dots = dots.as_array().ok_or(name)?;
    let well_formed = dots.iter().all(|dot| {
        dot.get("replica").and_then(Value::as_str).is_some()
            && dot.get("counter").and_then(Value::as_i64).is_some()
    });
    if well_formed { Ok(dots) } else { Err(name) }
}

/// An optional text field of a state: absent or null is `None`, text is kept, anything else is
/// malformed.
fn optional_text(dto: &Map, name: &'static str) -> Result<Option<Value>, &'static str> {
    match present(dto, name) {
        None => Ok(None),
        Some(value @ Value::Text(_)) => Ok(Some(value.clone())),
        Some(_) => Err(name),
    }
}

/// The state sign view of `dto` with the given signer fields, or the malformed field.
fn state_view_with(
    dto: &Map,
    signer: Option<Value>,
    signed_at: Option<Value>,
) -> Result<Map, &'static str> {
    let record = dto.get("record").and_then(Value::as_map).ok_or("record")?;
    let completed = match present(dto, "completed") {
        None => false,
        Some(completed) => completed.as_bool().ok_or("completed")?,
    };
    Ok(state_view(
        field(record, "spaceId"),
        field(record, "entryId"),
        dots_of(dto, "adds")?,
        dots_of(dto, "removes")?,
        field(dto, "leaseStamp"),
        field(dto, "leaseValue"),
        completed,
        signer,
        signed_at,
    ))
}

/// The [`state_sign_view`] of a (received) state DTO, from its own fields, as a receiver checks
/// `stateSig` against it: `spaceId` and `entryId` from its record, the dot lists (absent or null
/// is empty), `leaseStamp` and `leaseValue` as they are, `completed` (absent or null is false),
/// and `signer` and `signedAt` each appended when present.
///
/// `None` unless every field has the one form Java writes back (`ReplicatedSpace.stateSignBytes`
/// re-encodes the typed `StateSignView` of what it decoded, and the signature must cover the same
/// bytes here): `record` a map whose `spaceId` and `entryId` are non-empty text; each dot exactly
/// `{replica: text, counter: positive long}`, in that order and nothing else; `leaseStamp` (and
/// `signedAt`, when present) a stamp in canonical form ([`Stamp::parse_canonical`]); `leaseValue`
/// exactly `{holder: agent id, expiresAtMillis: positive long, kind: WRITE or TAKE}`;
/// `completed` a boolean; and `signer` text.
pub fn state_sign_view_of(dto: &Map) -> Option<Map> {
    let signer = optional_text(dto, "signer").ok()?;
    let signed_at = optional_text(dto, "signedAt").ok()?;
    let record = dto.get("record").and_then(Value::as_map)?;
    id_text(record, "spaceId")?;
    id_text(record, "entryId")?;
    for name in ["adds", "removes"] {
        if !dots_of(dto, name).ok()?.iter().all(is_canonical_dot) {
            return None;
        }
    }
    Stamp::canonical_of(dto.get("leaseStamp"))?;
    if !dto.get("leaseValue").is_some_and(is_canonical_lease) {
        return None;
    }
    if let Some(signed_at) = &signed_at {
        Stamp::canonical_of(Some(signed_at))?;
    }
    state_view_with(dto, signer, signed_at).ok()
}

/// The certificate of `agent` covering `stamp`, cloned for the wire.
fn covering(agent: &AgentIdentity, stamp: &str, field: &'static str) -> Result<Map, RecordError> {
    let parsed = Stamp::parse(stamp).ok_or(RecordError::MalformedStamp { field })?;
    agent
        .certificate_covering(parsed.physical)
        .cloned()
        .ok_or_else(|| RecordError::NoCoveringCertificate {
            agent: agent.agent_id().to_owned(),
            stamp: stamp.to_owned(),
        })
}

/// Signs a state DTO's mutable fields as its actor and returns the signed DTO (`wire.py`'s
/// `sign_state`, Java `ReplicatedSpace.signState`).
///
/// Without `agent` the peer signs and the DTO keeps the v0.1.12 shape. With `agent` (the agent
/// identity and the `signedAt` stamp the caller's HLC drew for it) the agent key signs (SPEC
/// §11a.4, v0.1.13): the DTO names the agent as `signer`, carries `signedAt`, and carries the
/// certificate covering that stamp as `stateCertificate`. Call [`AgentIdentity::renew_if_due`]
/// first for a renewing agent.
///
/// Any earlier `stateSig`, `stateCertificate`, `signer`, and `signedAt` are dropped, and the
/// result lists the DTO's other fields in their order followed by `stateSig`, `agentCertificate`
/// (when present), and the agent fields: the Java `EntryStateDto` order.
pub fn sign_state(
    dto: &Map,
    peer: &Identity,
    agent: Option<(&AgentIdentity, &str)>,
) -> Result<Map, RecordError> {
    let mut signed = dto.clone();
    signed.retain(|key, _| {
        !matches!(
            key.as_str(),
            Some("stateSig" | "stateCertificate" | "signer" | "signedAt")
        )
    });
    let agent_certificate = signed.remove("agentCertificate");
    let state_certificate = match agent {
        None => None,
        Some((agent, signed_at)) => Some(covering(agent, signed_at, "signedAt")?),
    };
    let view = state_view_with(
        &signed,
        agent.map(|(agent, _)| Value::from(agent.agent_id())),
        agent.map(|(_, signed_at)| Value::from(signed_at)),
    )
    .map_err(|field| RecordError::Malformed { field })?;
    let view = encode_map(&view);
    let signature = match agent {
        Some((agent, _)) => agent.sign(&view),
        None => peer.sign(&view),
    };
    signed.insert("stateSig", signature);
    if let Some(certificate) = agent_certificate {
        signed.insert("agentCertificate", certificate);
    }
    if let (Some((agent, signed_at)), Some(certificate)) = (agent, state_certificate) {
        signed.insert("stateCertificate", certificate);
        signed.insert("signer", agent.agent_id());
        signed.insert("signedAt", signed_at);
    }
    Ok(signed)
}

/// SPEC §11a.4's state rule after the record check (Java `ReplicatedSpace.verifyState`, the
/// Python peer's `_verify_state`): whether `dto`'s `stateSig` authenticates its transition for
/// `party`, the one actor the transition needs.
///
/// The caller names the party: for a completion, the holder of the entry's verified claim, its
/// `holderKey`, and whether the claim carries a `holderCertificate`; for any other transition,
/// the record's issuer, the DTO's `issuerPublicKey`, and whether it carries an
/// `agentCertificate`. The record itself is [`verify_record`]'s.
///
/// - An agent-signed state (`signer` present) must name exactly `party`, carry a
///   `stateCertificate` that `party_key` verifies for `party` at `signedAt`, by the certificate's
///   window alone (SPEC §9.2 F4: the fold's far-future rule judges how far `signedAt` leads, and
///   `_now_ms` bounds nothing here), and verify under that certificate's agent key.
/// - A peer-signed state verifies under `party_key`, unless the party is agent-attested: an
///   attested party's transitions must be agent-signed (v0.1.13), so its peer or a sibling
///   agent cannot act in its name.
///
/// The signature is checked over [`state_sign_view_of`], so a state Java would re-encode to
/// other bytes (a reordered or extended dot or `leaseValue`, a `+5:0:n` stamp) is refused, and
/// so is one without both dot lists (Java cannot sort a missing list, and refuses it).
pub fn verify_state_signature(
    dto: &Map,
    party: &str,
    party_key: &[u8],
    party_attested: bool,
    _now_ms: i64,
) -> bool {
    let lists = ["adds", "removes"]
        .iter()
        .all(|name| dto.get(name).and_then(Value::as_array).is_some());
    if party_key.len() != KEY_LENGTH || !lists {
        return false;
    }
    let Some(state_sig) = dto.get("stateSig").and_then(Value::as_bytes) else {
        return false;
    };
    let Some(view) = state_sign_view_of(dto) else {
        return false;
    };
    let view = encode_map(&view);
    let Some(signer) = present(dto, "signer") else {
        return !party_attested && Identity::verify(party_key, &view, state_sig);
    };
    let Some(signed_at) = Stamp::of(dto.get("signedAt")) else {
        return false;
    };
    let Some(certificate) = dto
        .get("stateCertificate")
        .filter(|certificate| certificate.as_map().is_some())
    else {
        return false;
    };
    signer.as_str() == Some(party)
        && verify_agent_certificate_covering(certificate, party_key, party, signed_at.physical)
        && agent_key(certificate).is_some_and(|key| Identity::verify(key, &view, state_sig))
}

// ---------------------------------------------------------------------------------------------
// Writes and deltas

/// What one write puts in its record: the inputs of [`entry_state`] and [`entry_delta`] besides
/// the writer. The caller draws the id and the stamp, since this crate has neither a clock nor
/// ids of its own.
#[derive(Debug, Clone, Copy)]
pub struct EntryWrite<'a> {
    /// The entry's id: a fresh UUID (`wire.py` draws `uuid4`).
    pub entry_id: &'a str,
    /// The space's id: [`crate::ids::space_id_local`] of `"<groupID>/<space name>"`.
    pub space_id: &'a str,
    /// The entry's type name (`"<Type>#v<version>"`).
    pub type_name: &'a str,
    /// The inline payload (CBOR), or `None` when it travels by `payload_ref`.
    pub payload: Option<&'a [u8]>,
    /// The block (`z...`) or content root (`b...`) holding the payload, or `None` when inline.
    pub payload_ref: Option<&'a str>,
    /// The record's tags; `None` is the empty map. Written in canonical order.
    pub tags: Option<&'a Map>,
    /// The content-key epoch the payload is sealed under, from 1; `None` for epoch 0 and
    /// unencrypted payloads, whose records sign the v0.1.12 bytes.
    pub key_epoch: Option<i64>,
    /// The record's issue stamp, from the caller's HLC for the issuer; also the lease stamp.
    pub issued: &'a str,
    /// When the write lease lapses, epoch milliseconds (`now + lease_millis` in `wire.py`).
    pub expires_at_millis: i64,
    /// The writer's dot counter for this add (`wire.py` always writes 1; Java its replica's
    /// running counter).
    pub counter: i64,
}

/// The signed state of a fresh write (`wire.py`'s `entry_delta` before encoding, Java
/// `ReplicatedSpace.write`): the record signed by its issuer, one add dot of this peer, the write
/// lease, and the state signature.
///
/// Without `agent` the issuer is `peer.agent(agent_name)` and the peer key signs record and
/// state. With `agent` (the agent identity and the `signedAt` stamp for its state signature) the
/// issuer is the agent and `agent_name` is unused: its key signs the record, the certificate
/// covering `issued` rides as `agentCertificate`, and the state is agent-signed ([`sign_state`]),
/// so receivers store the entry agent-attested.
pub fn entry_state(
    write: &EntryWrite<'_>,
    peer: &Identity,
    agent_name: &str,
    agent: Option<(&AgentIdentity, &str)>,
) -> Result<Map, RecordError> {
    if Stamp::parse(write.issued).is_none() {
        return Err(RecordError::MalformedStamp { field: "issued" });
    }
    let issuer = match agent {
        Some((agent, _)) => agent.agent_id().to_owned(),
        None => peer.agent(agent_name),
    };
    let record_certificate = match agent {
        Some((agent, _)) => Some(covering(agent, write.issued, "issued")?),
        None => None,
    };
    let tags = write.tags.map(cbor::canonical_map).unwrap_or_default();
    let view = sign_view(
        write.entry_id,
        write.space_id,
        write.type_name,
        write.payload,
        &issuer,
        write.issued,
        write.key_epoch,
        Some(&tags),
        write.payload_ref,
    );
    let view = encode_map(&view);
    let signature = match agent {
        Some((agent, _)) => agent.sign(&view),
        None => peer.sign(&view),
    };
    let lease = || {
        crate::cbor_map! {
            "holder" => issuer.as_str(),
            "expiresAtMillis" => write.expires_at_millis,
            "kind" => WRITE_LEASE_KIND,
        }
    };
    let mut record = Map::with_capacity(11);
    record.insert("entryId", write.entry_id);
    record.insert("spaceId", write.space_id);
    record.insert("type", write.type_name);
    record.insert("payload", write.payload);
    record.insert("payloadRef", write.payload_ref);
    record.insert("issuer", issuer.as_str());
    record.insert("issued", write.issued);
    record.insert("lease", lease());
    record.insert("tags", tags);
    record.insert("sig", signature);
    if let Some(epoch) = write.key_epoch {
        record.insert("keyEpoch", epoch);
    }
    let mut dto = Map::with_capacity(12);
    dto.insert("record", record);
    dto.insert("issuerPublicKey", peer.public_raw());
    dto.insert(
        "adds",
        crate::cbor_array![crate::cbor_map! {
            "replica" => peer.peer_id(),
            "counter" => write.counter,
        }],
    );
    dto.insert("removes", Value::Array(Vec::new()));
    dto.insert("leaseStamp", write.issued);
    dto.insert("leaseValue", lease());
    dto.insert("completed", false);
    if let Some(certificate) = record_certificate {
        dto.insert("agentCertificate", certificate);
    }
    sign_state(&dto, peer, agent)
}

/// A full write delta (`wire.py`'s `entry_delta`): [`entry_state`] as `{state, claimEntry: null,
/// claim: null}`. The caller wraps it in a rumor body on stream `"space:<space name>"` under item
/// `"w:<entry id>"`.
pub fn entry_delta(
    write: &EntryWrite<'_>,
    peer: &Identity,
    agent_name: &str,
    agent: Option<(&AgentIdentity, &str)>,
) -> Result<Vec<u8>, RecordError> {
    let state = entry_state(write, peer, agent_name, agent)?;
    Ok(delta(Some(&state), None))
}

/// A received space delta ([`decode_delta`]): the state it carries and the claim, with the entry
/// id it travels under.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Delta {
    /// The `EntryStateDto`, when not null.
    pub state: Option<Map>,
    /// `(claimEntry, claim)`, when both are not null.
    pub claim: Option<(String, Map)>,
}

/// A received space `SyncDelta` ([`decode_sync_delta`]), one stream of a `PULL_RESP`: its claims
/// under the entry ids they travel under, then its states.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SyncDelta {
    /// `claims`, in the order they arrived (canonical key order).
    pub claims: Vec<(String, Map)>,
    /// `states`, in the order they arrived.
    pub states: Vec<Map>,
}

/// The space delta a `space:` rumor carries (`SpaceWire.Delta`), decoded by the receiver's
/// procedure of SPEC §9.1 ([`crate::schema::decode`]): the item rules, the record rules of the
/// delta and every record it nests (the state, its record, lease, dots, and certificates, the
/// signed claim and its `TakeClaim` in declared order), and the canonical-bytes check. `None`
/// when any of them fails: the delta is undecodable, the receiver counts it
/// (`deltasUndecodable`), and strikes nobody. A stamp outside the canonical grammar, or in any
/// other CBOR form than one definite text, is one such failure; a counter above the logical limit
/// decodes, and the fold refuses it after verification.
pub fn decode_delta(bytes: &[u8]) -> Option<Delta> {
    let mut delta = crate::schema::decode_map(bytes, "SpaceWire.Delta")?;
    let state = delta.remove("state").and_then(Value::into_map);
    let claim_entry = delta.remove("claimEntry").and_then(Value::into_text);
    let claim = delta.remove("claim").and_then(Value::into_map);
    Some(Delta {
        state,
        claim: claim_entry.zip(claim),
    })
}

/// A space's `SyncDelta` (`{states, claims}`, one stream of a `PULL_RESP`), decoded by the
/// receiver's procedure as [`decode_delta`] decodes a delta: one state or claim that does not
/// decode makes the whole `SyncDelta` undecodable, as Java's codec refuses it. A null `states` or
/// `claims` reads as empty.
pub fn decode_sync_delta(bytes: &[u8]) -> Option<SyncDelta> {
    let mut sync = crate::schema::decode_map(bytes, "SpaceWire.SyncDelta")?;
    let claims = sync
        .remove("claims")
        .and_then(Value::into_map)
        .map(|claims| {
            claims
                .into_iter()
                .filter_map(|(entry, signed)| Some((entry.into_text()?, signed.into_map()?)))
                .collect()
        })
        .unwrap_or_default();
    let states = sync
        .remove("states")
        .and_then(Value::into_array)
        .map(|states| states.into_iter().filter_map(Value::into_map).collect())
        .unwrap_or_default();
    Some(SyncDelta { claims, states })
}

/// A Java `SpaceWire.Delta`: `{state, claimEntry, claim}`, each null when absent. A completion
/// travels with the claim that authenticates it (`claim` is `(entry id, signed claim)`).
pub fn delta(state: Option<&Map>, claim: Option<(&str, &Map)>) -> Vec<u8> {
    let (claim_entry, claim) = match claim {
        Some((entry_id, signed)) => (Value::from(entry_id), Value::Map(signed.clone())),
        None => (Value::Null, Value::Null),
    };
    cbor::encode(&crate::cbor_map! {
        "state" => state.cloned(),
        "claimEntry" => claim_entry,
        "claim" => claim,
    })
}

// ---------------------------------------------------------------------------------------------
// The recordless form (SPEC §7.3, v0.1.29)

/// Whether a state DTO travels without its record (Java `EntryStateDto.recordless`): `record`
/// absent or null.
pub fn is_recordless(dto: &Map) -> bool {
    present(dto, "record").is_none()
}

/// The entry a state DTO belongs to (Java `EntryStateDto.entryIdOf`): its record's `entryId`, or
/// the `entryId` a recordless state names. `None` when neither is non-empty text.
pub fn state_entry_id(dto: &Map) -> Option<&str> {
    match dto.get("record").and_then(Value::as_map) {
        Some(record) => id_text(record, "entryId"),
        None => id_text(dto, "entryId"),
    }
}

/// The recordless form of a state DTO (Java `EntryStateDto.withoutRecord`): the same mutable
/// fields, key, certificates, and signature in their order, `record` dropped and `entryId` (the
/// record's) appended last. A recordless DTO comes back unchanged; `None` when the record has no
/// text `entryId`.
///
/// The state signature covers [`state_sign_view_of`], which names the entry and its space but
/// not the record's bytes, so the signature holds across both forms. Java sends this form for a
/// renew, cancel, or complete only once the writer saw the record replicate and every member of
/// its view advertises `wire.recordless`.
pub fn without_record(dto: &Map) -> Option<Map> {
    let Some(record) = dto.get("record").and_then(Value::as_map) else {
        return is_recordless(dto).then(|| dto.clone());
    };
    let entry_id = id_text(record, "entryId")?.to_owned();
    let mut recordless = dto.clone();
    recordless.retain(|key, _| !matches!(key.as_str(), Some("record" | "entryId")));
    recordless.insert("entryId", entry_id);
    Some(recordless)
}

/// A state DTO over the record a receiver holds for its entry (Java `EntryStateDto.withRecord`):
/// `held` first as `record`, the other fields in their order, `entryId` dropped. `None` when the
/// DTO names another entry than `held` (Java's `IllegalArgumentException`).
///
/// The result is the full form, so [`verify_state_signature`] and the fold judge it exactly as a
/// state that arrived with its record.
pub fn with_record(dto: &Map, held: &Map) -> Option<Map> {
    if let Some(named) = present(dto, "entryId")
        && named.as_str()? != id_text(held, "entryId")?
    {
        return None;
    }
    let mut full = Map::with_capacity(dto.len() + 1);
    full.insert("record", held.clone());
    for (key, value) in dto.iter() {
        if !matches!(key.as_str(), Some("record" | "entryId")) {
            full.insert(key.clone(), value.clone());
        }
    }
    Some(full)
}

// ---------------------------------------------------------------------------------------------
// Take claims

/// A Java `TakeClaim` in field order: `entryId, spaceId, epoch, stamp, holder, bid,
/// expiresAtMillis`. `entryId` and `spaceId` are signed bindings, so a signed claim
/// cannot be transplanted onto another entry; the bid is always a CBOR double, as Java writes it.
pub fn take_claim(
    entry_id: &str,
    space_id: &str,
    epoch: i64,
    stamp: &str,
    holder: &str,
    bid: f64,
    expires_at_millis: i64,
) -> Map {
    let mut claim = Map::with_capacity(7);
    claim.insert("entryId", entry_id);
    claim.insert("spaceId", space_id);
    claim.insert("epoch", epoch);
    claim.insert("stamp", stamp);
    claim.insert("holder", holder);
    claim.insert("bid", Value::Float(bid));
    claim.insert("expiresAtMillis", expires_at_millis);
    claim
}

/// A Java `SpaceWire.SignedClaim`: `{claim, holderKey, signature}` with the holder's *peer* key.
///
/// Without `agent` the peer signs the claim's CBOR. With `agent` the agent key signs it and the
/// certificate covering the claim's `stamp` is appended as `holderCertificate` (v0.1.11;
/// receivers judge it at that stamp). Fails when the agent's claim has no parseable `stamp` or
/// the agent holds no certificate covering it.
pub fn signed_claim(
    claim: &Map,
    peer: &Identity,
    agent: Option<&AgentIdentity>,
) -> Result<Map, RecordError> {
    let certificate = match agent {
        None => None,
        Some(agent) => {
            let stamp = claim
                .get("stamp")
                .and_then(Value::as_str)
                .ok_or(RecordError::MalformedStamp { field: "stamp" })?;
            Some(covering(agent, stamp, "stamp")?)
        }
    };
    let claim = Value::Map(claim.clone());
    let bytes = cbor::encode(&claim);
    let signature = match agent {
        Some(agent) => agent.sign(&bytes),
        None => peer.sign(&bytes),
    };
    let mut signed = Map::with_capacity(4);
    signed.insert("claim", claim);
    signed.insert("holderKey", peer.public_raw());
    signed.insert("signature", signature);
    if let Some(certificate) = certificate {
        signed.insert("holderCertificate", certificate);
    }
    Ok(signed)
}

/// Whether a claim has the shape Java `TakeClaim` can hold and the claim fold accepts (the
/// checks the Python peer runs before the proof): text `entryId`, `spaceId`, and
/// `holder`; an integer `epoch` from 1 that fits a `long`; a `stamp` that parses; a finite `bid`
/// (absent is 0.0, and an integer reads as a double); and an integer `expiresAtMillis` that fits
/// a `long`. A NaN bid would make the total order lie, and epoch 0 is no take at all.
///
/// This is the shape Jackson decodes; a claim whose proof must verify alike everywhere must also
/// be in Java's canonical form ([`claim_is_canonical`], which [`verify_claim_proof`] requires).
pub fn claim_is_well_formed(claim: &Map) -> bool {
    let text = |name: &str| claim.get(name).and_then(Value::as_str).is_some();
    let bid_ok = match claim.get("bid") {
        None => true,
        Some(bid) => bid.as_f64().is_some_and(f64::is_finite),
    };
    text("entryId")
        && text("spaceId")
        && text("holder")
        && claim
            .get("epoch")
            .and_then(Value::as_i64)
            .is_some_and(|epoch| epoch > 0)
        && Stamp::of(claim.get("stamp")).is_some()
        && bid_ok
        && claim
            .get("expiresAtMillis")
            .and_then(Value::as_i64)
            .is_some()
}

/// Whether a received claim is exactly what Java writes back for the `TakeClaim` it decodes from
/// it, so a signature over the claim's CBOR here covers the bytes Java verifies
/// (`ReplicatedSpace.verifyClaim` signs and verifies `codec.toBytes(claim)`): the seven fields
/// `entryId, spaceId, epoch, stamp, holder, bid, expiresAtMillis` in that order and nothing
/// else ([`take_claim`]), non-empty text ids, an epoch from 1, a stamp in canonical form
/// ([`Stamp::parse_canonical`]), a holder that is a Java `AgentId` ([`ids::parse_agent_id`]), a
/// finite bid written as a CBOR double, and an expiry that fits a `long`.
///
/// [`claim_is_well_formed`] accepts more (an integer or absent bid, a `+5:0:n` stamp, extra
/// fields), as Jackson decodes them; Java then re-encodes such a claim to other bytes than its
/// holder sent, so only a claim that passes here can carry a proof both verify alike.
pub fn claim_is_canonical(claim: &Map) -> bool {
    let bid = match claim.get("bid") {
        Some(Value::Float(bid)) if bid.is_finite() => Some(*bid),
        _ => None,
    };
    let (
        Some(entry_id),
        Some(space_id),
        Some(epoch),
        Some(stamp),
        Some(holder),
        Some(bid),
        Some(expires),
    ) = (
        id_text(claim, "entryId"),
        id_text(claim, "spaceId"),
        positive_long(claim, "epoch"),
        text(claim, "stamp").filter(|stamp| Stamp::parse_canonical(stamp).is_some()),
        text(claim, "holder").filter(|holder| ids::parse_agent_id(holder).is_some()),
        bid,
        claim.get("expiresAtMillis").and_then(Value::as_i64),
    )
    else {
        return false;
    };
    *claim == take_claim(entry_id, space_id, epoch, stamp, holder, bid, expires)
}

/// Whether the claim's hold ends within [`MAX_CLAIM_HOLD_MILLIS`] of `now_ms`.
fn hold_within_bound(claim: &Map, now_ms: i64) -> bool {
    claim
        .get("expiresAtMillis")
        .and_then(Value::as_i64)
        .is_some_and(|expires| {
            i128::from(expires) <= i128::from(now_ms) + i128::from(MAX_CLAIM_HOLD_MILLIS)
        })
}

/// TECH-SPEC §7.6's proof rule for a received `SignedClaim` (Java `ReplicatedSpace.verifyClaim`,
/// `wire.py`'s `verify_claim_proof`), with every check that needs no replica state: the
/// signature of [`verify_claim_signature`] and the hold bound.
///
/// True only when the claim is well-formed ([`claim_is_well_formed`]: epoch from 1, finite bid,
/// a parseable stamp) and in the canonical form Java writes it back as ([`claim_is_canonical`]:
/// the seven fields in order, the bid a double, the stamp canonical; Java verifies over its
/// re-encoding, so any other form would verify different bytes there), its hold ends within
/// [`MAX_CLAIM_HOLD_MILLIS`] of `now_ms` (an eternal lease is refused), `holderKey` is 32 bytes
/// whose PeerID the `holder` is an agent of (a non-empty local name free of `/`), and the
/// `signature` over the claim's CBOR verifies: under `holderKey` without a certificate (absent
/// or null), or, with one, under the certificate's agent key once the certificate verifies under
/// `holderKey` for exactly the holder at the claim's own stamp, by its window alone (SPEC §4.2,
/// v0.1.30: the fold's far-future rule judges how far the stamp leads). A claim with a
/// certificate but a peer-key signature is refused.
///
/// The entry and space bindings, the epoch jump ([`claim_within_bounds`]), the issue bound
/// ([`claim_not_before_issue`]), the stamp rules, and revocation are the fold's, which knows the
/// entry.
pub fn verify_claim_proof(signed: &Value, now_ms: i64) -> bool {
    verify_claim_signature(signed)
        && signed
            .get("claim")
            .and_then(Value::as_map)
            .is_some_and(|claim| hold_within_bound(claim, now_ms))
}

/// [`verify_claim_proof`] without the hold bound: the claim is well formed and canonical, its
/// holder an agent of the peer `holderKey` hashes to, and its signature verifies (with its
/// certificate, if any, covering the claim's stamp). Java's `verifyClaim` checks exactly this;
/// the fold then judges the claim's stamp (the logical limit and the far-future rule) before the
/// epoch and hold bounds, as Java's `mergeClaim` does.
pub fn verify_claim_signature(signed: &Value) -> bool {
    let Some(claim_value) = signed.get("claim") else {
        return false;
    };
    let Some(claim) = claim_value.as_map() else {
        return false;
    };
    let Some(holder_key) = signed.get("holderKey").and_then(Value::as_bytes) else {
        return false;
    };
    let Some(signature) = signed.get("signature").and_then(Value::as_bytes) else {
        return false;
    };
    if holder_key.len() != KEY_LENGTH || !claim_is_well_formed(claim) || !claim_is_canonical(claim)
    {
        return false;
    }
    let (Some(holder), Some(stamp)) = (
        claim.get("holder").and_then(Value::as_str),
        Stamp::of(claim.get("stamp")),
    ) else {
        return false;
    };
    if !issued_by(holder, holder_key) {
        return false;
    }
    let bytes = cbor::encode(claim_value);
    match non_null(signed.get("holderCertificate")) {
        None => Identity::verify(holder_key, &bytes, signature),
        Some(certificate) => {
            verify_agent_certificate_covering(certificate, holder_key, holder, stamp.physical)
                && agent_key(certificate)
                    .is_some_and(|key| Identity::verify(key, &bytes, signature))
        }
    }
}

/// The claim bounds, as the claim fold applies them before the lattice (where higher epochs win
/// by design) sees a remote claim: its epoch is at most [`MAX_CLAIM_EPOCH_JUMP`] beyond
/// `observed_epoch` (the epoch of the claim this replica holds for the entry, 0 when none) and its
/// hold ends within [`MAX_CLAIM_HOLD_MILLIS`] of `now_ms`. False when either field is missing or
/// not an integer that fits a `long`.
pub fn claim_within_bounds(claim: &Map, observed_epoch: i64, now_ms: i64) -> bool {
    let epoch_ok = claim
        .get("epoch")
        .and_then(Value::as_i64)
        .is_some_and(|epoch| {
            i128::from(epoch) <= i128::from(observed_epoch) + i128::from(MAX_CLAIM_EPOCH_JUMP)
        });
    epoch_ok && hold_within_bound(claim, now_ms)
}

/// SPEC §7.4/§11 (Java `ReplicatedSpace.mergeClaim`): a claim answers a write, so its stamp may
/// lie at most [`MAX_CLAIM_PREDATES_ISSUE_MILLIS`] before `entry_issued`, the issue stamp of the
/// entry's record. False when either stamp does not parse. Anchored on the signed issue stamp, so
/// every replica draws the same line.
pub fn claim_not_before_issue(claim: &Map, entry_issued: &str) -> bool {
    match (Stamp::of(claim.get("stamp")), Stamp::parse(entry_issued)) {
        (Some(stamp), Some(issued)) => {
            i128::from(stamp.physical)
                >= i128::from(issued.physical) - i128::from(MAX_CLAIM_PREDATES_ISSUE_MILLIS)
        }
        _ => false,
    }
}

/// A claim-only delta (`wire.py`'s `claim_delta`), as a take publishes it:
/// `{state: null, claimEntry, claim}`.
pub fn claim_delta(entry_id: &str, signed: &Map) -> Vec<u8> {
    delta(None, Some((entry_id, signed)))
}

/// A claim's place in the lattice of SPEC §7.4: the *smallest* key wins. Epoch descending, bid
/// ascending, HLC stamp ascending (physical, logical, node), holder ascending, expiry descending;
/// identical to Java `TakeClaim.merge`.
///
/// Bids compare as Java `Double.compare` does (so `-0.0` sorts before `0.0`) and text as Java
/// `String.compareTo` does (UTF-16 code units); `wire.py`'s tuple order agrees on every claim
/// except those two edge cases.
#[derive(Debug, Clone, Copy)]
pub struct ClaimSortKey<'a> {
    epoch: i64,
    bid: f64,
    physical: i64,
    logical: i32,
    node: &'a str,
    holder: &'a str,
    expires_at_millis: i64,
}

impl ClaimSortKey<'_> {
    /// The claim's epoch.
    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    /// The claim's bid.
    pub fn bid(&self) -> f64 {
        self.bid
    }

    /// The claim's holder.
    pub fn holder(&self) -> &str {
        self.holder
    }

    /// When the claim's hold lapses, epoch milliseconds.
    pub fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }
}

impl Ord for ClaimSortKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .epoch
            .cmp(&self.epoch)
            .then_with(|| self.bid.total_cmp(&other.bid))
            .then_with(|| self.physical.cmp(&other.physical))
            .then_with(|| self.logical.cmp(&other.logical))
            .then_with(|| java_order(self.node, other.node))
            .then_with(|| java_order(self.holder, other.holder))
            .then_with(|| other.expires_at_millis.cmp(&self.expires_at_millis))
    }
}

impl PartialOrd for ClaimSortKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ClaimSortKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ClaimSortKey<'_> {}

/// The lattice key of a claim (`wire.py`'s `claim_sort_key`). An absent field takes `wire.py`'s
/// default (epoch 0, bid 0.0, stamp `0:0:`, holder empty, expiry 0); `None` when a present field
/// has the wrong type, an integer does not fit a `long`, the bid is NaN, or the stamp does not
/// parse, since such a claim has no place in a total order.
pub fn claim_sort_key(claim: &Map) -> Option<ClaimSortKey<'_>> {
    let (physical, logical, node) = match claim.get("stamp") {
        None => (0, 0, ""),
        Some(stamp) => {
            let stamp = Stamp::of(Some(stamp))?;
            (stamp.physical, stamp.logical, stamp.node)
        }
    };
    Some(ClaimSortKey {
        epoch: claim.get("epoch").map_or(Some(0), Value::as_i64)?,
        bid: claim
            .get("bid")
            .map_or(Some(0.0), Value::as_f64)
            .filter(|bid| !bid.is_nan())?,
        physical,
        logical,
        node,
        holder: claim.get("holder").map_or(Some(""), Value::as_str)?,
        expires_at_millis: claim
            .get("expiresAtMillis")
            .map_or(Some(0), Value::as_i64)?,
    })
}

/// The winning signed claim of two (`wire.py`'s `merge_claims`, Java `SignedClaim.merge`): `b`
/// when there is no `a`, otherwise the one whose `claim` has the smaller [`claim_sort_key`], `a`
/// on a tie. The winner is always one of the inputs, so its proof stays attached. A signed claim
/// whose key cannot be read never displaces one whose key can (the fold never admits one).
pub fn merge_claims(a: Option<&Map>, b: &Map) -> Map {
    fn key(signed: &Map) -> Option<ClaimSortKey<'_>> {
        signed
            .get("claim")
            .and_then(Value::as_map)
            .and_then(claim_sort_key)
    }
    let Some(a) = a else {
        return b.clone();
    };
    let winner = match (key(a), key(b)) {
        (Some(key_a), Some(key_b)) if key_b < key_a => b,
        (None, Some(_)) => b,
        _ => a,
    };
    winner.clone()
}

// ---------------------------------------------------------------------------------------------
// Payloads

/// Where a record's payload bytes are (SPEC §7.1, §7.2; the Python peer's `payload_of`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSource<'a> {
    /// The payload travels inside the record.
    Inline(&'a [u8]),
    /// The payload is a block of this id (`z...`, [`block_cid`]), fetched by `BLOCK_WANT`.
    Block(&'a str),
    /// The payload is an artifact of the content swarm under this root (`b...`).
    Content(&'a str),
    /// Neither a payload nor a reference: the payload is [`NULL_PAYLOAD`].
    Null,
}

/// Where `record`'s payload is: an inline `payload` wins; otherwise a non-empty text
/// `payloadRef` is a content root when it starts with `b` and a block otherwise; anything else
/// (absent, null, empty, or not text) is the CBOR null. `None` when `payload` is present but
/// neither null nor bytes.
pub fn payload_source(record: &Map) -> Option<PayloadSource<'_>> {
    if let Some(payload) = present(record, "payload") {
        return payload.as_bytes().map(PayloadSource::Inline);
    }
    let reference = record
        .get("payloadRef")
        .and_then(Value::as_str)
        .filter(|reference| !reference.is_empty());
    Some(match reference {
        None => PayloadSource::Null,
        Some(root) if root.starts_with('b') => PayloadSource::Content(root),
        Some(cid) => PayloadSource::Block(cid),
    })
}

/// The id of a block (SPEC §7.1, `wire.py`'s `block_cid`): multibase base58btc of SHA-256 over
/// its bytes, the `z...` reference a record carries for a payload above
/// [`crate::limits::INLINE_PAYLOAD_LIMIT`]. One implementation, owned by [`crate::bodies`].
pub use crate::bodies::block_cid;
