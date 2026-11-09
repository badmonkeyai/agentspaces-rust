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

//! The beacon document (SPEC §10.1, TECH-SPEC §10.0a), the pure half of `beacon.py` with Java
//! `BeaconDocument` as the authority on bytes: the JSON document a beacon serves at
//! [`WELL_KNOWN`] (or a social beacon under `/j/<code>`). Fetching is the peer crate's; this
//! module parses, builds, signs, verifies, and selects.
//!
//! Per group a document carries the name, the `aspace://` id, the signed founding advertisement
//! (base64 CBOR), the seeds, the wire hints, the multicast group, free parameters, and, at a
//! social beacon, the public delegation (`invite`). Document-wide it carries the issuer PeerID,
//! its raw key (base64), the issue time, a time to live in seconds, and the issuer's Ed25519
//! signature over the canonical bytes: every field but `signature`, in declared order, null
//! fields omitted, map keys sorted, no whitespace, exactly as Jackson writes them
//! ([`canonical_bytes`]). A reader ignores unknown fields. A document never carries a content
//! key, a credential, or a membership hint: parameters by those names
//! ([`FORBIDDEN_PARAMETERS`]) are refused when a group is built, parsed, or signed.
//!
//! The document is typed ([`BeaconDocument`], [`Group`], [`DocumentSeed`]) and read as Java's
//! Jackson mapper reads it ([`BeaconDocument::parse`]): an absent or null number is 0, a
//! fractional number is truncated, a number outside its Java type is refused, an absent or null
//! list is empty, and a value of the wrong JSON type is refused rather than coerced.
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::Value as Json;

use crate::cbor::{self, Map, Value};
use crate::founding;
use crate::identity::Identity;
use crate::ids::{self, URI_PREFIX};
// `seed_address` is `seed.py`'s, which `beacon.py` re-exports as well.
pub use crate::seed::{Seed, seed_address};
use crate::social::{base64_decode, base64_encode};
use crate::util::{encode_map, java_order};

/// The document version this library writes.
pub const VERSION: i32 = 1;
/// The well-known path (RFC 8615 shape) a beacon serves its document at.
pub const WELL_KNOWN: &str = "/.well-known/agentspaces/beacon.json";
/// The largest document accepted (Java `UrlLocator.Options.maxBytes`).
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// Parameter names (compared in lower case) a document never carries.
pub const FORBIDDEN_PARAMETERS: [&str; 8] = [
    "content-key",
    "contentkey",
    "credential",
    "membership",
    "hints",
    "secret",
    "invite-secret",
    "join-credential",
];

/// Why a beacon document was refused, or a group could not be selected or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BeaconError {
    /// The document is larger than [`MAX_DOCUMENT_BYTES`].
    #[error("the beacon document is {0} bytes, more than {MAX_DOCUMENT_BYTES}")]
    TooLarge(usize),
    /// The bytes are not JSON.
    #[error("not a JSON document: {0}")]
    Json(String),
    /// A field has a JSON type or a value its Java type cannot hold.
    #[error("not a beacon document: {field} is malformed")]
    Malformed {
        /// The field (`groups[].seeds[].priority` style).
        field: &'static str,
    },
    /// The version is below 1.
    #[error("not a beacon document: v={0}")]
    Version(i32),
    /// A group carries a forbidden parameter.
    #[error("a beacon document never carries {0:?}")]
    ForbiddenParameter(String),
    /// A carried signature does not verify under a key hashing to the issuer.
    #[error("the beacon document's signature does not verify")]
    BadSignature,
    /// The document is not signed by the pinned beacon.
    #[error("the beacon document is not signed by the pinned beacon {0}")]
    NotPinned(String),
    /// No group has the requested id.
    #[error("the beacon document carries no group {0}")]
    NoSuchGroup(String),
    /// No group has the requested name.
    #[error("the beacon document carries no group named {0:?}")]
    NoGroupNamed(String),
    /// Neither an id nor a name was given and the document does not carry exactly one group.
    #[error("the beacon document carries {0} groups; name one")]
    Ambiguous(usize),
    /// The group carries no founding.
    #[error("the beacon document carries no founding for {0:?}")]
    NoFounding(String),
    /// The group's founding is not base64 CBOR.
    #[error("the founding of {0:?} is not base64 CBOR")]
    FoundingNotCbor(String),
    /// The group's founding fails the four checks of SPEC §5.1.
    #[error("the founding of {0:?} does not verify")]
    FoundingInvalid(String),
    /// The founding verifies to another group than the group's id or the expected id.
    #[error("the founding of {name:?} derives to {derived}, not {expected}")]
    FoundingMismatch {
        /// The group's name.
        name: String,
        /// The GroupID the founding verifies to.
        derived: String,
        /// The id it should have been.
        expected: String,
    },
}

// ---------------------------------------------------------------------------------------------
// The document

/// One seed of a group as the document lists it (Java `BeaconDocument.Seed`): written with every
/// field, nulls included.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DocumentSeed {
    /// The scheme (`tcp`, `tls`, `dtls`, `wss`, ...); absent reads as `tcp` when dialing.
    pub transport: Option<String>,
    /// `host:port` (`[v6]:port`), possibly with a path for schemes that take one.
    pub address: Option<String>,
    /// Lower dials first.
    pub priority: i32,
}

/// One group of a document (Java `BeaconDocument.Group`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group's name.
    pub name: String,
    /// The `aspace://` id, when the group has a self-certifying one.
    pub id: Option<String>,
    /// The signed founding advertisement, base64 CBOR.
    pub founding: Option<String>,
    /// The seeds, by position.
    pub seeds: Vec<DocumentSeed>,
    /// Wire hints (`session`, `batch`, ...).
    pub wire: Option<BTreeMap<String, i32>>,
    /// The multicast group, `address:port`.
    pub multicast: Option<String>,
    /// Free parameters; never one of [`FORBIDDEN_PARAMETERS`].
    pub parameters: Option<BTreeMap<String, String>>,
    /// At a social beacon, the founder's delegation string (public data).
    pub invite: Option<String>,
}

impl Group {
    /// A group with only its name and no seeds.
    pub fn new(name: impl Into<String>) -> Self {
        Group {
            name: name.into(),
            id: None,
            founding: None,
            seeds: Vec::new(),
            wire: None,
            multicast: None,
            parameters: None,
            invite: None,
        }
    }

    /// The group with its id: a bare GroupID gains the `aspace://` prefix.
    pub fn with_id(mut self, group_id: &str) -> Self {
        self.id = Some(if group_id.starts_with(URI_PREFIX) {
            group_id.to_owned()
        } else {
            format!("{URI_PREFIX}{group_id}")
        });
        self
    }

    /// The group with its founding, already base64 CBOR.
    pub fn with_founding(mut self, founding_base64: impl Into<String>) -> Self {
        self.founding = Some(founding_base64.into());
        self
    }

    /// The group with its founding: the base64 CBOR of a signed group advertisement
    /// (`{advertisement, founderPublicKey, signature}`, as [`founding::found_group`] returns it).
    pub fn with_signed_founding(self, signed: &Map) -> Self {
        self.with_founding(base64_encode(&encode_map(signed)))
    }

    /// The group with one more seed, its priority its position (as `document_group` numbers
    /// `(transport, address)` pairs).
    pub fn with_seed(mut self, transport: impl Into<String>, address: impl Into<String>) -> Self {
        let priority = i32::try_from(self.seeds.len()).unwrap_or(i32::MAX);
        self.seeds.push(DocumentSeed {
            transport: Some(transport.into()),
            address: Some(address.into()),
            priority,
        });
        self
    }

    /// The group with one more seed, as given.
    pub fn with_document_seed(mut self, seed: DocumentSeed) -> Self {
        self.seeds.push(seed);
        self
    }

    /// The group with one wire hint set.
    pub fn with_wire(mut self, key: impl Into<String>, value: i32) -> Self {
        self.wire
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), value);
        self
    }

    /// The group with its multicast group.
    pub fn with_multicast(mut self, multicast: impl Into<String>) -> Self {
        self.multicast = Some(multicast.into());
        self
    }

    /// The group with one parameter set; a forbidden name is refused (a document never carries
    /// a secret).
    pub fn with_parameter(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, BeaconError> {
        let key = key.into();
        check_parameter(&key)?;
        self.parameters
            .get_or_insert_with(BTreeMap::new)
            .insert(key, value.into());
        Ok(self)
    }

    /// The group with the social beacon's delegation string.
    pub fn with_invite(mut self, delegation: impl Into<String>) -> Self {
        self.invite = Some(delegation.into());
        self
    }

    fn check_parameters(&self) -> Result<(), BeaconError> {
        self.parameters
            .iter()
            .flat_map(BTreeMap::keys)
            .try_for_each(|key| check_parameter(key))
    }
}

fn check_parameter(key: &str) -> Result<(), BeaconError> {
    if FORBIDDEN_PARAMETERS.contains(&key.to_lowercase().as_str()) {
        Err(BeaconError::ForbiddenParameter(key.to_owned()))
    } else {
        Ok(())
    }
}

/// `beacon.py`'s `document_group`: a group by name with its optional id (a bare GroupID gains
/// the `aspace://` prefix), founding (base64 CBOR), and `(transport, address)` seeds numbered by
/// position. The remaining fields are set with [`Group`]'s builders.
pub fn document_group(
    name: &str,
    group_id: Option<&str>,
    founding: Option<&str>,
    seeds: &[(&str, &str)],
) -> Group {
    let mut group = Group::new(name);
    if let Some(id) = group_id {
        group = group.with_id(id);
    }
    if let Some(founding) = founding {
        group = group.with_founding(founding);
    }
    seeds.iter().fold(group, |group, (transport, address)| {
        group.with_seed(*transport, *address)
    })
}

/// A beacon document (Java `BeaconDocument`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconDocument {
    /// The document version; at least 1 in a document a reader accepts.
    pub v: i32,
    /// The issuer's PeerID.
    pub issuer: Option<String>,
    /// The issuer's raw Ed25519 public key, standard base64.
    pub issuer_key: Option<String>,
    /// The issue instant, `java.time.Instant` text.
    pub issued: Option<String>,
    /// How long, in seconds, a reader may reuse the document.
    pub ttl: i64,
    /// The groups.
    pub groups: Vec<Group>,
    /// The issuer's Ed25519 signature over [`canonical_bytes`], standard base64.
    pub signature: Option<String>,
}

impl BeaconDocument {
    /// Parses a document as Java `BeaconDocument.parse` does: at most [`MAX_DOCUMENT_BYTES`],
    /// a JSON object, unknown fields ignored, `v` at least 1, and no forbidden parameter. A
    /// value of the wrong shape is refused (see the module documentation for the number rules).
    /// A leading UTF-8 byte order mark is skipped, as Jackson skips it.
    pub fn parse(bytes: &[u8]) -> Result<BeaconDocument, BeaconError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(BeaconError::TooLarge(bytes.len()));
        }
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let json: Json =
            serde_json::from_slice(bytes).map_err(|e| BeaconError::Json(e.to_string()))?;
        let doc = document_from_json(&json)?;
        if doc.v < 1 {
            return Err(BeaconError::Version(doc.v));
        }
        Ok(doc)
    }
}

// ---------------------------------------------------------------------------------------------
// Reading JSON as Jackson does

fn object<'a>(
    value: &'a Json,
    field: &'static str,
) -> Result<&'a serde_json::Map<String, Json>, BeaconError> {
    value.as_object().ok_or(BeaconError::Malformed { field })
}

/// A `String` field: absent or null is `None`; anything but a string is refused.
fn text(value: Option<&Json>, field: &'static str) -> Result<Option<String>, BeaconError> {
    match value {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(BeaconError::Malformed { field }),
    }
}

/// A Java integral field of the range `min..=max`: absent or null is 0, a fraction truncates
/// (Jackson's `ACCEPT_FLOAT_AS_INT`), numeric text is read as its number, and anything else or
/// out of range is refused.
fn integer(
    value: Option<&Json>,
    field: &'static str,
    min: i64,
    max: i64,
) -> Result<i64, BeaconError> {
    let malformed = BeaconError::Malformed { field };
    let n = match value {
        None | Some(Json::Null) => return Ok(0),
        Some(Json::Number(n)) => match n.as_i64() {
            Some(n) => n,
            None => {
                let x = n.as_f64().ok_or(malformed.clone())?.trunc();
                // `max as f64 + 1.0` is exact for i32 and rounds to 2^63 for i64.
                if !(x >= min as f64 && x < max as f64 + 1.0) {
                    return Err(malformed);
                }
                // In range by the check above.
                x as i64
            }
        },
        Some(Json::String(s)) if s.trim().is_empty() => return Ok(0),
        Some(Json::String(s)) => s.trim().parse::<i64>().map_err(|_| malformed.clone())?,
        Some(_) => return Err(malformed),
    };
    if (min..=max).contains(&n) {
        Ok(n)
    } else {
        Err(malformed)
    }
}

fn int32(value: Option<&Json>, field: &'static str) -> Result<i32, BeaconError> {
    let n = integer(value, field, i64::from(i32::MIN), i64::from(i32::MAX))?;
    i32::try_from(n).map_err(|_| BeaconError::Malformed { field })
}

/// A list field: absent or null is empty.
fn list<'a>(value: Option<&'a Json>, field: &'static str) -> Result<&'a [Json], BeaconError> {
    match value {
        None | Some(Json::Null) => Ok(&[]),
        Some(Json::Array(items)) => Ok(items),
        Some(_) => Err(BeaconError::Malformed { field }),
    }
}

/// A map field: absent or null is `None`; each value is read by `read`.
fn map_of<T>(
    value: Option<&Json>,
    field: &'static str,
    read: impl Fn(&Json) -> Result<T, BeaconError>,
) -> Result<Option<BTreeMap<String, T>>, BeaconError> {
    match value {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Object(entries)) => entries
            .iter()
            .map(|(key, value)| Ok((key.clone(), read(value)?)))
            .collect::<Result<_, _>>()
            .map(Some),
        Some(_) => Err(BeaconError::Malformed { field }),
    }
}

fn seed_from_json(value: &Json) -> Result<DocumentSeed, BeaconError> {
    let seed = object(value, "groups[].seeds[]")?;
    Ok(DocumentSeed {
        transport: text(seed.get("transport"), "groups[].seeds[].transport")?,
        address: text(seed.get("address"), "groups[].seeds[].address")?,
        priority: int32(seed.get("priority"), "groups[].seeds[].priority")?,
    })
}

fn group_from_json(value: &Json) -> Result<Group, BeaconError> {
    let group = object(value, "groups[]")?;
    let parsed = Group {
        name: text(group.get("name"), "groups[].name")?.ok_or(BeaconError::Malformed {
            field: "groups[].name",
        })?,
        id: text(group.get("id"), "groups[].id")?,
        founding: text(group.get("founding"), "groups[].founding")?,
        seeds: list(group.get("seeds"), "groups[].seeds")?
            .iter()
            .map(seed_from_json)
            .collect::<Result<_, _>>()?,
        wire: map_of(group.get("wire"), "groups[].wire", |v| {
            match v {
                // Java's Map<String, Integer> keeps a null; this reader refuses it instead.
                Json::Null => Err(BeaconError::Malformed {
                    field: "groups[].wire",
                }),
                v => int32(Some(v), "groups[].wire"),
            }
        })?,
        multicast: text(group.get("multicast"), "groups[].multicast")?,
        parameters: map_of(group.get("parameters"), "groups[].parameters", |v| {
            v.as_str().map(str::to_owned).ok_or(BeaconError::Malformed {
                field: "groups[].parameters",
            })
        })?,
        invite: text(group.get("invite"), "groups[].invite")?,
    };
    parsed.check_parameters()?;
    Ok(parsed)
}

fn document_from_json(value: &Json) -> Result<BeaconDocument, BeaconError> {
    let doc = object(value, "document")?;
    Ok(BeaconDocument {
        v: int32(doc.get("v"), "v")?,
        issuer: text(doc.get("issuer"), "issuer")?,
        issuer_key: text(doc.get("issuerKey"), "issuerKey")?,
        issued: text(doc.get("issued"), "issued")?,
        ttl: integer(doc.get("ttl"), "ttl", i64::MIN, i64::MAX)?,
        groups: list(doc.get("groups"), "groups")?
            .iter()
            .map(group_from_json)
            .collect::<Result<_, _>>()?,
        signature: text(doc.get("signature"), "signature")?,
    })
}

// ---------------------------------------------------------------------------------------------
// Writing JSON as Jackson does

/// A JSON string as Jackson's generator writes it: `"` and `\` escaped, the control characters
/// with a short escape as `\b \t \n \f \r`, every other one below U+0020 as upper-case
/// `\u00XX`, and everything else (DEL and non-ASCII included) as its UTF-8.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_field(out: &mut String, first: &mut bool, key: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    write_string(out, key);
    out.push(':');
}

fn write_text_field(out: &mut String, first: &mut bool, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        write_field(out, first, key);
        write_string(out, value);
    }
}

/// A map sorted by key, each value written by `value`: in Java's `String.compareTo` order
/// ([`java_order`]), the order `ORDER_MAP_ENTRIES_BY_KEYS` sorts map keys in.
fn write_sorted<T>(out: &mut String, map: &BTreeMap<String, T>, value: impl Fn(&mut String, &T)) {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| java_order(a, b));
    out.push('{');
    let mut first = true;
    for (key, item) in entries {
        write_field(out, &mut first, key);
        value(out, item);
    }
    out.push('}');
}

fn write_seed(out: &mut String, seed: &DocumentSeed) {
    out.push('{');
    let mut first = true;
    // Java's Seed record has no NON_NULL inclusion: a missing transport or address is null.
    for (key, value) in [("transport", &seed.transport), ("address", &seed.address)] {
        write_field(out, &mut first, key);
        match value {
            Some(text) => write_string(out, text),
            None => out.push_str("null"),
        }
    }
    write_field(out, &mut first, "priority");
    out.push_str(&seed.priority.to_string());
    out.push('}');
}

fn write_group(out: &mut String, group: &Group) {
    out.push('{');
    let mut first = true;
    write_text_field(out, &mut first, "name", Some(&group.name));
    write_text_field(out, &mut first, "id", group.id.as_deref());
    write_text_field(out, &mut first, "founding", group.founding.as_deref());
    write_field(out, &mut first, "seeds");
    out.push('[');
    for (i, seed) in group.seeds.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_seed(out, seed);
    }
    out.push(']');
    if let Some(wire) = &group.wire {
        write_field(out, &mut first, "wire");
        write_sorted(out, wire, |out, n| out.push_str(&n.to_string()));
    }
    write_text_field(out, &mut first, "multicast", group.multicast.as_deref());
    if let Some(parameters) = &group.parameters {
        write_field(out, &mut first, "parameters");
        write_sorted(out, parameters, |out, text| write_string(out, text));
    }
    write_text_field(out, &mut first, "invite", group.invite.as_deref());
    out.push('}');
}

/// The document's fields in declared order, without the closing brace, with or without the
/// signature.
fn write_document(doc: &BeaconDocument, signature: bool) -> String {
    let mut out = String::with_capacity(512);
    out.push('{');
    let mut first = true;
    write_field(&mut out, &mut first, "v");
    out.push_str(&doc.v.to_string());
    write_text_field(&mut out, &mut first, "issuer", doc.issuer.as_deref());
    write_text_field(&mut out, &mut first, "issuerKey", doc.issuer_key.as_deref());
    write_text_field(&mut out, &mut first, "issued", doc.issued.as_deref());
    write_field(&mut out, &mut first, "ttl");
    out.push_str(&doc.ttl.to_string());
    write_field(&mut out, &mut first, "groups");
    out.push('[');
    for (i, group) in doc.groups.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_group(&mut out, group);
    }
    out.push(']');
    if signature {
        write_text_field(&mut out, &mut first, "signature", doc.signature.as_deref());
    }
    out.push('}');
    out
}

/// The bytes the signature covers (Java `BeaconDocument.canonicalBytes`): every field but
/// `signature`, in declared order (`v`, `issuer`, `issuerKey`, `issued`, `ttl`, `groups`; a
/// group's `name`, `id`, `founding`, `seeds`, `wire`, `multicast`, `parameters`, `invite`; a
/// seed's `transport`, `address`, `priority`), null fields omitted (a seed's excepted), map keys
/// sorted, no whitespace, strings escaped as Jackson escapes them.
pub fn canonical_bytes(doc: &BeaconDocument) -> Vec<u8> {
    write_document(doc, false).into_bytes()
}

/// The document as one line of JSON, signature last (Java `BeaconDocument.toJson`).
pub fn to_json(doc: &BeaconDocument) -> Vec<u8> {
    write_document(doc, true).into_bytes()
}

/// Java `BeaconDocument.signed`: a document of version [`VERSION`] issued at `issued_iso` with a
/// TTL of `ttl_seconds`, signed by `issuer` over its [`canonical_bytes`]. Refused when a group
/// carries a forbidden parameter.
pub fn sign_document(
    issuer: &Identity,
    issued_iso: &str,
    ttl_seconds: i64,
    groups: Vec<Group>,
) -> Result<BeaconDocument, BeaconError> {
    groups.iter().try_for_each(Group::check_parameters)?;
    let mut doc = BeaconDocument {
        v: VERSION,
        issuer: Some(issuer.peer_id().to_owned()),
        issuer_key: Some(base64_encode(issuer.public_raw())),
        issued: Some(issued_iso.to_owned()),
        ttl: ttl_seconds,
        groups,
        signature: None,
    };
    doc.signature = Some(base64_encode(&issuer.sign(&canonical_bytes(&doc))));
    Ok(doc)
}

/// Java `BeaconDocument.signer`: the PeerID the carried key hashes to, when it equals `issuer`
/// and the signature verifies under it over [`canonical_bytes`]; `None` otherwise (an unsigned
/// document included).
pub fn document_signer(doc: &BeaconDocument) -> Option<String> {
    let issuer = doc.issuer.as_deref()?;
    let key = base64_decode(doc.issuer_key.as_deref()?)?;
    if key.len() != crate::crypto::KEY_LENGTH {
        return None;
    }
    let signer = ids::derive_id(&key);
    if signer != issuer {
        return None;
    }
    let signature = base64_decode(doc.signature.as_deref()?)?;
    Identity::verify(&key, &canonical_bytes(doc), &signature).then_some(signer)
}

/// Java `UrlLocator.hint`'s two checks on a fetched document: a carried signature must verify,
/// and a pinned `beacon_peer` must be the verified signer. Returns the signer, or `Ok(None)`
/// for an unsigned document when no beacon is pinned (as the Java reader accepts one). A
/// version below 1 is refused.
pub fn verify_document(
    doc: &BeaconDocument,
    beacon_peer: Option<&str>,
) -> Result<Option<String>, BeaconError> {
    if doc.v < 1 {
        return Err(BeaconError::Version(doc.v));
    }
    let signer = document_signer(doc);
    if doc.signature.is_some() && signer.is_none() {
        return Err(BeaconError::BadSignature);
    }
    if let Some(pinned) = beacon_peer
        && signer.as_deref() != Some(pinned)
    {
        return Err(BeaconError::NotPinned(pinned.to_owned()));
    }
    Ok(signer)
}

// ---------------------------------------------------------------------------------------------
// Selection

/// The group a document carries: by id (`aspace://<id>` or bare) when given, else by name, else
/// the only group (a social beacon serves one per code).
pub fn group_from_document<'a>(
    doc: &'a BeaconDocument,
    group_id: Option<&str>,
    name: Option<&str>,
) -> Result<&'a Group, BeaconError> {
    if let Some(group_id) = group_id {
        let wanted = ids::parse_group_id(group_id);
        return doc
            .groups
            .iter()
            .find(|g| wanted.is_some() && g.id.as_deref().and_then(ids::parse_group_id) == wanted)
            .ok_or_else(|| BeaconError::NoSuchGroup(group_id.to_owned()));
    }
    if let Some(name) = name {
        return doc
            .groups
            .iter()
            .find(|g| g.name == name)
            .ok_or_else(|| BeaconError::NoGroupNamed(name.to_owned()));
    }
    match doc.groups.as_slice() {
        [only] => Ok(only),
        groups => Err(BeaconError::Ambiguous(groups.len())),
    }
}

/// The decoded signed group advertisement a group carries (`{advertisement, founderPublicKey,
/// signature}`), `Ok(None)` when it carries none (or an empty one, or CBOR that is not a map).
/// Refused when the founding is not base64 CBOR.
pub fn founding_of(group: &Group) -> Result<Option<Map>, BeaconError> {
    let Some(founding) = group.founding.as_deref().filter(|f| !f.is_empty()) else {
        return Ok(None);
    };
    let value = base64_decode(founding)
        .and_then(|bytes| cbor::decode(&bytes).ok())
        .ok_or_else(|| BeaconError::FoundingNotCbor(group.name.clone()))?;
    Ok(value.into_map())
}

/// The GroupID the group's founding verifies to under the four checks of SPEC §5.1
/// ([`founding::verify_signed_group_ad`]), which must also be the group's `id` (when it carries
/// one) and, when given, the `expected` id (`aspace://<id>` or bare).
pub fn verified_group_id(group: &Group, expected: Option<&str>) -> Result<String, BeaconError> {
    let signed = founding_of(group)?.ok_or_else(|| BeaconError::NoFounding(group.name.clone()))?;
    let derived = founding::verify_signed_group_ad(&Value::Map(signed))
        .ok_or_else(|| BeaconError::FoundingInvalid(group.name.clone()))?;
    let mismatch = |expected: &str| BeaconError::FoundingMismatch {
        name: group.name.clone(),
        derived: derived.clone(),
        expected: expected.to_owned(),
    };
    if let Some(id) = group.id.as_deref()
        && ids::parse_group_id(id) != Some(derived.as_str())
    {
        return Err(mismatch(id));
    }
    if let Some(expected) = expected
        && ids::parse_group_id(expected) != Some(derived.as_str())
    {
        return Err(mismatch(expected));
    }
    Ok(derived)
}

/// The group's seeds a client can dial, by priority (stable), as [`Seed`]s whose scheme is the
/// seed's transport (`beacon.py`'s `seeds_of`): a seed whose transport (absent or empty reads as
/// `tcp`; compared in lower case) is not among `transports` is skipped, as is one without an
/// address or with an address [`seed_address`] refuses. `transports` is the caller's dialers,
/// for example `&["tcp", "tls"]` for the Python client.
pub fn seeds_of(group: &Group, transports: &[&str]) -> Vec<Seed> {
    let mut seeds: Vec<&DocumentSeed> = group.seeds.iter().collect();
    seeds.sort_by_key(|seed| seed.priority);
    seeds
        .into_iter()
        .filter_map(|seed| {
            let transport = match seed.transport.as_deref() {
                None | Some("") => "tcp".to_owned(),
                Some(transport) => transport.to_lowercase(),
            };
            if !transports.contains(&transport.as_str()) {
                return None;
            }
            let address = seed.address.as_deref().filter(|a| !a.is_empty())?;
            let (host, port) = seed_address(address).ok()?;
            Some(Seed::new(host, port, transport))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    fn written(text: &str) -> String {
        let mut out = String::new();
        write_string(&mut out, text);
        out
    }

    #[test]
    fn strings_are_escaped_as_jackson_escapes_them() {
        assert_eq!(written("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(written("\u{8}\t\n\u{c}\r"), r#""\b\t\n\f\r""#);
        assert_eq!(written("\u{1}\u{1f}\u{7f}"), "\"\\u0001\\u001F\u{7f}\"");
        assert_eq!(written("ü/€😀"), "\"ü/€😀\"");
        // A literal backslash-u is two characters to escape, never upper-cased (Python's
        // regex upper-cases it; Jackson does not).
        assert_eq!(written("\\u00ab"), r#""\\u00ab""#);
    }

    #[test]
    fn map_keys_sort_by_utf16_units() {
        assert_eq!(java_order("\u{FFFD}", "\u{1F600}"), Ordering::Greater);
        assert_eq!("\u{FFFD}".cmp("\u{1F600}"), Ordering::Less);
        let group = Group::new("g")
            .with_wire("\u{1F600}", 1)
            .with_wire("\u{FFFD}", 2)
            .with_wire("a", 3);
        let mut out = String::new();
        write_group(&mut out, &group);
        assert_eq!(
            out,
            "{\"name\":\"g\",\"seeds\":[],\"wire\":{\"a\":3,\"\u{1F600}\":1,\"\u{FFFD}\":2}}"
        );
    }

    #[test]
    fn numbers_are_read_as_jackson_reads_them() {
        let read = |json: &str| int32(serde_json::from_str::<Json>(json).ok().as_ref(), "n");
        assert_eq!(read("7"), Ok(7));
        assert_eq!(read("7.9"), Ok(7));
        assert_eq!(read("-7.9"), Ok(-7));
        assert_eq!(read("7e2"), Ok(700));
        assert_eq!(read("null"), Ok(0));
        assert_eq!(read("\"12\""), Ok(12));
        assert!(read("2147483648").is_err());
        assert!(read("1e300").is_err());
        assert!(read("true").is_err());
        assert!(read("[]").is_err());
        assert_eq!(integer(None, "n", i64::MIN, i64::MAX), Ok(0));
        let big: Json = serde_json::from_str("9223372036854775808").unwrap_or(Json::Null);
        assert!(integer(Some(&big), "n", i64::MIN, i64::MAX).is_err());
    }

    #[test]
    fn seed_addresses() {
        let seed_address = |address: &str| seed_address(address).ok();
        assert_eq!(seed_address(" h:1 "), Some(("h".into(), 1)));
        assert_eq!(seed_address("[::1]:7500"), Some(("::1".into(), 7500)));
        assert_eq!(seed_address("[::1]::7500"), Some(("::1".into(), 7500)));
        assert_eq!(seed_address("a:b:7"), Some(("a:b".into(), 7)));
        assert_eq!(seed_address("h:"), None);
        assert_eq!(seed_address(":7"), None);
        assert_eq!(seed_address("h"), None);
        assert_eq!(seed_address("h:70000"), None);
        assert_eq!(seed_address("h:7/aspace"), None);
        let endpoint = Seed {
            host: "::1".into(),
            port: 7,
            scheme: "tls".into(),
        };
        assert_eq!(endpoint.to_string(), "tls://[::1]:7");
    }
}
