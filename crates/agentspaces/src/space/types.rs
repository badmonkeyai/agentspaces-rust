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

//! The values the space verbs take and give: [`EntryId`], [`Lease`], [`Template`],
//! [`EntryView`], [`Attestation`], [`SpaceEvent`], and [`SpaceError`].

#![warn(missing_docs)]

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::filters::{Conditions, FilterError, Matcher};
use agentspaces_wire::fold::Refusal;
use agentspaces_wire::limits::MAX_CLAIM_HOLD_MILLIS;
use agentspaces_wire::time;

use crate::entry::{self, Entry, EntryError};
use crate::peer::PeerError;

// ---------------------------------------------------------------------------------------------
// Entry ids

/// An entry's id: the version 4 UUID its writer drew, in text form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId(String);

impl EntryId {
    /// An entry id from its text.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id's text, owned.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for EntryId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for EntryId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<String> for EntryId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for EntryId {
    fn from(id: &str) -> Self {
        Self(id.to_owned())
    }
}

impl PartialEq<str> for EntryId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for EntryId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// ---------------------------------------------------------------------------------------------
// Leases

/// How long something lasts: a write's lease, a take's hold, a result's lease, or a leased
/// subscription ([`crate::space::Space::notify`]). Always a positive number of milliseconds.
///
/// Built from milliseconds ([`Lease::from_millis`]), a [`Duration`] (`TryFrom`), or text
/// ([`Lease::parse`], [`FromStr`]): the short forms `"250ms"`, `"30s"`, `"10m"`, `"2h"`, `"1d"`
/// (`space.py`'s `duration_millis`) or a `java.time.Duration` such as `"PT30S"` or `"PT1H30M"`.
///
/// ```
/// use std::time::Duration;
/// use agentspaces::space::Lease;
///
/// assert_eq!(Lease::parse("30s")?.millis(), 30_000);
/// assert_eq!("PT10M".parse::<Lease>()?, Lease::try_from(Duration::from_secs(600))?);
/// assert!(Lease::parse("0s").is_err());
/// # Ok::<(), agentspaces::space::SpaceError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Lease {
    millis: i64,
}

impl Lease {
    /// A write's default lease, 10 minutes (`space.py`'s `write`).
    pub const DEFAULT_WRITE: Lease = Lease { millis: 600_000 };
    /// A take's default hold, 1 minute (`space.py`'s `take`).
    pub const DEFAULT_TAKE: Lease = Lease { millis: 60_000 };
    /// A result's default lease, 1 hour (`space.py`'s `complete`).
    pub const DEFAULT_RESULT: Lease = Lease { millis: 3_600_000 };
    /// A leased subscription's default lease, 1 hour (`space.py`'s `notify`).
    pub const DEFAULT_NOTIFY: Lease = Lease { millis: 3_600_000 };
    /// The longest hold a take may ask for: receivers refuse a claim held longer
    /// ([`MAX_CLAIM_HOLD_MILLIS`], 24 hours).
    pub const MAX_TAKE: Lease = Lease {
        millis: MAX_CLAIM_HOLD_MILLIS,
    };

    /// A lease of `millis` milliseconds; [`SpaceError::InvalidLease`] unless positive.
    pub fn from_millis(millis: i64) -> Result<Lease, SpaceError> {
        if millis > 0 {
            Ok(Lease { millis })
        } else {
            Err(SpaceError::InvalidLease(format!(
                "a lease must be positive, not {millis} ms"
            )))
        }
    }

    /// A lease from text: `<digits><unit>` with the unit `ms`, `s`, `m`, `h`, or `d` (spaces
    /// around and between allowed), or a `java.time.Duration` (`PT...`) as the wire prints
    /// one ([`time::parse_duration_millis`]). Anything else, zero, and an overflow are
    /// [`SpaceError::InvalidLease`].
    pub fn parse(text: &str) -> Result<Lease, SpaceError> {
        let invalid = || SpaceError::InvalidLease(format!("not a lease: {text:?}"));
        let trimmed = text.trim();
        if trimmed.starts_with("PT") {
            let millis = time::parse_duration_millis(trimmed).map_err(|_| invalid())?;
            return Lease::from_millis(millis);
        }
        let split = trimmed
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(invalid)?;
        let (digits, unit) = trimmed.split_at(split);
        let amount: i64 = digits.parse().map_err(|_| invalid())?;
        let scale: i64 = match unit.trim() {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => return Err(invalid()),
        };
        let millis = amount.checked_mul(scale).ok_or_else(invalid)?;
        Lease::from_millis(millis)
    }

    /// The lease in milliseconds.
    pub fn millis(self) -> i64 {
        self.millis
    }

    /// The lease as a [`Duration`].
    pub fn duration(self) -> Duration {
        Duration::from_millis(u64::try_from(self.millis).unwrap_or_default())
    }
}

impl TryFrom<Duration> for Lease {
    type Error = SpaceError;

    /// A lease of the duration's whole milliseconds; [`SpaceError::InvalidLease`] when that is
    /// zero or does not fit an `i64`.
    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        let millis = i64::try_from(duration.as_millis()).map_err(|_| {
            SpaceError::InvalidLease(format!("{duration:?} does not fit in milliseconds"))
        })?;
        Lease::from_millis(millis)
    }
}

impl FromStr for Lease {
    type Err = SpaceError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Lease::parse(text)
    }
}

impl fmt::Display for Lease {
    /// The shortest exact short form: `10m`, `90s`, `250ms`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let millis = self.millis;
        for (unit, scale) in [
            ("d", 86_400_000),
            ("h", 3_600_000),
            ("m", 60_000),
            ("s", 1_000),
        ] {
            if millis % scale == 0 {
                return write!(f, "{}{unit}", millis / scale);
            }
        }
        write!(f, "{millis}ms")
    }
}

// ---------------------------------------------------------------------------------------------
// Templates

/// A query over a space (`space.py`'s `Template`, Java `Template`): the entry schema (its wire
/// type name, `"<Type>#v<version>"`), conditions on payload fields, and conditions on tags, all
/// of which must hold ([`Conditions`], with the Java `Matchers` semantics).
///
/// ```
/// use agentspaces::space::Template;
/// use agentspaces::wire::filters::Matcher;
///
/// let template = Template::new("com.acme.Task#v1")
///     .where_("topic", Matcher::Eq("index".into()))
///     .where_clause("priority>=3")?
///     .tag("region", Matcher::In(vec!["eu".into(), "us".into()]));
/// assert_eq!(template.schema(), "com.acme.Task#v1");
/// # Ok::<(), agentspaces::space::SpaceError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Template {
    schema: String,
    conditions: Conditions,
}

impl Template {
    /// Every entry of `schema`.
    pub fn new(schema: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            conditions: Conditions::new(),
        }
    }

    /// Every entry of `T`'s schema ([`Entry::SCHEMA`]): the template of the typed verbs
    /// ([`typed`](crate::space::typed)), narrowed with conditions as any template.
    ///
    /// ```
    /// use agentspaces::Entry;
    /// use agentspaces::space::Template;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize, Entry)]
    /// #[entry(schema = "com.acme.Task#v1")]
    /// struct Task {
    ///     topic: String,
    ///     priority: i32,
    /// }
    ///
    /// let urgent = Template::of::<Task>().where_clause("priority>=3")?;
    /// assert_eq!(urgent.schema(), "com.acme.Task#v1");
    /// # Ok::<(), agentspaces::space::SpaceError>(())
    /// ```
    pub fn of<T: Entry>() -> Self {
        Self::new(T::SCHEMA)
    }

    /// Entries of `schema` meeting `conditions`.
    pub fn with_conditions(schema: impl Into<String>, conditions: Conditions) -> Self {
        Self {
            schema: schema.into(),
            conditions,
        }
    }

    /// This template and a matcher on a payload field (an absent field reads as null).
    pub fn where_(mut self, field: impl Into<String>, matcher: Matcher) -> Self {
        self.conditions = self.conditions.with_field(field, matcher);
        self
    }

    /// This template and a clause of the portable filter grammar (`"priority>=3"`,
    /// `"region in eu,us"`, SPEC §7.2), or [`SpaceError::Filter`] when it does not parse.
    pub fn where_clause(mut self, clause: &str) -> Result<Self, SpaceError> {
        self.conditions = self.conditions.with_clause(clause)?;
        Ok(self)
    }

    /// This template and a matcher on a tag (an absent tag reads as null).
    pub fn tag(mut self, key: impl Into<String>, matcher: Matcher) -> Self {
        self.conditions = self.conditions.with_tag(key, matcher);
        self
    }

    /// This template and a tag that must equal `value`.
    pub fn tag_eq(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tag(key, Matcher::Eq(Value::Text(value.into())))
    }

    /// The schema the template selects.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// The field and tag conditions.
    pub fn conditions(&self) -> &Conditions {
        &self.conditions
    }

    /// Whether an entry of `schema` with `payload` and `tags` matches: the schema is this
    /// template's and every condition holds. A payload that is not a map has no fields (each
    /// reads as null).
    pub fn matches(&self, schema: &str, payload: &Value, tags: &Map) -> bool {
        if schema != self.schema {
            return false;
        }
        match payload.as_map() {
            Some(fields) => self.conditions.matches(fields, tags),
            None => self.conditions.matches(&Map::new(), tags),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Entry views

/// How an entry's writer is known (Java `Attestation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attestation {
    /// The record is signed by the writing peer's key on behalf of one of its agent names: the
    /// peer asserts which agent wrote it.
    PeerAsserted,
    /// The record is signed by the agent's own key under a certificate its peer issued (SPEC
    /// §11a.3): the agent itself wrote it, and only it (never its peer or a sibling agent) can
    /// renew, cancel, or (when it holds the take) complete it.
    AgentAttested,
}

impl Attestation {
    /// The Java name: `PEER_ASSERTED` or `AGENT_ATTESTED`.
    pub fn as_str(self) -> &'static str {
        match self {
            Attestation::PeerAsserted => "PEER_ASSERTED",
            Attestation::AgentAttested => "AGENT_ATTESTED",
        }
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An entry as this peer holds it: what its signed record says and what has happened to it.
/// Every field comes from state that verified when it folded: the issuer is the record's signer.
///
/// The decoded payload is shared: cloning a view (as each watch's event is a clone of one view)
/// never copies it.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryView {
    pub(crate) entry_id: EntryId,
    pub(crate) schema: String,
    pub(crate) payload: Arc<Value>,
    pub(crate) tags: Map,
    pub(crate) issuer: String,
    pub(crate) issued: String,
    pub(crate) attestation: Attestation,
    pub(crate) expires_at_millis: i64,
    pub(crate) completed: bool,
    pub(crate) holder: Option<String>,
}

impl EntryView {
    /// The entry's id.
    pub fn entry_id(&self) -> &EntryId {
        &self.entry_id
    }

    /// The entry's schema (its wire type name).
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// The decoded payload.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// The decoded payload, owned (copied only when another view still shares it).
    pub fn into_payload(self) -> Value {
        Arc::unwrap_or_clone(self.payload)
    }

    /// The payload read as `T` ([`entry::decode_entry`]: [`Entry::from_payload`], by default
    /// [`entry::from_value`]), refusing an entry of another schema.
    ///
    /// # Errors
    ///
    /// [`EntryError::WrongSchema`] when the entry is not of `T`'s schema, [`EntryError::Decode`]
    /// (naming the path to the offending value) when its payload does not fit `T`.
    pub fn decode<T: Entry>(&self) -> Result<T, EntryError> {
        entry::decode_entry(&self.schema, &self.payload)
    }

    /// The record's tags (text to text).
    pub fn tags(&self) -> &Map {
        &self.tags
    }

    /// A tag's value.
    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags.get(key).and_then(Value::as_str)
    }

    /// The writer: the AgentID whose signature the record carries.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The record's issue stamp (`physical:logical:node`).
    pub fn issued(&self) -> &str {
        &self.issued
    }

    /// Whether the writer is peer-asserted or agent-attested.
    pub fn attestation(&self) -> Attestation {
        self.attestation
    }

    /// When the write lease lapses (renewals included), epoch milliseconds.
    pub fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }

    /// Whether the entry is completed (consumed for good by its taker).
    pub fn completed(&self) -> bool {
        self.completed
    }

    /// The holder of the entry's take: the AgentID of a live claim, or, for a completed entry,
    /// of the claim that completed it; `None` when nobody holds it.
    pub fn holder(&self) -> Option<&str> {
        self.holder.as_deref()
    }
}

// ---------------------------------------------------------------------------------------------
// Events

/// What happened to an entry (Java `SpaceEvent.Kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// A live entry folded here for the first time.
    Written,
    /// A take claim on the entry is in force: a member's claim folded, or this peer won its take.
    Taken,
    /// The entry was completed.
    Completed,
    /// The entry's write lease lapsed while it was still open.
    Expired,
    /// A take's hold lapsed without a completion: the entry is available again.
    Reappeared,
}

impl EventKind {
    /// The Java name: `WRITTEN`, `TAKEN`, `COMPLETED`, `EXPIRED`, or `REAPPEARED`.
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Written => "WRITTEN",
            EventKind::Taken => "TAKEN",
            EventKind::Completed => "COMPLETED",
            EventKind::Expired => "EXPIRED",
            EventKind::Reappeared => "REAPPEARED",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One transition of one entry, as a watch delivers it ([`crate::space::Space::watch`]). Events
/// are delivered at least once: deduplicate on `(entry.entry_id(), kind)` (and, for `Taken` and
/// `Reappeared`, the holder) when it matters.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SpaceEvent {
    /// What happened.
    pub kind: EventKind,
    /// The entry, as this peer held it when the event was delivered.
    pub entry: EntryView,
}

// ---------------------------------------------------------------------------------------------
// Errors

/// Why a space verb could not be carried out.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpaceError {
    /// The peer refused the call (closed, a revoked agent, an agent of another peer, a payload
    /// too large, ...). A [`PeerError::Refused`] converts to [`SpaceError::Refused`] instead.
    #[error(transparent)]
    Peer(PeerError),
    /// A lease is not positive, does not parse, or is longer than allowed.
    #[error("{0}")]
    InvalidLease(String),
    /// A filter clause does not parse.
    #[error(transparent)]
    Filter(#[from] FilterError),
    /// A typed verb's value has no payload form, an entry asked for by id does not decode as the
    /// type, or a typed verb's template is of another schema than its type
    /// ([`typed`](crate::space::typed)).
    #[error(transparent)]
    Entry(#[from] EntryError),
    /// No entry of this id is held in the space.
    #[error("no entry {0} is held in this space")]
    UnknownEntry(EntryId),
    /// The entry was written by another agent than the one acting: only its issuer renews or
    /// cancels it.
    #[error("{entry_id} was written by {issuer}, not by {actor}")]
    NotIssuer {
        /// The entry.
        entry_id: EntryId,
        /// Its issuer.
        issuer: String,
        /// Who tried to act on it.
        actor: String,
    },
    /// The take's hold lapsed or was lost (another holder won, or the entry was completed or
    /// withdrawn): it can no longer be renewed or completed (Java `LeaseExpiredException`).
    #[error("the take of {0} lapsed or was lost")]
    NotHeld(EntryId),
    /// The entry's write lease already lapsed, or the entry is completed or withdrawn: it cannot
    /// be renewed (Java `LeaseExpiredException`).
    #[error("the write lease of {0} lapsed, or the entry is no longer live")]
    LeaseLapsed(EntryId),
    /// The subscription's lease lapsed, or it was closed, before a renewal.
    #[error("the subscription is closed or its lease lapsed")]
    SubscriptionClosed,
    /// This peer's own fold refused a state it built; nothing was sent. [`Refusal::Full`] when
    /// the space already holds its bound of entries
    /// ([`PeerConfig::space_max_entries`](crate::peer::PeerConfig::space_max_entries));
    /// otherwise a bug, or a revocation that landed meanwhile.
    #[error("the fold refused the state built for {entry_id}: {refusal}")]
    Refused {
        /// The entry.
        entry_id: EntryId,
        /// The fold's reason.
        refusal: Refusal,
    },
    /// A blocking call was made from inside a Tokio runtime ([`crate::blocking`]); use the async
    /// API there.
    #[error(
        "a blocking agentspaces call was made from inside a Tokio runtime; use the async API there"
    )]
    InsideRuntime,
    /// The blocking facade's runtime could not be built.
    #[error("the blocking runtime could not start: {0}")]
    Runtime(String),
}

impl From<PeerError> for SpaceError {
    /// [`SpaceError::Peer`], but a refusal of this peer's own fold ([`PeerError::Refused`]) is
    /// [`SpaceError::Refused`], whichever layer reported it.
    fn from(error: PeerError) -> Self {
        match error {
            PeerError::Refused { entry_id, refusal } => SpaceError::Refused {
                entry_id: EntryId::new(entry_id),
                refusal,
            },
            other => SpaceError::Peer(other),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// What the space handles and the actor pass each other

/// A claim this peer published for a take: what the settle check and the take's later renewals
/// and completion name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimTicket {
    /// The claim's epoch.
    pub epoch: i64,
    /// The holder (an AgentID).
    pub holder: String,
    /// When the claim's hold lapses, epoch milliseconds.
    pub expires_at: i64,
}

/// The result a completion writes into the take's space.
#[derive(Debug, Clone)]
pub(crate) struct ResultWrite {
    /// Its schema.
    pub schema: String,
    /// Its payload.
    pub payload: Value,
    /// Its write lease, milliseconds.
    pub lease_millis: i64,
    /// Its tags.
    pub tags: Map,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_parse_short_forms_and_java_durations() {
        let cases = [
            ("250ms", 250),
            ("30s", 30_000),
            (" 10 m ", 600_000),
            ("2h", 7_200_000),
            ("1d", 86_400_000),
            ("PT30S", 30_000),
            ("PT1H30M", 5_400_000),
            ("PT0.5S", 500),
        ];
        for (text, millis) in cases {
            assert_eq!(
                Lease::parse(text).map(Lease::millis).ok(),
                Some(millis),
                "{text}"
            );
        }
        for bad in [
            "",
            "30",
            "s",
            "0s",
            "-5s",
            "5x",
            "PT",
            "PT0S",
            "99999999999999999999d",
        ] {
            assert!(Lease::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Lease::from_millis(5).map(Lease::millis).ok(), Some(5));
        assert!(Lease::from_millis(0).is_err());
        assert!(Lease::try_from(Duration::ZERO).is_err());
        assert!(Lease::try_from(Duration::from_micros(999)).is_err());
        assert_eq!(
            Lease::try_from(Duration::from_secs(90)).ok(),
            Lease::parse("90s").ok()
        );
        assert_eq!(Lease::DEFAULT_WRITE.to_string(), "10m");
        assert_eq!(
            Lease::parse("1500ms")
                .map(|l| l.to_string())
                .ok()
                .as_deref(),
            Some("1500ms")
        );
        assert_eq!(Lease::DEFAULT_TAKE.duration(), Duration::from_secs(60));
    }

    #[test]
    fn templates_match_schema_fields_and_tags() {
        let template = Template::new("T#v1")
            .where_("topic", Matcher::Eq("index".into()))
            .where_clause("priority>=3")
            .expect("a clause")
            .tag_eq("region", "eu");
        let payload = Value::Map(
            [("topic", Value::from("index")), ("priority", Value::Int(4))]
                .into_iter()
                .collect(),
        );
        let tags: Map = [("region", "eu")].into_iter().collect();
        assert!(template.matches("T#v1", &payload, &tags));
        assert!(!template.matches("U#v1", &payload, &tags));
        assert!(!template.matches("T#v1", &payload, &Map::new()));
        assert!(!template.matches("T#v1", &Value::Int(3), &tags));
        assert!(Template::new("T#v1").matches("T#v1", &Value::Null, &Map::new()));
        assert!(matches!(
            Template::new("T#v1").where_clause("nope"),
            Err(SpaceError::Filter(_))
        ));
    }

    #[test]
    fn entry_ids_compare_with_text() {
        let id = EntryId::new("abc");
        assert_eq!(id, "abc");
        assert_eq!(id.as_str(), "abc");
        assert_eq!(id.to_string(), "abc");
        assert_eq!(EntryId::from("abc"), id);
    }
}
