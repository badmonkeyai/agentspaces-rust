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

//! Self-certifying groups (SPEC §4.4, §5.1): founding documents, group advertisements, and the
//! four-check receiver rule, a port of the founding half of `identity.py` with Java
//! `GroupFounding` as the authority on bytes.
//!
//! - The *founding fields* are the group's immutable fields in canonical order: `name`, `founder`
//!   (the founder's PeerID), `issued`, `ttl`, `membershipPolicy`, `defaultStrategy`, and `gossip`
//!   (`fanout`, `period`), the Java record `FoundingFields`.
//! - The founder signs the CBOR of those fields with its Ed25519 key. The *founding document* is
//!   `{fields, signature}`, and the GroupID is the hash of its CBOR
//!   ([`group_id_from_founding_document`]). RFC 8032 signing is deterministic, so the same founder
//!   founding the same fields always derives the same id.
//! - The *signed group advertisement* `{advertisement, founderPublicKey, signature}` is what a
//!   founder joins with and serves to newcomers as a `GROUP_AD` body. [`verify_signed_group_ad`]
//!   is the rule every network-learned one must pass before a node joins or acts on it.
//!
//! Instants and durations are `java.time` text as Java prints it (`"2026-01-01T00:00:00Z"`,
//! `"PT24H"`, not `"P1D"`), because the signature covers those exact bytes.
#![warn(missing_docs)]

use crate::cbor::{Map, Value};
use crate::identity::Identity;
use crate::ids::{self, URI_PREFIX};
use crate::time::{self, TimeError};
use crate::util::encode_map;

/// The membership policies a group may found with (SPEC §5.1), as their Java enum names: anyone
/// joins, a signed invitation is required, or a pluggable validator decides.
pub const MEMBERSHIP_POLICIES: [&str; 3] = ["OPEN", "INVITE", "POLICY"];

/// The conflict strategies a group's spaces may default to (SPEC §7.4), as their Java enum names.
pub const CONFLICT_STRATEGIES: [&str; 3] = ["LEASE_RACE", "AUCTION", "ORDERED"];

/// Why a group could not be founded, or why an advertisement has no founding fields.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FoundingError {
    /// A field is missing or has the wrong type (`gossip.fanout` must be an integer, the other
    /// fields text, and `gossip` a map).
    #[error("founding field {field} is missing or has the wrong type")]
    Malformed {
        /// The field, dotted for the gossip parameters (`gossip.fanout`).
        field: &'static str,
    },
    /// Not one of [`MEMBERSHIP_POLICIES`].
    #[error("unknown membership policy {0:?}")]
    UnknownPolicy(String),
    /// Not one of [`CONFLICT_STRATEGIES`].
    #[error("unknown conflict strategy {0:?}")]
    UnknownStrategy(String),
    /// A gossip fanout outside `1..=i32::MAX` (Java `GossipParameters` takes a positive `int`).
    #[error("gossip fanout {0} is not a positive 32-bit integer")]
    InvalidFanout(i64),
    /// A zero gossip period (Java `GossipParameters` refuses it).
    #[error("the gossip period must be positive")]
    ZeroPeriod,
    /// An instant or duration that is not `java.time` text this wire carries.
    #[error("founding field {field}: {source}")]
    Time {
        /// The field (`issued`, `ttl`, or `gossip.period`).
        field: &'static str,
        /// Why it did not parse.
        source: TimeError,
    },
}

/// The founding fields of a group, borrowed from a fields map or an advertisement.
struct Charter<'a> {
    name: &'a str,
    founder: &'a str,
    issued: &'a str,
    ttl: &'a str,
    policy: &'a str,
    strategy: &'a str,
    fanout: i128,
    period: &'a str,
}

impl<'a> Charter<'a> {
    /// Reads the charter from a map whose founder field is `founder_key` (`founder` in founding
    /// fields, `issuer` in an advertisement), checking each type as `founding_fields_of` does.
    fn read(map: &'a Map, founder_key: &'static str) -> Result<Self, FoundingError> {
        let text = |key: &'static str| {
            map.get(key)
                .and_then(Value::as_str)
                .ok_or(FoundingError::Malformed { field: key })
        };
        let gossip = map
            .get("gossip")
            .and_then(Value::as_map)
            .ok_or(FoundingError::Malformed { field: "gossip" })?;
        let fanout =
            gossip
                .get("fanout")
                .and_then(Value::as_i128)
                .ok_or(FoundingError::Malformed {
                    field: "gossip.fanout",
                })?;
        let period =
            gossip
                .get("period")
                .and_then(Value::as_str)
                .ok_or(FoundingError::Malformed {
                    field: "gossip.period",
                })?;
        Ok(Charter {
            name: text("name")?,
            founder: text(founder_key)?,
            issued: text("issued")?,
            ttl: text("ttl")?,
            policy: text("membershipPolicy")?,
            strategy: text("defaultStrategy")?,
            fanout,
            period,
        })
    }

    /// Whether Java decodes these fields into a typed `FoundingFields` and writes them back as
    /// they are (`GroupFounding.verify` signs and verifies `CODEC.toBytes(fieldsOf(ad))`): a known
    /// policy and strategy, a fanout in `1..=i32::MAX`, a positive period, and instants and
    /// durations in the exact text `java.time` prints ([`time::is_canonical_instant`],
    /// [`time::is_canonical_duration`]).
    fn is_canonical(&self) -> bool {
        MEMBERSHIP_POLICIES.contains(&self.policy)
            && CONFLICT_STRATEGIES.contains(&self.strategy)
            && (1..=i128::from(i32::MAX)).contains(&self.fanout)
            && time::is_canonical_instant(self.issued)
            && time::is_canonical_duration(self.ttl)
            && time::is_canonical_duration(self.period)
            && self.period != "PT0S"
    }

    fn gossip(&self) -> Value {
        crate::cbor_map! { "fanout" => Value::Int(self.fanout), "period" => self.period }
    }

    /// `GroupFounding.FoundingFields` in canonical order.
    fn fields(&self) -> Map {
        let mut fields = Map::with_capacity(7);
        fields.insert("name", self.name);
        fields.insert("founder", self.founder);
        fields.insert("issued", self.issued);
        fields.insert("ttl", self.ttl);
        fields.insert("membershipPolicy", self.policy);
        fields.insert("defaultStrategy", self.strategy);
        fields.insert("gossip", self.gossip());
        fields
    }

    /// A `GroupAdvertisement` in Java record order.
    fn advertisement(&self, group_id: &str) -> Map {
        let mut ad = Map::with_capacity(9);
        ad.insert("id", format!("{URI_PREFIX}{group_id}"));
        ad.insert("issuer", self.founder);
        ad.insert("group", group_id);
        ad.insert("issued", self.issued);
        ad.insert("ttl", self.ttl);
        ad.insert("name", self.name);
        ad.insert("membershipPolicy", self.policy);
        ad.insert("defaultStrategy", self.strategy);
        ad.insert("gossip", self.gossip());
        ad
    }
}

/// `GroupFounding.FoundingFields` in canonical field order (SPEC §5.1): `name`, `founder`,
/// `issued`, `ttl`, `membershipPolicy`, `defaultStrategy`, `gossip` {`fanout`, `period`}, the
/// immutable fields no later party may change. A plain builder, as `identity.py`'s: nothing is
/// validated (see [`found_group`] for that).
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the Java record and identity.py's founding_fields field for field"
)]
pub fn founding_fields(
    name: &str,
    founder_peer_id: &str,
    issued_iso: &str,
    ttl_iso: &str,
    policy: &str,
    strategy: &str,
    fanout: i64,
    period_iso: &str,
) -> Map {
    Charter {
        name,
        founder: founder_peer_id,
        issued: issued_iso,
        ttl: ttl_iso,
        policy,
        strategy,
        fanout: i128::from(fanout),
        period: period_iso,
    }
    .fields()
}

/// `GroupFounding.FoundingDocument`: `{fields, signature}`, the founding fields plus the founder's
/// Ed25519 signature over their CBOR. Its CBOR hashes to the GroupID (SPEC §4.4).
pub fn founding_document(fields: &Map, signature: &[u8]) -> Map {
    let mut document = Map::with_capacity(2);
    document.insert("fields", fields.clone());
    document.insert("signature", signature);
    document
}

/// `GroupId.fromFounding` over the CBOR of a founding document: the self-certifying GroupID
/// (SPEC §4.4). Identical to [`ids::derive_id`]; the name records what the material is.
pub fn group_id_from_founding_document(document_bytes: &[u8]) -> String {
    ids::group_id_from_founding(document_bytes)
}

/// A `GroupAdvertisement` (SPEC §5.1) in Java record order: `id`, `issuer`, `group`, `issued`,
/// `ttl`, `name`, `membershipPolicy`, `defaultStrategy`, `gossip`. `id` is `aspace://<groupID>`
/// and every other value is copied from the founding `fields`, which is what makes the
/// advertisement re-derivable. Refuses fields of the wrong shape ([`FoundingError::Malformed`]).
pub fn group_advertisement(group_id: &str, fields: &Map) -> Result<Map, FoundingError> {
    Ok(Charter::read(fields, "founder")?.advertisement(group_id))
}

/// `GroupFounding.found`: signs the founding fields with `identity` (the founder), derives the
/// self-certifying GroupID, and returns the signed group advertisement
/// `{advertisement, founderPublicKey, signature}` to join with and to serve to newcomers as a
/// `GROUP_AD` body (SPEC §5.1, §9). The GroupID is the advertisement's `group`.
///
/// Refuses what Java's typed `found` could not express: a policy outside
/// [`MEMBERSHIP_POLICIES`], a strategy outside [`CONFLICT_STRATEGIES`], a fanout outside
/// `1..=i32::MAX`, an `issued_iso`, `ttl_iso`, or `period_iso` that does not parse, and a zero
/// period.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors Java GroupFounding.found and identity.py's found_group"
)]
pub fn found_group(
    identity: &Identity,
    name: &str,
    policy: &str,
    strategy: &str,
    fanout: i64,
    period_iso: &str,
    issued_iso: &str,
    ttl_iso: &str,
) -> Result<Map, FoundingError> {
    if !MEMBERSHIP_POLICIES.contains(&policy) {
        return Err(FoundingError::UnknownPolicy(policy.to_owned()));
    }
    if !CONFLICT_STRATEGIES.contains(&strategy) {
        return Err(FoundingError::UnknownStrategy(strategy.to_owned()));
    }
    if !(1..=i64::from(i32::MAX)).contains(&fanout) {
        return Err(FoundingError::InvalidFanout(fanout));
    }
    let time_error = |field| move |source| FoundingError::Time { field, source };
    time::parse_instant_millis(issued_iso).map_err(time_error("issued"))?;
    time::parse_duration_millis(ttl_iso).map_err(time_error("ttl"))?;
    if time::parse_duration_millis(period_iso).map_err(time_error("gossip.period"))? == 0 {
        return Err(FoundingError::ZeroPeriod);
    }
    let charter = Charter {
        name,
        founder: identity.peer_id(),
        issued: issued_iso,
        ttl: ttl_iso,
        policy,
        strategy,
        fanout: i128::from(fanout),
        period: period_iso,
    };
    let fields = charter.fields();
    let signature = identity.sign(&encode_map(&fields));
    let group_id = derive_group_id(&fields, &signature);
    let mut signed = Map::with_capacity(3);
    signed.insert("advertisement", charter.advertisement(&group_id));
    signed.insert("founderPublicKey", identity.public_raw());
    signed.insert("signature", signature);
    Ok(signed)
}

/// `GroupFounding.fieldsOf`: the founding fields an advertisement carries, rebuilt in canonical
/// order from the (possibly decoded, possibly hostile) advertisement. Refuses a shape that cannot
/// be a founding document: a missing field, a `gossip` that is not a map, a `gossip.fanout` that
/// is not an integer, or any other field that is not text. Values are not otherwise judged (an
/// unknown policy is carried as it is, as `identity.py` carries it).
pub fn founding_fields_of(advertisement: &Map) -> Result<Map, FoundingError> {
    Ok(Charter::read(advertisement, "issuer")?.fields())
}

/// `GroupFounding.verify`, the receiver rule of SPEC §5.1: the verified GroupID of a signed group
/// advertisement, or `None`. The four checks, in order:
///
/// 1. the 32-byte `founderPublicKey` hashes to the advertisement's `issuer`;
/// 2. the `signature` verifies under that key over the founding fields rebuilt from the
///    advertisement ([`founding_fields_of`]), which must be the fields Java decodes and writes
///    back unchanged: a policy among [`MEMBERSHIP_POLICIES`], a strategy among
///    [`CONFLICT_STRATEGIES`], a fanout in `1..=i32::MAX`, a positive gossip period, and
///    `issued`, `ttl`, and `period` in the exact text `java.time` prints
///    ([`time::is_canonical_instant`], [`time::is_canonical_duration`]). Java verifies over its
///    re-encoding of the typed fields, so fields in any other form would verify other bytes
///    there;
/// 3. the founding document derives to the advertisement's `group`;
/// 4. the advertisement's `id` is `aspace://` and that group.
///
/// A network-learned group advertisement must pass before a node joins or acts on it; a hostile
/// seed that fails any check can delay a join but never substitute a policy. Any malformed shape
/// is `None`, never a panic.
pub fn verify_signed_group_ad(signed: &Value) -> Option<String> {
    let signed = signed.as_map()?;
    let advertisement = signed.get("advertisement")?.as_map()?;
    let key = signed.get("founderPublicKey")?.as_bytes()?;
    let signature = signed.get("signature")?.as_bytes()?;
    if key.len() != crate::crypto::KEY_LENGTH {
        return None;
    }
    let issuer = advertisement.get("issuer")?.as_str()?;
    if ids::derive_id(key) != issuer {
        return None;
    }
    let charter = Charter::read(advertisement, "issuer").ok()?;
    if !charter.is_canonical() {
        return None;
    }
    let fields = charter.fields();
    if !Identity::verify(key, &encode_map(&fields), signature) {
        return None;
    }
    let group_id = derive_group_id(&fields, signature);
    let group_matches = advertisement.get("group").and_then(Value::as_str) == Some(&group_id);
    let id_matches = advertisement
        .get("id")
        .and_then(Value::as_str)
        .and_then(|id| id.strip_prefix(URI_PREFIX))
        == Some(&group_id);
    (group_matches && id_matches).then_some(group_id)
}

/// The GroupID of founding fields and the founder's signature over them.
fn derive_group_id(fields: &Map, signature: &[u8]) -> String {
    group_id_from_founding_document(&encode_map(&founding_document(fields, signature)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_group_refuses_what_java_cannot_express() {
        let founder = Identity::from_seed(&[5; 32]);
        let found = |policy, strategy, fanout, period, issued, ttl| {
            found_group(&founder, "g", policy, strategy, fanout, period, issued, ttl)
        };
        let ok = (
            "OPEN",
            "AUCTION",
            3,
            "PT1S",
            "2026-01-01T00:00:00Z",
            "PT24H",
        );
        assert!(found(ok.0, ok.1, ok.2, ok.3, ok.4, ok.5).is_ok());
        assert_eq!(
            found("open", ok.1, ok.2, ok.3, ok.4, ok.5),
            Err(FoundingError::UnknownPolicy("open".into()))
        );
        assert_eq!(
            found(ok.0, "FIFO", ok.2, ok.3, ok.4, ok.5),
            Err(FoundingError::UnknownStrategy("FIFO".into()))
        );
        for fanout in [0, -1, i64::from(i32::MAX) + 1] {
            assert_eq!(
                found(ok.0, ok.1, fanout, ok.3, ok.4, ok.5),
                Err(FoundingError::InvalidFanout(fanout))
            );
        }
        assert_eq!(
            found(ok.0, ok.1, ok.2, "PT0S", ok.4, ok.5),
            Err(FoundingError::ZeroPeriod)
        );
        assert!(matches!(
            found(ok.0, ok.1, ok.2, "P1D", ok.4, ok.5),
            Err(FoundingError::Time {
                field: "gossip.period",
                ..
            })
        ));
        assert!(matches!(
            found(ok.0, ok.1, ok.2, ok.3, "2026-01-01", ok.5),
            Err(FoundingError::Time {
                field: "issued",
                ..
            })
        ));
        assert!(matches!(
            found(ok.0, ok.1, ok.2, ok.3, ok.4, "P1D"),
            Err(FoundingError::Time { field: "ttl", .. })
        ));
    }

    #[test]
    fn group_advertisement_needs_founding_fields() {
        let fields = founding_fields(
            "g",
            "zPeer",
            "2026-01-01T00:00:00Z",
            "PT1H",
            "OPEN",
            "ORDERED",
            2,
            "PT1S",
        );
        let ad = group_advertisement("zGroup", &fields).unwrap();
        assert_eq!(
            ad.get("id").and_then(Value::as_str),
            Some("aspace://zGroup")
        );
        assert_eq!(ad.get("issuer").and_then(Value::as_str), Some("zPeer"));
        assert_eq!(founding_fields_of(&ad), Ok(fields.clone()));
        let mut broken = fields;
        broken.remove("founder");
        assert_eq!(
            group_advertisement("zGroup", &broken),
            Err(FoundingError::Malformed { field: "founder" })
        );
    }
}
