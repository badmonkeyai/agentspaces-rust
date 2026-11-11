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

//! The serving half of anti-entropy (SPEC §5.3, §7.3, §9): the digest and delta encodings a node
//! that answers `DIGEST` frames produces and reads, exactly as Java's `ReplicatedSpace`,
//! `AdCache`, `RevocationRegistry`, `CredentialRevocationRegistry`, and the membership view
//! write them, so a Java member and a Rust listening member reconcile with each other.
//!
//! Every digest is UTF-8 text, one `key=value` line (or one key) per item and a newline after
//! each, in Java `TreeMap` order (UTF-16 code units). A partner answers with what the asker's
//! digest does not name:
//!
//! - a space (`space:<name>`): `e:<entryId>=<stateHash>` per entry and `c:<entryId>=<claimHash>`
//!   per winning claim ([`state_hash`], [`claim_hash`]); the delta is a `SyncDelta`
//!   `{states, claims}` of the signed states and claims the asker lacks ([`sync_delta`]). A
//!   line the asker prefixes `a:` (refused and acknowledged) counts as held.
//! - the advertisements (`ads`): the SHA-256 of the lines, then the lines `<id>=<issuedMillis>`
//!   ([`ad_digest`]); the delta is an `AdCache.Delta` `{ads}` of stored advertisements
//!   ([`ads_delta`]).
//! - the revocations (`revocations`, `credential-revocations`): `r:<revoked peer>=<hex SHA-256
//!   of adBytes>` and `c:<KIND>:<canonical target>=<hex>` ([`revocation_line`]); the delta is
//!   an array of `SignedRevocation` records ([`revocations_delta`]).
//! - the membership view (`view`): the live members' PeerIDs, the sender's own included
//!   ([`view_digest`]); the delta is an array of signed peer advertisements, the `peers` stream
//!   payloads ([`view_delta`], [`parse_view_delta`]).
//!
//! The state hash is Java's `Integer.toHexString(Objects.hash(adds, removes, lease.stamp,
//! completed))` over the entry's joined state, reproduced bit for bit from the record hashes
//! `java.lang.runtime.ObjectMethods` derives and pinned by the golden vectors; the claim hash is
//! `epoch:stamp:bid:expiresAtMillis` with the bid as Java prints a double. A hash that differs
//! from the asker's only costs a redundant item in the delta, which the asker folds as unchanged.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};

use crate::cbor::{self, Map, Value};
use crate::crypto;
use crate::filters::java_double_string;

/// The membership view's anti-entropy stream (Java `PeerNode.VIEW_STATE`).
pub const STREAM_VIEW: &str = "view";

/// `String.hashCode()`: the UTF-16 code units, 31-chained, wrapped to `i32`.
pub fn java_string_hash(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// `Long.hashCode(value)`: `(int) (value ^ (value >>> 32))`.
pub fn java_long_hash(value: i64) -> i32 {
    let bits = value as u64;
    // The low 32 bits, reinterpreted: Java's narrowing `(int)` cast.
    (bits ^ (bits >> 32)) as u32 as i32
}

/// `Boolean.hashCode(value)`.
fn java_boolean_hash(value: bool) -> i32 {
    if value { 1231 } else { 1237 }
}

/// A record's hash as `java.lang.runtime.ObjectMethods` derives it: 31-chained from 0.
fn record_hash(components: &[i32]) -> i32 {
    components
        .iter()
        .fold(0i32, |hash, c| hash.wrapping_mul(31).wrapping_add(*c))
}

/// `Objects.hash(...)` (`Arrays.hashCode`): 31-chained from 1.
fn objects_hash(components: &[i32]) -> i32 {
    components
        .iter()
        .fold(1i32, |hash, c| hash.wrapping_mul(31).wrapping_add(*c))
}

/// An integer read the way Java's codec reads a `long` from a number (a double truncates).
fn long_of(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Int(int)) => i64::try_from(*int).unwrap_or(0),
        // Java's `(long) double`: toward zero, saturating, NaN as 0, which Rust's cast matches.
        Some(Value::Float(float)) => *float as i64,
        _ => 0,
    }
}

/// A `Dot(String replica, long counter)` record's hash.
fn dot_hash(replica: &str, counter: i64) -> i32 {
    record_hash(&[java_string_hash(replica), java_long_hash(counter)])
}

/// A `Set<Dot>`'s hash: the sum of its members' hashes, each distinct dot once.
fn dot_set_hash(dots: Option<&Value>) -> i32 {
    let Some(dots) = dots.and_then(Value::as_array) else {
        return 0;
    };
    let mut seen: HashSet<(&str, i64)> = HashSet::with_capacity(dots.len());
    let mut hash = 0i32;
    for dot in dots {
        let Some(dot) = dot.as_map() else {
            continue;
        };
        let replica = dot.get("replica").and_then(Value::as_str).unwrap_or("");
        let counter = long_of(dot.get("counter"));
        if seen.insert((replica, counter)) {
            hash = hash.wrapping_add(dot_hash(replica, counter));
        }
    }
    hash
}

/// An `HlcTimestamp(long physical, int logical, String node)` record's hash, from its text
/// `physical:logical:node` (a part that does not parse hashes as 0).
pub fn hlc_hash(encoded: &str) -> i32 {
    let mut parts = encoded.splitn(3, ':');
    let physical = parts
        .next()
        .and_then(|part| part.parse::<i64>().ok())
        .unwrap_or(0);
    let logical = parts
        .next()
        .and_then(|part| part.parse::<i32>().ok())
        .unwrap_or(0);
    let node = parts.next().unwrap_or("");
    record_hash(&[java_long_hash(physical), logical, java_string_hash(node)])
}

/// `Integer.toHexString`: two's complement, lower case, no padding.
fn java_hex(value: i32) -> String {
    format!("{:x}", value as u32)
}

/// `ReplicatedSpace.stateHash`: `Integer.toHexString(Objects.hash(adds, removes, lease.stamp,
/// completed))` over an entry's joined state (`adds`, `removes`, `leaseStamp`, `completed`).
pub fn state_hash(state: &Map) -> String {
    let lease_stamp = state
        .get("leaseStamp")
        .and_then(Value::as_str)
        .unwrap_or("0:0:");
    java_hex(objects_hash(&[
        dot_set_hash(state.get("adds")),
        dot_set_hash(state.get("removes")),
        hlc_hash(lease_stamp),
        java_boolean_hash(
            state
                .get("completed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    ]))
}

/// `ReplicatedSpace.claimHash`: `epoch:stamp:bid:expiresAtMillis` of a claim (the `claim` map
/// inside a signed claim), the bid as Java prints a double.
pub fn claim_hash(claim: &Map) -> String {
    let bid = claim.get("bid").and_then(Value::as_f64).unwrap_or(0.0);
    format!(
        "{}:{}:{}:{}",
        long_of(claim.get("epoch")),
        claim.get("stamp").and_then(Value::as_str).unwrap_or(""),
        java_double_string(bid),
        long_of(claim.get("expiresAtMillis")),
    )
}

/// Java `String.compareTo`: by UTF-16 code units, which is the order of a `TreeMap<String, _>`.
fn java_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The digest text of `lines` (`key=value`), sorted as a Java `TreeMap` sorts its keys, a
/// newline after each.
pub fn digest_text(lines: &mut [(String, String)]) -> String {
    lines.sort_by(|(a, _), (b, _)| java_order(a, b));
    let mut text = String::new();
    for (key, value) in lines.iter() {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    text
}

/// The lines of a received digest, the way `deltaFor` reads them (`split("\n")`), as byte
/// slices of the digest.
pub fn digest_lines(digest: &[u8]) -> HashSet<&[u8]> {
    digest.split(|byte| *byte == b'\n').collect()
}

/// Whether a received digest's lines name `line`, as is or acknowledged (`a:` + the line).
pub fn names_line(lines: &HashSet<&[u8]>, line: &str) -> bool {
    if lines.contains(line.as_bytes()) {
        return true;
    }
    let acknowledged = format!("a:{line}");
    lines.contains(acknowledged.as_bytes())
}

/// The digest line of one entry: `e:<entryId>=<stateHash of its joined state>`.
pub fn state_line(entry_id: &str, joined: &Map) -> String {
    format!("e:{entry_id}={}", state_hash(joined))
}

/// The digest line of one winning claim: `c:<entryId>=<claimHash>` of the signed claim's
/// `claim`.
pub fn claim_line(entry_id: &str, signed: &Map) -> String {
    let claim = signed.get("claim").and_then(Value::as_map);
    let hash = claim.map(claim_hash).unwrap_or_default();
    format!("c:{entry_id}={hash}")
}

/// `ReplicatedSpace.digest` of one space: a line per entry ([`state_line`] over its joined
/// state) and per winning signed claim ([`claim_line`]).
pub fn space_digest<'a>(
    states: impl Iterator<Item = (&'a str, &'a Map)>,
    claims: impl Iterator<Item = (&'a str, &'a Map)>,
) -> Vec<u8> {
    let mut lines: Vec<(String, String)> = Vec::new();
    for (entry_id, joined) in states {
        lines.push((format!("e:{entry_id}"), state_hash(joined)));
    }
    for (entry_id, signed) in claims {
        let hash = signed
            .get("claim")
            .and_then(Value::as_map)
            .map(claim_hash)
            .unwrap_or_default();
        lines.push((format!("c:{entry_id}"), hash));
    }
    digest_text(&mut lines).into_bytes()
}

/// A `SpaceWire.SyncDelta` `{states, claims}`: the signed states and the signed claims by entry
/// id, the claims written in canonical key order (SPEC §9.1).
pub fn sync_delta(states: &[&Map], claims: &[(&str, &Map)]) -> Vec<u8> {
    let mut claim_map = Map::with_capacity(claims.len());
    for (entry_id, signed) in claims {
        claim_map.insert(*entry_id, (*signed).clone());
    }
    let mut delta = Map::with_capacity(2);
    delta.insert(
        "states",
        Value::Array(
            states
                .iter()
                .map(|state| Value::Map((*state).clone()))
                .collect(),
        ),
    );
    delta.insert("claims", cbor::canonical_map(&claim_map));
    cbor::encode(&Value::Map(delta))
}

/// `AdCache.digest`: the SHA-256 of the lines `<id>=<issuedMillis>` (one per id, the latest
/// issue kept), then the lines.
pub fn ad_digest<'a>(ads: impl Iterator<Item = (&'a str, i64)>) -> Vec<u8> {
    let mut latest: BTreeMap<&str, i64> = BTreeMap::new();
    for (id, issued) in ads {
        let held = latest.entry(id).or_insert(issued);
        if issued > *held {
            *held = issued;
        }
    }
    let mut lines: Vec<(String, String)> = latest
        .into_iter()
        .map(|(id, issued)| (id.to_owned(), issued.to_string()))
        .collect();
    let text = digest_text(&mut lines).into_bytes();
    let mut digest = crypto::port().sha256(&text).to_vec();
    digest.extend_from_slice(&text);
    digest
}

/// The `<id>=<issuedMillis>` keys of a received ads digest (`AdCache.parseDigestKeys`): the
/// lines after its 32-byte hash; none when the digest is no longer than the hash.
pub fn ad_digest_keys(digest: &[u8]) -> HashSet<&[u8]> {
    match digest.get(32..) {
        Some(lines) if !lines.is_empty() => lines
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect(),
        _ => HashSet::new(),
    }
}

/// The key an advertisement goes under in an ads digest: `<id>=<issuedMillis>`.
pub fn ad_key(id: &str, issued_ms: i64) -> String {
    format!("{id}={issued_ms}")
}

/// An `AdCache.Delta` `{ads}` of stored advertisements.
pub fn ads_delta(stored: &[&Value]) -> Vec<u8> {
    let mut delta = Map::with_capacity(1);
    delta.insert(
        "ads",
        Value::Array(stored.iter().map(|ad| (*ad).clone()).collect()),
    );
    cbor::encode(&Value::Map(delta))
}

/// A revocation digest line, `<key>=<hex SHA-256 of the signed advertisement bytes>`, the key
/// `r:<revoked peer>` on `revocations` or `c:<KIND>:<canonical target>` on
/// `credential-revocations`.
pub fn revocation_line(key: &str, digest: &[u8; 32]) -> String {
    let mut line = String::with_capacity(key.len() + 65);
    line.push_str(key);
    line.push('=');
    for byte in digest {
        line.push_str(&format!("{byte:02x}"));
    }
    line
}

/// A revocation stream's digest: its lines ([`revocation_line`]) in key order.
pub fn revocation_digest(lines: impl Iterator<Item = String>) -> Vec<u8> {
    let mut sorted: Vec<String> = lines.collect();
    sorted.sort_by(|a, b| java_order(a, b));
    let mut text = String::new();
    for line in sorted {
        text.push_str(&line);
        text.push('\n');
    }
    text.into_bytes()
}

/// A revocation stream's delta: the array of `SignedRevocation` records the asker lacks.
pub fn revocations_delta(signed: &[&Map]) -> Vec<u8> {
    cbor::encode(&Value::Array(
        signed
            .iter()
            .map(|map| Value::Map((*map).clone()))
            .collect(),
    ))
}

/// The membership view's digest: the PeerIDs, one per line, in order (the sender's own among
/// them).
pub fn view_digest<'a>(members: impl Iterator<Item = &'a str>) -> Vec<u8> {
    let mut ids: Vec<&str> = members.collect();
    ids.sort_by(|a, b| java_order(a, b));
    ids.dedup();
    let mut text = String::new();
    for id in ids {
        text.push_str(id);
        text.push('\n');
    }
    text.into_bytes()
}

/// The membership view's delta: the signed peer advertisements (`peers` stream payloads) of the
/// members the asker lacks, as an array of byte strings.
pub fn view_delta(payloads: &[&[u8]]) -> Vec<u8> {
    cbor::encode(&Value::Array(
        payloads
            .iter()
            .map(|payload| Value::Bytes(payload.to_vec()))
            .collect(),
    ))
}

/// The payloads of a received view delta (`byte[][]` under the wire encoding): `None` unless
/// the bytes are the canonical encoding of an array of byte strings.
pub fn parse_view_delta(delta: &[u8]) -> Option<Vec<Vec<u8>>> {
    match crate::schema::load_canonical(delta)? {
        Value::Array(items) => items.into_iter().map(Value::into_bytes).collect(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_map;

    #[test]
    fn java_hashes_match_the_jdk() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("a"), 97);
        assert_eq!(java_string_hash("hello"), 99_162_322);
        // A surrogate pair hashes as two UTF-16 units.
        assert_eq!(java_string_hash("\u{1F600}"), 0xD83D * 31 + 0xDE00);
        assert_eq!(java_long_hash(0), 0);
        assert_eq!(java_long_hash(1), 1);
        assert_eq!(java_long_hash(-1), 0);
        assert_eq!(java_long_hash(1 << 32), 1);
        assert_eq!(java_hex(-1), "ffffffff");
        assert_eq!(java_hex(255), "ff");
    }

    #[test]
    fn digest_lines_sort_as_a_tree_map_and_acknowledged_lines_count() {
        let mut lines = vec![
            ("e:b".to_owned(), "1".to_owned()),
            ("c:a".to_owned(), "2".to_owned()),
            ("e:a".to_owned(), "3".to_owned()),
        ];
        let text = digest_text(&mut lines);
        assert_eq!(text, "c:a=2\ne:a=3\ne:b=1\n");
        let parsed = digest_lines(text.as_bytes());
        assert!(names_line(&parsed, "e:a=3"));
        assert!(!names_line(&parsed, "e:a=4"));
        let acknowledged = digest_lines(b"a:e:x=1\n");
        assert!(names_line(&acknowledged, "e:x=1"));
    }

    #[test]
    fn the_ads_digest_carries_its_hash_first() {
        let digest = ad_digest([("aspace://g/agent/x", 1_735_689_600_000)].into_iter());
        assert_eq!(
            digest.len(),
            32 + "aspace://g/agent/x=1735689600000\n".len()
        );
        let keys = ad_digest_keys(&digest);
        assert!(keys.contains(&b"aspace://g/agent/x=1735689600000"[..]));
        assert!(ad_digest_keys(&[]).is_empty());
        assert!(ad_digest_keys(&[0; 32]).is_empty());
    }

    #[test]
    fn view_deltas_round_trip_and_refuse_other_shapes() {
        let delta = view_delta(&[b"one", b"two"]);
        assert_eq!(
            parse_view_delta(&delta),
            Some(vec![b"one".to_vec(), b"two".to_vec()])
        );
        let wrong = cbor::encode(&Value::Array(vec![Value::from("text")]));
        assert_eq!(parse_view_delta(&wrong), None);
        assert_eq!(parse_view_delta(&[0xff]), None);
        assert_eq!(view_digest(["b", "a", "b"].into_iter()), b"a\nb\n");
    }

    #[test]
    fn state_hashes_count_set_members_once_and_every_component() {
        let dot = || cbor_map! { "replica" => "r", "counter" => 1 };
        let state = |adds: Vec<Value>, stamp: &str, completed: bool| {
            let mut map = Map::new();
            map.insert("adds", Value::Array(adds));
            map.insert("removes", Value::Array(Vec::new()));
            map.insert("leaseStamp", stamp);
            map.insert("completed", completed);
            map
        };
        let hash = state_hash(&state(vec![dot()], "5:0:r", false));
        assert_eq!(state_hash(&state(vec![dot(), dot()], "5:0:r", false)), hash);
        assert_ne!(state_hash(&state(vec![dot()], "5:0:r", true)), hash);
        assert_ne!(state_hash(&state(vec![dot()], "6:0:r", false)), hash);
    }
}
