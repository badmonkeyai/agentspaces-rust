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

//! Revocations (SPEC §5.6, v0.1.13), a port of `revocation.py`: the `revocations` stream's peer
//! revocations and the `credential-revocations` stream's revocations of agents, agent keys,
//! X.509 leaves, and join credentials, verified exactly as a Java member verifies them except
//! for the CA-rooted path, which this core does not carry (a CA-rooted record is ignored, never
//! trusted).
//!
//! A [`Registry`] keeps one record per target, chosen by Java's total order: authority (the
//! founder, then the agent's own peer), then the newer `issued`, then the larger SHA-256 of the
//! signed advertisement bytes. It holds at most [`MAX_RETAINED`] targets per table. Enforcement
//! ([`Registry::refuses`]) applies the freeze rule: a revocation refuses every signature under
//! `key-compromise` or at an unknown time, and otherwise those made at or after its effective
//! instant.
//!
//! The builders ([`credential_revocation`], the target constructors, [`sign_revocation`]) write
//! Java's record order (`CredentialRevocation`, `CredentialRevocation.Target`,
//! `SignedRevocation`), so a revocation this core issues is byte-identical to Java's.
//!
//! The module is sans-IO: the founder and the group are plain values the caller keeps current
//! ([`Registry::set_founder`], [`Registry::set_group`]) rather than callbacks, and every instant
//! is an argument in epoch milliseconds.
#![warn(missing_docs)]

use std::collections::BTreeMap;

use crate::cbor::{self, Map, Value};
use crate::crypto::{self, KEY_LENGTH};
use crate::filters::java_whitespace;
use crate::identity::Identity;
use crate::ids::{self, URI_PREFIX};
use crate::time;
use crate::util::{encode_map, present};

/// The rumor stream that carries peer revocations.
pub const PEER_STREAM: &str = "revocations";
/// The rumor stream that carries credential revocations.
pub const CREDENTIAL_STREAM: &str = "credential-revocations";
/// Both revocation streams.
pub const STREAMS: [&str; 2] = [PEER_STREAM, CREDENTIAL_STREAM];

/// The reason that refuses every signature, whatever its time.
pub const KEY_COMPROMISE: &str = "key-compromise";
/// The reason a credential revocation without one (absent, null, or blank) carries (Java
/// `CredentialRevocation.UNSPECIFIED`).
pub const UNSPECIFIED: &str = "unspecified";
/// The reasons a credential revocation may carry (Java `CredentialRevocation.REASONS`).
pub const REASONS: [&str; 5] = [
    KEY_COMPROMISE,
    "retired",
    "superseded",
    "privilege-withdrawn",
    UNSPECIFIED,
];
/// The most bytes of `evidence` a credential revocation may carry (Java
/// `CredentialRevocation.MAX_EVIDENCE`, 96 KiB); Java refuses a larger one at decode.
pub const MAX_EVIDENCE: usize = 96 * 1024;
/// The target kinds of a credential revocation (Java `CredentialRevocation.Target`).
pub const KINDS: [&str; 4] = ["AGENT", "AGENT_KEY", "X509_LEAF", "JOIN_CREDENTIAL"];

/// How far in the future a revocation's `issued` may lie and still be accepted (ten minutes).
pub const MAX_ISSUED_SKEW_MILLIS: i64 = 10 * 60 * 1000;
/// The most targets one registry table holds; a new target beyond it is refused.
pub const MAX_RETAINED: usize = 4096;

/// The length of the SHA-256 fingerprints and hashes a target carries.
const DIGEST_LENGTH: usize = 32;

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Targets and ids

/// Java `CredentialRevocation.Target.canonical`: the target's text within its kind (`AGENT`: the
/// agent; `AGENT_KEY`: `<agent>#<hex fingerprint>`; `X509_LEAF`: the hex certificate fingerprint;
/// `JOIN_CREDENTIAL`: the hex credential hash). `None` when the kind is unknown or its field is
/// missing; sizes are not checked here ([`is_valid_target`] checks them).
pub fn canonical_target(target: &Map) -> Option<String> {
    let bytes = |key: &str| target.get(key).and_then(Value::as_bytes).map(hex_lower);
    let agent = || target.get("agent").and_then(Value::as_str);
    match target.get("kind")?.as_str()? {
        "AGENT" => agent().map(str::to_owned),
        "AGENT_KEY" => Some(format!("{}#{}", agent()?, bytes("keyFingerprint")?)),
        "X509_LEAF" => bytes("certificateFingerprint"),
        "JOIN_CREDENTIAL" => bytes("credentialHash"),
        _ => None,
    }
}

/// Java `CredentialRevocation.idFor`: `aspace://<group>/revocation/<kind>/<canonical>`, the kind
/// in lower case. `None` when [`canonical_target`] is.
pub fn revocation_id(group: &str, target: &Map) -> Option<String> {
    let canonical = canonical_target(target)?;
    let kind = target.get("kind")?.as_str()?.to_lowercase();
    Some(format!("{URI_PREFIX}{group}/revocation/{kind}/{canonical}"))
}

/// Whether a target has the shape Java's `Target` constructor requires: a known kind, the agent
/// for `AGENT` and `AGENT_KEY` as a Java `AgentId` ([`ids::parse_agent_id`]: `<peerId>/<name>`,
/// the name non-empty and free of `/`; Java cannot decode any other), and a 32-byte fingerprint
/// or hash where the kind needs one.
pub fn is_valid_target(target: &Map) -> bool {
    let sized = |key: &str| {
        target
            .get(key)
            .and_then(Value::as_bytes)
            .is_some_and(|b| b.len() == DIGEST_LENGTH)
    };
    let agent = || {
        target
            .get("agent")
            .and_then(Value::as_str)
            .is_some_and(|agent| ids::parse_agent_id(agent).is_some())
    };
    match target.get("kind").and_then(Value::as_str) {
        Some("AGENT") => agent(),
        Some("AGENT_KEY") => agent() && sized("keyFingerprint"),
        Some("X509_LEAF") => sized("certificateFingerprint"),
        Some("JOIN_CREDENTIAL") => sized("credentialHash"),
        _ => false,
    }
}

/// Java `Target.agent`: every key of one agent.
pub fn agent_target(agent: &str) -> Map {
    let mut target = Map::with_capacity(2);
    target.insert("kind", "AGENT");
    target.insert("agent", agent);
    target
}

/// Java `Target.agentKey`: one agent key, by the SHA-256 of its raw public key.
pub fn agent_key_target(agent: &str, key_fingerprint: &[u8; DIGEST_LENGTH]) -> Map {
    let mut target = Map::with_capacity(3);
    target.insert("kind", "AGENT_KEY");
    target.insert("agent", agent);
    target.insert("keyFingerprint", key_fingerprint);
    target
}

/// Java `Target.x509Leaf`: one X.509 channel leaf, by its issuer DN, hex serial, and the SHA-256
/// of its DER.
pub fn x509_leaf_target(
    issuer_dn: &str,
    serial_hex: &str,
    certificate_fingerprint: &[u8; DIGEST_LENGTH],
) -> Map {
    let mut target = Map::with_capacity(4);
    target.insert("kind", "X509_LEAF");
    target.insert("x509Issuer", issuer_dn);
    target.insert("x509Serial", serial_hex);
    target.insert("certificateFingerprint", certificate_fingerprint);
    target
}

/// Java `Target.joinCredential`: one join credential, by the SHA-256 of its bytes
/// ([`crate::social::credential_hash`] or [`crate::social::delegation_hash`]).
pub fn join_credential_target(credential_hash: &[u8; DIGEST_LENGTH]) -> Map {
    let mut target = Map::with_capacity(2);
    target.insert("kind", "JOIN_CREDENTIAL");
    target.insert("credentialHash", credential_hash);
    target
}

/// Java `String.isBlank`: empty, or every character Java whitespace (`Character.isWhitespace`,
/// which counts U+001C to U+001F but not the no-break spaces U+00A0, U+2007, and U+202F, unlike
/// Rust's `char::is_whitespace`).
fn java_blank(text: &str) -> bool {
    text.chars().all(java_whitespace)
}

/// The reason a credential revocation's `reason` field reads as, as Java's
/// `CredentialRevocation` constructor reads it: absent, null, or blank ([`java_blank`]) is
/// `unspecified`; other text is itself; any other value is `None` (Jackson turns a number into
/// its text, which is no known reason, and refuses an array or a map).
fn reason_of(ad: &Map) -> Option<&str> {
    match ad.get("reason") {
        None | Some(Value::Null) => Some(UNSPECIFIED),
        Some(Value::Text(text)) if java_blank(text) => Some(UNSPECIFIED),
        Some(Value::Text(text)) => Some(text.as_str()),
        Some(_) => None,
    }
}

/// A `CredentialRevocation` in Java record order (`id`, `issuer`, `group`, `issued`, `ttl`,
/// `target`, `reason`, then `effectiveFrom` only when given), with the canonical id. A blank
/// reason (Java `String.isBlank`) reads as `unspecified`, as Java's constructor reads it. `None`
/// when the target is not valid ([`is_valid_target`]) or the reason is not one of [`REASONS`].
/// The instants and the lifetime are `java.time` text and are not checked here.
pub fn credential_revocation(
    issuer: &str,
    group: &str,
    issued_iso: &str,
    ttl_iso: &str,
    target: &Map,
    reason: &str,
    effective_from_iso: Option<&str>,
) -> Option<Map> {
    let reason = if java_blank(reason) {
        UNSPECIFIED
    } else {
        reason
    };
    if !is_valid_target(target) || !REASONS.contains(&reason) {
        return None;
    }
    let mut ad = Map::with_capacity(8);
    ad.insert("id", revocation_id(group, target)?);
    ad.insert("issuer", issuer);
    ad.insert("group", group);
    ad.insert("issued", issued_iso);
    ad.insert("ttl", ttl_iso);
    ad.insert("target", target.clone());
    ad.insert("reason", reason);
    if let Some(effective) = effective_from_iso {
        ad.insert("effectiveFrom", effective);
    }
    Some(ad)
}

/// A `SignedRevocation` `{adBytes, publicKey, signature}`: the advertisement's CBOR, the
/// issuer's raw public key, and its signature over those bytes. The rumor payload of either
/// stream is this map's CBOR.
pub fn sign_revocation(ad: &Map, issuer: &Identity) -> Map {
    let ad_bytes = encode_map(ad);
    let signature = issuer.sign(&ad_bytes);
    let mut signed = Map::with_capacity(3);
    signed.insert("adBytes", ad_bytes);
    signed.insert("publicKey", issuer.public_raw());
    signed.insert("signature", signature);
    signed
}

// ---------------------------------------------------------------------------------------------
// The registry

/// Who issued a kept revocation, in the order Java ranks them: the founder outranks the
/// agent's own peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority {
    /// The peer that hosts the revoked agent (rank 1 in `revocation.py`).
    OwnPeer,
    /// The group's founder (rank 3 in `revocation.py`).
    Founder,
}

/// One accepted revocation as a [`Registry`] keeps it: `revocation.py`'s
/// `(rank, issued, hash, ad)` tuple with the freeze rule's inputs read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRevocation {
    /// Who issued it.
    pub authority: Authority,
    /// Its `issued` instant in epoch milliseconds.
    pub issued_ms: i64,
    /// SHA-256 of its signed advertisement bytes.
    pub digest: [u8; 32],
    /// From when it refuses signatures: `effectiveFrom`, else `issued` (Java `effectiveSince`).
    pub effective_ms: i64,
    /// Whether its reason is [`KEY_COMPROMISE`].
    pub compromise: bool,
    /// The decoded advertisement.
    pub ad: Map,
}

impl HeldRevocation {
    /// Java `CredentialRevocation.refusesAt`, the freeze rule: a signature made at `signing_ms`
    /// is refused always under [`KEY_COMPROMISE`] or when the time is unknown (`None`), and
    /// otherwise when it is at or after [`HeldRevocation::effective_ms`].
    pub fn refuses_at(&self, signing_ms: Option<i64>) -> bool {
        match signing_ms {
            Some(at) if !self.compromise => at >= self.effective_ms,
            _ => true,
        }
    }

    fn order(&self) -> (Authority, i64, &[u8; 32]) {
        (self.authority, self.issued_ms, &self.digest)
    }
}

/// One group's accepted revocations as a client holds and applies them (`revocation.py`'s
/// `Registry`, Java `RevocationView`).
///
/// Where Python takes callables for the founder and the group, this registry takes values: the
/// caller sets them when it learns them ([`Registry::set_founder`] once the founding verifies,
/// [`Registry::set_group`] on join). Without a founder no peer revocation and no
/// founder-only credential revocation is accepted; without a group, a revocation for any group
/// is (as Python's `group` callable returning `None`).
///
/// The registry is not internally synchronized; wrap it in a lock to share it between threads.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    founder: Option<String>,
    group: Option<String>,
    peers: BTreeMap<String, HeldRevocation>,
    credentials: BTreeMap<String, HeldRevocation>,
}

impl Registry {
    /// An empty registry for the group's founder PeerID and GroupID, either of which may be
    /// unknown yet.
    pub fn new(founder: Option<String>, group: Option<String>) -> Self {
        Registry {
            founder,
            group,
            ..Registry::default()
        }
    }

    /// The founder's PeerID, if known.
    pub fn founder(&self) -> Option<&str> {
        self.founder.as_deref()
    }

    /// Sets (or forgets) the founder's PeerID. Records already kept are not re-judged.
    pub fn set_founder(&mut self, founder: Option<String>) {
        self.founder = founder;
    }

    /// The GroupID revocations must name, if set.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Sets (or clears) the GroupID revocations must name.
    pub fn set_group(&mut self, group: Option<String>) {
        self.group = group;
    }

    /// The kept peer revocations, by revoked PeerID.
    pub fn peers(&self) -> &BTreeMap<String, HeldRevocation> {
        &self.peers
    }

    /// The kept credential revocations, by `<KIND>:<canonical target>` (for example
    /// `AGENT:<agentId>` or `AGENT_KEY:<agentId>#<hex fingerprint>`).
    pub fn credentials(&self) -> &BTreeMap<String, HeldRevocation> {
        &self.credentials
    }

    /// Verifies and accepts one rumor payload of `stream` (the CBOR of a `SignedRevocation`);
    /// returns whether it newly revoked its target. Bytes that do not decode are refused.
    pub fn accept(&mut self, stream: &str, payload: &[u8], now_ms: i64) -> bool {
        match cbor::decode(payload) {
            Ok(signed) => self.accept_signed(stream, &signed, now_ms),
            Err(_) => false,
        }
    }

    /// Verifies and accepts one decoded `SignedRevocation` `{adBytes, publicKey, signature}`;
    /// returns whether it newly revoked its target (a record that outranks a kept one replaces
    /// it but returns `false`).
    ///
    /// The checks, all of which must pass: the advertisement decodes to a map whose `issuer` is
    /// the PeerID of the carried 32-byte key; the signature verifies under that key over
    /// `adBytes`; `issued` parses and lies no more than [`MAX_ISSUED_SKEW_MILLIS`] past
    /// `now_ms`; the `group` is the registry's (when set); and the stream's own rule holds. On
    /// [`PEER_STREAM`] only the founder revokes a peer. On [`CREDENTIAL_STREAM`] the target is
    /// valid, the reason known (an absent, null, or blank one is [`UNSPECIFIED`], as Java's
    /// constructor reads it), a `ttl` present, any byte `evidence` at most [`MAX_EVIDENCE`]
    /// bytes, the id canonical, any `effectiveFrom` no later than `issued`, and the issuer is the
    /// founder or, for an agent or agent key, the agent's own peer.
    pub fn accept_signed(&mut self, stream: &str, signed: &Value, now_ms: i64) -> bool {
        if !STREAMS.contains(&stream) {
            return false;
        }
        let Some(signed) = signed.as_map() else {
            return false;
        };
        let field = |key: &str| signed.get(key).and_then(Value::as_bytes);
        let (Some(ad_bytes), Some(key), Some(signature)) =
            (field("adBytes"), field("publicKey"), field("signature"))
        else {
            return false;
        };
        if key.len() != KEY_LENGTH {
            return false;
        }
        let Ok(Value::Map(ad)) = cbor::decode(ad_bytes) else {
            return false;
        };
        let Some(issued_ms) = ad
            .get("issued")
            .and_then(Value::as_str)
            .and_then(|text| time::parse_instant_millis(text).ok())
        else {
            return false;
        };
        let issuer = ad.get("issuer").and_then(Value::as_str);
        if issuer != Some(ids::derive_id(key).as_str())
            || !Identity::verify(key, ad_bytes, signature)
            || issued_ms > now_ms.saturating_add(MAX_ISSUED_SKEW_MILLIS)
        {
            return false;
        }
        if let Some(group) = &self.group
            && ad.get("group").and_then(Value::as_str) != Some(group.as_str())
        {
            return false;
        }
        let digest = crypto::port().sha256(ad_bytes);
        if stream == PEER_STREAM {
            self.accept_peer(ad, issued_ms, digest)
        } else {
            self.accept_credential(ad, issued_ms, digest)
        }
    }

    fn accept_peer(&mut self, ad: Map, issued_ms: i64, digest: [u8; 32]) -> bool {
        // Founder-rooted only: a CA-rooted record (evidence) is not trusted here, and only the
        // founder may name a successor.
        let Some(founder) = self.founder.as_deref() else {
            return false;
        };
        if ad.get("issuer").and_then(Value::as_str) != Some(founder) {
            return false;
        }
        let Some(revoked) = ad.get("revoked").and_then(Value::as_str).map(str::to_owned) else {
            return false;
        };
        let held = HeldRevocation {
            authority: Authority::Founder,
            issued_ms,
            digest,
            effective_ms: issued_ms,
            compromise: ad.get("reason").and_then(Value::as_str) == Some(KEY_COMPROMISE),
            ad,
        };
        keep(&mut self.peers, revoked, held)
    }

    fn accept_credential(&mut self, ad: Map, issued_ms: i64, digest: [u8; 32]) -> bool {
        let Some(target) = ad.get("target").and_then(Value::as_map) else {
            return false;
        };
        // Java's constructor reads an absent, null, or blank reason as `unspecified` and never
        // looks at it again in `verify`, so such a record is enforced there and must be here.
        let reason = reason_of(&ad);
        if !is_valid_target(target) || !reason.is_some_and(|r| REASONS.contains(&r)) {
            return false;
        }
        // What else Java's decode refuses: no lifetime, and evidence beyond MAX_EVIDENCE.
        let oversized_evidence = ad
            .get("evidence")
            .and_then(Value::as_bytes)
            .is_some_and(|evidence| evidence.len() > MAX_EVIDENCE);
        if present(&ad, "ttl").is_none() || oversized_evidence {
            return false;
        }
        let id = ad
            .get("group")
            .and_then(Value::as_str)
            .and_then(|group| revocation_id(group, target));
        if id.is_none() || ad.get("id").and_then(Value::as_str) != id.as_deref() {
            return false;
        }
        let effective_ms = match ad.get("effectiveFrom") {
            None | Some(Value::Null) => issued_ms,
            Some(value) => match value.as_str().map(time::parse_instant_millis) {
                Some(Ok(at)) if at <= issued_ms => at,
                _ => return false,
            },
        };
        let issuer = ad.get("issuer").and_then(Value::as_str).unwrap_or_default();
        let kind = target
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let authority = if self.founder.as_deref() == Some(issuer) {
            Authority::Founder
        } else if matches!(kind, "AGENT" | "AGENT_KEY")
            && target
                .get("agent")
                .and_then(Value::as_str)
                .and_then(|agent| agent.strip_prefix(issuer))
                .is_some_and(|rest| rest.starts_with('/'))
        {
            Authority::OwnPeer
        } else {
            return false;
        };
        let Some(canonical) = canonical_target(target) else {
            return false;
        };
        let key = format!("{kind}:{canonical}");
        let held = HeldRevocation {
            authority,
            issued_ms,
            digest,
            effective_ms,
            compromise: reason == Some(KEY_COMPROMISE),
            ad,
        };
        keep(&mut self.credentials, key, held)
    }

    /// Whether the peer is revoked.
    pub fn peer_revoked(&self, peer_id: &str) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// Java `RevocationView.refuses`: whether a newly arriving signature by `agent_id` is
    /// refused, because its peer is revoked, or its agent-wide revocation or (given the agent's
    /// raw public key) its key revocation refuses `signing_ms` under the freeze rule
    /// ([`HeldRevocation::refuses_at`]; `None` is an unknown time, always refused). An id
    /// without `/` is not an agent and is never refused here.
    pub fn refuses(
        &self,
        agent_id: &str,
        agent_key: Option<&[u8]>,
        signing_ms: Option<i64>,
    ) -> bool {
        let Some((peer, _)) = agent_id.split_once('/') else {
            return false;
        };
        if self.peer_revoked(peer) {
            return true;
        }
        if self
            .credentials
            .get(&format!("AGENT:{agent_id}"))
            .is_some_and(|held| held.refuses_at(signing_ms))
        {
            return true;
        }
        agent_key.is_some_and(|key| {
            let fingerprint = hex_lower(&crypto::port().sha256(key));
            self.credentials
                .get(&format!("AGENT_KEY:{agent_id}#{fingerprint}"))
                .is_some_and(|held| held.refuses_at(signing_ms))
        })
    }
}

/// One record per target under the total order (authority, issued, digest); returns whether the
/// target is newly revoked. A new target beyond [`MAX_RETAINED`] is refused.
fn keep(
    table: &mut BTreeMap<String, HeldRevocation>,
    key: String,
    candidate: HeldRevocation,
) -> bool {
    let full = table.len() >= MAX_RETAINED;
    match table.get_mut(&key) {
        Some(held) => {
            if candidate.order() > held.order() {
                *held = candidate;
            }
            false
        }
        None if full => false,
        None => {
            table.insert(key, candidate);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(authority: Authority, issued_ms: i64, digest: u8) -> HeldRevocation {
        HeldRevocation {
            authority,
            issued_ms,
            digest: [digest; 32],
            effective_ms: issued_ms,
            compromise: false,
            ad: Map::new(),
        }
    }

    #[test]
    fn the_keep_order_is_authority_then_issued_then_digest() {
        let mut table = BTreeMap::new();
        assert!(keep(&mut table, "t".into(), held(Authority::OwnPeer, 5, 9)));
        assert!(!keep(
            &mut table,
            "t".into(),
            held(Authority::OwnPeer, 4, 9)
        ));
        assert_eq!(table["t"].issued_ms, 5);
        assert!(!keep(
            &mut table,
            "t".into(),
            held(Authority::OwnPeer, 5, 10)
        ));
        assert_eq!(table["t"].digest, [10; 32]);
        assert!(!keep(
            &mut table,
            "t".into(),
            held(Authority::Founder, 1, 0)
        ));
        assert_eq!(table["t"].authority, Authority::Founder);
        assert!(!keep(
            &mut table,
            "t".into(),
            held(Authority::OwnPeer, 99, 99)
        ));
        assert_eq!(table["t"].authority, Authority::Founder);
    }

    #[test]
    fn the_tables_are_bounded() {
        let mut table = BTreeMap::new();
        for i in 0..MAX_RETAINED {
            assert!(keep(
                &mut table,
                i.to_string(),
                held(Authority::Founder, 0, 0)
            ));
        }
        assert!(!keep(
            &mut table,
            "one more".into(),
            held(Authority::Founder, 0, 0)
        ));
        assert_eq!(table.len(), MAX_RETAINED);
        // A kept target is still replaced by a higher-ranked record.
        assert!(!keep(
            &mut table,
            "0".into(),
            held(Authority::Founder, 1, 0)
        ));
        assert_eq!(table["0"].issued_ms, 1);
    }

    #[test]
    fn the_freeze_rule() {
        let mut revocation = held(Authority::OwnPeer, 100, 0);
        assert!(!revocation.refuses_at(Some(99)));
        assert!(revocation.refuses_at(Some(100)));
        assert!(revocation.refuses_at(None));
        revocation.compromise = true;
        assert!(revocation.refuses_at(Some(0)));
    }

    #[test]
    fn targets_canonicalize_by_kind() {
        assert_eq!(
            canonical_target(&agent_target("p/a")).as_deref(),
            Some("p/a")
        );
        let key = agent_key_target("p/a", &[0xAB; 32]);
        assert_eq!(
            canonical_target(&key),
            Some(format!("p/a#{}", "ab".repeat(32)))
        );
        assert_eq!(
            revocation_id("zG", &join_credential_target(&[1; 32])),
            Some(format!(
                "aspace://zG/revocation/join_credential/{}",
                "01".repeat(32)
            ))
        );
        let mut unknown = agent_target("p/a");
        unknown.insert("kind", "PEER");
        assert_eq!(canonical_target(&unknown), None);
        assert!(!is_valid_target(&unknown));
        let mut short = join_credential_target(&[1; 32]);
        short.insert("credentialHash", vec![1u8; 31]);
        assert!(!is_valid_target(&short));
    }

    #[test]
    fn a_registry_never_refuses_a_non_agent_and_ignores_garbage() {
        let mut registry = Registry::new(None, None);
        assert!(!registry.refuses("zPeer", None, None));
        assert!(!registry.accept(CREDENTIAL_STREAM, b"\xff", 0));
        assert!(!registry.accept(CREDENTIAL_STREAM, &[], 0));
        assert!(!registry.accept_signed("other", &Value::Null, 0));
        assert!(!registry.accept_signed(PEER_STREAM, &Value::Map(Map::new()), 0));
    }
}
