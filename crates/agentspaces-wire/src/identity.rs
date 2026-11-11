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

//! Peer identities, subordinate agent identities, and agent certificates (SPEC §4.1, §4.2,
//! §11a.2a, §11a.3; TECH-SPEC §7.2), a port of `identity.py`'s `Identity`, `AgentIdentity`, and
//! certificate functions, with Java `PeerIdentity`, `AgentCertificates`, and
//! `RenewingAgentIdentity` as the authority on bytes.
//!
//! - An [`Identity`] is an Ed25519 key pair. Its PeerID is multibase base58btc of SHA-256 over the
//!   raw 32-byte public key ([`crate::ids::derive_id`]), and an AgentID is `<peerId>/<localName>`.
//! - An agent certificate binds an agent's own Ed25519 key (and optionally its X25519 encryption
//!   key) to the agent's peer for a validity window `[issued, issued + ttl)`. The peer signs the
//!   CBOR of the certificate body: the Java record `AgentCertificate` in declared field order
//!   (`agent`, `agentPublicKey`, `issued`, `ttl`, `peerSignature` set to null, then
//!   `encryptionPublicKey` only when present), so the bytes match Java's.
//! - An [`AgentIdentity`] holds the agent key, its current certificate, and up to
//!   [`AgentIdentity::RETAINED`] certificates in all. A renewing one re-issues its certificate for
//!   the same key at half-life when the caller asks ([`AgentIdentity::renew_if_due`]).
//!
//! The module is sans-IO: no clock (every time is an argument in epoch milliseconds) and no files
//! (the keystore lives in the peer crate). Every judgment of untrusted input returns `bool` or
//! `Option` and never panics.
#![warn(missing_docs)]

use std::collections::VecDeque;
use std::fmt;

use crate::cbor::{Map, Value};
use crate::crypto::{self, CryptoError, Zeroizing};
use crate::ids;
use crate::limits::MAX_DRIFT_MILLIS;
use crate::time::{self, TimeError};
use crate::util::encode_map;

/// Why an identity, certificate, or agent identity could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// A key could not be generated or read.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// An issue instant or a lifetime is not `java.time` text this wire carries.
    #[error(transparent)]
    Time(#[from] TimeError),
    /// An agent's local name is empty or contains `/` or `:` (Java `AgentId` refuses each; SPEC
    /// §9.2, R5).
    #[error("an agent's local name must be non-empty and contain no '/' and no ':': {0:?}")]
    InvalidLocalName(String),
    /// A peer was asked to certify an agent that belongs to another peer.
    #[error("certificate for {agent} cannot be issued by {peer}")]
    ForeignAgent {
        /// The agent the certificate names.
        agent: String,
        /// The PeerID of the peer that was asked to sign it.
        peer: String,
    },
    /// A certificate body lacks a field, or the field has the wrong type.
    #[error("the certificate body lacks {field} or carries it with the wrong type")]
    MalformedCertificate {
        /// The field.
        field: &'static str,
    },
}

// ---------------------------------------------------------------------------------------------
// Identity

/// An Ed25519 identity: a peer's key pair (or an agent's own key, or a key derived from a group
/// secret) with its Java-compatible PeerID.
///
/// The 32-byte RFC 8032 seed is held in a [`Zeroizing`] buffer, wiped on drop, and never printed:
/// [`fmt::Debug`] shows the PeerID only. Signing is deterministic, so the same seed signs the same
/// message to the same bytes in every implementation.
#[derive(Clone)]
pub struct Identity {
    seed: Zeroizing<[u8; 32]>,
    public_raw: [u8; 32],
    peer_id: String,
}

impl Identity {
    /// A fresh identity from the installed crypto port's random source.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = crypto::random_seed()?;
        Ok(Self::from_seed(&seed))
    }

    /// The identity of a 32-byte Ed25519 seed (RFC 8032's private key), as Java
    /// `Ed25519.fromSeed` builds one: how the invite signing key is derived from a group secret.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let public_raw = crypto::port().ed25519_public_key(seed);
        Identity {
            seed: Zeroizing::new(*seed),
            public_raw,
            peer_id: ids::derive_id(&public_raw),
        }
    }

    /// The identity of an Ed25519 private key in the exact 48-byte RFC 8410 PKCS#8 form Java's
    /// keystore writes (`peer.key`); any other form is refused
    /// ([`crypto::ed25519_seed_from_pkcs8`]).
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CryptoError> {
        let seed = crypto::ed25519_seed_from_pkcs8(der)?;
        Ok(Self::from_seed(&seed))
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn public_raw(&self) -> &[u8; 32] {
        &self.public_raw
    }

    /// The PeerID: multibase base58btc of SHA-256 over [`Identity::public_raw`].
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// The private key as the 48-byte RFC 8410 PKCS#8 DER Java's keystore writes, wiped on drop.
    pub fn pkcs8(&self) -> Zeroizing<Vec<u8>> {
        crypto::ed25519_pkcs8(&self.seed)
    }

    /// The deterministic Ed25519 signature (RFC 8032) of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        crypto::port().ed25519_sign(&self.seed, message)
    }

    /// Whether `signature` is a valid Ed25519 signature of `message` under the raw 32-byte
    /// `public_key`, by the installed port's strict verification. False on any malformed input.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        crypto::port().ed25519_verify(public_key, message, signature)
    }

    /// The AgentID string form `<peerId>/<localName>` of one of this peer's agents. The name is
    /// not checked here; [`Identity::subordinate`] refuses one Java `AgentId` would refuse.
    pub fn agent(&self, local_name: &str) -> String {
        format!("{}/{local_name}", self.peer_id)
    }

    /// Java `PeerIdentity.subordinate`: certifies `key` (a fresh key when `None`) as the agent
    /// `<peerId>/<local_name>` from `issued_iso` (`java.time.Instant` text) for `ttl_iso`
    /// (`java.time.Duration` text as Java prints it, "PT24H"). The identity does not renew.
    ///
    /// Refuses a local name that is empty or contains `/` or `:`, an instant or duration that does not
    /// parse, and a failure of the random source.
    pub fn subordinate(
        &self,
        local_name: &str,
        issued_iso: &str,
        ttl_iso: &str,
        key: Option<Identity>,
    ) -> Result<AgentIdentity, IdentityError> {
        self.certify(local_name, issued_iso, ttl_iso, key, None, false)
    }

    /// Java `PeerIdentity.renewingSubordinate` (SPEC §4.2, v0.1.13): certifies `key` (a fresh key
    /// when `None`) as `<peerId>/<local_name>` from `now_ms` for `ttl_iso`, and returns an
    /// identity this peer re-issues the certificate of at half-life through
    /// [`AgentIdentity::renew_if_due`].
    pub fn renewing_subordinate(
        &self,
        local_name: &str,
        ttl_iso: &str,
        key: Option<Identity>,
        now_ms: i64,
    ) -> Result<AgentIdentity, IdentityError> {
        self.certify(
            local_name,
            &time::instant_iso(now_ms),
            ttl_iso,
            key,
            None,
            true,
        )
    }

    /// [`Identity::renewing_subordinate`] whose certificates also certify the agent's X25519
    /// `encryption_public_raw` key (SPEC §11a.2a), appended to every certificate body.
    pub fn renewing_subordinate_with_encryption(
        &self,
        local_name: &str,
        ttl_iso: &str,
        key: Option<Identity>,
        encryption_public_raw: &[u8; 32],
        now_ms: i64,
    ) -> Result<AgentIdentity, IdentityError> {
        self.certify(
            local_name,
            &time::instant_iso(now_ms),
            ttl_iso,
            key,
            Some(*encryption_public_raw),
            true,
        )
    }

    fn certify(
        &self,
        local_name: &str,
        issued_iso: &str,
        ttl_iso: &str,
        key: Option<Identity>,
        encryption_public_raw: Option<[u8; 32]>,
        renewing: bool,
    ) -> Result<AgentIdentity, IdentityError> {
        if !ids::is_local_name(local_name) {
            return Err(IdentityError::InvalidLocalName(local_name.to_owned()));
        }
        // A renewing identity re-reads both; refusing them here keeps renewal from failing later.
        time::parse_instant_millis(issued_iso)?;
        time::parse_duration_millis(ttl_iso)?;
        let key = match key {
            Some(key) => key,
            None => Identity::generate()?,
        };
        let agent_id = self.agent(local_name);
        let body = agent_certificate(
            &agent_id,
            key.public_raw(),
            issued_iso,
            ttl_iso,
            None,
            encryption_public_raw.as_ref(),
        );
        let certificate = sign_agent_certificate(&body, self)?;
        Ok(AgentIdentity {
            agent_id,
            key,
            certificate,
            earlier: VecDeque::new(),
            renewal_ttl: renewing.then(|| ttl_iso.to_owned()),
            encryption_public_raw,
        })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("peer_id", &self.peer_id)
            .field("seed", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Agent certificates

/// An `AgentCertificate` in Java record order: `agent`, `agentPublicKey`, `issued`, `ttl`,
/// `peerSignature`, and (v0.1.13, SPEC §11a.2a) the agent's X25519 `encryptionPublicKey`,
/// appended and omitted when absent so a certificate without it keeps its exact bytes. With
/// `peer_signature` `None` (CBOR null) this is the body the peer signs (Java
/// `AgentCertificate.unsigned`).
pub fn agent_certificate(
    agent: &str,
    agent_public_raw: &[u8; 32],
    issued_iso: &str,
    ttl_iso: &str,
    peer_signature: Option<&[u8; 64]>,
    encryption_public_raw: Option<&[u8; 32]>,
) -> Map {
    certificate_map(
        Value::from(agent),
        Value::from(agent_public_raw),
        Value::from(issued_iso),
        Value::from(ttl_iso),
        Value::from(peer_signature),
        encryption_public_raw.map(Value::from),
    )
}

fn certificate_map(
    agent: Value,
    agent_public_key: Value,
    issued: Value,
    ttl: Value,
    peer_signature: Value,
    encryption_public_key: Option<Value>,
) -> Map {
    let mut certificate = Map::with_capacity(6);
    certificate.insert("agent", agent);
    certificate.insert("agentPublicKey", agent_public_key);
    certificate.insert("issued", issued);
    certificate.insert("ttl", ttl);
    certificate.insert("peerSignature", peer_signature);
    if let Some(key) = encryption_public_key {
        certificate.insert("encryptionPublicKey", key);
    }
    certificate
}

/// The signed body of a (possibly decoded, possibly reordered) certificate: the same fields in
/// canonical order with `peerSignature` null, `encryptionPublicKey` kept only when present and not
/// null, and any other field dropped. Values are copied as they are, not type-checked; `None`
/// when `agent`, `agentPublicKey`, `issued`, or `ttl` is missing.
pub fn certificate_body(certificate: &Map) -> Option<Map> {
    let field = |name: &str| certificate.get(name).cloned();
    Some(certificate_map(
        field("agent")?,
        field("agentPublicKey")?,
        field("issued")?,
        field("ttl")?,
        Value::Null,
        field("encryptionPublicKey").filter(|key| !key.is_null()),
    ))
}

/// The window `[issued, issued + ttl)` of a certificate in epoch milliseconds, widened to `i128`
/// so no sum overflows. `None` when either field is missing or not text this wire carries.
fn window(certificate: &Map) -> Option<(i128, i128)> {
    let issued = time::parse_instant_millis(certificate.get("issued")?.as_str()?).ok()?;
    let ttl = time::parse_duration_millis(certificate.get("ttl")?.as_str()?).ok()?;
    let issued = i128::from(issued);
    Some((issued, issued + i128::from(ttl)))
}

/// Java `AgentCertificate.covers` (SPEC §4.2, v0.1.13): whether `signing_ms` lies in
/// `[issued, issued + ttl)`, the issue instant taken at millisecond precision as hybrid logical
/// clock stamps are. False when `issued` or `ttl` is missing or malformed.
pub fn certificate_covers(certificate: &Map, signing_ms: i64) -> bool {
    window(certificate).is_some_and(|(issued, expires)| {
        let signing = i128::from(signing_ms);
        issued <= signing && signing < expires
    })
}

/// Java `AgentCertificates.sign`: `peer` signs the canonical body of `body` (see
/// [`certificate_body`]) and the signed certificate is returned, `peerSignature` in its place.
/// Only the peer the agent name belongs to may certify it: an agent that is not
/// `<peer.peer_id()>/...` is [`IdentityError::ForeignAgent`].
pub fn sign_agent_certificate(body: &Map, peer: &Identity) -> Result<Map, IdentityError> {
    let agent = body
        .get("agent")
        .and_then(Value::as_str)
        .ok_or(IdentityError::MalformedCertificate { field: "agent" })?;
    if !belongs_to(agent, peer.peer_id()) {
        return Err(IdentityError::ForeignAgent {
            agent: agent.to_owned(),
            peer: peer.peer_id().to_owned(),
        });
    }
    let mut certificate = certificate_body(body).ok_or(IdentityError::MalformedCertificate {
        field: "agentPublicKey, issued, or ttl",
    })?;
    let signature = peer.sign(&encode_map(&certificate));
    certificate.insert("peerSignature", signature);
    Ok(certificate)
}

/// Java `AgentCertificates.verify`: true only when `certificate` is a map that carries a byte
/// string `peerSignature` and a 32-byte `agentPublicKey`, an `encryptionPublicKey` that is absent,
/// null, or 32 bytes, and an `agent` equal to `agent_id`, a Java `AgentId`
/// ([`ids::parse_agent_id`]), and belonging to the peer `peer_public_raw` (32 bytes) hashes to;
/// whose `issued` and `ttl` are the text Java writes back ([`time::is_canonical_instant`],
/// [`time::is_canonical_duration`]) and whose `ttl` is positive; that is unexpired at `now_ms`
/// (expiry is `issued + ttl`, the first refused instant); and whose peer signature verifies over
/// the canonical body. Java verifies over its re-encoding of the typed certificate, so a
/// certificate in any other form would verify other bytes there. Never panics on a hostile shape.
pub fn verify_agent_certificate(
    certificate: &Value,
    peer_public_raw: &[u8],
    agent_id: &str,
    now_ms: i64,
) -> bool {
    let Some(certificate) = certificate.as_map() else {
        return false;
    };
    let Some(signature) = certificate.get("peerSignature").and_then(Value::as_bytes) else {
        return false;
    };
    let agent_key_ok = certificate
        .get("agentPublicKey")
        .and_then(Value::as_bytes)
        .is_some_and(|key| key.len() == crypto::KEY_LENGTH);
    let encryption_key_ok = match certificate.get("encryptionPublicKey") {
        None | Some(Value::Null) => true,
        Some(key) => key
            .as_bytes()
            .is_some_and(|key| key.len() == crypto::KEY_LENGTH),
    };
    if !agent_key_ok || !encryption_key_ok || peer_public_raw.len() != crypto::KEY_LENGTH {
        return false;
    }
    let agent_ok = certificate
        .get("agent")
        .and_then(Value::as_str)
        .is_some_and(|agent| {
            agent == agent_id
                && ids::parse_agent_id(agent).is_some()
                && belongs_to(agent, &ids::derive_id(peer_public_raw))
        });
    if !agent_ok {
        return false;
    }
    // Java verifies over its re-encoding of the typed certificate, so the instant and the
    // lifetime must already be the text Java writes back, and the lifetime positive (Java's
    // constructor refuses any other).
    let canonical_times = certificate
        .get("issued")
        .and_then(Value::as_str)
        .is_some_and(time::is_canonical_instant)
        && certificate
            .get("ttl")
            .and_then(Value::as_str)
            .is_some_and(|ttl| time::is_canonical_duration(ttl) && ttl != "PT0S");
    if !canonical_times {
        return false;
    }
    let unexpired = window(certificate).is_some_and(|(_, expires)| i128::from(now_ms) < expires);
    if !unexpired {
        return false;
    }
    certificate_body(certificate)
        .is_some_and(|body| Identity::verify(peer_public_raw, &encode_map(&body), signature))
}

/// Java `AgentCertificates.verifyAt` (SPEC §4.2, v0.1.13): a certificate judged at the signing
/// time of what it certifies, not at receipt. True only when its window covers `signing_ms`,
/// `signing_ms` leads the receiver's `receiver_now_ms` by at most [`MAX_DRIFT_MILLIS`], and
/// [`verify_agent_certificate`] passes at `signing_ms`. An agent's history therefore stays
/// verifiable after its certificate lapses. An agent card's attestation keeps this bound; a
/// space's records, claims, and `signedAt` use [`verify_agent_certificate_covering`] since
/// v0.1.30, and the far-future rule bounds their stamps instead.
pub fn verify_agent_certificate_at(
    certificate: &Value,
    peer_public_raw: &[u8],
    agent_id: &str,
    signing_ms: i64,
    receiver_now_ms: i64,
) -> bool {
    let Some(map) = certificate.as_map() else {
        return false;
    };
    certificate_covers(map, signing_ms)
        && i128::from(signing_ms) <= i128::from(receiver_now_ms) + i128::from(MAX_DRIFT_MILLIS)
        && verify_agent_certificate(certificate, peer_public_raw, agent_id, signing_ms)
}

/// Java `AgentCertificates.verifyCovering` (SPEC §4.2, v0.1.30): a certificate for a space's
/// record, take claim, or agent-signed state's `signedAt`, judged at the signing time of what it
/// certifies. True only when its window covers `signing_ms` and [`verify_agent_certificate`]
/// passes at `signing_ms`. Unlike [`verify_agent_certificate_at`] it sets no bound on how far the
/// signing time leads the receiver's clock: the space judges that lead afterwards by the
/// far-future rule of SPEC §7.3, as it judges a peer-signed carrier's stamp.
pub fn verify_agent_certificate_covering(
    certificate: &Value,
    peer_public_raw: &[u8],
    agent_id: &str,
    signing_ms: i64,
) -> bool {
    certificate
        .as_map()
        .is_some_and(|map| certificate_covers(map, signing_ms))
        && verify_agent_certificate(certificate, peer_public_raw, agent_id, signing_ms)
}

/// Whether `agent` is `<peer_id>/...`.
fn belongs_to(agent: &str, peer_id: &str) -> bool {
    agent
        .strip_prefix(peer_id)
        .is_some_and(|rest| rest.starts_with('/'))
}

// ---------------------------------------------------------------------------------------------
// AgentIdentity

/// A subordinate agent identity (SPEC §4.2, §11a.3): the agent's own Ed25519 key plus the
/// peer-signed certificate that vouches for it. Records and claims the agent writes are signed
/// with [`AgentIdentity::sign`]; the certificate covering the signing time travels beside them.
///
/// A renewing identity ([`Identity::renewing_subordinate`]) re-issues its certificate for the same
/// key once half its lifetime has passed, and keeps up to [`AgentIdentity::RETAINED`]
/// certificates in all, so a claim whose stamp a renewal kept stays certifiable. There is no clock
/// inside: where `identity.py` renews lazily on every sign and lookup, a caller here calls
/// [`AgentIdentity::renew_if_due`] with its peer and the time before signing or looking up.
#[derive(Clone)]
pub struct AgentIdentity {
    agent_id: String,
    key: Identity,
    certificate: Map,
    /// Earlier certificates, oldest first, at most `RETAINED - 1`.
    earlier: VecDeque<Map>,
    /// The lifetime each renewal certifies for; `Some` exactly when the identity renews.
    renewal_ttl: Option<String>,
    encryption_public_raw: Option<[u8; 32]>,
}

impl AgentIdentity {
    /// How many certificates are kept, the current one included (`identity.py`
    /// `AgentIdentity.RETAINED`; 128 days at a 24-hour lifetime).
    pub const RETAINED: usize = 256;

    /// The AgentID, `<peerId>/<localName>`.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// The local name: the AgentID after the first `/`.
    pub fn local_name(&self) -> &str {
        self.agent_id
            .split_once('/')
            .map_or(self.agent_id.as_str(), |(_, local)| local)
    }

    /// The agent's own key.
    pub fn key(&self) -> &Identity {
        &self.key
    }

    /// The agent key's raw 32-byte Ed25519 public key, the one its certificates certify.
    pub fn public_raw(&self) -> &[u8; 32] {
        self.key.public_raw()
    }

    /// The X25519 public key the certificates certify, when they do (SPEC §11a.2a).
    pub fn encryption_public_raw(&self) -> Option<&[u8; 32]> {
        self.encryption_public_raw.as_ref()
    }

    /// The newest certificate.
    pub fn certificate(&self) -> &Map {
        &self.certificate
    }

    /// Every held certificate, newest first.
    pub fn certificates(&self) -> impl Iterator<Item = &Map> {
        std::iter::once(&self.certificate).chain(self.earlier.iter().rev())
    }

    /// Whether this identity re-issues its certificate ([`Identity::renewing_subordinate`]).
    pub fn is_renewing(&self) -> bool {
        self.renewal_ttl.is_some()
    }

    /// Re-issues the certificate for the same key (and encryption key) when half its lifetime has
    /// passed at `now_ms`: the new certificate is issued at `now_ms` for the identity's lifetime,
    /// signed by `peer`, becomes [`AgentIdentity::certificate`], and the oldest certificate beyond
    /// [`AgentIdentity::RETAINED`] is forgotten. Returns whether it re-issued; always `false` for
    /// an identity that does not renew.
    ///
    /// `peer` must be the peer the agent belongs to ([`IdentityError::ForeignAgent`] otherwise),
    /// and `now_ms` must print as a four-digit-year instant ([`IdentityError::Time`] otherwise).
    pub fn renew_if_due(&mut self, peer: &Identity, now_ms: i64) -> Result<bool, IdentityError> {
        let Some(ttl_iso) = &self.renewal_ttl else {
            return Ok(false);
        };
        let issued = self
            .certificate
            .get("issued")
            .and_then(Value::as_str)
            .ok_or(IdentityError::MalformedCertificate { field: "issued" })?;
        let ttl = self
            .certificate
            .get("ttl")
            .and_then(Value::as_str)
            .ok_or(IdentityError::MalformedCertificate { field: "ttl" })?;
        let half_life = i128::from(time::parse_instant_millis(issued)?)
            + i128::from(time::parse_duration_millis(ttl)? / 2);
        if i128::from(now_ms) < half_life {
            return Ok(false);
        }
        let issued_iso = time::instant_iso(now_ms);
        time::parse_instant_millis(&issued_iso)?;
        let body = agent_certificate(
            &self.agent_id,
            self.key.public_raw(),
            &issued_iso,
            ttl_iso,
            None,
            self.encryption_public_raw.as_ref(),
        );
        let renewed = sign_agent_certificate(&body, peer)?;
        self.earlier
            .push_back(std::mem::replace(&mut self.certificate, renewed));
        while self.earlier.len() >= Self::RETAINED {
            self.earlier.pop_front();
        }
        Ok(true)
    }

    /// The newest held certificate whose window covers `signing_ms`, or `None`: what a writer
    /// attaches so receivers can judge it at that time ([`verify_agent_certificate_at`]).
    pub fn certificate_covering(&self, signing_ms: i64) -> Option<&Map> {
        self.certificates()
            .find(|certificate| certificate_covers(certificate, signing_ms))
    }

    /// The agent key's deterministic Ed25519 signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message)
    }
}

impl fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("agent_id", &self.agent_id)
            .field("key", &self.key)
            .field("renewing", &self.is_renewing())
            .field("certificates", &(self.earlier.len() + 1))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Identity {
        Identity::from_seed(&[1u8; 32])
    }

    #[test]
    fn debug_redacts_the_seed() {
        let identity = peer();
        let shown = format!("{identity:?}");
        assert!(shown.contains(identity.peer_id()));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("[1, 1"));
        let key = Identity::from_seed(&[2; 32]);
        let agent = identity
            .subordinate("a", "2025-01-01T00:00:00Z", "PT1H", Some(key))
            .unwrap();
        let shown = format!("{agent:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("[2, 2"));
    }

    #[test]
    fn history_is_bounded() {
        let peer = peer();
        let key = Identity::from_seed(&[2; 32]);
        let mut agent = peer
            .renewing_subordinate("a", "PT2S", Some(key), 0)
            .unwrap();
        for step in 1..=300_i64 {
            assert!(agent.renew_if_due(&peer, step * 1000).unwrap());
        }
        assert_eq!(agent.certificates().count(), AgentIdentity::RETAINED);
        assert_eq!(
            agent.certificate().get("issued").and_then(Value::as_str),
            Some(time::instant_iso(300_000).as_str())
        );
        // The oldest kept is the 256th newest, issued at 45 s.
        let oldest = agent.certificates().last().unwrap();
        assert_eq!(
            oldest.get("issued").and_then(Value::as_str),
            Some(time::instant_iso(45_000).as_str())
        );
        assert!(agent.certificate_covering(44_999).is_none());
        assert!(agent.certificate_covering(45_000).is_some());
    }

    #[test]
    fn extreme_times_do_not_overflow() {
        let peer = peer();
        let agent = peer.agent("a");
        let body = agent_certificate(
            &agent,
            &[3; 32],
            "9999-12-31T23:59:59.999Z",
            "PT2562047788015H",
            None,
            None,
        );
        let certificate = sign_agent_certificate(&body, &peer).unwrap();
        assert!(certificate_covers(&certificate, i64::MAX));
        assert!(!certificate_covers(&certificate, i64::MIN));
        let value = Value::Map(certificate);
        let key = peer.public_raw();
        assert!(verify_agent_certificate(&value, key, &agent, i64::MAX));
        assert!(!verify_agent_certificate_at(
            &value,
            key,
            &agent,
            i64::MAX,
            i64::MIN
        ));
        assert!(verify_agent_certificate_at(
            &value,
            key,
            &agent,
            i64::MAX,
            i64::MAX
        ));
    }
}
