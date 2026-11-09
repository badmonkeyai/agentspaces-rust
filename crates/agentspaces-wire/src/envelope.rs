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

//! Envelopes and frames (SPEC §9, §5.6; TECH-SPEC §3), a port of `wire.py`'s `envelope`,
//! `encode_frame`, `decode_frame`, `decode_frame_detailed`, `encode_bare_frame`, and
//! `FrameFilter`, with the session path of the Ruby gem's and the TypeScript client's
//! `decode_frame_detailed` and Java `WireCodec` as the authority on bytes.
//!
//! An envelope is the CBOR map `{ver, group, kind, from, to, stamp, body}` in that order
//! ([`envelope`]). A frame wraps it in one of three forms:
//!
//! | form     | `senderPublicKey` | `signature`                 | built by                           |
//! |----------|-------------------|-----------------------------|------------------------------------|
//! | signed   | 32-byte key       | Ed25519 over the envelope   | [`encode_frame`]                   |
//! | attested | absent or null    | absent or null              | [`encode_bare_frame`]              |
//! | session  | absent or null    | HMAC-SHA-256 tag (32 bytes) | [`encode_session_frame`]           |
//!
//! [`decode_frame_detailed`] accepts each form only where it may appear: a bare frame on a
//! connection whose transport attested exactly its sender, a session frame on the connection
//! whose session names its sender and whose key verifies its tag, and a hello
//! ([`HELLO_KINDS`]) only fully signed. The version check runs first, so a frame of another
//! wire version costs no signature work.
//!
//! [`FrameFilter`] then admits each verified frame once and fresh, and [`accepts`] is the reader
//! filter on group and destination.
#![warn(missing_docs)]

use std::collections::{HashSet, VecDeque};

use crate::cbor::{self, Map, Value};
use crate::crypto::KEY_LENGTH;
use crate::hlc;
use crate::identity::Identity;
use crate::ids;
use crate::limits::{
    FRAME_FILTER_CAPACITY, MAX_FRAME_AGE_MILLIS, MAX_HLC_SKEW_MILLIS, WIRE_VERSION,
};
use crate::session::{self, HELLO_KINDS, MAC_LENGTH};
use crate::util::{encode_map, encode_map_into, non_null};

// ---------------------------------------------------------------------------------------------
// Envelopes

/// An `Envelope` in Java record order: `ver`, `group`, `kind`, `from`, `to`, `stamp`, `body`,
/// with `ver` set to [`WIRE_VERSION`].
///
/// `to` binds the frame to its recipient; `None` writes null, the unaddressed frame of
/// the bootstrap self-introduction. `stamp` is the sender's HLC stamp in the Java string form
/// `physical:logical:node`.
pub fn envelope(
    group: &str,
    kind: &str,
    from: &str,
    stamp: &str,
    body: &[u8],
    to: Option<&str>,
) -> Map {
    let mut env = Map::with_capacity(7);
    env.insert("ver", WIRE_VERSION);
    env.insert("group", group);
    env.insert("kind", kind);
    env.insert("from", from);
    env.insert("to", to);
    env.insert("stamp", stamp);
    env.insert("body", body);
    env
}

/// `WireCodec.Signed`: the frame `{envelope, senderPublicKey, signature}` with the signer's raw
/// public key and its Ed25519 signature over the envelope's CBOR.
pub fn encode_frame(env: &Map, signer: &Identity) -> Vec<u8> {
    let envelope_bytes = encode_map(env);
    let signature = signer.sign(&envelope_bytes);
    let mut frame = Vec::with_capacity(envelope_bytes.len() + 128);
    frame.push(0xBF);
    cbor::encode_into(&Value::from("envelope"), &mut frame);
    frame.extend_from_slice(&envelope_bytes);
    cbor::encode_into(&Value::from("senderPublicKey"), &mut frame);
    cbor::encode_into(&Value::from(signer.public_raw()), &mut frame);
    cbor::encode_into(&Value::from("signature"), &mut frame);
    cbor::encode_into(&Value::from(signature), &mut frame);
    frame.push(0xFF);
    frame
}

/// `WireCodec.encodeSession`: the frame `{envelope, senderPublicKey: null, signature: tag}` with
/// the HMAC-SHA-256 session tag ([`session::session_tag`]) of the envelope's CBOR under `key` in
/// place of the signature, what a node sends to the peer of an established session
/// ([`session::Session::key_for`]). The bytes are [`session::encode_session_frame`]'s for the
/// same envelope, without wrapping the envelope (and its body) in a [`Value`] first. A hello never
/// travels this way.
pub fn encode_session_frame(env: &Map, key: &[u8; MAC_LENGTH]) -> Vec<u8> {
    session::session_frame(&encode_map(env), key)
}

/// `WireCodec.encodeBare`: the frame `{envelope}` with no key and no signature, what a node sends
/// on a connection whose transport attested it, toward a peer that announced it accepts bare
/// frames there (`CHANNEL_HELLO`). A hello never travels this way.
pub fn encode_bare_frame(env: &Map) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0xBF);
    cbor::encode_into(&Value::from("envelope"), &mut frame);
    encode_map_into(env, &mut frame);
    frame.push(0xFF);
    frame
}

/// The fields of an envelope, in Java record order.
const ENVELOPE_FIELDS: [&str; 7] = ["ver", "group", "kind", "from", "to", "stamp", "body"];

/// Whether a received envelope is exactly what Java writes back for the `Envelope` it decodes
/// from it, so a signature or session tag over its CBOR here covers the bytes Java verifies
/// (`WireCodec.decodeDetailed` verifies `codec.toBytes(envelope)`): the seven fields of
/// [`envelope`] in order and nothing else, a non-empty text `group`, `kind`, and `from`, a `to`
/// that is null or non-empty text, a `stamp` in canonical form ([`hlc::Stamp::parse_canonical`]),
/// and a byte-string `body`. `ver` is checked before this. The kind is not checked against
/// [`crate::bodies::FRAME_KINDS`]: the layer above ignores and counts an unknown one.
fn is_canonical_envelope(env: &Map) -> bool {
    let non_empty = |name: &str| {
        env.get(name)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
    };
    let to_ok = match env.get("to") {
        Some(Value::Null) => true,
        _ => non_empty("to"),
    };
    env.len() == ENVELOPE_FIELDS.len()
        && env
            .keys()
            .zip(ENVELOPE_FIELDS)
            .all(|(key, name)| key.as_str() == Some(name))
        && non_empty("group")
        && non_empty("kind")
        && non_empty("from")
        && to_ok
        && hlc::Stamp::canonical_of(env.get("stamp")).is_some()
        && env.get("body").and_then(Value::as_bytes).is_some()
}

// ---------------------------------------------------------------------------------------------
// Decoding

/// How a decoded frame was authenticated (`WireCodec.Auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Auth {
    /// Fully signed: the Ed25519 signature verified under the carried key, which hashes to the
    /// sender.
    Signed,
    /// Bare, on a connection whose transport attested exactly the sender (SPEC §5.6).
    Attested,
    /// Tagged under the session key of the connection's session with the sender (SPEC §5.6,
    /// v0.1.17).
    Session,
}

impl Auth {
    /// The lower-case name the Python client reports (`"signed"`, `"attested"`, `"session"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Auth::Signed => "signed",
            Auth::Attested => "attested",
            Auth::Session => "session",
        }
    }
}

/// Decodes and verifies a fully signed frame and returns its envelope, or `None`. Bare and
/// session frames are refused: this is [`decode_frame_detailed`] on a connection with neither an
/// attested peer nor a session.
///
/// The checks, in order: the frame is a map whose `envelope` is a map; the envelope's `ver` is
/// the integer [`WIRE_VERSION`] (before any signature work, SPEC §9); `senderPublicKey` is 32
/// bytes that hash to the envelope's `from`; the envelope is already the form Java writes it back
/// as (its seven fields in order, a canonical stamp, a null or non-empty `to`), since Java
/// verifies over that re-encoding; the Ed25519 `signature` verifies over the envelope's CBOR.
/// Never panics.
pub fn decode_frame(frame: &[u8]) -> Option<Map> {
    decode_frame_detailed(frame, None, None).map(|(env, _)| env)
}

/// `WireCodec.decodeDetailed`: the envelope of a frame and how it was authenticated, or `None`.
///
/// - `attested` is the PeerID the connection's transport attested for its remote end, if any.
///   A bare frame (no key, no signature) is accepted only when its `from` is exactly that peer.
/// - `session` is the connection's established session, `(remote PeerID, key)`, if any
///   ([`session::Session::established`]). A session frame (no key, a [`MAC_LENGTH`]-byte tag in
///   `signature`) is accepted only when its `from` is that peer and the tag verifies under the
///   key over the envelope's canonical re-encoding.
/// - A hello (`SESSION_HELLO`, `CHANNEL_HELLO`) is accepted only fully signed.
///
/// An absent key or signature and a null one are alike. The version check runs before any other
/// judgment. A signed or session frame's envelope must already be in the form Java writes back
/// (seven fields in order, a canonical stamp, a null or non-empty `to`): Java verifies the
/// signature or tag over its re-encoding, so an envelope in another form would cover other bytes
/// there. A bare frame carries no signature, so its envelope's form is not judged. Every
/// malformed or hostile input is `None`, never a panic.
pub fn decode_frame_detailed(
    frame: &[u8],
    attested: Option<&str>,
    session: Option<(&str, &[u8; MAC_LENGTH])>,
) -> Option<(Map, Auth)> {
    let mut signed = cbor::decode(frame).ok()?.into_map()?;
    let env = signed.remove("envelope")?.into_map()?;
    if env.get("ver") != Some(&Value::Int(i128::from(WIRE_VERSION))) {
        return None;
    }
    let key = non_null(signed.get("senderPublicKey"));
    let signature = non_null(signed.get("signature"));
    let from = env.get("from").and_then(Value::as_str);
    let hello = env
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| HELLO_KINDS.contains(&kind));
    match (key, signature) {
        (None, None) => {
            let sender_attested = attested.is_some_and(|peer| Some(peer) == from);
            (!hello && sender_attested).then_some((env, Auth::Attested))
        }
        (None, Some(tag)) => {
            let (peer, session_key) = session?;
            let tag = tag.as_bytes()?;
            if hello
                || Some(peer) != from
                || tag.len() != MAC_LENGTH
                || !is_canonical_envelope(&env)
            {
                return None;
            }
            session::verify_session_tag(&encode_map(&env), tag, session_key)
                .then_some((env, Auth::Session))
        }
        (Some(key), signature) => {
            let key = key.as_bytes().filter(|key| key.len() == KEY_LENGTH)?;
            if Some(ids::derive_id(key).as_str()) != from || !is_canonical_envelope(&env) {
                return None;
            }
            let signature = signature.and_then(Value::as_bytes).unwrap_or_default();
            Identity::verify(key, &encode_map(&env), signature).then_some((env, Auth::Signed))
        }
    }
}

/// The reader filter (`Peer._accepts`, SPEC §9): whether a verified envelope is for
/// `group` and either unaddressed (`to` absent or null, the bootstrap exception) or addressed to
/// `own_peer_id`. A frame for a group this node never joined, or addressed to another peer, is
/// dropped. A joiner mid join-by-GroupID passes the wanted GroupID as `group`.
pub fn accepts(env: &Map, group: &str, own_peer_id: &str) -> bool {
    let for_group = env.get("group").and_then(Value::as_str) == Some(group);
    let for_us = match env.get("to") {
        None | Some(Value::Null) => true,
        Some(to) => to.as_str() == Some(own_peer_id),
    };
    for_group && for_us
}

/// The physical milliseconds of an envelope's HLC stamp: the text before the first `:` read as a
/// signed decimal `i64` (Java `Long.parseLong`: an optional sign, then ASCII digits), or `None`
/// when the stamp is not text or that part is not such a number ([`hlc::physical_lenient`], the
/// Java frame filter's rules, looser than [`hlc::Stamp::parse`]).
pub fn stamp_physical(env: &Map) -> Option<i64> {
    hlc::physical_lenient(env.get("stamp")?.as_str()?)
}

// ---------------------------------------------------------------------------------------------
// The frame filter

/// Admits each verified frame once, fresh (SPEC §9's frame-age window and replay filter; the
/// Java node's `isStaleOrReplay`): a stamp older than [`MAX_FRAME_AGE_MILLIS`] is stale, one
/// further ahead than [`MAX_HLC_SKEW_MILLIS`] is refused, and a `(from, stamp)` pair seen before
/// is a replay. All three are dropped silently and counted: late, duplicated, and replayed frames
/// are the normal case on a network, not evidence of anything.
///
/// The filter remembers at most `capacity` pairs and forgets the oldest first. It holds no clock:
/// the caller passes its own time to [`FrameFilter::admit`].
#[derive(Debug, Clone)]
pub struct FrameFilter {
    seen: HashSet<(String, String)>,
    order: VecDeque<(String, String)>,
    capacity: usize,
    stale: u64,
    ahead: u64,
    replayed: u64,
}

impl Default for FrameFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameFilter {
    /// A filter remembering [`FRAME_FILTER_CAPACITY`] pairs.
    pub fn new() -> Self {
        Self::with_capacity(FRAME_FILTER_CAPACITY)
    }

    /// A filter remembering at most `capacity` pairs (0 remembers none, so no frame is ever a
    /// replay).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
            stale: 0,
            ahead: 0,
            replayed: 0,
        }
    }

    /// Whether to handle a verified envelope received at `now_ms` on the caller's clock.
    ///
    /// An envelope whose stamp has no readable physical time ([`stamp_physical`]) or whose
    /// `from` is not text is refused without being counted (a verified frame always has both).
    /// Otherwise a stale stamp counts in [`FrameFilter::stale`], a stamp too far ahead in
    /// [`FrameFilter::ahead`], and a repeated `(from, stamp)` in [`FrameFilter::replayed`]; an
    /// admitted pair is remembered. The arithmetic is exact, so a hostile stamp cannot overflow.
    pub fn admit(&mut self, env: &Map, now_ms: i64) -> bool {
        let Some(physical) = stamp_physical(env) else {
            return false;
        };
        let (Some(from), Some(stamp)) = (
            env.get("from").and_then(Value::as_str),
            env.get("stamp").and_then(Value::as_str),
        ) else {
            return false;
        };
        let (now, physical) = (i128::from(now_ms), i128::from(physical));
        if now - physical > i128::from(MAX_FRAME_AGE_MILLIS) {
            self.stale = self.stale.saturating_add(1);
            return false;
        }
        if physical - now > i128::from(MAX_HLC_SKEW_MILLIS) {
            self.ahead = self.ahead.saturating_add(1);
            return false;
        }
        let key = (from.to_owned(), stamp.to_owned());
        if self.seen.contains(&key) {
            self.replayed = self.replayed.saturating_add(1);
            return false;
        }
        self.seen.insert(key.clone());
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

    /// How many frames were dropped as older than [`MAX_FRAME_AGE_MILLIS`].
    pub fn stale(&self) -> u64 {
        self.stale
    }

    /// How many frames were dropped as further ahead than [`MAX_HLC_SKEW_MILLIS`].
    pub fn ahead(&self) -> u64 {
        self.ahead
    }

    /// How many frames were dropped as replays of a remembered `(from, stamp)` pair.
    pub fn replayed(&self) -> u64 {
        self.replayed
    }

    /// How many pairs the filter remembers at most.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many pairs the filter remembers now.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the filter remembers no pair.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}
