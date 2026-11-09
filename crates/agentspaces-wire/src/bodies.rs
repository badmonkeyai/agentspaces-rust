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

//! Frame bodies and capability payloads (SPEC §5, §7.1, §8, §9), a port of `wire.py`'s body
//! helpers with Java `Bodies` as the authority on bytes: every map is written in the Java
//! record's field order, and a map-valued field (`digests`, `deltas`) in canonical order, as the
//! Java codec writes a `java.util.Map` since wire v3.
//!
//! Builders return the CBOR body (`Vec<u8>`) where `wire.py` returns bytes, and a [`Map`] where it
//! returns a dict (a capability payload the caller encodes into a `PIPE_DATA` body). The parsers
//! (`parse_*`) read what the Python peer reads from a received body; each returns `None` for a
//! body of the wrong shape and never panics.
//!
//! The frame kinds are the variants of Java `Envelope.Kind` ([`FRAME_KINDS`]).
#![warn(missing_docs)]

use crate::cbor::{self, Map, Value};
use crate::crypto;
use crate::envelope::envelope;
use crate::ids;
use crate::util::encode_map;

// ---------------------------------------------------------------------------------------------
// Kinds

/// `PING`: a liveness probe ([`ping_body`]), answered with an `ACK`.
pub const KIND_PING: &str = "PING";
/// `PING_REQ`: asks the receiver to probe a target for the asker.
pub const KIND_PING_REQ: &str = "PING_REQ";
/// `ACK`: the answer to a `PING` or `PING_REQ` ([`ack_body`]).
pub const KIND_ACK: &str = "ACK";
/// `RUMOR`: one item on a named stream ([`rumor_body`]).
pub const KIND_RUMOR: &str = "RUMOR";
/// `DIGEST`: an anti-entropy digest ([`digest_body`]), answered with a `PULL_RESP`.
pub const KIND_DIGEST: &str = "DIGEST";
/// `PULL_RESP`: the per-stream deltas the asker lacked ([`pull_resp_body`]).
pub const KIND_PULL_RESP: &str = "PULL_RESP";
/// `QUERY`: a discovery query.
pub const KIND_QUERY: &str = "QUERY";
/// `QUERY_HIT`: an answer to a `QUERY`.
pub const KIND_QUERY_HIT: &str = "QUERY_HIT";
/// `BLOCK_WANT`: asks for one block by id ([`block_want_body`]).
pub const KIND_BLOCK_WANT: &str = "BLOCK_WANT";
/// `BLOCK`: one block under its id ([`block_body`]).
pub const KIND_BLOCK: &str = "BLOCK";
/// `PIPE_DATA`: a capability frame ([`pipe_data_body`]).
pub const KIND_PIPE_DATA: &str = "PIPE_DATA";
/// `BATCH`: several inner envelopes from one sender in one signed envelope (SPEC §9).
pub const KIND_BATCH: &str = "BATCH";
/// `HAVE`: lazy push, items the sender forwarded without carrying them (SPEC §5.3).
pub const KIND_HAVE: &str = "HAVE";
/// `GRAFT`: lazy push, a request for one announced item.
pub const KIND_GRAFT: &str = "GRAFT";
/// `PRUNE`: lazy push, the duplicate that demoted the receiver to lazy.
pub const KIND_PRUNE: &str = "PRUNE";
/// `RELAY_FRAME`: a complete signed frame carried for a peer that cannot be dialed directly
/// ([`relay_frame_body`], SPEC §5.4).
pub const KIND_RELAY_FRAME: &str = "RELAY_FRAME";
/// `CHANNEL_HELLO`: the announcement that the sender accepts channel-attested frames on this
/// connection ([`channel_hello_body`], SPEC §5.6). Only ever accepted fully signed.
pub const KIND_CHANNEL_HELLO: &str = "CHANNEL_HELLO";
/// `SESSION_HELLO`: one half of a session key agreement ([`crate::session::hello_body`],
/// SPEC §5.6). Only ever accepted fully signed.
pub const KIND_SESSION_HELLO: &str = "SESSION_HELLO";
/// `GROUP_AD_WANT`: the join-by-GroupID request ([`group_ad_want_envelope`], SPEC §9, §10.1).
pub const KIND_GROUP_AD_WANT: &str = "GROUP_AD_WANT";
/// `GROUP_AD`: the join-by-GroupID answer ([`group_ad_body`]).
pub const KIND_GROUP_AD: &str = "GROUP_AD";

/// Every frame kind of wire version 3, in the declaration order of Java `Envelope.Kind`.
pub const FRAME_KINDS: [&str; 20] = [
    KIND_PING,
    KIND_PING_REQ,
    KIND_ACK,
    KIND_RUMOR,
    KIND_DIGEST,
    KIND_PULL_RESP,
    KIND_QUERY,
    KIND_QUERY_HIT,
    KIND_BLOCK_WANT,
    KIND_BLOCK,
    KIND_PIPE_DATA,
    KIND_BATCH,
    KIND_HAVE,
    KIND_GRAFT,
    KIND_PRUNE,
    KIND_RELAY_FRAME,
    KIND_CHANNEL_HELLO,
    KIND_SESSION_HELLO,
    KIND_GROUP_AD_WANT,
    KIND_GROUP_AD,
];

/// Whether `kind` is one of [`FRAME_KINDS`]. A Java node refuses an envelope of any other kind; this
/// client ignores and counts one.
pub fn is_known_kind(kind: &str) -> bool {
    FRAME_KINDS.contains(&kind)
}

// ---------------------------------------------------------------------------------------------
// Streams and capabilities

/// The rumor stream of signed peer advertisements ([`crate::ads::signed_peer_ad`]).
pub const STREAM_PEERS: &str = "peers";
/// The rumor stream of stored advertisements ([`crate::ads::stored_ad`], SPEC §6.2).
pub const STREAM_ADS: &str = "ads";
/// The prefix of a replicated space's rumor stream: `space:<name>`.
pub const STREAM_SPACE_PREFIX: &str = "space:";
/// The forward budget a rumor starts with (`hopsRemaining`), as every client sends it.
pub const RUMOR_HOPS: i32 = 6;

/// The capability of the `PIPE_DATA` a relay sends back to an origin when the next hop of a path
/// could not carry its frame ([`relay_signal_body`], SPEC §5.4).
pub const RELAY_SIGNAL_CAPABILITY: &str = "aspace:cap/relay-signal";
/// The reason [`relay_signal_body`] reports when the next hop is unreachable.
pub const RELAY_SIGNAL_UNREACHABLE: &str = "unreachable";
/// The push-sum aggregation capability ([`aggregate_frame`], SPEC §8).
pub const AGGREGATE_CAPABILITY: &str = "aspace:cap/aggregate";
/// The gossip-learning capability ([`learn_exchange`], SPEC §8).
pub const GOSSIP_LEARN_CAPABILITY: &str = "aspace:cap/gossip-learn";

// ---------------------------------------------------------------------------------------------
// Membership and gossip bodies

/// The `PING` body `{nonce}` (`Bodies.Ping` as older nodes send it, without the v0.1.17
/// piggyback fields).
pub fn ping_body(nonce: i64) -> Vec<u8> {
    let mut body = Map::with_capacity(1);
    body.insert("nonce", nonce);
    encode_map(&body)
}

/// The nonce of a `PING` (or `ACK`) body: an integer `nonce`, 0 when absent or null (Jackson's
/// default for the primitive `long`); `None` when the body is not a map or the nonce is not an
/// `i64`.
pub fn parse_ping(body: &[u8]) -> Option<i64> {
    let value = cbor::decode(body).ok()?;
    match value.as_map()?.get("nonce") {
        None | Some(Value::Null) => Some(0),
        Some(nonce) => nonce.as_i64(),
    }
}

/// The `ACK` body `{nonce, onBehalf: null}` answering a `PING` with its nonce.
pub fn ack_body(nonce: i64) -> Vec<u8> {
    let mut body = Map::with_capacity(2);
    body.insert("nonce", nonce);
    body.insert("onBehalf", Value::Null);
    encode_map(&body)
}

/// The `RUMOR` body `{streamId, itemId, hopsRemaining, payload}` (`Bodies.Rumor`): one item on a
/// named stream, with the forward budget that each hop decrements ([`RUMOR_HOPS`] to start).
pub fn rumor_body(stream_id: &str, item_id: &str, hops: i32, payload: &[u8]) -> Vec<u8> {
    let mut body = Map::with_capacity(4);
    body.insert("streamId", stream_id);
    body.insert("itemId", item_id);
    body.insert("hopsRemaining", hops);
    body.insert("payload", payload);
    encode_map(&body)
}

/// A received `RUMOR` body ([`parse_rumor`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rumor {
    /// The stream: [`STREAM_PEERS`], [`STREAM_ADS`], `space:<name>`, a revocation stream.
    pub stream_id: String,
    /// The item's unique id; empty when the sender sent none.
    pub item_id: String,
    /// The remaining forward budget; 0 when the sender sent none.
    pub hops_remaining: i64,
    /// The stream-specific payload; empty when the sender sent none (Python's
    /// `rumor.get("payload") or b""`).
    pub payload: Vec<u8>,
}

/// The rumor a `RUMOR` body carries: `streamId` must be text; `itemId` text, `hopsRemaining` an
/// `i64`, and `payload` bytes, each absent or null read as empty or 0. Any other shape is `None`.
pub fn parse_rumor(body: &[u8]) -> Option<Rumor> {
    let value = cbor::decode(body).ok()?;
    let rumor = value.as_map()?;
    Some(Rumor {
        stream_id: rumor.get("streamId")?.as_str()?.to_owned(),
        item_id: optional(rumor, "itemId", Value::as_str)?
            .unwrap_or_default()
            .to_owned(),
        hops_remaining: optional(rumor, "hopsRemaining", Value::as_i64)?.unwrap_or(0),
        payload: optional(rumor, "payload", Value::as_bytes)?
            .unwrap_or_default()
            .to_vec(),
    })
}

/// The `DIGEST` body `{digests}` (`Bodies.Digest` as older nodes send it): the asker's digest
/// per stream, a stream name to bytes map written in canonical order. An empty digest for a
/// stream asks for all of it.
pub fn digest_body(digests: &Map) -> Vec<u8> {
    let mut body = Map::with_capacity(1);
    body.insert("digests", cbor::canonical_map(digests));
    encode_map(&body)
}

/// The `digests` map of a `DIGEST` body, or `None` when the body is not a map or its `digests`
/// is not a map. Values are not judged.
pub fn parse_digest(body: &[u8]) -> Option<Map> {
    cbor::decode(body)
        .ok()?
        .into_map()?
        .remove("digests")?
        .into_map()
}

/// The `PULL_RESP` body `{deltas}` (`Bodies.PullResp`): the opaque delta bytes per stream the
/// asker lacked, written in canonical order.
pub fn pull_resp_body(deltas: &Map) -> Vec<u8> {
    let mut body = Map::with_capacity(1);
    body.insert("deltas", cbor::canonical_map(deltas));
    encode_map(&body)
}

/// The `deltas` map of a `PULL_RESP` body; an absent or null `deltas` is the empty map (Python's
/// `resp.get("deltas") or {}`). `None` when the body is not a map or `deltas` is not a map.
pub fn parse_pull_resp(body: &[u8]) -> Option<Map> {
    let mut resp = cbor::decode(body).ok()?.into_map()?;
    match resp.remove("deltas") {
        None | Some(Value::Null) => Some(Map::new()),
        Some(deltas) => deltas.into_map(),
    }
}

/// The `CHANNEL_HELLO` body `{acceptsBare, attestedRemote}` (`Bodies.ChannelHello`, SPEC §5.6):
/// this peer accepts channel-attested frames on the connection whose remote end it attested as
/// `attested_remote`.
pub fn channel_hello_body(accepts_bare: bool, attested_remote: &str) -> Vec<u8> {
    let mut body = Map::with_capacity(2);
    body.insert("acceptsBare", accepts_bare);
    body.insert("attestedRemote", attested_remote);
    encode_map(&body)
}

/// A received `CHANNEL_HELLO` body ([`parse_channel_hello`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHello {
    /// Whether the sender accepts channel-attested frames on this connection.
    pub accepts_bare: bool,
    /// The PeerID the sender's transport attested for this end; the announcement counts only
    /// when it names the receiver.
    pub attested_remote: String,
}

/// The announcement a `CHANNEL_HELLO` body carries: a boolean `acceptsBare` and a text
/// `attestedRemote`, or `None`.
pub fn parse_channel_hello(body: &[u8]) -> Option<ChannelHello> {
    let value = cbor::decode(body).ok()?;
    let hello = value.as_map()?;
    Some(ChannelHello {
        accepts_bare: hello.get("acceptsBare")?.as_bool()?,
        attested_remote: hello.get("attestedRemote")?.as_str()?.to_owned(),
    })
}

// ---------------------------------------------------------------------------------------------
// Capability frames and relays

/// The `PIPE_DATA` body `{capability, payload}`: one capability frame (`CapabilityPipes.send`).
pub fn pipe_data_body(capability: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Map::with_capacity(2);
    body.insert("capability", capability);
    body.insert("payload", payload);
    encode_map(&body)
}

/// A received `PIPE_DATA` body ([`parse_pipe_data`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeData {
    /// The capability the frame belongs to.
    pub capability: String,
    /// The capability's payload; empty when the sender sent none.
    pub payload: Vec<u8>,
}

/// The capability frame a `PIPE_DATA` body carries: a text `capability` and a byte `payload`
/// (absent or null read as empty), or `None`.
pub fn parse_pipe_data(body: &[u8]) -> Option<PipeData> {
    let value = cbor::decode(body).ok()?;
    let pipe = value.as_map()?;
    Some(PipeData {
        capability: pipe.get("capability")?.as_str()?.to_owned(),
        payload: optional(pipe, "payload", Value::as_bytes)?
            .unwrap_or_default()
            .to_vec(),
    })
}

/// The `RELAY_FRAME` body (`Bodies.RelayFrame`, SPEC §5.4): the origin's complete signed `frame`
/// for `target`, carried by the relay the envelope is addressed to.
///
/// With `path` (the relays to traverse, v0.1.23) the body appends `path` and `hop`, the index of
/// the relay this envelope is addressed to (`None` writes 0); without one both are absent, the
/// one-hop form, and `hop` is ignored.
pub fn relay_frame_body(
    target: &str,
    frame: &[u8],
    path: Option<&[&str]>,
    hop: Option<u32>,
) -> Vec<u8> {
    let mut body = Map::with_capacity(4);
    body.insert("target", target);
    body.insert("frame", frame);
    if let Some(path) = path {
        body.insert("path", text_array(path));
        body.insert("hop", hop.unwrap_or(0));
    }
    encode_map(&body)
}

/// A received `RELAY_FRAME` body ([`parse_relay_frame`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    /// The peer the inner frame is for.
    pub target: String,
    /// The origin's complete signed frame, verbatim.
    pub frame: Vec<u8>,
    /// The relays to traverse; `None` in the one-hop form.
    pub path: Option<Vec<String>>,
    /// The index in `path` of the relay the envelope was addressed to; `None` without a path.
    pub hop: Option<u32>,
}

impl RelayFrame {
    /// The same frame addressed to the next relay on its path (`RelayFrame.nextHop`): `hop`
    /// plus one, saturating; unchanged in the one-hop form.
    pub fn next_hop(&self) -> RelayFrame {
        RelayFrame {
            hop: self.hop.map(|hop| hop.saturating_add(1)),
            ..self.clone()
        }
    }

    /// The body of this relay frame ([`relay_frame_body`]).
    pub fn body(&self) -> Vec<u8> {
        let path: Option<Vec<&str>> = self
            .path
            .as_ref()
            .map(|path| path.iter().map(String::as_str).collect());
        relay_frame_body(&self.target, &self.frame, path.as_deref(), self.hop)
    }
}

/// The relay frame a `RELAY_FRAME` body carries: a text `target`, a byte `frame`, and
/// optionally a `path` of text and a non-negative `hop` (each absent or null read as `None`),
/// or `None`.
pub fn parse_relay_frame(body: &[u8]) -> Option<RelayFrame> {
    let value = cbor::decode(body).ok()?;
    let relay = value.as_map()?;
    let path = match optional(relay, "path", Value::as_array)? {
        None => None,
        Some(items) => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        ),
    };
    let hop = match optional(relay, "hop", Value::as_i128)? {
        None => None,
        Some(hop) => Some(u32::try_from(hop).ok()?),
    };
    Some(RelayFrame {
        target: relay.get("target")?.as_str()?.to_owned(),
        frame: relay.get("frame")?.as_bytes()?.to_vec(),
        path,
        hop,
    })
}

/// The `PIPE_DATA` body a relay sends back to an origin when the next hop of a path could not
/// carry its frame (`aspace:cap/relay-signal`, SPEC §5.4): capability [`RELAY_SIGNAL_CAPABILITY`]
/// with the payload `{target, failedHop, reason}` (`reason` is [`RELAY_SIGNAL_UNREACHABLE`] for
/// an unreachable hop).
pub fn relay_signal_body(target: &str, failed_hop: &str, reason: &str) -> Vec<u8> {
    let mut signal = Map::with_capacity(3);
    signal.insert("target", target);
    signal.insert("failedHop", failed_hop);
    signal.insert("reason", reason);
    pipe_data_body(RELAY_SIGNAL_CAPABILITY, &encode_map(&signal))
}

/// A received relay signal ([`parse_relay_signal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySignal {
    /// The peer the undelivered frame was for.
    pub target: String,
    /// The relay that could not carry it on.
    pub failed_hop: String,
    /// Why, e.g. [`RELAY_SIGNAL_UNREACHABLE`].
    pub reason: String,
}

/// The signal a relay-signal payload (the `payload` of a [`RELAY_SIGNAL_CAPABILITY`] pipe frame)
/// carries: text `target`, `failedHop`, and `reason`, or `None`.
pub fn parse_relay_signal(payload: &[u8]) -> Option<RelaySignal> {
    let value = cbor::decode(payload).ok()?;
    let signal = value.as_map()?;
    Some(RelaySignal {
        target: signal.get("target")?.as_str()?.to_owned(),
        failed_hop: signal.get("failedHop")?.as_str()?.to_owned(),
        reason: signal.get("reason")?.as_str()?.to_owned(),
    })
}

// ---------------------------------------------------------------------------------------------
// Blocks

/// The id of a block (SPEC §7.1, `BlockExchange.cidOf`): multibase base58btc of SHA-256 over
/// the bytes.
pub fn block_cid(data: &[u8]) -> String {
    ids::derive_id(data)
}

/// The `BLOCK_WANT` body `{cid}`: one block by id.
pub fn block_want_body(cid: &str) -> Vec<u8> {
    let mut body = Map::with_capacity(1);
    body.insert("cid", cid);
    encode_map(&body)
}

/// The id a `BLOCK_WANT` body asks for: a text `cid`, or `None`.
pub fn parse_block_want(body: &[u8]) -> Option<String> {
    cbor::decode(body)
        .ok()?
        .into_map()?
        .remove("cid")?
        .into_text()
}

/// The `BLOCK` body `{cid, bytes}`: the bytes under their id.
pub fn block_body(cid: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Map::with_capacity(2);
    body.insert("cid", cid);
    body.insert("bytes", data);
    encode_map(&body)
}

/// A received `BLOCK` body ([`parse_block`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The id the sender claims for the bytes.
    pub cid: String,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Block {
    /// Whether the bytes hash to the claimed id ([`block_cid`]); a receiver keeps a block only
    /// when they do (and only one it asked for).
    pub fn verifies(&self) -> bool {
        block_cid(&self.bytes) == self.cid
    }
}

/// The block a `BLOCK` body carries: a text `cid` and byte `bytes`, or `None`. The id is not
/// checked here ([`Block::verifies`]).
pub fn parse_block(body: &[u8]) -> Option<Block> {
    let mut block = cbor::decode(body).ok()?.into_map()?;
    Some(Block {
        cid: block.remove("cid")?.into_text()?,
        bytes: block.remove("bytes")?.into_bytes()?,
    })
}

// ---------------------------------------------------------------------------------------------
// Join by GroupID (§9)

/// The `GROUP_AD_WANT` envelope (SPEC §9, §10.1): the wanted group in `group` and an empty body.
/// A real request travels unaddressed (`to` `None`) because the seed's PeerID is unknown until it
/// answers; the golden vector addresses it to exercise the destination binding.
pub fn group_ad_want_envelope(group: &str, from: &str, stamp: &str, to: Option<&str>) -> Map {
    envelope(group, KIND_GROUP_AD_WANT, from, stamp, &[], to)
}

/// The `GROUP_AD` body: the `SignedGroupAdvertisement` `{advertisement, founderPublicKey,
/// signature}` (as [`crate::founding::found_group`] returns it) re-written in that order, or
/// `None` when one of the three is missing.
pub fn group_ad_body(signed: &Map) -> Option<Vec<u8>> {
    let mut body = Map::with_capacity(3);
    for field in ["advertisement", "founderPublicKey", "signature"] {
        body.insert(field, signed.get(field)?.clone());
    }
    Some(encode_map(&body))
}

// ---------------------------------------------------------------------------------------------
// Capability payloads (§8)

/// The aggregate Roster's participant token (SPEC §8 `aspace:cap/aggregate`,
/// `PushSumAggregate.tokenOf`): the first 8 bytes of SHA-256 over the PeerID's UTF-8, read
/// big-endian as a signed `i64`. A negative token encodes as a CBOR negative integer.
pub fn aggregate_roster_token(peer_id: &str) -> i64 {
    let digest = crypto::port().sha256(peer_id.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(first)
}

/// The four fields of the aggregate `Frame` union, in Java field order.
const AGGREGATE_FIELDS: [&str; 4] = ["share", "extremum", "histogram", "roster"];

/// One variant of the `aspace:cap/aggregate` `Frame` union (SPEC §8): the Java records
/// `Share`, `Extremum`, `Histogram`, and `Roster` of `PushSumAggregate`. Every number but a
/// roster token is a Java `double` and so always encodes as a 64-bit float.
#[derive(Debug, Clone, PartialEq)]
pub enum Aggregate {
    /// `Share {epochId, value, weight}`: a push-sum share.
    Share {
        /// The aggregation epoch.
        epoch_id: String,
        /// The value share.
        value: f64,
        /// The weight share.
        weight: f64,
    },
    /// `Extremum {epochId, max, value}`: the running maximum (or minimum).
    Extremum {
        /// The aggregation epoch.
        epoch_id: String,
        /// Whether this is a maximum (`true`) or a minimum.
        max: bool,
        /// The extremum.
        value: f64,
    },
    /// `Histogram {epochId, lo, hi, buckets}`: a push-sum histogram over `[lo, hi]`.
    Histogram {
        /// The aggregation epoch.
        epoch_id: String,
        /// The low edge.
        lo: f64,
        /// The high edge.
        hi: f64,
        /// The bucket shares.
        buckets: Vec<f64>,
    },
    /// `Roster {epochId, members}`: the participants' tokens ([`aggregate_roster_token`]).
    Roster {
        /// The aggregation epoch.
        epoch_id: String,
        /// The member tokens.
        members: Vec<i64>,
    },
}

impl Aggregate {
    /// The union field this variant fills: `share`, `extremum`, `histogram`, or `roster`.
    pub fn field(&self) -> &'static str {
        match self {
            Aggregate::Share { .. } => "share",
            Aggregate::Extremum { .. } => "extremum",
            Aggregate::Histogram { .. } => "histogram",
            Aggregate::Roster { .. } => "roster",
        }
    }

    /// The variant's record in Java field order.
    fn record(&self) -> Map {
        let mut record = Map::with_capacity(4);
        match self {
            Aggregate::Share {
                epoch_id,
                value,
                weight,
            } => {
                record.insert("epochId", epoch_id);
                record.insert("value", *value);
                record.insert("weight", *weight);
            }
            Aggregate::Extremum {
                epoch_id,
                max,
                value,
            } => {
                record.insert("epochId", epoch_id);
                record.insert("max", *max);
                record.insert("value", *value);
            }
            Aggregate::Histogram {
                epoch_id,
                lo,
                hi,
                buckets,
            } => {
                record.insert("epochId", epoch_id);
                record.insert("lo", *lo);
                record.insert("hi", *hi);
                record.insert(
                    "buckets",
                    buckets.iter().copied().map(Value::from).collect::<Vec<_>>(),
                );
            }
            Aggregate::Roster { epoch_id, members } => {
                record.insert("epochId", epoch_id);
                record.insert(
                    "members",
                    members.iter().copied().map(Value::from).collect::<Vec<_>>(),
                );
            }
        }
        record
    }

    /// The variant a decoded aggregate `Frame` carries: exactly one of `share`, `extremum`,
    /// `histogram`, `roster` is a map of the right shape and the other three are absent or
    /// null. Integers are accepted where a double is expected (Jackson reads them so). `None`
    /// for any other shape.
    pub fn from_frame(frame: &Value) -> Option<Aggregate> {
        let frame = frame.as_map()?;
        let mut chosen = None;
        for field in AGGREGATE_FIELDS {
            match frame.get(field) {
                None | Some(Value::Null) => {}
                Some(Value::Map(record)) if chosen.is_none() => chosen = Some((field, record)),
                Some(_) => return None,
            }
        }
        let (field, record) = chosen?;
        let epoch_id = record.get("epochId")?.as_str()?.to_owned();
        let double = |name: &str| record.get(name).and_then(Value::as_f64);
        Some(match field {
            "share" => Aggregate::Share {
                epoch_id,
                value: double("value")?,
                weight: double("weight")?,
            },
            "extremum" => Aggregate::Extremum {
                epoch_id,
                max: record.get("max")?.as_bool()?,
                value: double("value")?,
            },
            "histogram" => Aggregate::Histogram {
                epoch_id,
                lo: double("lo")?,
                hi: double("hi")?,
                buckets: record
                    .get("buckets")?
                    .as_array()?
                    .iter()
                    .map(Value::as_f64)
                    .collect::<Option<_>>()?,
            },
            _ => Aggregate::Roster {
                epoch_id,
                members: record
                    .get("members")?
                    .as_array()?
                    .iter()
                    .map(Value::as_i64)
                    .collect::<Option<_>>()?,
            },
        })
    }
}

/// The `aspace:cap/aggregate` `PIPE_DATA` payload (SPEC §8): the `Frame` union
/// `{share, extremum, histogram, roster}` carrying `variant` in its field and null in the other
/// three. Encode it into a [`pipe_data_body`] under [`AGGREGATE_CAPABILITY`].
pub fn aggregate_frame(variant: &Aggregate) -> Map {
    let mut frame = Map::with_capacity(4);
    for field in AGGREGATE_FIELDS {
        frame.insert(field, Value::Null);
    }
    frame.insert(variant.field(), variant.record());
    frame
}

/// The gossip-learn exchange kind that offers a model.
pub const LEARN_OFFER: &str = "OFFER";
/// The gossip-learn exchange kind that accepts an offer with the accepter's model.
pub const LEARN_ACCEPT: &str = "ACCEPT";
/// The gossip-learn exchange kind that declines while busy.
pub const LEARN_BUSY: &str = "BUSY";

/// The gossip-learn content identifier (SPEC §8 `aspace:cap/gossip-learn`): multibase
/// base58btc of SHA-256 over the model's encoding, the derivation of `BlockExchange.cidOf`.
pub fn learn_content_id(encoding: &[u8]) -> String {
    ids::derive_id(encoding)
}

/// `WeightAveraging.encode`: a model vector as big-endian IEEE-754 doubles, no CBOR.
pub fn encode_model(weights: &[f64]) -> Vec<u8> {
    weights.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// `WeightAveraging.decode`: the model vector of an encoding, or `None` when its length is not a
/// multiple of 8.
pub fn decode_model(encoding: &[u8]) -> Option<Vec<f64>> {
    let (chunks, rest) = encoding.as_chunks::<8>();
    rest.is_empty()
        .then(|| chunks.iter().copied().map(f64::from_be_bytes).collect())
}

/// The `aspace:cap/gossip-learn` `PIPE_DATA` payload, `GossipLearner.Exchange` in field order:
/// `modelId`, `token`, `kind` ([`LEARN_OFFER`], [`LEARN_ACCEPT`], or [`LEARN_BUSY`]), `round`,
/// `inline` (the encoding when it fits the inline limit, else null), `cid` (the block-exchange
/// id when it does not, else null) (SPEC §8).
pub fn learn_exchange(
    model_id: &str,
    token: i64,
    kind: &str,
    round: i64,
    inline: Option<&[u8]>,
    cid: Option<&str>,
) -> Map {
    let mut exchange = Map::with_capacity(6);
    exchange.insert("modelId", model_id);
    exchange.insert("token", token);
    exchange.insert("kind", kind);
    exchange.insert("round", round);
    exchange.insert("inline", inline);
    exchange.insert("cid", cid);
    exchange
}

// ---------------------------------------------------------------------------------------------
// Helpers

/// A field that may be absent or null (`Ok(None)`) but otherwise must read as `T`: the outer
/// `Option` is `None` for a present value of the wrong type.
fn optional<'a, T>(
    map: &'a Map,
    key: &str,
    read: impl FnOnce(&'a Value) -> Option<T>,
) -> Option<Option<T>> {
    match map.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(value) => read(value).map(Some),
    }
}

/// A CBOR array of text.
fn text_array(items: &[&str]) -> Vec<Value> {
    items.iter().map(|item| Value::from(*item)).collect()
}
