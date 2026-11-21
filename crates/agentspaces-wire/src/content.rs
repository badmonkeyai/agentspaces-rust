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

//! The content swarm's forms (SPEC §8, annex G, annex I.1a; Python
//! `capabilities/content.py`): the `Manifest` and `Holding` records, the run-length bitfield, and
//! the level-1 messages, tags 1 to 11, each a CBOR map with the integer tag `t` first.
//!
//! [`decode`] reads a message the way every implementation reads it since v0.1.32: it peeks at
//! the tag, reads the body strictly under its annex I.1a schema ([`crate::schema`]), and checks
//! the bounds of §8. A message that fails is dropped and counted by the caller, and its sender
//! takes no strike. The level-2 forms (tag 12, sketches, `NODES.deltas`) are refused here, as a
//! level-1 member refuses them.

use crate::cbor::{self, Map, Value};
use crate::pdt::cid;
use crate::schema;

/// The capability type.
pub const CAPABILITY: &str = "aspace:cap/content-swarm";
/// The entry type of a manifest.
pub const MANIFEST_TYPE: &str = "ai.badmonkey.agentspaces.agent.content.Manifest#v1";
/// The entry type of a holding.
pub const HOLDING_TYPE: &str = "ai.badmonkey.agentspaces.agent.content.Holding#v1";
/// The record version.
pub const VERSION: i64 = 1;
/// A table rides inline up to this many pieces.
pub const INLINE_TABLE_PIECES: i64 = 64;
/// The bytes of a piece hash.
pub const HASH_BYTES: usize = 32;
/// The smallest piece.
pub const MIN_PIECE_SIZE: i64 = 64 * 1024;
/// The largest piece.
pub const MAX_PIECE_SIZE: i64 = 4 * 1024 * 1024;
/// The default piece.
pub const DEFAULT_PIECE_SIZE: i64 = 1024 * 1024;
/// A holding's bitfield above this many bytes is sent as null.
pub const MAX_HAVE_BYTES: usize = 8 * 1024;
/// The unit of a range.
pub const RANGE_UNIT: i64 = 64 * 1024;
/// The largest range.
pub const MAX_RANGE: i64 = 4 * 1024 * 1024;

/// `PIECE_WANT`.
pub const T_PIECE_WANT: i64 = 1;
/// `PIECE`.
pub const T_PIECE: i64 = 2;
/// `HAVE`.
pub const T_HAVE: i64 = 3;
/// `CANCEL`.
pub const T_CANCEL: i64 = 4;
/// `REJECT`.
pub const T_REJECT: i64 = 5;
/// `MANIFEST_WANT`.
pub const T_MANIFEST_WANT: i64 = 6;
/// `MANIFEST`.
pub const T_MANIFEST: i64 = 7;
/// `NODE_WANT`.
pub const T_NODE_WANT: i64 = 8;
/// `NODES`.
pub const T_NODES: i64 = 9;
/// `TREE_WANT`.
pub const T_TREE_WANT: i64 = 10;
/// `TREE_END`.
pub const T_TREE_END: i64 = 11;

/// `REJECT` reason: not held.
pub const REASON_NOT_HELD: i64 = 1;
/// `REJECT` reason: over the upload budget.
pub const REASON_OVER_BUDGET: i64 = 2;
/// `REJECT` reason: refused by policy (or sealing this holder cannot serve).
pub const REASON_POLICY: i64 = 3;
/// `REJECT` reason: unknown root.
pub const REASON_UNKNOWN_ROOT: i64 = 4;

/// `TREE_END` reason: the walk finished.
pub const END_DONE: i64 = 1;
/// `TREE_END` reason: the budget was reached.
pub const END_BUDGET: i64 = 2;
/// `TREE_END` reason: a `haves` root is not held.
pub const END_HAVES_NOT_HELD: i64 = 3;
/// `TREE_END` reason: the walk cap.
pub const END_WALK_CAP: i64 = 4;

/// At most this many CIDs in a `NODE_WANT` or a `NODES.missing`.
pub const MAX_WANT_CIDS: usize = 256;
/// At most this many bytes of nodes in a `NODES`.
pub const MAX_NODES_BYTES: usize = 4 * 1024 * 1024;
/// At most this many `haves` in a `TREE_WANT`.
pub const MAX_HAVES: usize = 64;
/// The largest `TREE_WANT` budget.
pub const MAX_TREE_BUDGET: i64 = 64 * 1024 * 1024;
/// At most this many CIDs in a `TREE_END` frontier.
pub const MAX_FRONTIER: usize = 1024;
/// A holder walks at most this many nodes for one `TREE_WANT`.
pub const MAX_TREE_WALK: usize = 100_000;

/// No sealing.
pub const SEALING_NONE: &str = "none";
/// Sealed under the group key.
pub const SEALING_GROUP_KEY: &str = "group-key";
/// Hashes over plaintext pieces.
pub const HASHING_PLAIN: &str = "plain";
/// Hashes over sealed pieces.
pub const HASHING_SEALED: &str = "sealed";
/// The flat piece table (an absent layout means it).
pub const LAYOUT_PIECES: &str = "pieces";
/// A blob tree.
pub const LAYOUT_TREE: &str = "tree";

fn int(v: i64) -> Value {
    Value::Int(i128::from(v))
}

fn opt_text(v: &Option<String>) -> Value {
    v.as_deref().map_or(Value::Null, Value::from)
}

fn opt_bytes(v: &Option<Vec<u8>>) -> Value {
    v.as_ref().map_or(Value::Null, |b| Value::Bytes(b.clone()))
}

fn texts(v: &[String]) -> Value {
    Value::Array(v.iter().map(Value::from).collect())
}

fn opt_texts(v: &Option<Vec<String>>) -> Value {
    v.as_ref().map_or(Value::Null, |t| texts(t))
}

fn text_map(v: &Option<Vec<(String, String)>>) -> Value {
    match v {
        None => Value::Null,
        Some(pairs) => {
            let mut m = Map::new();
            for (k, val) in pairs {
                m.insert(k.as_str(), val.as_str());
            }
            Value::Map(cbor::canonical_map(&m))
        }
    }
}

fn read_text(map: &Map, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_string)
}

fn read_opt_text(map: &Map, key: &str) -> Option<Option<String>> {
    match map.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(v) => v.as_str().map(|s| Some(s.to_string())),
    }
}

fn read_opt_bytes(map: &Map, key: &str) -> Option<Option<Vec<u8>>> {
    match map.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(v) => v.as_bytes().map(|b| Some(b.to_vec())),
    }
}

fn read_texts(map: &Map, key: &str) -> Option<Vec<String>> {
    map.get(key)?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn read_opt_texts(map: &Map, key: &str) -> Option<Option<Vec<String>>> {
    match map.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(_) => read_texts(map, key).map(Some),
    }
}

fn read_text_map(map: &Map, key: &str) -> Option<Option<Vec<(String, String)>>> {
    match map.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(v) => Some(Some(
            v.as_map()?
                .iter()
                .map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
                .collect::<Option<Vec<_>>>()?,
        )),
    }
}

/// The content root of a piece table: the raw-codec CIDv1 of its sha2-256.
pub fn content_root(table: &[u8]) -> String {
    cid::of(table, cid::RAW)
}

/// The number of pieces of `size` bytes at `piece_size`.
pub fn pieces_of(size: i64, piece_size: i64) -> i64 {
    if size <= 0 { 0 } else { (size + piece_size - 1) / piece_size }
}

/// The run-length bitfield of the pieces held: alternating runs of zeros and ones as unsigned
/// varints, 7 bits per byte, zeros first, from piece 0.
pub fn encode_have(held: &[bool]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut i, mut value) = (0, false);
    while i < held.len() {
        let mut run = 0u64;
        while i < held.len() && held[i] == value {
            run += 1;
            i += 1;
        }
        while run & !0x7F != 0 {
            out.push((run & 0x7F) as u8 | 0x80);
            run >>= 7;
        }
        out.push(run as u8);
        value = !value;
    }
    out
}

/// The pieces a bitfield states, out of `pieces`; every piece when it is null.
pub fn decode_have(data: Option<&[u8]>, pieces: usize) -> Vec<bool> {
    let Some(data) = data else {
        return vec![true; pieces];
    };
    let mut held = vec![false; pieces];
    let (mut pos, mut i, mut value) = (0, 0usize, false);
    while pos < data.len() && i < pieces {
        let (mut run, mut shift) = (0u64, 0u32);
        while pos < data.len() {
            let b = data[pos];
            pos += 1;
            if shift < 64 {
                run |= u64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        let end = pieces.min(i.saturating_add(usize::try_from(run).unwrap_or(usize::MAX)));
        if value {
            held[i..end].fill(true);
        }
        i = end;
        value = !value;
    }
    held
}

/// An artifact's manifest (annex G).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// 1.
    pub v: i64,
    /// The root CID.
    pub root: String,
    /// The bytes.
    pub size: i64,
    /// The piece size.
    pub piece_size: i64,
    /// The number of pieces.
    pub pieces: i64,
    /// The piece hashes, inline up to 64 pieces.
    pub table: Option<Vec<u8>>,
    /// The block CID of a larger table.
    pub table_ref: Option<String>,
    /// Reserved (null).
    pub table_refs: Option<Vec<String>>,
    /// A display name, at most 256 bytes.
    pub name: Option<String>,
    /// The media type.
    pub media_type: Option<String>,
    /// `none` or `group-key`.
    pub sealing: String,
    /// The key epoch when sealed.
    pub key_epoch: Option<i64>,
    /// `plain` or `sealed`.
    pub hashing: String,
    /// The first publisher's PeerID.
    pub origin: String,
    /// Epoch milliseconds.
    pub created: i64,
    /// Attributes, at most 32 entries and 4 KiB.
    pub attrs: Option<Vec<(String, String)>>,
    /// `pieces` (absent) or `tree`.
    pub layout: Option<String>,
}

impl Manifest {
    /// The record as a CBOR value, fields in declared order.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("v", int(self.v));
        m.insert("root", self.root.as_str());
        m.insert("size", int(self.size));
        m.insert("pieceSize", int(self.piece_size));
        m.insert("pieces", int(self.pieces));
        m.insert("table", opt_bytes(&self.table));
        m.insert("tableRef", opt_text(&self.table_ref));
        m.insert("tableRefs", opt_texts(&self.table_refs));
        m.insert("name", opt_text(&self.name));
        m.insert("mediaType", opt_text(&self.media_type));
        m.insert("sealing", self.sealing.as_str());
        m.insert("keyEpoch", self.key_epoch.map_or(Value::Null, int));
        m.insert("hashing", self.hashing.as_str());
        m.insert("origin", self.origin.as_str());
        m.insert("created", int(self.created));
        m.insert("attrs", text_map(&self.attrs));
        if let Some(layout) = &self.layout {
            m.insert("layout", layout.as_str());
        }
        Value::Map(m)
    }

    /// The record's bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// The record the bytes hold under its schema, or `None`.
    pub fn decode(bytes: &[u8]) -> Option<Manifest> {
        Self::from_map(&schema::decode_map(bytes, "Manifest")?)
    }

    /// The record a decoded map holds.
    pub fn from_map(m: &Map) -> Option<Manifest> {
        let i = |k: &str| m.get(k).and_then(Value::as_i64);
        Some(Manifest {
            v: i("v")?,
            root: read_text(m, "root")?,
            size: i("size")?,
            piece_size: i("pieceSize")?,
            pieces: i("pieces")?,
            table: read_opt_bytes(m, "table")?,
            table_ref: read_opt_text(m, "tableRef")?,
            table_refs: read_opt_texts(m, "tableRefs")?,
            name: read_opt_text(m, "name")?,
            media_type: read_opt_text(m, "mediaType")?,
            sealing: read_text(m, "sealing")?,
            key_epoch: match m.get("keyEpoch") {
                None | Some(Value::Null) => None,
                Some(v) => Some(v.as_i64()?),
            },
            hashing: read_text(m, "hashing")?,
            origin: read_text(m, "origin")?,
            created: i("created")?,
            attrs: read_text_map(m, "attrs")?,
            layout: read_opt_text(m, "layout")?,
        })
    }

    /// The first broken invariant of annex G, or `None`. A `tree` manifest names a blob tree, so
    /// it may carry no table, and its table is not over its root.
    pub fn violation(&self) -> Option<String> {
        if self.v != VERSION {
            return Some(format!("unsupported manifest version {}", self.v));
        }
        let ps = self.piece_size;
        if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&ps) || ps & (ps - 1) != 0 {
            return Some("pieceSize is not a power of two in [64 KiB, 4 MiB]".to_string());
        }
        if self.size < 0 || self.pieces != pieces_of(self.size, ps) {
            return Some("pieces does not match ceil(size / pieceSize)".to_string());
        }
        let tree = self.layout.as_deref() == Some(LAYOUT_TREE);
        match (&self.table, &self.table_ref) {
            (Some(_), Some(_)) => return Some("at most one of table and tableRef may be present".to_string()),
            (None, None) if !tree => return Some("exactly one of table and tableRef must be present".to_string()),
            _ => {}
        }
        if let Some(table) = &self.table {
            if self.pieces > INLINE_TABLE_PIECES {
                return Some("inline table above the inline bound".to_string());
            }
            if table.len() as i64 != self.pieces * HASH_BYTES as i64 {
                return Some("table length does not match pieces".to_string());
            }
            if !tree && content_root(table) != self.root {
                return Some("table does not hash to the root".to_string());
            }
        }
        if self.sealing != SEALING_NONE && self.sealing != SEALING_GROUP_KEY {
            return Some("unknown sealing".to_string());
        }
        if self.hashing != HASHING_PLAIN && self.hashing != HASHING_SEALED {
            return Some("unknown hashing".to_string());
        }
        if let Some(layout) = &self.layout
            && layout != LAYOUT_PIECES
            && layout != LAYOUT_TREE
        {
            return Some(format!("unknown layout {layout}"));
        }
        if tree && cid::codec_of(&self.root) != Some(cid::DAG_CBOR) {
            return Some("a tree manifest's root is a dag-cbor CID".to_string());
        }
        if !cid::is_cid(&self.root) {
            return Some("root is not a content root".to_string());
        }
        if self.name.as_ref().is_some_and(|n| n.len() > 256) {
            return Some("name longer than 256 bytes".to_string());
        }
        if let Some(attrs) = &self.attrs
            && (attrs.len() > 32 || attrs.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > 4096)
        {
            return Some("attrs above 32 entries or 4 KiB".to_string());
        }
        None
    }
}

/// A holder's statement that it holds a root (annex G).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holding {
    /// 1.
    pub v: i64,
    /// The root.
    pub root: String,
    /// The holder's PeerID.
    pub holder: String,
    /// Whether it holds every piece (or every node, for a tree).
    pub complete: bool,
    /// The bitfield, null when complete or above 8 KiB.
    pub have: Option<Vec<u8>>,
    /// The pieces held, or the nodes held under a tree root.
    pub count: i64,
    /// The relays the holder is attached to.
    pub via: Option<Vec<String>>,
    /// Cost hints.
    pub cost: Option<Vec<(String, String)>>,
}

impl Holding {
    /// A complete holding of a tree root with `count` nodes.
    pub fn complete_tree(root: &str, holder: &str, count: i64, via: Option<Vec<String>>) -> Holding {
        Holding {
            v: VERSION,
            root: root.to_string(),
            holder: holder.to_string(),
            complete: true,
            have: None,
            count,
            via,
            cost: None,
        }
    }

    /// The record as a CBOR value, fields in declared order.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("v", int(self.v));
        m.insert("root", self.root.as_str());
        m.insert("holder", self.holder.as_str());
        m.insert("complete", self.complete);
        m.insert("have", opt_bytes(&self.have));
        m.insert("count", int(self.count));
        m.insert("via", opt_texts(&self.via));
        m.insert("cost", text_map(&self.cost));
        Value::Map(m)
    }

    /// The record's bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// The tags a holding entry carries: `root` and `holder`.
    pub fn tags(&self) -> Map {
        let mut tags = Map::new();
        tags.insert("root", self.root.as_str());
        tags.insert("holder", self.holder.as_str());
        cbor::canonical_map(&tags)
    }

    /// The record the bytes hold under its schema, or `None`.
    pub fn decode(bytes: &[u8]) -> Option<Holding> {
        Self::from_map(&schema::decode_map(bytes, "Holding")?)
    }

    /// The record a decoded map holds.
    pub fn from_map(m: &Map) -> Option<Holding> {
        Some(Holding {
            v: m.get("v")?.as_i64()?,
            root: read_text(m, "root")?,
            holder: read_text(m, "holder")?,
            complete: m.get("complete")?.as_bool()?,
            have: read_opt_bytes(m, "have")?,
            count: m.get("count")?.as_i64()?,
            via: read_opt_texts(m, "via")?,
            cost: read_text_map(m, "cost")?,
        })
    }
}

/// One level-1 content-swarm message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Tag 1: ask a holder for a range of a piece.
    PieceWant { root: String, index: i64, offset: i64, length: i64, req: i64 },
    /// Tag 2: a range of a piece.
    Piece { root: String, index: i64, offset: i64, bytes: Vec<u8>, req: i64 },
    /// Tag 3: what the sender now holds of a root.
    Have { root: String, have: Option<Vec<u8>>, complete: bool },
    /// Tag 4: withdraw a request.
    Cancel { root: String, index: i64, req: i64 },
    /// Tag 5: a refusal; `index` -1 answers a tree request.
    Reject { root: String, index: i64, reason: i64 },
    /// Tag 6: ask for a manifest.
    ManifestWant { root: String },
    /// Tag 7: a manifest's record bytes.
    Manifest { root: String, record: Vec<u8> },
    /// Tag 8: ask for nodes by CID.
    NodeWant { req: i64, cids: Vec<String> },
    /// Tag 9: nodes (plaintext) and the CIDs the holder lacks; `sealed`/`epoch` in group-key mode.
    Nodes { req: i64, nodes: Option<Vec<Vec<u8>>>, sealed: Option<Vec<u8>>, epoch: Option<i64>, missing: Option<Vec<String>> },
    /// Tag 10: ask for a tree breadth first from `root`, pruned under `haves`.
    TreeWant { req: i64, root: String, haves: Option<Vec<String>>, budget: i64 },
    /// Tag 11: the end of a tree answer.
    TreeEnd { req: i64, frontier: Vec<String>, reason: i64 },
}

#[allow(missing_docs)]
impl Message {
    /// The message's tag.
    pub fn tag(&self) -> i64 {
        match self {
            Message::PieceWant { .. } => T_PIECE_WANT,
            Message::Piece { .. } => T_PIECE,
            Message::Have { .. } => T_HAVE,
            Message::Cancel { .. } => T_CANCEL,
            Message::Reject { .. } => T_REJECT,
            Message::ManifestWant { .. } => T_MANIFEST_WANT,
            Message::Manifest { .. } => T_MANIFEST,
            Message::NodeWant { .. } => T_NODE_WANT,
            Message::Nodes { .. } => T_NODES,
            Message::TreeWant { .. } => T_TREE_WANT,
            Message::TreeEnd { .. } => T_TREE_END,
        }
    }

    /// The message as a CBOR value, `t` first and fields in declared order.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("t", int(self.tag()));
        match self {
            Message::PieceWant { root, index, offset, length, req } => {
                m.insert("root", root.as_str());
                m.insert("index", int(*index));
                m.insert("offset", int(*offset));
                m.insert("length", int(*length));
                m.insert("req", int(*req));
            }
            Message::Piece { root, index, offset, bytes, req } => {
                m.insert("root", root.as_str());
                m.insert("index", int(*index));
                m.insert("offset", int(*offset));
                m.insert("bytes", Value::Bytes(bytes.clone()));
                m.insert("req", int(*req));
            }
            Message::Have { root, have, complete } => {
                m.insert("root", root.as_str());
                m.insert("have", opt_bytes(have));
                m.insert("complete", *complete);
            }
            Message::Cancel { root, index, req } => {
                m.insert("root", root.as_str());
                m.insert("index", int(*index));
                m.insert("req", int(*req));
            }
            Message::Reject { root, index, reason } => {
                m.insert("root", root.as_str());
                m.insert("index", int(*index));
                m.insert("reason", int(*reason));
            }
            Message::ManifestWant { root } => {
                m.insert("root", root.as_str());
            }
            Message::Manifest { root, record } => {
                m.insert("root", root.as_str());
                m.insert("record", Value::Bytes(record.clone()));
            }
            Message::NodeWant { req, cids } => {
                m.insert("req", int(*req));
                m.insert("cids", texts(cids));
            }
            Message::Nodes { req, nodes, sealed, epoch, missing } => {
                m.insert("req", int(*req));
                m.insert(
                    "nodes",
                    nodes.as_ref().map_or(Value::Null, |n| Value::Array(n.iter().map(|b| Value::Bytes(b.clone())).collect())),
                );
                m.insert("sealed", opt_bytes(sealed));
                m.insert("epoch", epoch.map_or(Value::Null, int));
                m.insert("missing", opt_texts(missing));
            }
            Message::TreeWant { req, root, haves, budget } => {
                m.insert("req", int(*req));
                m.insert("root", root.as_str());
                m.insert("haves", opt_texts(haves));
                m.insert("budget", int(*budget));
                m.insert("sketch", Value::Null);
            }
            Message::TreeEnd { req, frontier, reason } => {
                m.insert("req", int(*req));
                m.insert("frontier", texts(frontier));
                m.insert("reason", int(*reason));
            }
        }
        Value::Map(m)
    }

    /// The message's bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// The first bound of §8 the message breaks, or `None`.
    pub fn violation(&self) -> Option<String> {
        let cid_ok = |c: &str| cid::is_cid(c);
        match self {
            Message::PieceWant { root, index, offset, length, .. } => {
                if *index < 0 || *offset < 0 || *length <= 0 || *length > MAX_RANGE {
                    return Some("piece range out of bounds".to_string());
                }
                if offset % RANGE_UNIT != 0 {
                    return Some("range offset not aligned to 64 KiB".to_string());
                }
                (!cid_ok(root)).then(|| "root is not a CID".to_string())
            }
            Message::Piece { index, offset, bytes, .. } => {
                (*index < 0 || *offset < 0 || bytes.len() as i64 > MAX_RANGE).then(|| "piece out of bounds".to_string())
            }
            Message::Have { have, .. } => {
                have.as_ref().is_some_and(|h| h.len() > MAX_HAVE_BYTES).then(|| "bitfield above 8 KiB".to_string())
            }
            Message::Reject { reason, .. } => (!(1..=4).contains(reason)).then(|| format!("unknown reason {reason}")),
            Message::NodeWant { cids, .. } => {
                if cids.is_empty() || cids.len() > MAX_WANT_CIDS {
                    return Some(format!("NODE_WANT of {} CIDs; 1 to {MAX_WANT_CIDS}", cids.len()));
                }
                (!cids.iter().all(|c| cid_ok(c))).then(|| "NODE_WANT names a non-CID".to_string())
            }
            Message::Nodes { nodes, sealed, missing, .. } => {
                let bytes = nodes.as_ref().map_or(0, |n| n.iter().map(Vec::len).sum()) + sealed.as_ref().map_or(0, Vec::len);
                if bytes > MAX_NODES_BYTES {
                    return Some("NODES above 4 MiB".to_string());
                }
                if nodes.is_some() == sealed.is_some() {
                    return Some("NODES carries exactly one of nodes and sealed".to_string());
                }
                if missing.as_ref().is_some_and(|m| m.len() > MAX_WANT_CIDS || !m.iter().all(|c| cid_ok(c))) {
                    return Some("NODES.missing out of bounds".to_string());
                }
                None
            }
            Message::TreeWant { root, haves, budget, .. } => {
                if !cid_ok(root) {
                    return Some("TREE_WANT root is not a CID".to_string());
                }
                if *budget <= 0 || *budget > MAX_TREE_BUDGET {
                    return Some("TREE_WANT budget outside (0, 64 MiB]".to_string());
                }
                haves
                    .as_ref()
                    .is_some_and(|h| h.len() > MAX_HAVES || !h.iter().all(|c| cid_ok(c)))
                    .then(|| "TREE_WANT haves out of bounds".to_string())
            }
            Message::TreeEnd { frontier, reason, .. } => {
                if frontier.len() > MAX_FRONTIER || !frontier.iter().all(|c| cid_ok(c)) {
                    return Some("TREE_END frontier out of bounds".to_string());
                }
                (!(1..=4).contains(reason)).then(|| format!("unknown TREE_END reason {reason}"))
            }
            _ => None,
        }
    }
}

/// Why a message was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    /// The bytes hold no map with an integer `t`.
    NoTag,
    /// A tag this member does not read (tag 12 and above, at level 1).
    UnknownTag(i64),
    /// The body breaks its annex I.1a schema.
    Undecodable(i64),
    /// The body breaks a bound of §8.
    OutOfBounds(i64, String),
}

impl Dropped {
    /// Whether the counter is `pieceMessagesDropped` (tags 1 to 7) rather than
    /// `treeMessagesDropped`.
    pub fn is_piece_message(&self) -> bool {
        match self {
            Dropped::Undecodable(t) | Dropped::OutOfBounds(t, _) => (1..=7).contains(t),
            _ => false,
        }
    }
}

/// The tag of a message, peeked before the strict read.
pub fn peek_tag(bytes: &[u8]) -> Option<i64> {
    // an indefinite map whose first key is "t" and whose value is a small integer
    if bytes.len() < 4 || bytes[0] != 0xBF || bytes[1] != 0x61 || bytes[2] != b't' {
        return None;
    }
    match bytes[3] {
        b @ 0..=23 => Some(i64::from(b)),
        24 => bytes.get(4).map(|b| i64::from(*b)),
        _ => None,
    }
}

/// Reads one message strictly under its schema and the bounds of §8.
pub fn decode(bytes: &[u8]) -> Result<Message, Dropped> {
    let tag = peek_tag(bytes).ok_or(Dropped::NoTag)?;
    let name = match tag {
        T_PIECE_WANT => "Messages.PieceWant",
        T_PIECE => "Messages.Piece",
        T_HAVE => "Messages.Have",
        T_CANCEL => "Messages.Cancel",
        T_REJECT => "Messages.Reject",
        T_MANIFEST_WANT => "Messages.ManifestWant",
        T_MANIFEST => "Messages.ManifestReply",
        T_NODE_WANT => "Messages.NodeWant",
        T_NODES => "Messages.Nodes",
        T_TREE_WANT => "Messages.TreeWant",
        T_TREE_END => "Messages.TreeEnd",
        other => return Err(Dropped::UnknownTag(other)),
    };
    let m = schema::decode_map(bytes, name).ok_or(Dropped::Undecodable(tag))?;
    let bad = || Dropped::Undecodable(tag);
    let i = |k: &str| m.get(k).and_then(Value::as_i64).ok_or_else(bad);
    let t = |k: &str| read_text(&m, k).ok_or_else(bad);
    let message = match tag {
        T_PIECE_WANT => Message::PieceWant { root: t("root")?, index: i("index")?, offset: i("offset")?, length: i("length")?, req: i("req")? },
        T_PIECE => Message::Piece {
            root: t("root")?,
            index: i("index")?,
            offset: i("offset")?,
            bytes: read_opt_bytes(&m, "bytes").flatten().ok_or_else(bad)?,
            req: i("req")?,
        },
        T_HAVE => Message::Have {
            root: t("root")?,
            have: read_opt_bytes(&m, "have").ok_or_else(bad)?,
            complete: m.get("complete").and_then(Value::as_bool).ok_or_else(bad)?,
        },
        T_CANCEL => Message::Cancel { root: t("root")?, index: i("index")?, req: i("req")? },
        T_REJECT => Message::Reject { root: t("root")?, index: i("index")?, reason: i("reason")? },
        T_MANIFEST_WANT => Message::ManifestWant { root: t("root")? },
        T_MANIFEST => Message::Manifest { root: t("root")?, record: read_opt_bytes(&m, "record").flatten().ok_or_else(bad)? },
        T_NODE_WANT => Message::NodeWant { req: i("req")?, cids: read_texts(&m, "cids").ok_or_else(bad)? },
        T_NODES => {
            if m.get("deltas").is_some() {
                return Err(Dropped::Undecodable(tag));
            }
            let nodes = match m.get("nodes") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_array()
                        .ok_or_else(bad)?
                        .iter()
                        .map(|n| n.as_bytes().map(<[u8]>::to_vec))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(bad)?,
                ),
            };
            Message::Nodes {
                req: i("req")?,
                nodes,
                sealed: read_opt_bytes(&m, "sealed").ok_or_else(bad)?,
                epoch: match m.get("epoch") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(v.as_i64().ok_or_else(bad)?),
                },
                missing: read_opt_texts(&m, "missing").ok_or_else(bad)?,
            }
        }
        T_TREE_WANT => {
            if !matches!(m.get("sketch"), None | Some(Value::Null)) {
                return Err(Dropped::OutOfBounds(tag, "a sketch TREE_WANT is a level-2 form".to_string()));
            }
            Message::TreeWant { req: i("req")?, root: t("root")?, haves: read_opt_texts(&m, "haves").ok_or_else(bad)?, budget: i("budget")? }
        }
        T_TREE_END => {
            if m.get("sketch").is_some() {
                return Err(Dropped::Undecodable(tag));
            }
            Message::TreeEnd { req: i("req")?, frontier: read_texts(&m, "frontier").ok_or_else(bad)?, reason: i("reason")? }
        }
        _ => return Err(Dropped::UnknownTag(tag)),
    };
    if let Some(why) = message.violation() {
        return Err(Dropped::OutOfBounds(tag, why));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitfield_round_trips() {
        let held = [false, true, false, true, true, true, false];
        assert_eq!(encode_have(&[false, true, true, true][..]), vec![1, 3]);
        let enc = encode_have(&held);
        assert_eq!(decode_have(Some(&enc), held.len()), held);
        assert_eq!(decode_have(None, 3), vec![true; 3]);
    }
}
