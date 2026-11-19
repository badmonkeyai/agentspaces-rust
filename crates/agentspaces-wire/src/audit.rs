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

//! The audit's wire forms (SPEC annex I.6, v0.1.35, `wire.ae=2`): the `DIGEST` fields `tree`,
//! `ids`, `budget`, and the reserved `sketch`, the `TreeNode` record, and `PULL_RESP.remainder`,
//! with the form rules that make a carrier breaking one undecodable; and the partner's answers:
//! a root, request nodes under a budget, and a fetch by ids in the order of *The fetch*.
//!
//! A sender writes these fields only toward a member whose current card carries
//! [`HINT_AE`]` = `[`AE_LEVEL`], since a reader of v0.1.34 or earlier refuses a field its schema
//! does not name (rule P1). [`parse_digest`] and [`parse_pull_resp`] run the receiver's
//! procedure of SPEC §9.1 and name the form rule a carrier broke ([`FormError`]); the record
//! schemas of [`crate::schema`] apply the same rules, so every reader of a `DIGEST` or a
//! `PULL_RESP` refuses a malformed carrier.
#![warn(missing_docs)]

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use crate::cbor::{self, Map, Value};
use crate::hlc::Stamp;
use crate::schema;
use crate::trie::{
    AuditTrie, CHILD_BYTES, FANOUT, FINGERPRINT_BYTES, INNER_PREIMAGE_BYTES, KEY_NIBBLES, LEAF_MAX,
    NodeKind, Path, child_of, has_control,
};
use crate::util::encode_map;

/// The hint a member that implements the audit advertises, a key of its resource hints.
pub const HINT_AE: &str = "wire.ae";
/// The value of [`HINT_AE`] this crate implements.
pub const AE_LEVEL: &str = "2";
/// Nodes one stream's `tree` holds at most.
pub const TREE_NODES_MAX: usize = 256;
/// Distinct ids one stream's `ids` names at most.
pub const IDS_MAX: usize = 4096;
/// Nibbles in a path at most.
pub const PATH_MAX: usize = KEY_NIBBLES;
/// The budget a member asks for by default: 1 MiB.
pub const BUDGET_DEFAULT: i64 = 1 << 20;
/// The largest budget this crate's partner honours, its own cap on an answer: half the frame.
pub const BUDGET_CEILING: i64 = 4 << 20;
/// Sessions a partner keeps open per asker at most.
pub const SESSIONS_MAX: usize = 4;
/// Exchanges a session holds before it closes.
pub const SESSION_EXCHANGES_MAX: u32 = 64;
/// How long a session lives with no exchange, milliseconds.
pub const SESSION_IDLE_MILLIS: i64 = 30_000;

/// Whether a card's resource hints carry `wire.ae=2`.
pub fn hints_audit(hints: Option<&Value>) -> bool {
    hints
        .and_then(|hints| hints.get(HINT_AE))
        .and_then(Value::as_str)
        == Some(AE_LEVEL)
}

// ---------------------------------------------------------------------------------------------
// Form rules

/// The form rule a `DIGEST` or `PULL_RESP` carrier broke (SPEC annex I.6): each makes the carrier
/// undecodable, and each has its own name for counters and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormError {
    /// The bytes are not one canonical item of the wire encoding, or the record breaks the record
    /// rules P1 to P4 of its schema (a field it does not name, out of order, of another kind).
    Undecodable,
    /// A path byte above `0x0F`.
    PathNibble,
    /// A path of more than 64 bytes.
    PathLong,
    /// A tree node with none of `count`, `nodes`, and `lines`.
    NoForm,
    /// A tree node with more than one of `count`, `nodes`, and `lines`.
    TwoForms,
    /// A negative `count`.
    CountNegative,
    /// `nodes` of another length than 384 bytes.
    NodesLength,
    /// `nodes` whose sixteen counts sum to 32 or fewer.
    NodesFew,
    /// `nodes` listing a child with the count 0 and a fingerprint other than 16 zero bytes.
    NodesEmptyChild,
    /// `nodes` whose counts pass what a signed 64-bit count holds.
    NodesOverflow,
    /// `lines` holding an empty line: a leading, a doubled, or a trailing LF.
    LinesEmptyLine,
    /// `lines` holding a control character other than its separating LFs.
    LinesControl,
    /// `lines` with two lines out of strictly ascending order.
    LinesOrder,
    /// A stream's `tree` of more than 256 nodes.
    TreeTooMany,
    /// A stream's `ids` of more than 4096 ids.
    IdsTooMany,
    /// A stream's `ids` naming one id twice.
    IdsTwice,
    /// A `budget` of zero or below.
    BudgetNotPositive,
    /// A negative `remainder`.
    RemainderNegative,
}

impl FormError {
    /// A stable kebab-case name for logs and counters.
    pub fn as_str(self) -> &'static str {
        match self {
            FormError::Undecodable => "undecodable",
            FormError::PathNibble => "path-nibble",
            FormError::PathLong => "path-long",
            FormError::NoForm => "no-form",
            FormError::TwoForms => "two-forms",
            FormError::CountNegative => "count-negative",
            FormError::NodesLength => "nodes-length",
            FormError::NodesFew => "nodes-few",
            FormError::NodesEmptyChild => "nodes-empty-child",
            FormError::NodesOverflow => "nodes-overflow",
            FormError::LinesEmptyLine => "lines-empty-line",
            FormError::LinesControl => "lines-control",
            FormError::LinesOrder => "lines-order",
            FormError::TreeTooMany => "tree-too-many",
            FormError::IdsTooMany => "ids-too-many",
            FormError::IdsTwice => "ids-twice",
            FormError::BudgetNotPositive => "budget-not-positive",
            FormError::RemainderNegative => "remainder-negative",
        }
    }
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for FormError {}

/// The form rules of an inner node's preimage.
pub fn check_nodes(nodes: &[u8]) -> Result<(), FormError> {
    if nodes.len() != INNER_PREIMAGE_BYTES {
        return Err(FormError::NodesLength);
    }
    let mut sum: i64 = 0;
    for child in 0..FANOUT {
        let (fp, count) = child_of(nodes, child).ok_or(FormError::NodesLength)?;
        let count = i64::try_from(count).map_err(|_| FormError::NodesOverflow)?;
        if count == 0 && fp != [0u8; FINGERPRINT_BYTES] {
            return Err(FormError::NodesEmptyChild);
        }
        sum = sum.checked_add(count).ok_or(FormError::NodesOverflow)?;
    }
    if sum <= LEAF_MAX as i64 {
        return Err(FormError::NodesFew);
    }
    Ok(())
}

/// The form rules of an answer of lines.
pub fn check_lines(lines: &str) -> Result<(), FormError> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut previous: Option<&str> = None;
    for line in lines.split('\n') {
        if line.is_empty() {
            return Err(FormError::LinesEmptyLine);
        }
        if has_control(line) {
            return Err(FormError::LinesControl);
        }
        if previous.is_some_and(|previous| previous.as_bytes() >= line.as_bytes()) {
            return Err(FormError::LinesOrder);
        }
        previous = Some(line);
    }
    Ok(())
}

/// The form rules of a path, one nibble per byte.
pub fn check_path(path: &[u8]) -> Result<(), FormError> {
    if path.len() > PATH_MAX {
        return Err(FormError::PathLong);
    }
    if path.iter().any(|&nibble| nibble > 0x0F) {
        return Err(FormError::PathNibble);
    }
    Ok(())
}

fn present<'a>(map: &'a Map, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !value.is_null())
}

/// The form rules of one decoded `TreeNode` map; fields of another kind are left for the record
/// rules to refuse.
pub fn tree_node_form(map: &Map) -> Result<(), FormError> {
    if let Some(path) = present(map, "path").and_then(Value::as_bytes) {
        check_path(path)?;
    }
    let forms = ["count", "nodes", "lines"]
        .iter()
        .filter(|field| present(map, field).is_some())
        .count();
    match forms {
        0 => return Err(FormError::NoForm),
        1 => {}
        _ => return Err(FormError::TwoForms),
    }
    if present(map, "count")
        .and_then(Value::as_i128)
        .is_some_and(|count| count < 0)
    {
        return Err(FormError::CountNegative);
    }
    if let Some(nodes) = present(map, "nodes").and_then(Value::as_bytes) {
        check_nodes(nodes)?;
    }
    if let Some(lines) = present(map, "lines").and_then(Value::as_str) {
        check_lines(lines)?;
    }
    Ok(())
}

/// The form rules of one decoded `DIGEST` body map, its tree nodes' included.
pub fn digest_form(map: &Map) -> Result<(), FormError> {
    if let Some(tree) = present(map, "tree").and_then(Value::as_map) {
        for nodes in tree.values() {
            let Some(nodes) = nodes.as_array() else {
                continue;
            };
            if nodes.len() > TREE_NODES_MAX {
                return Err(FormError::TreeTooMany);
            }
            for node in nodes.iter().filter_map(Value::as_map) {
                tree_node_form(node)?;
            }
        }
    }
    if let Some(ids) = present(map, "ids").and_then(Value::as_map) {
        for named in ids.values() {
            let Some(named) = named.as_array() else {
                continue;
            };
            if named.len() > IDS_MAX {
                return Err(FormError::IdsTooMany);
            }
            let mut seen = HashSet::with_capacity(named.len());
            if !named.iter().all(|id| seen.insert(id)) {
                return Err(FormError::IdsTwice);
            }
        }
    }
    if present(map, "budget")
        .and_then(Value::as_i128)
        .is_some_and(|budget| budget <= 0)
    {
        return Err(FormError::BudgetNotPositive);
    }
    Ok(())
}

/// The form rules of one decoded `PULL_RESP` body map.
pub fn pull_resp_form(map: &Map) -> Result<(), FormError> {
    if let Some(remainder) = present(map, "remainder").and_then(Value::as_map)
        && remainder
            .values()
            .any(|left| left.as_i128().is_some_and(|left| left < 0))
    {
        return Err(FormError::RemainderNegative);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tree nodes

/// One node of an audit: its path and exactly one form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    /// The path, one nibble per byte; the root's is empty.
    pub path: Vec<u8>,
    /// The node's form.
    pub form: TreeForm,
}

/// What a tree node carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeForm {
    /// A request, with the asker's own count at the path.
    Count(u64),
    /// An answer for an inner node: its 384-byte preimage.
    Nodes(Vec<u8>),
    /// An answer of lines: the joined lines under the path, empty when there are none.
    Lines(String),
}

impl TreeNode {
    /// A request for the node at `path`, with the asker's count there.
    pub fn request(path: &Path, count: u64) -> TreeNode {
        TreeNode {
            path: path.nibbles(),
            form: TreeForm::Count(count),
        }
    }

    /// An answer of an inner node's preimage.
    pub fn inner(path: &Path, nodes: Vec<u8>) -> TreeNode {
        TreeNode {
            path: path.nibbles(),
            form: TreeForm::Nodes(nodes),
        }
    }

    /// An answer of lines.
    pub fn lines(path: &Path, lines: String) -> TreeNode {
        TreeNode {
            path: path.nibbles(),
            form: TreeForm::Lines(lines),
        }
    }

    /// The node's path, when its bytes are nibbles (always, for a node that decoded).
    pub fn trie_path(&self) -> Option<Path> {
        Path::from_nibbles(&self.path)
    }

    /// Whether it is a request.
    pub fn is_request(&self) -> bool {
        matches!(self.form, TreeForm::Count(_))
    }

    /// The bytes of its answer's preimage (`nodes`, or `lines` as UTF-8); empty for a request.
    pub fn preimage(&self) -> &[u8] {
        match &self.form {
            TreeForm::Count(_) => &[],
            TreeForm::Nodes(nodes) => nodes,
            TreeForm::Lines(lines) => lines.as_bytes(),
        }
    }

    /// The node as its record map (`Bodies.TreeNode`).
    pub fn to_map(&self) -> Map {
        let mut map = Map::with_capacity(2);
        map.insert("path", self.path.clone());
        match &self.form {
            TreeForm::Count(count) => map.insert("count", Value::Int(i128::from(*count))),
            TreeForm::Nodes(nodes) => map.insert("nodes", nodes.clone()),
            TreeForm::Lines(lines) => map.insert("lines", lines.as_str()),
        };
        map
    }

    /// The bytes of its record.
    pub fn encoded_len(&self) -> usize {
        encode_map(&self.to_map()).len()
    }

    fn from_map(map: &Map) -> Option<TreeNode> {
        let path = map.get("path")?.as_bytes()?.to_vec();
        let form = if let Some(count) = present(map, "count") {
            TreeForm::Count(count.as_u64()?)
        } else if let Some(nodes) = present(map, "nodes") {
            TreeForm::Nodes(nodes.as_bytes()?.to_vec())
        } else {
            TreeForm::Lines(present(map, "lines")?.as_str()?.to_owned())
        };
        Some(TreeNode { path, form })
    }
}

// ---------------------------------------------------------------------------------------------
// Bodies

/// A `DIGEST` body (`Bodies.Digest`) with every field of v0.1.35. Each map-valued field is a list
/// of (stream, value) pairs, written in canonical key order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DigestBody {
    /// The text digest per stream; `None` writes `digests` null. An empty digest asks for the
    /// whole stream.
    pub digests: Option<Vec<(String, Vec<u8>)>>,
    /// The per-stream hashes of a round's opening.
    pub hashes: Option<Vec<(String, Vec<u8>)>>,
    /// The streams whose text digest the partner wants.
    pub want: Option<Vec<String>>,
    /// The audit's request or answer nodes per stream.
    pub tree: Option<Vec<(String, Vec<TreeNode>)>>,
    /// The entry ids to fetch per stream.
    pub ids: Option<Vec<(String, Vec<String>)>>,
    /// The bytes the answer this body draws may hold.
    pub budget: Option<i64>,
    /// Reserved for a later reconciliation form: never sent, and ignored when received.
    pub sketch: Option<Vec<(String, Vec<u8>)>>,
}

impl DigestBody {
    /// Whether it carries a field of annex I.6, which only a member of `wire.ae=2` reads.
    pub fn carries_audit(&self) -> bool {
        self.tree.is_some() || self.ids.is_some() || self.budget.is_some() || self.sketch.is_some()
    }

    /// The body's bytes: the fields in the record's order, `digests` always (null when absent),
    /// every other field omitted when absent.
    pub fn encode(&self) -> Vec<u8> {
        fn bytes_map(pairs: &[(String, Vec<u8>)]) -> Value {
            let mut map = Map::with_capacity(pairs.len());
            for (stream, bytes) in pairs {
                map.insert(stream.as_str(), bytes.clone());
            }
            Value::Map(cbor::canonical_map(&map))
        }
        let mut body = Map::with_capacity(7);
        body.insert(
            "digests",
            self.digests.as_deref().map_or(Value::Null, bytes_map),
        );
        if let Some(hashes) = &self.hashes {
            body.insert("hashes", bytes_map(hashes));
        }
        if let Some(want) = &self.want {
            body.insert(
                "want",
                Value::Array(
                    want.iter()
                        .map(|stream| Value::from(stream.as_str()))
                        .collect(),
                ),
            );
        }
        if let Some(tree) = &self.tree {
            let mut map = Map::with_capacity(tree.len());
            for (stream, nodes) in tree {
                map.insert(
                    stream.as_str(),
                    Value::Array(nodes.iter().map(|node| Value::Map(node.to_map())).collect()),
                );
            }
            body.insert("tree", cbor::canonical_map(&map));
        }
        if let Some(ids) = &self.ids {
            let mut map = Map::with_capacity(ids.len());
            for (stream, named) in ids {
                map.insert(
                    stream.as_str(),
                    Value::Array(named.iter().map(|id| Value::from(id.as_str())).collect()),
                );
            }
            body.insert("ids", cbor::canonical_map(&map));
        }
        if let Some(budget) = self.budget {
            body.insert("budget", budget);
        }
        if let Some(sketch) = &self.sketch {
            body.insert("sketch", bytes_map(sketch));
        }
        encode_map(&body)
    }
}

/// A `PULL_RESP` body (`Bodies.PullResp`) with its v0.1.35 `remainder`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PullRespBody {
    /// The delta per stream.
    pub deltas: Vec<(String, Vec<u8>)>,
    /// Per stream, the states the partner held for a budgeted request and left out for the
    /// budget; present exactly in answer to a body that carried `budget`.
    pub remainder: Option<Vec<(String, i64)>>,
}

impl PullRespBody {
    /// The body's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut deltas = Map::with_capacity(self.deltas.len());
        for (stream, delta) in &self.deltas {
            deltas.insert(stream.as_str(), delta.clone());
        }
        let mut body = Map::with_capacity(2);
        body.insert("deltas", cbor::canonical_map(&deltas));
        if let Some(remainder) = &self.remainder {
            let mut map = Map::with_capacity(remainder.len());
            for (stream, left) in remainder {
                map.insert(stream.as_str(), *left);
            }
            body.insert("remainder", cbor::canonical_map(&map));
        }
        encode_map(&body)
    }

    /// The remainder of one stream; zero when the body carries none for it.
    pub fn remainder_of(&self, stream: &str) -> i64 {
        self.remainder
            .iter()
            .flatten()
            .find(|(name, _)| name == stream)
            .map_or(0, |(_, left)| *left)
    }
}

fn pairs_of<T>(
    value: Option<&Value>,
    read: impl Fn(&Value) -> Option<T>,
) -> Option<Option<Vec<(String, T)>>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Some(None);
    };
    let map = value.as_map()?;
    let mut out = Vec::with_capacity(map.len());
    for (key, item) in map {
        out.push((key.as_str()?.to_owned(), read(item)?));
    }
    Some(Some(out))
}

/// Reads a `DIGEST` body under the receiver's procedure (SPEC §9.1) and the form rules of annex
/// I.6, naming the rule a malformed carrier broke.
pub fn parse_digest(body: &[u8]) -> Result<DigestBody, FormError> {
    let value = schema::load_canonical(body).ok_or(FormError::Undecodable)?;
    let map = value.as_map().ok_or(FormError::Undecodable)?;
    digest_form(map)?;
    if !schema::conforms(&value, "Bodies.Digest") {
        return Err(FormError::Undecodable);
    }
    let bytes = |item: &Value| item.as_bytes().map(<[u8]>::to_vec);
    let texts = |item: &Value| -> Option<Vec<String>> {
        item.as_array()?
            .iter()
            .map(|text| text.as_str().map(str::to_owned))
            .collect()
    };
    let nodes = |item: &Value| -> Option<Vec<TreeNode>> {
        item.as_array()?
            .iter()
            .map(|node| TreeNode::from_map(node.as_map()?))
            .collect()
    };
    let undecodable = FormError::Undecodable;
    Ok(DigestBody {
        digests: pairs_of(map.get("digests"), bytes).ok_or(undecodable)?,
        hashes: pairs_of(map.get("hashes"), bytes).ok_or(undecodable)?,
        want: match present(map, "want") {
            None => None,
            Some(want) => Some(texts(want).ok_or(undecodable)?),
        },
        tree: pairs_of(map.get("tree"), nodes).ok_or(undecodable)?,
        ids: pairs_of(map.get("ids"), texts).ok_or(undecodable)?,
        budget: match present(map, "budget") {
            None => None,
            Some(budget) => Some(budget.as_i64().ok_or(undecodable)?),
        },
        sketch: pairs_of(map.get("sketch"), bytes).ok_or(undecodable)?,
    })
}

/// Reads a `PULL_RESP` body under the receiver's procedure and the form rule of `remainder`.
pub fn parse_pull_resp(body: &[u8]) -> Result<PullRespBody, FormError> {
    let value = schema::load_canonical(body).ok_or(FormError::Undecodable)?;
    let map = value.as_map().ok_or(FormError::Undecodable)?;
    pull_resp_form(map)?;
    if !schema::conforms(&value, "Bodies.PullResp") {
        return Err(FormError::Undecodable);
    }
    let undecodable = FormError::Undecodable;
    Ok(PullRespBody {
        deltas: pairs_of(map.get("deltas"), |item| {
            item.as_bytes().map(<[u8]>::to_vec)
        })
        .ok_or(undecodable)?
        .unwrap_or_default(),
        remainder: pairs_of(map.get("remainder"), Value::as_i64).ok_or(undecodable)?,
    })
}

// ---------------------------------------------------------------------------------------------
// The partner's answers

/// The root answer of a stream (step 2 of *The audit*): `nodes` when the root is inner, else its
/// lines (the empty text for an empty set).
pub fn answer_root(trie: &mut AuditTrie) -> TreeNode {
    let root = trie.node(&Path::ROOT);
    match root.kind {
        NodeKind::Inner => TreeNode::inner(&Path::ROOT, root.preimage),
        _ => TreeNode::lines(
            &Path::ROOT,
            String::from_utf8(root.preimage).unwrap_or_default(),
        ),
    }
}

/// The partner's answer to one stream's request nodes (step 4 of *The audit*), in the order
/// asked, each path answered once, up to `budget` bytes (capped at [`BUDGET_CEILING`], the
/// first node always): `lines` when its own count or the request's is at most 32, `nodes`
/// otherwise, except that when the request's count alone chose lines and those lines would by
/// themselves pass the budget, `nodes`. Also whether the body named a path twice.
pub fn answer_requests(
    trie: &mut AuditTrie,
    stream: &str,
    requests: &[TreeNode],
    budget: Option<i64>,
) -> (Vec<TreeNode>, bool) {
    let cap = budget.map_or(BUDGET_CEILING, |budget| budget.min(BUDGET_CEILING));
    let cap = usize::try_from(cap).unwrap_or(0);
    // The body's own bytes beside its nodes: the map, the stream name, the list head and the
    // other fields.
    let mut used = 64 + stream.len();
    let mut reply = Vec::with_capacity(requests.len());
    let mut seen = HashSet::with_capacity(requests.len());
    let mut repeated = false;
    for request in requests {
        let (Some(path), TreeForm::Count(asked)) = (request.trie_path(), &request.form) else {
            continue;
        };
        if !seen.insert(path) {
            repeated = true;
            continue;
        }
        let (count, _) = trie.fingerprint_at(&path);
        let answer = if count == 0 {
            TreeNode::lines(&path, String::new())
        } else if count <= LEAF_MAX || path.len() >= KEY_NIBBLES {
            let node = trie.node(&path);
            TreeNode::lines(&path, String::from_utf8(node.preimage).unwrap_or_default())
        } else if *asked <= LEAF_MAX && count.saturating_mul(4) <= cap as u64 {
            // Every slot holds a line of at least four bytes, so a count past a quarter of the
            // budget passes it without being read; below that, the gathering stops once the lines
            // pass the budget.
            match trie.joined_under(&path, cap.saturating_sub(32)) {
                Some(lines) => TreeNode::lines(&path, String::from_utf8(lines).unwrap_or_default()),
                None => TreeNode::inner(&path, trie.node(&path).preimage),
            }
        } else {
            TreeNode::inner(&path, trie.node(&path).preimage)
        };
        let size = answer.encoded_len();
        if !reply.is_empty() && used.saturating_add(size) > cap {
            break; // left out for the budget: the asker asks again in its next exchange
        }
        used = used.saturating_add(size);
        reply.push(answer);
    }
    (reply, repeated)
}

/// Whether an opening's hash for a stream names this member's stream as it holds it: the hash
/// equals the stream's trie stream hash or its text digest's hash, whichever kind the asker took
/// (annex I.6), so a stale view of the asker's card never makes two equal streams differ.
pub fn same_stream(
    trie_hash: Option<&[u8; 32]>,
    text_hash: Option<&[u8; 32]>,
    theirs: &[u8],
) -> bool {
    trie_hash.is_some_and(|hash| hash[..] == *theirs)
        || text_hash.is_some_and(|hash| hash[..] == *theirs)
}

/// Whether the sixteen counts of an inner preimage sum to exactly `expected`.
pub fn counts_sum_to(nodes: &[u8], expected: u64) -> bool {
    let mut sum: u64 = 0;
    for child in 0..FANOUT {
        let Some((_, count)) = child_of(nodes, child) else {
            return false;
        };
        let Some(next) = sum.checked_add(count) else {
            return false;
        };
        sum = next;
    }
    sum == expected
}

/// Bytes one child takes in an inner preimage, re-exported for readers of `nodes`.
pub const NODE_CHILD_BYTES: usize = CHILD_BYTES;

// ---------------------------------------------------------------------------------------------
// The fetch's answer

/// One item a fetch (or a budgeted text pull) may answer with: an entry's signed state with the
/// claim that travels with it, or a claim alone.
#[derive(Debug, Clone, Copy)]
pub struct Offer<'a> {
    /// The entry id.
    pub entry_id: &'a str,
    /// The entry's signed state (`EntryStateDto`), when it goes.
    pub state: Option<&'a Map>,
    /// Whether that state is present (neither completed nor withdrawn).
    pub present: bool,
    /// The entry's signed claim, when it goes.
    pub claim: Option<&'a Map>,
}

impl<'a> Offer<'a> {
    /// Present states first, then tombstones, then claims alone.
    fn rank(&self) -> u8 {
        match (self.state, self.present) {
            (None, _) => 2,
            (Some(_), true) => 0,
            (Some(_), false) => 1,
        }
    }

    /// The state's lease stamp, else the claim's own stamp.
    fn stamp(&self) -> Option<Stamp<'a>> {
        match self.state {
            Some(state) => Stamp::of(state.get("leaseStamp")),
            None => Stamp::of(self.claim?.get("claim")?.get("stamp")),
        }
    }

    /// The bytes the item adds to a delta: each record's encoding, and the claim's key.
    fn size(&self) -> usize {
        let state = self.state.map_or(0, |state| encode_map(state).len());
        let claim = self
            .claim
            .map_or(0, |claim| encode_map(claim).len() + self.entry_id.len() + 9);
        state + claim
    }
}

/// The order of *The fetch*: every present state before every tombstone, claims alone last;
/// within each, newest first by the stamp order of SPEC §7.3, a stamped item before one without;
/// equal stamps by ascending UTF-8 bytes of the ids.
pub fn offer_order(a: &Offer<'_>, b: &Offer<'_>) -> Ordering {
    a.rank()
        .cmp(&b.rank())
        .then_with(|| match (a.stamp(), b.stamp()) {
            (Some(x), Some(y)) => y.cmp(&x),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.entry_id.as_bytes().cmp(b.entry_id.as_bytes()))
}

/// Bytes of a delta beside its items: the record's field names and its list and map heads.
pub const DELTA_BASE: usize = 32;
/// Bytes of a `PULL_RESP` body beside its deltas.
pub const PULL_RESP_BASE: usize = 32;

/// Bytes one stream adds to a `PULL_RESP` body beside its delta.
pub fn stream_overhead(stream: &str) -> usize {
    2 * (stream.len() + 9) + 9
}

/// A delta cut to a budget (*The budget*): the offers sorted by [`offer_order`] and taken until
/// the next would pass `budget` bytes, the first always when `first` (an answer carries its first
/// item whatever its size). The delta (`None` when nothing was taken) and the count of offers
/// left out.
pub fn bounded_delta(
    mut offers: Vec<Offer<'_>>,
    budget: usize,
    first: bool,
) -> (Option<Vec<u8>>, u64) {
    offers.sort_by(offer_order);
    let mut used = DELTA_BASE;
    let mut states: Vec<&Map> = Vec::new();
    let mut claims: Vec<(&str, &Map)> = Vec::new();
    let mut taken = 0usize;
    for offer in &offers {
        let size = offer.size();
        if used.saturating_add(size) > budget && !(first && taken == 0) {
            break;
        }
        used = used.saturating_add(size);
        taken += 1;
        if let Some(state) = offer.state {
            states.push(state);
        }
        if let Some(claim) = offer.claim {
            claims.push((offer.entry_id, claim));
        }
    }
    let left = (offers.len() - taken) as u64;
    if taken == 0 {
        return (None, left);
    }
    (Some(crate::serving::sync_delta(&states, &claims)), left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_rules_name_their_reason() {
        assert_eq!(check_lines(""), Ok(()));
        assert_eq!(check_lines("c:a=1\ne:a=1"), Ok(()));
        assert_eq!(check_lines("\ne:a=1"), Err(FormError::LinesEmptyLine));
        assert_eq!(check_lines("e:a=1\n"), Err(FormError::LinesEmptyLine));
        assert_eq!(
            check_lines("e:a=1\n\ne:b=1"),
            Err(FormError::LinesEmptyLine)
        );
        assert_eq!(check_lines("e:b=1\ne:a=1"), Err(FormError::LinesOrder));
        assert_eq!(check_lines("e:a=1\ne:a=1"), Err(FormError::LinesOrder));
        assert_eq!(check_lines("e:a\t=1"), Err(FormError::LinesControl));
        assert_eq!(check_lines("e:a\u{7f}=1"), Err(FormError::LinesControl));
    }

    #[test]
    fn nodes_rules_name_their_reason() {
        let mut nodes = vec![0u8; INNER_PREIMAGE_BYTES];
        nodes[16 + 7] = 33;
        nodes[0] = 1;
        assert_eq!(check_nodes(&nodes), Ok(()));
        assert_eq!(check_nodes(&nodes[..383]), Err(FormError::NodesLength));
        nodes[16 + 7] = 32;
        assert_eq!(check_nodes(&nodes), Err(FormError::NodesFew));
        nodes[16 + 7] = 33;
        nodes[24] = 9;
        assert_eq!(check_nodes(&nodes), Err(FormError::NodesEmptyChild));
        nodes[24] = 0;
        nodes[16] = 0x80;
        assert_eq!(check_nodes(&nodes), Err(FormError::NodesOverflow));
        nodes[16] = 0x7F;
        nodes[24 + 16] = 0x7F;
        nodes[24] = 1;
        assert_eq!(check_nodes(&nodes), Err(FormError::NodesOverflow));
        assert!(counts_sum_to(&[0u8; 384], 0));
    }

    #[test]
    fn paths_are_nibbles() {
        assert_eq!(check_path(&[0x0F; 64]), Ok(()));
        assert_eq!(check_path(&[0; 65]), Err(FormError::PathLong));
        assert_eq!(check_path(&[0x10]), Err(FormError::PathNibble));
        assert!(hints_audit(Some(&Value::Map({
            let mut hints = Map::new();
            hints.insert(HINT_AE, AE_LEVEL);
            hints
        }))));
        assert!(!hints_audit(None));
    }
}
