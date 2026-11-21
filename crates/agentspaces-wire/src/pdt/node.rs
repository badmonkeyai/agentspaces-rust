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

//! The node codec (annex H, nodes and CIDs; Java `NodeCodec`, Python `pdt/nodes.py`).
//!
//! A node is a canonical DAG-CBOR map with text keys: definite lengths, shortest integer heads,
//! keys ordered by length then bytes, and a link as CBOR tag 42 over a byte string of `0x00`
//! and the 36-byte binary CID. Every node carries `k`, its kind, and only the keys of its kind's
//! schema. Application keys and values are *embedded* as raw CBOR items in the form the entry
//! codec gives them, spliced in and skipped over; each must be in the wire encoding (rules S1 to
//! S12, [`crate::cbor::decode`]), except that an item that is exactly a link item in a value
//! slot names a spilled node.
//!
//! Bounds: a node is at most 1 MiB (an `sn` envelope 1 MiB + 48 KiB) and carries at most 1,024
//! links; nested CBOR is at most 64 levels. A decoder refuses a node over a bound, an unknown or
//! reserved kind, a key outside the kind's schema, keys out of order or repeated, a link of the
//! wrong shape, or a bare link item in a key slot, and names the rule.
//!
//! The level-2 fields with their own grammar (`dn.e` datoms, `t.r` runs) are carried as one raw
//! CBOR item ([`Field::Raw`]) whose links this module finds; their typed readers live with the
//! level-2 values.

use super::NodeError;
use super::cid;

/// The bytes a node holds at most (every kind but `sn`).
pub const MAX_NODE_BYTES: usize = 1024 * 1024;
/// The bytes an `sn` envelope holds at most.
pub const MAX_SEALED_NODE_BYTES: usize = 1024 * 1024 + 48 * 1024;
/// The links a node carries at most, spilled-value links counted.
pub const MAX_LINKS: usize = 1024;
/// The deepest nesting of CBOR inside a node, and the deepest tree.
pub const MAX_DEPTH: usize = 64;
/// The tag of a link item.
pub const LINK_TAG: u64 = 42;
/// The bytes of a link's byte string: `0x00` and the binary CID.
pub const LINK_BYTES: usize = 1 + cid::BINARY_LENGTH;
/// The bytes of a whole link item: `d8 2a 58 25 00` and the binary CID.
pub const LINK_ITEM_LENGTH: usize = 4 + LINK_BYTES;

/// The kind key.
pub const KIND_KEY: &str = "k";

/// A map node.
pub const KIND_M: &str = "m";
/// A map collision node (past level 51).
pub const KIND_MC: &str = "mc";
/// A vector node, interior or leaf.
pub const KIND_V: &str = "v";
/// A vector root.
pub const KIND_VR: &str = "vr";
/// A blob interior node.
pub const KIND_B: &str = "b";
/// A spilled value.
pub const KIND_X: &str = "x";
/// A sealed envelope (`sealed-nodes` mode).
pub const KIND_SN: &str = "sn";
/// A DataScript root (level 2).
pub const KIND_DB: &str = "db";
/// A DataScript index node (level 2).
pub const KIND_DN: &str = "dn";
/// A relaxed vector root (level 2).
pub const KIND_RR: &str = "rr";
/// A relaxed vector interior node (level 2).
pub const KIND_RV: &str = "rv";
/// A text leaf (level 2).
pub const KIND_T: &str = "t";
/// A version-graph node (level 2, behind `pdt.ancestry`).
pub const KIND_VG: &str = "vg";
/// A Bao outboard node (level 2, behind `pdt.bao`).
pub const KIND_BO: &str = "bo";

/// The kinds a level-1 member reads as values.
pub const LEVEL1_KINDS: [&str; 7] = [KIND_M, KIND_MC, KIND_V, KIND_VR, KIND_B, KIND_X, KIND_SN];
/// The kinds PDT 2 adds.
pub const LEVEL2_KINDS: [&str; 7] = [KIND_DB, KIND_DN, KIND_RR, KIND_RV, KIND_T, KIND_VG, KIND_BO];
/// The kinds reserved and refused by name.
pub const RESERVED_KINDS: [&str; 3] = ["s", "tm", "ec"];
/// The keys of a `db` root's index map, in DAG-CBOR order.
pub const INDEX_KEYS: [&str; 3] = ["aevt", "avet", "eavt"];

/// The type of a schema field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// An unsigned integer.
    Uint,
    /// A link.
    Link,
    /// A link or null.
    LinkOrNull,
    /// A list of links.
    Links,
    /// One embedded item.
    Embedded,
    /// A list of embedded items.
    Embeddeds,
    /// A list of unsigned integers.
    Uints,
    /// A byte string.
    Bytes,
    /// Well-formed UTF-8 text.
    Text,
    /// A CID as text.
    Cid,
    /// A list of CIDs as text.
    Cids,
    /// The `db` index map: exactly `aevt`, `avet`, `eavt` to links.
    Index,
    /// A list in a level-2 grammar (datoms, runs), carried raw.
    Raw,
}

/// The schema of a kind: its keys other than `k`, each with its type.
pub fn schema(kind: &str) -> Option<&'static [(&'static str, FieldType)]> {
    use FieldType::*;
    Some(match kind {
        KIND_M => &[
            ("d", Uint),
            ("n", Uint),
            ("e", Embeddeds),
            ("c", Links),
            ("cnt", Uint),
        ],
        KIND_MC => &[("e", Embeddeds)],
        KIND_V => &[("c", Links), ("e", Embeddeds)],
        KIND_VR | KIND_RR => &[("n", Uint), ("s", Uint), ("r", LinkOrNull), ("t", Embeddeds)],
        KIND_B => &[("h", Uint), ("c", Links), ("z", Uints)],
        KIND_X => &[("v", Embedded)],
        KIND_SN => &[("ct", Bytes), ("ep", Uint), ("ln", Links), ("nc", Bytes)],
        KIND_DB => &[
            ("v", Uint),
            ("s", Embedded),
            ("me", Uint),
            ("mt", Uint),
            ("bf", Uint),
            ("i", Index),
            ("t", LinkOrNull),
        ],
        KIND_DN => &[("l", Uint), ("x", Text), ("e", Raw), ("c", Links)],
        KIND_RV => &[("c", Links), ("z", Uints)],
        KIND_T => &[("r", Raw), ("v", Uint)],
        KIND_VG => &[("r", Cid), ("b", Cids), ("i", Text), ("t", Text), ("p", Links)],
        KIND_BO => &[("g", Uint), ("n", Uint), ("p", Bytes), ("c", Links)],
        _ => return None,
    })
}

/// The value of one field of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// An unsigned integer.
    Uint(u64),
    /// A link, by CID.
    Link(String),
    /// Null (a `LinkOrNull` field without a link).
    Null,
    /// Links, by CID.
    Links(Vec<String>),
    /// One embedded CBOR item.
    Embedded(Vec<u8>),
    /// Embedded CBOR items.
    Embeddeds(Vec<Vec<u8>>),
    /// Unsigned integers.
    Uints(Vec<u64>),
    /// A byte string.
    Bytes(Vec<u8>),
    /// Text (also a CID as text).
    Text(String),
    /// Texts (CIDs as text).
    Texts(Vec<String>),
    /// The `db` index map: the links of `aevt`, `avet`, `eavt`.
    Index([String; 3]),
    /// One raw CBOR item in a level-2 grammar.
    Raw(Vec<u8>),
}

/// A decoded node: its kind and its other fields in canonical key order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The kind (`k`).
    pub kind: String,
    /// The other fields, in canonical key order once decoded.
    pub fields: Vec<(String, Field)>,
}

impl Node {
    /// A node of `kind` with no fields yet.
    pub fn new(kind: &str) -> Self {
        Node {
            kind: kind.to_string(),
            fields: Vec::new(),
        }
    }

    /// This node with `key` set to `value`.
    pub fn with(mut self, key: &str, value: Field) -> Self {
        self.fields.push((key.to_string(), value));
        self
    }

    /// The field under `key`.
    pub fn get(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The unsigned integer under `key`.
    pub fn uint(&self, key: &str) -> Option<u64> {
        match self.get(key) {
            Some(Field::Uint(n)) => Some(*n),
            _ => None,
        }
    }

    /// The links under `key` (an empty slice when absent).
    pub fn links(&self, key: &str) -> &[String] {
        match self.get(key) {
            Some(Field::Links(l)) => l,
            _ => &[],
        }
    }

    /// The embedded items under `key` (an empty slice when absent).
    pub fn embeddeds(&self, key: &str) -> &[Vec<u8>] {
        match self.get(key) {
            Some(Field::Embeddeds(e)) => e,
            _ => &[],
        }
    }

    /// The unsigned integers under `key` (an empty slice when absent).
    pub fn uints(&self, key: &str) -> &[u64] {
        match self.get(key) {
            Some(Field::Uints(u)) => u,
            _ => &[],
        }
    }
}

/// Canonical key order: shorter first, then bytewise.
pub fn compare_keys(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

// ------------------------------------------------------------------ links

/// The CBOR item a value slot carries for a spilled node.
pub fn link_item(cid: &str) -> Result<Vec<u8>, NodeError> {
    let mut out = Vec::with_capacity(LINK_ITEM_LENGTH);
    out.extend_from_slice(&[0xD8, 0x2A, 0x58, LINK_BYTES as u8, 0x00]);
    out.extend_from_slice(&cid::binary(cid)?);
    Ok(out)
}

/// Whether an embedded item is exactly a link item.
pub fn is_link_shaped(item: &[u8]) -> bool {
    item.len() == LINK_ITEM_LENGTH
        && item[0] == 0xD8
        && u64::from(item[1]) == LINK_TAG
        && item[2] == 0x58
        && usize::from(item[3]) == LINK_BYTES
        && item[4] == 0x00
}

/// The CID an embedded item names when it is exactly a link item.
pub fn spilled_link(item: &[u8]) -> Result<Option<String>, NodeError> {
    if !is_link_shaped(item) {
        return Ok(None);
    }
    cid::from_binary(&item[5..])
        .map(Some)
        .map_err(|e| NodeError::new(format!("spilled value link refused: {}", e.rule)))
}

fn check_embedded(key: &str, item: &[u8], key_slot: bool) -> Result<(), NodeError> {
    if !key_slot && is_link_shaped(item) {
        return Ok(());
    }
    crate::cbor::decode(item).map(|_| ()).map_err(|e| {
        let slot = if key_slot { "key item" } else { "embedded item" };
        NodeError::new(format!("'{key}' {slot} breaks the wire encoding: {e}"))
    })
}

fn keyed(kind: &str, key: &str) -> bool {
    (kind == KIND_M || kind == KIND_MC) && key == "e"
}

fn bound_of(kind: &str) -> usize {
    if kind == KIND_SN {
        MAX_SEALED_NODE_BYTES
    } else {
        MAX_NODE_BYTES
    }
}

fn kind_known(kind: &str) -> Result<(), NodeError> {
    if RESERVED_KINDS.contains(&kind) {
        return Err(NodeError::new(format!("kind '{kind}' is reserved")));
    }
    if schema(kind).is_none() {
        return Err(NodeError::new(format!("unknown kind '{kind}'")));
    }
    Ok(())
}

// ------------------------------------------------------------------ encode

/// The head of a CBOR item of `major` with `value`, in its shortest form.
pub fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value < 0x100 {
        out.extend_from_slice(&[m | 24, value as u8]);
    } else if value < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn text_item(text: &str, out: &mut Vec<u8>) {
    head(3, text.len() as u64, out);
    out.extend_from_slice(text.as_bytes());
}

/// The canonical bytes of a node: `k` and the keys of its kind's schema, in canonical order.
pub fn encode(node: &Node) -> Result<Vec<u8>, NodeError> {
    kind_known(&node.kind)?;
    let schema = schema(&node.kind).unwrap_or(&[]);
    let mut fields: Vec<(&str, &Field)> = Vec::with_capacity(node.fields.len() + 1);
    for (key, value) in &node.fields {
        if key == KIND_KEY {
            return Err(NodeError::new("the kind is the node's 'kind', not a field"));
        }
        if !schema.iter().any(|(k, _)| k == key) {
            return Err(NodeError::new(format!(
                "key '{key}' outside the schema of kind '{}'",
                node.kind
            )));
        }
        fields.push((key.as_str(), value));
    }
    let kind_field = Field::Text(node.kind.clone());
    fields.push((KIND_KEY, &kind_field));
    fields.sort_by(|a, b| compare_keys(a.0, b.0));
    for pair in fields.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(NodeError::new(format!("duplicate key '{}'", pair[0].0)));
        }
    }
    let mut out = Vec::new();
    let mut links = 0usize;
    head(5, fields.len() as u64, &mut out);
    for (key, value) in fields {
        text_item(key, &mut out);
        if key == KIND_KEY {
            text_item(&node.kind, &mut out);
            continue;
        }
        let ty = schema
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, t)| *t)
            .unwrap_or(FieldType::Raw);
        write_field(&node.kind, key, ty, value, &mut links, &mut out)?;
    }
    if out.len() > bound_of(&node.kind) {
        return Err(NodeError::new(format!(
            "node of {} bytes exceeds {} bytes",
            out.len(),
            bound_of(&node.kind)
        )));
    }
    Ok(out)
}

fn write_link(cid: &str, links: &mut usize, out: &mut Vec<u8>) -> Result<(), NodeError> {
    *links += 1;
    if *links > MAX_LINKS {
        return Err(NodeError::new(format!(
            "node has more than {MAX_LINKS} links"
        )));
    }
    out.extend_from_slice(&link_item(cid)?);
    Ok(())
}

fn write_embedded(
    key: &str,
    item: &[u8],
    key_slot: bool,
    links: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), NodeError> {
    if skip(item, 0)? != item.len() {
        return Err(NodeError::new(format!(
            "'{key}' embedded item has trailing bytes"
        )));
    }
    check_embedded(key, item, key_slot)?;
    if is_link_shaped(item) {
        *links += 1;
        if *links > MAX_LINKS {
            return Err(NodeError::new(format!(
                "node has more than {MAX_LINKS} links"
            )));
        }
    }
    out.extend_from_slice(item);
    Ok(())
}

fn mismatch(key: &str, ty: FieldType) -> NodeError {
    NodeError::new(format!("'{key}' must hold a {ty:?} field"))
}

fn write_field(
    kind: &str,
    key: &str,
    ty: FieldType,
    value: &Field,
    links: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), NodeError> {
    match (ty, value) {
        (FieldType::Uint, Field::Uint(n)) => head(0, *n, out),
        (FieldType::Link, Field::Link(c)) | (FieldType::LinkOrNull, Field::Link(c)) => {
            write_link(c, links, out)?
        }
        (FieldType::LinkOrNull, Field::Null) => out.push(0xF6),
        (FieldType::Links, Field::Links(list)) => {
            head(4, list.len() as u64, out);
            for c in list {
                write_link(c, links, out)?;
            }
        }
        (FieldType::Embedded, Field::Embedded(item)) => {
            write_embedded(key, item, false, links, out)?
        }
        (FieldType::Embeddeds, Field::Embeddeds(items)) => {
            head(4, items.len() as u64, out);
            let keyed = keyed(kind, key);
            for (i, item) in items.iter().enumerate() {
                write_embedded(key, item, keyed && i % 2 == 0, links, out)?;
            }
        }
        (FieldType::Uints, Field::Uints(list)) => {
            head(4, list.len() as u64, out);
            for n in list {
                head(0, *n, out);
            }
        }
        (FieldType::Bytes, Field::Bytes(b)) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        (FieldType::Text, Field::Text(t)) => text_item(t, out),
        (FieldType::Cid, Field::Text(t)) => {
            cid::parse(t).map_err(|e| NodeError::new(format!("'{key}': {}", e.rule)))?;
            text_item(t, out);
        }
        (FieldType::Cids, Field::Texts(list)) => {
            head(4, list.len() as u64, out);
            for t in list {
                cid::parse(t).map_err(|e| NodeError::new(format!("'{key}': {}", e.rule)))?;
                text_item(t, out);
            }
        }
        (FieldType::Index, Field::Index(links_of)) => {
            head(5, 3, out);
            for (name, c) in INDEX_KEYS.iter().zip(links_of.iter()) {
                text_item(name, out);
                write_link(c, links, out)?;
            }
        }
        (FieldType::Raw, Field::Raw(item)) => {
            if skip(item, 0)? != item.len() {
                return Err(NodeError::new(format!("'{key}' item has trailing bytes")));
            }
            *links += raw_links(item)?.len();
            if *links > MAX_LINKS {
                return Err(NodeError::new(format!(
                    "node has more than {MAX_LINKS} links"
                )));
            }
            out.extend_from_slice(item);
        }
        _ => return Err(mismatch(key, ty)),
    }
    Ok(())
}

// ------------------------------------------------------------------ decode

struct In<'a> {
    b: &'a [u8],
    p: usize,
    links: usize,
}

impl<'a> In<'a> {
    fn new(b: &'a [u8]) -> Self {
        In { b, p: 0, links: 0 }
    }

    fn peek(&self) -> Result<u8, NodeError> {
        self.b
            .get(self.p)
            .copied()
            .ok_or_else(|| NodeError::new("truncated node"))
    }

    fn u8(&mut self) -> Result<u8, NodeError> {
        let v = self.peek()?;
        self.p += 1;
        Ok(v)
    }

    fn advance(&mut self, count: u64) -> Result<(), NodeError> {
        let remaining = (self.b.len() - self.p) as u64;
        if count > remaining {
            return Err(NodeError::new("truncated node"));
        }
        self.p += count as usize;
        Ok(())
    }

    fn argument(&mut self, info: u8) -> Result<u64, NodeError> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.u8()?),
            25 => {
                let mut v = 0u64;
                for _ in 0..2 {
                    v = (v << 8) | u64::from(self.u8()?);
                }
                v
            }
            26 => {
                let mut v = 0u64;
                for _ in 0..4 {
                    v = (v << 8) | u64::from(self.u8()?);
                }
                v
            }
            27 => {
                let mut v = 0u64;
                for _ in 0..8 {
                    v = (v << 8) | u64::from(self.u8()?);
                }
                v
            }
            28..=30 => {
                return Err(NodeError::new(format!(
                    "reserved additional information {info}"
                )));
            }
            _ => return Err(NodeError::new("indefinite length in a structured field")),
        })
    }

    /// A definite head of `major` in its shortest form, at most 2^63 - 1 as Java reads it.
    fn head(&mut self, major: u8, what: &str) -> Result<u64, NodeError> {
        let initial = self.u8()?;
        if initial >> 5 != major {
            return Err(NodeError::new(format!(
                "'{what}' must be CBOR major type {major}, found major type {}",
                initial >> 5
            )));
        }
        let info = initial & 0x1F;
        if info == 31 {
            return Err(NodeError::new(format!("'{what}' uses an indefinite length")));
        }
        let value = self.argument(info)?;
        if value > i64::MAX as u64 {
            return Err(NodeError::new(format!("'{what}' integer above 2^63 - 1")));
        }
        let shortest = match info {
            24 => value >= 24,
            25 => value >= 0x100,
            26 => value >= 0x1_0000,
            27 => value >= 0x1_0000_0000,
            _ => true,
        };
        if !shortest {
            return Err(NodeError::new(format!(
                "'{what}' integer not in shortest form"
            )));
        }
        Ok(value)
    }

    fn text(&mut self, what: &str) -> Result<String, NodeError> {
        let length = self.head(3, what)?;
        let start = self.p;
        self.advance(length)?;
        std::str::from_utf8(&self.b[start..self.p])
            .map(str::to_string)
            .map_err(|_| NodeError::new(format!("'{what}' text is not well-formed UTF-8")))
    }

    fn cid_text(&mut self, what: &str) -> Result<String, NodeError> {
        let text = self.text(what)?;
        cid::parse(&text).map_err(|e| NodeError::new(format!("'{what}': {}", e.rule)))?;
        Ok(text)
    }

    fn byte_string(&mut self, what: &str) -> Result<Vec<u8>, NodeError> {
        let length = self.head(2, what)?;
        let start = self.p;
        self.advance(length)?;
        Ok(self.b[start..self.p].to_vec())
    }

    fn count_link(&mut self) -> Result<(), NodeError> {
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(NodeError::new(format!(
                "node has more than {MAX_LINKS} links"
            )));
        }
        Ok(())
    }

    fn link(&mut self, what: &str) -> Result<String, NodeError> {
        self.count_link()?;
        let tag = self.head(6, what)?;
        if tag != LINK_TAG {
            return Err(NodeError::new(format!(
                "'{what}' carries tag {tag}; a link is tag {LINK_TAG}"
            )));
        }
        let length = self.head(2, what)?;
        if length != LINK_BYTES as u64 {
            return Err(NodeError::new(format!(
                "'{what}' link of {length} bytes; a link holds 0x00 and a 36-byte CID"
            )));
        }
        if self.u8()? != 0x00 {
            return Err(NodeError::new(format!(
                "'{what}' link does not start with the 0x00 identity byte"
            )));
        }
        let start = self.p;
        self.advance(cid::BINARY_LENGTH as u64)?;
        cid::from_binary(&self.b[start..self.p])
            .map_err(|e| NodeError::new(format!("'{what}' link refused: {}", e.rule)))
    }

    fn embedded(&mut self, what: &str, key_slot: bool) -> Result<Vec<u8>, NodeError> {
        let start = self.p;
        self.p = skip(self.b, start)?;
        let item = &self.b[start..self.p];
        check_embedded(what, item, key_slot)?;
        if is_link_shaped(item) {
            self.count_link()?;
        }
        Ok(item.to_vec())
    }
}

fn skip_item(inp: &mut In<'_>, depth: usize) -> Result<(), NodeError> {
    if depth > MAX_DEPTH {
        return Err(NodeError::new(format!(
            "CBOR nesting deeper than {MAX_DEPTH} levels"
        )));
    }
    let initial = inp.u8()?;
    let (major, info) = (initial >> 5, initial & 0x1F);
    if major == 7 {
        match info {
            24 => inp.advance(1)?,
            25 => inp.advance(2)?,
            26 => inp.advance(4)?,
            27 => inp.advance(8)?,
            28..=30 => {
                return Err(NodeError::new(format!(
                    "reserved additional information {info}"
                )));
            }
            31 => return Err(NodeError::new("unexpected break code")),
            _ => {}
        }
        return Ok(());
    }
    if info == 31 {
        match major {
            2 | 3 => {
                while inp.peek()? != 0xFF {
                    let chunk = inp.u8()?;
                    if chunk >> 5 != major || chunk & 0x1F == 31 {
                        return Err(NodeError::new("malformed indefinite string chunk"));
                    }
                    let length = inp.argument(chunk & 0x1F)?;
                    inp.advance(length)?;
                }
                inp.advance(1)?;
            }
            4 => {
                while inp.peek()? != 0xFF {
                    skip_item(inp, depth + 1)?;
                }
                inp.advance(1)?;
            }
            5 => {
                while inp.peek()? != 0xFF {
                    skip_item(inp, depth + 1)?;
                    skip_item(inp, depth + 1)?;
                }
                inp.advance(1)?;
            }
            _ => {
                return Err(NodeError::new(format!(
                    "indefinite length on major type {major}"
                )));
            }
        }
        return Ok(());
    }
    let argument = inp.argument(info)?;
    match major {
        2 | 3 => inp.advance(argument)?,
        4 => {
            for _ in 0..argument {
                skip_item(inp, depth + 1)?;
            }
        }
        5 => {
            for _ in 0..argument {
                skip_item(inp, depth + 1)?;
                skip_item(inp, depth + 1)?;
            }
        }
        6 => skip_item(inp, depth + 1)?,
        _ => {}
    }
    Ok(())
}

/// The offset just past one CBOR item of any form that starts at `offset`.
pub fn skip(data: &[u8], offset: usize) -> Result<usize, NodeError> {
    let mut inp = In::new(data);
    inp.p = offset;
    skip_item(&mut inp, 0)?;
    Ok(inp.p)
}

/// The links inside one raw item of a level-2 grammar: every tag-42 item, in document order.
fn raw_links(item: &[u8]) -> Result<Vec<String>, NodeError> {
    fn walk(inp: &mut In<'_>, depth: usize, out: &mut Vec<String>) -> Result<(), NodeError> {
        if depth > MAX_DEPTH {
            return Err(NodeError::new(format!(
                "CBOR nesting deeper than {MAX_DEPTH} levels"
            )));
        }
        let initial = inp.peek()?;
        let (major, info) = (initial >> 5, initial & 0x1F);
        if major == 6 && info < 28 {
            let start = inp.p;
            inp.u8()?;
            let tag = inp.argument(info)?;
            if tag == LINK_TAG {
                inp.p = start;
                out.push(inp.link("item")?);
                return Ok(());
            }
            return walk(inp, depth + 1, out);
        }
        if (major == 4 || major == 5) && info < 28 {
            inp.u8()?;
            let count = inp.argument(info)?;
            let items = if major == 5 { count * 2 } else { count };
            for _ in 0..items {
                walk(inp, depth + 1, out)?;
            }
            return Ok(());
        }
        skip_item(inp, depth)
    }
    let mut out = Vec::new();
    let mut inp = In::new(item);
    walk(&mut inp, 0, &mut out)?;
    Ok(out)
}

/// The kind and the offset of each field of a node, after the structural checks.
fn scan(data: &[u8]) -> Result<(String, Vec<(String, usize)>), NodeError> {
    let sealed_prefix: &[u8] = b"\xa5\x61\x6b\x62\x73\x6e";
    if data.len() > MAX_NODE_BYTES && !data.starts_with(sealed_prefix) {
        return Err(NodeError::new(format!(
            "node of {} bytes exceeds {MAX_NODE_BYTES} bytes (1 MiB)",
            data.len()
        )));
    }
    if data.len() > MAX_SEALED_NODE_BYTES {
        return Err(NodeError::new(format!(
            "node of {} bytes exceeds {MAX_SEALED_NODE_BYTES} bytes (1 MiB + 48 KiB)",
            data.len()
        )));
    }
    let mut inp = In::new(data);
    let entries = inp.head(5, "node")?;
    let mut kind = None;
    let mut offsets: Vec<(String, usize)> = Vec::new();
    for _ in 0..entries {
        let key = inp.text("key")?;
        if let Some((previous, _)) = offsets.last() {
            match compare_keys(previous, &key) {
                std::cmp::Ordering::Equal => {
                    return Err(NodeError::new(format!("duplicate key '{key}'")));
                }
                std::cmp::Ordering::Greater => {
                    return Err(NodeError::new(format!(
                        "keys out of canonical order: '{key}' after '{previous}'"
                    )));
                }
                std::cmp::Ordering::Less => {}
            }
        }
        offsets.push((key.clone(), inp.p));
        if key == KIND_KEY {
            kind = Some(inp.text(KIND_KEY)?);
        } else {
            skip_item(&mut inp, 0)?;
        }
    }
    if inp.p != data.len() {
        return Err(NodeError::new("trailing bytes after the node map"));
    }
    let kind = kind.ok_or_else(|| NodeError::new(format!("node has no '{KIND_KEY}' field")))?;
    kind_known(&kind)?;
    if data.len() > bound_of(&kind) {
        return Err(NodeError::new(format!(
            "node of {} bytes exceeds {MAX_NODE_BYTES} bytes (1 MiB)",
            data.len()
        )));
    }
    Ok((kind, offsets))
}

fn read_field(
    inp: &mut In<'_>,
    kind: &str,
    key: &str,
    ty: FieldType,
) -> Result<Field, NodeError> {
    Ok(match ty {
        FieldType::Uint => Field::Uint(inp.head(0, key)?),
        FieldType::Link => Field::Link(inp.link(key)?),
        FieldType::LinkOrNull => {
            if inp.peek()? == 0xF6 {
                inp.u8()?;
                Field::Null
            } else {
                Field::Link(inp.link(key)?)
            }
        }
        FieldType::Links => {
            let n = inp.head(4, key)?;
            let mut out = Vec::new();
            for _ in 0..n {
                out.push(inp.link(key)?);
            }
            Field::Links(out)
        }
        FieldType::Embedded => Field::Embedded(inp.embedded(key, false)?),
        FieldType::Embeddeds => {
            let n = inp.head(4, key)?;
            let keyed = keyed(kind, key);
            let mut out = Vec::new();
            for i in 0..n {
                out.push(inp.embedded(key, keyed && i % 2 == 0)?);
            }
            Field::Embeddeds(out)
        }
        FieldType::Uints => {
            let n = inp.head(4, key)?;
            let mut out = Vec::new();
            for _ in 0..n {
                out.push(inp.head(0, key)?);
            }
            Field::Uints(out)
        }
        FieldType::Bytes => Field::Bytes(inp.byte_string(key)?),
        FieldType::Text => Field::Text(inp.text(key)?),
        FieldType::Cid => Field::Text(inp.cid_text(key)?),
        FieldType::Cids => {
            let n = inp.head(4, key)?;
            let mut out = Vec::new();
            for _ in 0..n {
                out.push(inp.cid_text(key)?);
            }
            Field::Texts(out)
        }
        FieldType::Index => {
            let refuse =
                || NodeError::new(format!("'{key}' must map exactly aevt, avet and eavt to links, in that order"));
            if inp.head(5, key)? != 3 {
                return Err(refuse());
            }
            let mut links: [String; 3] = Default::default();
            for (i, expected) in INDEX_KEYS.iter().enumerate() {
                if inp.text(key)? != *expected {
                    return Err(refuse());
                }
                links[i] = inp.link(key)?;
            }
            Field::Index(links)
        }
        FieldType::Raw => {
            let start = inp.p;
            if inp.peek()? >> 5 != 4 {
                return Err(NodeError::new(format!("'{key}' must be a list")));
            }
            inp.p = skip(inp.b, start)?;
            let item = inp.b[start..inp.p].to_vec();
            for _ in raw_links(&item)? {
                inp.count_link()?;
            }
            Field::Raw(item)
        }
    })
}

/// A node in canonical key order; `cid`, when given, names the node in a refusal.
pub fn decode(data: &[u8], cid: Option<&str>) -> Result<Node, NodeError> {
    decode_inner(data).map_err(|e| e.with_cid(cid))
}

fn decode_inner(data: &[u8]) -> Result<Node, NodeError> {
    let (kind, offsets) = scan(data)?;
    let schema = schema(&kind).unwrap_or(&[]);
    let mut inp = In::new(data);
    let mut node = Node::new(&kind);
    for (key, offset) in offsets {
        if key == KIND_KEY {
            continue;
        }
        let ty = schema
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, t)| *t)
            .ok_or_else(|| {
                NodeError::new(format!("key '{key}' outside the schema of kind '{kind}'"))
            })?;
        inp.p = offset;
        let field = read_field(&mut inp, &kind, &key, ty)?;
        node.fields.push((key, field));
    }
    Ok(node)
}

/// The kind of a node, after the structural checks.
pub fn kind_of(data: &[u8]) -> Result<String, NodeError> {
    scan(data).map(|(kind, _)| kind)
}

/// The linked CIDs of a node in field order, spilled-value links included; none for a raw
/// chunk (whose CID has the raw codec).
pub fn links(data: &[u8], cid: Option<&str>) -> Result<Vec<String>, NodeError> {
    if cid.is_some_and(|c| cid::codec_of(c) == Some(cid::RAW)) {
        return Ok(Vec::new());
    }
    let node = decode(data, cid)?;
    node_links(&node).map_err(|e| e.with_cid(cid))
}

/// The linked CIDs of a decoded node, in field order.
pub fn node_links(node: &Node) -> Result<Vec<String>, NodeError> {
    let mut out = Vec::new();
    for (key, field) in &node.fields {
        match field {
            Field::Embedded(item) => {
                if let Some(c) = spilled_link(item)? {
                    out.push(c);
                }
            }
            Field::Embeddeds(items) => {
                let keyed = keyed(&node.kind, key);
                for (i, item) in items.iter().enumerate() {
                    if keyed && i % 2 == 0 {
                        continue;
                    }
                    if let Some(c) = spilled_link(item)? {
                        out.push(c);
                    }
                }
            }
            Field::Link(c) => out.push(c.clone()),
            Field::Links(list) => out.extend(list.iter().cloned()),
            Field::Index(list) => out.extend(list.iter().cloned()),
            Field::Raw(item) => out.extend(raw_links(item)?),
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_map_node_round_trips() {
        let node = Node::new(KIND_M)
            .with("d", Field::Uint(0))
            .with("n", Field::Uint(0))
            .with("e", Field::Embeddeds(vec![]))
            .with("c", Field::Links(vec![]))
            .with("cnt", Field::Uint(0));
        let bytes = encode(&node).unwrap();
        assert_eq!(bytes[0], 0xA6);
        let back = decode(&bytes, None).unwrap();
        assert_eq!(encode(&back).unwrap(), bytes);
    }

    #[test]
    fn refuses_out_of_order_and_unknown() {
        // {"k": "m", "c": []}: keys out of order
        let bad = [0xA2, 0x61, b'k', 0x61, b'm', 0x61, b'c', 0x80];
        assert!(decode(&bad, None).unwrap_err().rule.contains("canonical order"));
        let reserved = [0xA1, 0x61, b'k', 0x61, b's'];
        assert!(decode(&reserved, None).unwrap_err().rule.contains("reserved"));
        let unknown = [0xA1, 0x61, b'k', 0x61, b'q'];
        assert!(decode(&unknown, None).unwrap_err().rule.contains("unknown kind"));
    }

    #[test]
    fn refuses_a_link_in_a_key_slot() {
        let link = link_item(&cid::of(b"x", cid::RAW)).unwrap();
        let node = Node::new(KIND_MC).with("e", Field::Embeddeds(vec![link.clone(), vec![0x01]]));
        assert!(encode(&node).is_err());
        let ok = Node::new(KIND_MC).with("e", Field::Embeddeds(vec![vec![0x61, b'a'], link]));
        let bytes = encode(&ok).unwrap();
        assert_eq!(links(&bytes, None).unwrap().len(), 1);
    }
}
