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

//! Value slots and spill (annex H, spill; Python `pdt/values.py`).
//!
//! A map entry, a vector element, or a vector tail item is a [`Slot`]: a CBOR item held inline,
//! or a spilled node. An embedded value whose CBOR exceeds 1 KiB moves into its own `x` node; a
//! map, array, or byte string above 4 KiB becomes a sub-tree (`m`, `vr`, or a blob) and is
//! linked. Only an indefinite-length map or a definite array spills to a sub-tree, so reassembly
//! is byte-identical to the entry codec's output. An indefinite map whose keys are out of
//! canonical order spills as an `x` envelope that links a `vr` of its keys and values, which
//! keeps their order. Keys never spill. A value whose `x` node would exceed 1 MiB is refused.

use std::sync::Arc;

use super::champ::ChampNode;
use super::node::{self, Field, KIND_B, KIND_M, KIND_T, KIND_VR, KIND_X, MAX_DEPTH, Node};
use super::store::{Flusher, Nodes};
use super::vector::VecRoot;
use super::{NodeError, PdtError, Result, blob, cid};

/// An embedded value above this many bytes spills into an `x` node.
pub const VALUE_LIMIT: usize = 1024;
/// A map, array, or byte string above this many bytes spills into a sub-tree.
pub const TREE_LIMIT: usize = 4096;
/// The largest item an `x` node holds under the 1 MiB node bound.
pub const MAX_X_VALUE: usize = node::MAX_NODE_BYTES - 7;

/// A value in a slot: inline, stored as a spilled node, or a spilled node not yet written.
#[derive(Clone, Debug)]
pub enum Slot {
    /// A CBOR item held in the slot.
    Inline(Arc<[u8]>),
    /// A spilled node held in a store, by CID.
    Stored(String),
    /// A pending `x` node over this item.
    X(Arc<[u8]>),
    /// A pending sub-map (its root carries `cnt`).
    Map(Arc<ChampNode>),
    /// A pending sub-vector.
    Vector(Arc<VecRoot>),
    /// A pending ordered map: an `x` envelope linking a `vr` of keys and values.
    Ordered(Arc<VecRoot>),
    /// A pending blob over these bytes (a spilled byte string's content).
    Blob(Arc<[u8]>),
}

impl Slot {
    /// The item a parent node carries for this slot, writing any pending node.
    pub fn embed(&self, flusher: &mut Flusher<'_>) -> Result<Vec<u8>> {
        match self {
            Slot::Inline(item) => Ok(item.to_vec()),
            other => Ok(node::link_item(&other.flush(flusher)?)?),
        }
    }

    /// The CID of a spilled slot, writing it when pending; an inline slot has none.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        match self {
            Slot::Inline(_) => Err(PdtError::Invalid(
                "an inline value has no node".to_string(),
            )),
            Slot::Stored(c) => Ok(c.clone()),
            Slot::X(item) => write_x(item, flusher),
            Slot::Map(map) => map.flush(flusher),
            Slot::Vector(vector) => vector.flush(flusher),
            Slot::Ordered(items) => {
                let vr = items.flush(flusher)?;
                write_x(&node::link_item(&vr)?, flusher)
            }
            Slot::Blob(content) => Ok(blob::write_bytes(content, flusher)?.root),
        }
    }

    /// Whether two slots surely hold the same value without loading anything.
    pub fn same(&self, other: &Slot) -> bool {
        match (self, other) {
            (Slot::Inline(a), Slot::Inline(b)) => a == b,
            (Slot::Stored(a), Slot::Stored(b)) => a == b,
            (Slot::X(a), Slot::X(b)) => a == b,
            (Slot::Blob(a), Slot::Blob(b)) => a == b,
            _ => false,
        }
    }

    /// The CBOR bytes of this value, loading and reassembling a spilled node.
    pub fn resolve(&self, store: &dyn Nodes) -> Result<Vec<u8>> {
        resolve(self, store, 0)
    }
}

fn write_x(item: &[u8], flusher: &mut Flusher<'_>) -> Result<String> {
    let bytes = node::encode(&Node::new(KIND_X).with("v", Field::Embedded(item.to_vec())))?;
    Ok(flusher.write(bytes, cid::DAG_CBOR))
}

/// Refuses a key that is a bare link item: keys never spill.
pub fn check_key(key: &[u8]) -> Result<()> {
    if node::is_link_shaped(key) {
        return Err(PdtError::Invalid(
            "a key must not be a bare link item (CBOR tag 42 over a CID)".to_string(),
        ));
    }
    Ok(())
}

/// The slot an embedded item read from a node stands for: a spilled node or the item itself.
pub fn ref_of(item: &[u8]) -> Result<Slot> {
    Ok(match node::spilled_link(item)? {
        Some(c) => Slot::Stored(c),
        None => Slot::Inline(Arc::from(item)),
    })
}

fn header_length(info: u8) -> usize {
    if info < 24 { 1 } else { 1 + (1 << (info - 24)) }
}

/// Applies the spill rules to one encoded value: inline, or a pending spill node.
pub fn spill(item: &[u8]) -> Result<Slot> {
    if node::is_link_shaped(item) {
        return Err(PdtError::Invalid(
            "a value must not be a bare link item (CBOR tag 42 over a CID): a link item in a value \
             slot names a spilled node; hold a CID as text"
                .to_string(),
        ));
    }
    if item.len() <= VALUE_LIMIT {
        return Ok(Slot::Inline(Arc::from(item)));
    }
    let (major, info) = (item[0] >> 5, item[0] & 0x1F);
    if item.len() > TREE_LIMIT {
        if major == 5 && info == 31 {
            return if canonical_keys(item)? {
                Ok(Slot::Map(Arc::new(sub_map(item)?)))
            } else {
                Ok(Slot::Ordered(Arc::new(sub_ordered(item)?)))
            };
        }
        if major == 4 && info != 31 {
            return Ok(Slot::Vector(Arc::new(sub_vector(item)?)));
        }
        if major == 2 && info != 31 {
            return Ok(Slot::Blob(Arc::from(&item[header_length(info)..])));
        }
    }
    if item.len() > MAX_X_VALUE {
        return Err(PdtError::Invalid(format!(
            "a value of {} CBOR bytes exceeds the {MAX_X_VALUE} bytes an x node can hold under \
             the 1 MiB node bound; store a value this large as a byte string, which becomes a \
             blob, or split it into a map or a vector",
            item.len()
        )));
    }
    Ok(Slot::X(Arc::from(item)))
}

/// The key and value items of an indefinite map, in written order.
fn map_items(item: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    let mut out = Vec::new();
    let mut p = 1;
    while p < item.len() && item[p] != 0xFF {
        let key_end = node::skip(item, p)?;
        let value_end = node::skip(item, key_end)?;
        out.push((&item[p..key_end], &item[key_end..value_end]));
        p = value_end;
    }
    Ok(out)
}

/// Whether an indefinite map's keys come in canonical order (shorter first, then bytewise).
pub fn canonical_keys(item: &[u8]) -> Result<bool> {
    let mut previous: Option<&[u8]> = None;
    for (key, _) in map_items(item)? {
        if let Some(prev) = previous
            && (prev.len(), prev) >= (key.len(), key)
        {
            return Ok(false);
        }
        previous = Some(key);
    }
    Ok(true)
}

fn sub_map(item: &[u8]) -> Result<ChampNode> {
    let mut root = ChampNode::empty();
    let mut count = 0u64;
    let store = super::store::MemoryNodes::new();
    for (key, value) in map_items(item)? {
        check_key(key)?;
        let (next, change) = root.assoc(&super::sha256(key), 0, key, spill(value)?, &store)?;
        if let Some(next) = next {
            root = next;
        }
        if change == super::champ::Change::Added {
            count += 1;
        }
    }
    root.cnt = Some(count);
    Ok(root)
}

fn sub_ordered(item: &[u8]) -> Result<VecRoot> {
    let store = super::store::MemoryNodes::new();
    let mut items = VecRoot::empty();
    for (key, value) in map_items(item)? {
        check_key(key)?;
        items = items.conj(spill(key)?, &store)?;
        items = items.conj(spill(value)?, &store)?;
    }
    Ok(items)
}

fn sub_vector(item: &[u8]) -> Result<VecRoot> {
    let store = super::store::MemoryNodes::new();
    let info = item[0] & 0x1F;
    let mut p = 1;
    let n = if info < 24 {
        u64::from(info)
    } else {
        let width = 1usize << (info - 24);
        let mut n = 0u64;
        for b in &item[1..1 + width] {
            n = (n << 8) | u64::from(*b);
        }
        p += width;
        n
    };
    let mut root = VecRoot::empty();
    for _ in 0..n {
        let end = node::skip(item, p)?;
        root = root.conj(spill(&item[p..end])?, &store)?;
        p = end;
    }
    Ok(root)
}

/// The CBOR item of a byte string over `raw`.
pub fn byte_string(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 9);
    node::head(2, raw.len() as u64, &mut out);
    out.extend_from_slice(raw);
    out
}

fn too_deep(cid: Option<&str>) -> PdtError {
    let e = NodeError::new(format!("spilled values nested deeper than {MAX_DEPTH} levels"));
    PdtError::Node(e.with_cid(cid))
}

/// The CBOR bytes of a slot, loading and reassembling spilled nodes.
pub fn resolve(slot: &Slot, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    if depth > MAX_DEPTH {
        return Err(too_deep(None));
    }
    match slot {
        Slot::Inline(item) => Ok(item.to_vec()),
        Slot::Blob(content) => Ok(byte_string(content)),
        Slot::X(item) => match node::spilled_link(item)? {
            Some(c) => resolve_linked(&c, store, depth + 1),
            None => Ok(item.to_vec()),
        },
        Slot::Ordered(items) => reassemble_ordered(items, store, depth),
        Slot::Map(map) => reassemble_map(map, store, depth),
        Slot::Vector(vector) => reassemble_array(vector, store, depth),
        Slot::Stored(c) => resolve_cid(c, store, depth),
    }
}

/// The CBOR bytes of the spilled node `cid`.
pub fn resolve_cid(c: &str, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    if depth > MAX_DEPTH {
        return Err(too_deep(Some(c)));
    }
    let data = store.load(c)?;
    if cid::codec_of(c) == Some(cid::RAW) {
        return Ok(byte_string(&data));
    }
    let kind = node::kind_of(&data).map_err(|e| e.with_cid(Some(c)))?;
    match kind.as_str() {
        KIND_X => {
            let n = node::decode(&data, Some(c))?;
            let Some(Field::Embedded(value)) = n.get("v") else {
                return Err(NodeError::at("x node without a value", c).into());
            };
            match node::spilled_link(value)? {
                Some(linked) => resolve_linked(&linked, store, depth + 1),
                None => Ok(value.clone()),
            }
        }
        KIND_M => reassemble_map(&ChampNode::load_root(c, &data)?, store, depth),
        KIND_VR => reassemble_array(&VecRoot::decode(c, &data)?, store, depth),
        KIND_B => Ok(byte_string(&blob::read_all(store, c)?)),
        KIND_T => Err(NodeError::at("a level-one tree holds no text node", c).into()),
        other => Err(NodeError::at(format!("a spilled value cannot be a node of kind '{other}'"), c).into()),
    }
}

fn resolve_linked(c: &str, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    if depth > MAX_DEPTH {
        return Err(too_deep(Some(c)));
    }
    let data = store.load(c)?;
    if cid::codec_of(c) == Some(cid::RAW) {
        return Ok(byte_string(&data));
    }
    let kind = node::kind_of(&data).map_err(|e| e.with_cid(Some(c)))?;
    match kind.as_str() {
        KIND_VR => reassemble_ordered(&VecRoot::decode(c, &data)?, store, depth),
        KIND_B => Ok(byte_string(&blob::read_all(store, c)?)),
        other => Err(NodeError::at(format!("an x envelope links a node of kind '{other}'"), c).into()),
    }
}

fn reassemble_ordered(root: &VecRoot, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    let n = root.count();
    if !n.is_multiple_of(2) {
        return Err(PdtError::Node(NodeError::new(format!(
            "an ordered-map envelope links a vector of {n} items; keys and values pair up"
        ))));
    }
    let mut out = vec![0xBF];
    for i in 0..n {
        out.extend(resolve(&root.nth(i, store)?, store, depth + 1)?);
    }
    out.push(0xFF);
    Ok(out)
}

fn reassemble_map(root: &ChampNode, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    let mut entries = root.entries(0, store)?;
    entries.sort_by(|a, b| (a.0.len(), &a.0[..]).cmp(&(b.0.len(), &b.0[..])));
    let mut out = vec![0xBF];
    for (key, value) in entries {
        out.extend_from_slice(&key);
        out.extend(resolve(&value, store, depth + 1)?);
    }
    out.push(0xFF);
    Ok(out)
}

fn reassemble_array(root: &VecRoot, store: &dyn Nodes, depth: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    node::head(4, root.count(), &mut out);
    for i in 0..root.count() {
        out.extend(resolve(&root.nth(i, store)?, store, depth + 1)?);
    }
    Ok(out)
}
