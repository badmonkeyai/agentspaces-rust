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

//! `PMap` and `PSet`, the CHAMP trie of annex H (maps and sets; Python `pdt/champ.py`).
//!
//! The hash of a key is sha2-256 of the key's canonical CBOR; level `d` reads bits `5d` to
//! `5d+4` of the digest as a big-endian bit string. A node is `{k:"m", d, n, e, c}`: `d` marks the
//! slots that hold an entry inline, `n` the slots that hold a child, `e` lists entries in
//! ascending slot order, `c` children in ascending slot order; the root alone adds `cnt`. After a
//! removal a child with one entry and no children inlines into its parent, so the layout depends
//! only on the key set and equal maps have equal roots. Past level 51 keys sit in an `mc` node
//! sorted by key bytes. A set is a map whose every value is null.
//!
//! Every operation returns a new value and leaves the receiver unchanged; new nodes live in
//! memory until [`PMap::flush`] writes them.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::node::{self, Field, KIND_M, KIND_MC, Node};
use super::store::{Flusher, Nodes, Written};
use super::value::{self, Slot};
use super::{NodeError, PdtError, Result, cid, sha256};

/// The level at which keys sit in a collision node.
pub const COLLISION_LEVEL: usize = 52;

/// The five-bit slot of a digest at a level.
pub fn index(digest: &[u8; 32], level: usize) -> u32 {
    let first = level * 5;
    let mut idx = 0u32;
    for i in 0..5 {
        let bit = first + i;
        let v = if bit < 256 {
            (digest[bit >> 3] >> (7 - (bit & 7))) & 1
        } else {
            0
        };
        idx = (idx << 1) | u32::from(v);
    }
    idx
}

fn popcount_below(mask: u32, bit: u32) -> usize {
    (mask & (bit - 1)).count_ones() as usize
}

/// What an `assoc` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Nothing: the key held the same value.
    None,
    /// A new key.
    Added,
    /// A new value for a key.
    Replaced,
}

/// A child of a map node: stored, or in memory.
#[derive(Clone, Debug)]
pub enum Child {
    /// A stored node, by CID.
    Stored(String),
    /// A node in memory.
    Mem(Arc<ChampNode>),
}

/// A node of the trie: kind `m` or, past level 51, `mc`.
#[derive(Clone, Debug, Default)]
pub struct ChampNode {
    collision: bool,
    datamap: u32,
    nodemap: u32,
    keys: Vec<Arc<[u8]>>,
    values: Vec<Slot>,
    children: Vec<Child>,
    /// The entry count a root carries (`cnt`).
    pub cnt: Option<u64>,
    cid: Option<String>,
}

impl ChampNode {
    /// The empty node.
    pub fn empty() -> Self {
        Self::default()
    }

    fn copy(&self) -> Self {
        ChampNode {
            cid: None,
            cnt: None,
            ..self.clone()
        }
    }

    fn data_index(&self, bit: u32) -> usize {
        popcount_below(self.datamap, bit)
    }

    fn node_index(&self, bit: u32) -> usize {
        popcount_below(self.nodemap, bit)
    }

    fn single_entry(&self) -> bool {
        self.keys.len() == 1 && self.children.is_empty()
    }

    fn child(&self, i: usize, level: usize, store: &dyn Nodes) -> Result<Arc<ChampNode>> {
        match &self.children[i] {
            Child::Mem(node) => Ok(node.clone()),
            Child::Stored(c) => Ok(Arc::new(ChampNode::load(c, level, store)?)),
        }
    }

    /// A stored node at `level`, verified for its level.
    pub fn load(c: &str, level: usize, store: &dyn Nodes) -> Result<ChampNode> {
        let data = store.load(c)?;
        let node = ChampNode::decode(c, &data, false)?;
        node.verify_at(level)?;
        Ok(node)
    }

    /// A root node from its bytes, verified at level 0.
    pub fn load_root(c: &str, data: &[u8]) -> Result<ChampNode> {
        let node = ChampNode::decode(c, data, true)?;
        node.verify_at(0)?;
        Ok(node)
    }

    fn verify_at(&self, level: usize) -> Result<()> {
        let cid = self.cid.as_deref().unwrap_or("");
        if self.collision && level < COLLISION_LEVEL {
            return Err(NodeError::at(
                format!("collision node at level {level}; keys collide only past level {}", COLLISION_LEVEL - 1),
                cid,
            )
            .into());
        }
        if !self.collision && level >= COLLISION_LEVEL {
            return Err(NodeError::at(
                format!("map node at level {level}; keys past level {} sit in a collision node", COLLISION_LEVEL - 1),
                cid,
            )
            .into());
        }
        if self.collision {
            return Ok(());
        }
        let mut remaining = self.datamap;
        for (i, key) in self.keys.iter().enumerate() {
            let slot = remaining.trailing_zeros();
            remaining &= remaining - 1;
            let named = index(&sha256(key), level);
            if named != slot {
                return Err(NodeError::at(
                    format!("entry {i} sits in slot {slot} at level {level} where its key digest names slot {named}"),
                    cid,
                )
                .into());
            }
        }
        Ok(())
    }

    /// The slot of `key` under this node, if any.
    pub fn find(&self, digest: &[u8; 32], level: usize, key: &[u8], store: &dyn Nodes) -> Result<Option<Slot>> {
        let mut holder: Arc<ChampNode>;
        let mut node = self;
        let mut level = level;
        loop {
            if node.collision {
                return Ok(node
                    .keys
                    .iter()
                    .position(|k| &k[..] == key)
                    .map(|i| node.values[i].clone()));
            }
            let bit = 1u32 << index(digest, level);
            if node.datamap & bit != 0 {
                let i = node.data_index(bit);
                return Ok((&node.keys[i][..] == key).then(|| node.values[i].clone()));
            }
            if node.nodemap & bit != 0 {
                level += 1;
                holder = node.child(node.node_index(bit), level, store)?;
                node = &*holder;
                continue;
            }
            return Ok(None);
        }
    }

    /// Every (key, slot) under this node: entries before children, in slot order.
    pub fn entries(&self, level: usize, store: &dyn Nodes) -> Result<Vec<(Arc<[u8]>, Slot)>> {
        let mut out = Vec::new();
        self.collect(level, store, &mut out)?;
        Ok(out)
    }

    fn collect(&self, level: usize, store: &dyn Nodes, out: &mut Vec<(Arc<[u8]>, Slot)>) -> Result<()> {
        if level > node::MAX_DEPTH {
            return Err(NodeError::new("map deeper than 64 levels").into());
        }
        out.extend(self.keys.iter().cloned().zip(self.values.iter().cloned()));
        for i in 0..self.children.len() {
            self.child(i, level + 1, store)?.collect(level + 1, store, out)?;
        }
        Ok(())
    }

    /// This node with `key` set to `value`: the new node (None when unchanged) and the change.
    pub fn assoc(
        &self,
        digest: &[u8; 32],
        level: usize,
        key: &[u8],
        value: Slot,
        store: &dyn Nodes,
    ) -> Result<(Option<ChampNode>, Change)> {
        if self.collision {
            return Ok(self.assoc_collision(key, value));
        }
        let bit = 1u32 << index(digest, level);
        if self.datamap & bit != 0 {
            let i = self.data_index(bit);
            if &self.keys[i][..] == key {
                if self.values[i].same(&value) {
                    return Ok((None, Change::None));
                }
                let mut n = self.copy();
                n.values[i] = value;
                return Ok((Some(n), Change::Replaced));
            }
            let other_digest = sha256(&self.keys[i]);
            let sub = merge_two(
                self.keys[i].clone(),
                self.values[i].clone(),
                &other_digest,
                Arc::from(key),
                value,
                digest,
                level + 1,
            );
            let mut n = self.copy();
            n.keys.remove(i);
            n.values.remove(i);
            n.datamap &= !bit;
            n.nodemap |= bit;
            let at = n.node_index(bit);
            n.children.insert(at, Child::Mem(Arc::new(sub)));
            return Ok((Some(n), Change::Added));
        }
        if self.nodemap & bit != 0 {
            let i = self.node_index(bit);
            let child = self.child(i, level + 1, store)?;
            let (next, change) = child.assoc(digest, level + 1, key, value, store)?;
            let Some(next) = next else {
                return Ok((None, change));
            };
            let mut n = self.copy();
            n.children[i] = Child::Mem(Arc::new(next));
            return Ok((Some(n), change));
        }
        let mut n = self.copy();
        n.datamap |= bit;
        let at = n.data_index(bit);
        n.keys.insert(at, Arc::from(key));
        n.values.insert(at, value);
        Ok((Some(n), Change::Added))
    }

    fn assoc_collision(&self, key: &[u8], value: Slot) -> (Option<ChampNode>, Change) {
        let mut pos = 0;
        while pos < self.keys.len() {
            let k = &self.keys[pos][..];
            if k == key {
                if self.values[pos].same(&value) {
                    return (None, Change::None);
                }
                let mut n = self.copy();
                n.values[pos] = value;
                return (Some(n), Change::Replaced);
            }
            if k > key {
                break;
            }
            pos += 1;
        }
        let mut n = self.copy();
        n.keys.insert(pos, Arc::from(key));
        n.values.insert(pos, value);
        (Some(n), Change::Added)
    }

    /// This node without `key`: the new node and the removed slot, or None when absent.
    pub fn dissoc(&self, digest: &[u8; 32], level: usize, key: &[u8], store: &dyn Nodes) -> Result<Option<(ChampNode, Slot)>> {
        if self.collision {
            return Ok(self.keys.iter().position(|k| &k[..] == key).map(|i| {
                let mut n = self.copy();
                n.keys.remove(i);
                let removed = n.values.remove(i);
                (n, removed)
            }));
        }
        let bit = 1u32 << index(digest, level);
        if self.datamap & bit != 0 {
            let i = self.data_index(bit);
            if &self.keys[i][..] != key {
                return Ok(None);
            }
            let mut n = self.copy();
            n.keys.remove(i);
            let removed = n.values.remove(i);
            n.datamap &= !bit;
            return Ok(Some((n, removed)));
        }
        if self.nodemap & bit != 0 {
            let i = self.node_index(bit);
            let child = self.child(i, level + 1, store)?;
            let Some((next, removed)) = child.dissoc(digest, level + 1, key, store)? else {
                return Ok(None);
            };
            let mut n = self.copy();
            if next.single_entry() {
                n.children.remove(i);
                n.nodemap &= !bit;
                n.datamap |= bit;
                let at = n.data_index(bit);
                n.keys.insert(at, next.keys[0].clone());
                n.values.insert(at, next.values[0].clone());
                return Ok(Some((n, removed)));
            }
            n.children[i] = Child::Mem(Arc::new(next));
            return Ok(Some((n, removed)));
        }
        Ok(None)
    }

    /// The canonical bytes of this node, writing every pending node below it.
    pub fn encode(&self, flusher: &mut Flusher<'_>) -> Result<Vec<u8>> {
        let mut entries = Vec::with_capacity(self.keys.len() * 2);
        for (k, v) in self.keys.iter().zip(&self.values) {
            entries.push(k.to_vec());
            entries.push(v.embed(flusher)?);
        }
        if self.collision {
            return Ok(node::encode(&Node::new(KIND_MC).with("e", Field::Embeddeds(entries)))?);
        }
        let mut children = Vec::with_capacity(self.children.len());
        for c in &self.children {
            children.push(match c {
                Child::Stored(c) => c.clone(),
                Child::Mem(n) => n.flush(flusher)?,
            });
        }
        let mut n = Node::new(KIND_M)
            .with("d", Field::Uint(u64::from(self.datamap)))
            .with("n", Field::Uint(u64::from(self.nodemap)))
            .with("e", Field::Embeddeds(entries))
            .with("c", Field::Links(children));
        if let Some(cnt) = self.cnt {
            n = n.with("cnt", Field::Uint(cnt));
        }
        Ok(node::encode(&n)?)
    }

    /// Writes this node and every pending node below it; returns its CID.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        if let Some(c) = &self.cid {
            return Ok(c.clone());
        }
        let bytes = self.encode(flusher)?;
        Ok(flusher.write(bytes, cid::DAG_CBOR))
    }

    /// A node from its bytes; `root` allows `cnt`.
    pub fn decode(c: &str, data: &[u8], root: bool) -> Result<ChampNode> {
        let n = node::decode(data, Some(c))?;
        if n.kind != KIND_M && n.kind != KIND_MC {
            return Err(NodeError::at(format!("expected a map node, found kind '{}'", n.kind), c).into());
        }
        let e = n.embeddeds("e");
        if e.len() % 2 != 0 {
            return Err(NodeError::at(format!("entry list has an odd length {}", e.len()), c).into());
        }
        let mut keys = Vec::with_capacity(e.len() / 2);
        let mut values = Vec::with_capacity(e.len() / 2);
        for (i, pair) in e.chunks(2).enumerate() {
            if node::is_link_shaped(&pair[0]) {
                return Err(NodeError::at(format!("entry {i} has a bare link item as its key; keys never spill"), c).into());
            }
            keys.push(Arc::from(&pair[0][..]));
            values.push(value::ref_of(&pair[1])?);
        }
        let cnt = n.uint("cnt");
        if cnt.is_some() && !root {
            return Err(NodeError::at("'cnt' on a node that is not a map root", c).into());
        }
        if n.kind == KIND_MC {
            if keys.windows(2).any(|w| w[0] >= w[1]) {
                return Err(NodeError::at("collision node keys out of order", c).into());
            }
            return Ok(ChampNode {
                collision: true,
                keys,
                values,
                cid: Some(c.to_string()),
                ..Default::default()
            });
        }
        let datamap = n.uint("d").unwrap_or(0);
        let nodemap = n.uint("n").unwrap_or(0);
        if datamap > u64::from(u32::MAX) || nodemap > u64::from(u32::MAX) {
            return Err(NodeError::at("datamap or nodemap above 32 bits", c).into());
        }
        let (datamap, nodemap) = (datamap as u32, nodemap as u32);
        if datamap & nodemap != 0 {
            return Err(NodeError::at("datamap and nodemap share a slot", c).into());
        }
        if datamap.count_ones() as usize != keys.len() {
            return Err(NodeError::at(
                format!("datamap names {} slots for {} entries", datamap.count_ones(), keys.len()),
                c,
            )
            .into());
        }
        let links = n.links("c");
        if nodemap.count_ones() as usize != links.len() {
            return Err(NodeError::at(
                format!("nodemap names {} slots for {} children", nodemap.count_ones(), links.len()),
                c,
            )
            .into());
        }
        Ok(ChampNode {
            collision: false,
            datamap,
            nodemap,
            keys,
            values,
            children: links.iter().cloned().map(Child::Stored).collect(),
            cnt,
            cid: Some(c.to_string()),
        })
    }
}

fn merge_two(
    k1: Arc<[u8]>,
    v1: Slot,
    d1: &[u8; 32],
    k2: Arc<[u8]>,
    v2: Slot,
    d2: &[u8; 32],
    level: usize,
) -> ChampNode {
    if level >= COLLISION_LEVEL {
        let (keys, values) = if k1 < k2 { (vec![k1, k2], vec![v1, v2]) } else { (vec![k2, k1], vec![v2, v1]) };
        return ChampNode {
            collision: true,
            keys,
            values,
            ..Default::default()
        };
    }
    let (i1, i2) = (index(d1, level), index(d2, level));
    if i1 != i2 {
        let (keys, values) = if i1 < i2 { (vec![k1, k2], vec![v1, v2]) } else { (vec![k2, k1], vec![v2, v1]) };
        return ChampNode {
            datamap: (1 << i1) | (1 << i2),
            keys,
            values,
            ..Default::default()
        };
    }
    let sub = merge_two(k1, v1, d1, k2, v2, d2, level + 1);
    ChampNode {
        nodemap: 1 << i1,
        children: vec![Child::Mem(Arc::new(sub))],
        ..Default::default()
    }
}

/// One key's change between two maps: the slot before (None when added) and after (None when
/// removed).
pub type Changed = (Option<Slot>, Option<Slot>);

fn diff_raw(
    mine: &ChampNode,
    base: &ChampNode,
    level: usize,
    store: &dyn Nodes,
    out: &mut BTreeMap<Vec<u8>, Changed>,
) -> Result<()> {
    if mine.cid.is_some() && mine.cid == base.cid {
        return Ok(());
    }
    if mine.collision || base.collision {
        let m: BTreeMap<_, _> = mine.entries(level, store)?.into_iter().map(|(k, v)| (k.to_vec(), v)).collect();
        let b: BTreeMap<_, _> = base.entries(level, store)?.into_iter().map(|(k, v)| (k.to_vec(), v)).collect();
        diff_entries(m, b, out);
        return Ok(());
    }
    for slot in 0..32 {
        let bit = 1u32 << slot;
        let (m_entry, m_child) = (mine.datamap & bit != 0, mine.nodemap & bit != 0);
        let (b_entry, b_child) = (base.datamap & bit != 0, base.nodemap & bit != 0);
        if !(m_entry || m_child || b_entry || b_child) {
            continue;
        }
        if m_child && b_child {
            let mc = mine.child(mine.node_index(bit), level + 1, store)?;
            let bc = base.child(base.node_index(bit), level + 1, store)?;
            diff_raw(&mc, &bc, level + 1, store, out)?;
            continue;
        }
        let side = |n: &ChampNode, entry: bool, child: bool| -> Result<BTreeMap<Vec<u8>, Slot>> {
            if entry {
                let i = n.data_index(bit);
                return Ok(BTreeMap::from([(n.keys[i].to_vec(), n.values[i].clone())]));
            }
            if child {
                let c = n.child(n.node_index(bit), level + 1, store)?;
                return Ok(c.entries(level + 1, store)?.into_iter().map(|(k, v)| (k.to_vec(), v)).collect());
            }
            Ok(BTreeMap::new())
        };
        diff_entries(side(mine, m_entry, m_child)?, side(base, b_entry, b_child)?, out);
    }
    Ok(())
}

fn equal_slots(a: &Slot, b: &Slot) -> bool {
    a.same(b)
}

fn diff_entries(mine: BTreeMap<Vec<u8>, Slot>, base: BTreeMap<Vec<u8>, Slot>, out: &mut BTreeMap<Vec<u8>, Changed>) {
    for (key, value) in &mine {
        match base.get(key) {
            None => {
                out.insert(key.clone(), (None, Some(value.clone())));
            }
            Some(before) if !equal_slots(before, value) => {
                out.insert(key.clone(), (Some(before.clone()), Some(value.clone())));
            }
            _ => {}
        }
    }
    for (key, value) in base {
        if !mine.contains_key(&key) {
            out.insert(key, (Some(value), None));
        }
    }
}

/// A persistent map from CBOR keys to CBOR values over a node store.
#[derive(Clone, Debug)]
pub struct PMap {
    root: Arc<ChampNode>,
    count: u64,
}

impl Default for PMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl PMap {
    /// The empty map.
    pub fn empty() -> Self {
        PMap {
            root: Arc::new(ChampNode::empty()),
            count: 0,
        }
    }

    /// The map whose root node is `root` in `store`.
    pub fn load(store: &dyn Nodes, root: &str) -> Result<PMap> {
        let data = store.load(root)?;
        let node = ChampNode::load_root(root, &data)?;
        if node.collision {
            return Err(NodeError::at("a map root is never a collision node", root).into());
        }
        let count = node
            .cnt
            .ok_or_else(|| NodeError::at("a map root carries 'cnt'", root))?;
        Ok(PMap {
            root: Arc::new(node),
            count,
        })
    }

    /// The number of entries.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Whether the map holds no entry.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The slot of `key` (its canonical CBOR), if any.
    pub fn get_slot(&self, store: &dyn Nodes, key: &[u8]) -> Result<Option<Slot>> {
        self.root.find(&sha256(key), 0, key, store)
    }

    /// The CBOR value of `key`, reassembled, if any.
    pub fn get(&self, store: &dyn Nodes, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.get_slot(store, key)? {
            Some(slot) => Ok(Some(slot.resolve(store)?)),
            None => Ok(None),
        }
    }

    /// Whether `key` is present.
    pub fn contains(&self, store: &dyn Nodes, key: &[u8]) -> Result<bool> {
        Ok(self.get_slot(store, key)?.is_some())
    }

    /// This map with `key` set to `value` (both canonical CBOR items).
    pub fn assoc(&self, store: &dyn Nodes, key: &[u8], value: &[u8]) -> Result<PMap> {
        value::check_key(key)?;
        crate::cbor::decode(key).map_err(|e| PdtError::Invalid(format!("key breaks the wire encoding: {e}")))?;
        let slot = value::spill(value)?;
        let (next, change) = self.root.assoc(&sha256(key), 0, key, slot, store)?;
        Ok(match next {
            None => self.clone(),
            Some(n) => PMap {
                root: Arc::new(n),
                count: self.count + u64::from(change == Change::Added),
            },
        })
    }

    /// This map with `key` set to `value`, encoded with the workspace codec.
    pub fn assoc_value(&self, store: &dyn Nodes, key: &crate::cbor::Value, value: &crate::cbor::Value) -> Result<PMap> {
        self.assoc(store, &crate::cbor::encode(key), &crate::cbor::encode(value))
    }

    /// This map without `key`.
    pub fn dissoc(&self, store: &dyn Nodes, key: &[u8]) -> Result<PMap> {
        Ok(match self.root.dissoc(&sha256(key), 0, key, store)? {
            None => self.clone(),
            Some((n, _)) => PMap {
                root: Arc::new(n),
                count: self.count - 1,
            },
        })
    }

    /// Every (key, slot), in trie order.
    pub fn entries(&self, store: &dyn Nodes) -> Result<Vec<(Vec<u8>, Slot)>> {
        Ok(self.root.entries(0, store)?.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
    }

    /// Every (key, value) reassembled, in canonical key order.
    pub fn items(&self, store: &dyn Nodes) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.count as usize);
        for (k, v) in self.entries(store)? {
            out.push((k, v.resolve(store)?));
        }
        out.sort_by(|a, b| (a.0.len(), &a.0).cmp(&(b.0.len(), &b.0)));
        Ok(out)
    }

    /// Writes every pending node and returns the root's CID.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        if self.root.cnt == Some(self.count) && self.root.cid.is_some() {
            return Ok(self.root.cid.clone().unwrap_or_default());
        }
        let mut root = (*self.root).clone();
        root.cid = None;
        root.cnt = Some(self.count);
        root.flush(flusher)
    }

    /// Writes every pending node into `store`; returns the root and the nodes written.
    pub fn commit(&self, store: &dyn Nodes) -> Result<(String, Written)> {
        let mut flusher = Flusher::new(store);
        let root = self.flush(&mut flusher)?;
        Ok((root, flusher.into_written()))
    }

    /// The changes from `base` to this map, keyed by key bytes; pruned where subtrees share a CID.
    pub fn diff(&self, base: &PMap, store: &dyn Nodes) -> Result<BTreeMap<Vec<u8>, Changed>> {
        let mut out = BTreeMap::new();
        diff_raw(&self.root, &base.root, 0, store, &mut out)?;
        Ok(out)
    }
}

/// A persistent set: a map whose every value is null.
#[derive(Clone, Debug, Default)]
pub struct PSet {
    map: PMap,
}

impl PSet {
    /// The empty set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The set whose root node is `root`.
    pub fn load(store: &dyn Nodes, root: &str) -> Result<PSet> {
        Ok(PSet {
            map: PMap::load(store, root)?,
        })
    }

    /// The number of members.
    pub fn count(&self) -> u64 {
        self.map.count()
    }

    /// Whether `member` (canonical CBOR) is present.
    pub fn contains(&self, store: &dyn Nodes, member: &[u8]) -> Result<bool> {
        self.map.contains(store, member)
    }

    /// This set with `member`.
    pub fn conj(&self, store: &dyn Nodes, member: &[u8]) -> Result<PSet> {
        Ok(PSet {
            map: self.map.assoc(store, member, &[0xF6])?,
        })
    }

    /// This set without `member`.
    pub fn disj(&self, store: &dyn Nodes, member: &[u8]) -> Result<PSet> {
        Ok(PSet {
            map: self.map.dissoc(store, member)?,
        })
    }

    /// The members, in canonical order.
    pub fn members(&self, store: &dyn Nodes) -> Result<Vec<Vec<u8>>> {
        Ok(self.map.items(store)?.into_iter().map(|(k, _)| k).collect())
    }

    /// The underlying map.
    pub fn as_map(&self) -> &PMap {
        &self.map
    }

    /// Writes every pending node and returns the root's CID.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        self.map.flush(flusher)
    }
}
