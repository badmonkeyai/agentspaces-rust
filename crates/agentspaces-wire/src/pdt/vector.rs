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

//! `PVector`, Clojure's trie with the tail (annex H, vectors; Python `pdt/vector.py`).
//!
//! The root is `{k:"vr", n: count, s: shift, r: link or null, t: [tail items, 1 to 32]}` (`s` = 5
//! and `r` null while the trie is empty), an interior node `{k:"v", c:[links]}`, a leaf
//! `{k:"v", e:[items]}` exactly 32 wide; five index bits per level; tailoff = n < 32 ? 0 :
//! ((n-1) >>> 5) << 5. The shape is a function of the count, so the layout is canonical. A
//! relaxed (`rr`) root is a level-2 form, refused here by name.

use std::sync::Arc;

use super::node::{self, Field, KIND_RR, KIND_V, KIND_VR, Node};
use super::store::{Flusher, Nodes, Written};
use super::value::{self, Slot};
use super::{NodeError, PdtError, Result, cid};

/// Index bits per level.
pub const BITS: u32 = 5;
/// The width of a node.
pub const WIDTH: usize = 32;
const MASK: u64 = 31;
/// The largest shift.
pub const MAX_SHIFT: u32 = 30;
/// The largest count.
pub const MAX_COUNT: u64 = 0x7FFF_FFFF;

/// The index of the first element in the tail.
pub fn tailoff(n: u64) -> u64 {
    if n < WIDTH as u64 { 0 } else { ((n - 1) >> BITS) << BITS }
}

/// The shift a vector of `n` elements has.
pub fn shift_for(n: u64) -> u32 {
    let off = tailoff(n);
    let mut s = BITS;
    while off > 0 && ((off - 1) >> s) >= WIDTH as u64 {
        s += BITS;
    }
    s
}

/// A child of an interior node: stored, or in memory.
#[derive(Clone, Debug)]
pub enum VecChild {
    /// A stored node, by CID.
    Stored(String),
    /// A node in memory.
    Mem(Arc<VecNode>),
}

impl VecChild {
    fn node(&self, store: &dyn Nodes) -> Result<Arc<VecNode>> {
        match self {
            VecChild::Mem(n) => Ok(n.clone()),
            VecChild::Stored(c) => Ok(Arc::new(VecNode::decode(c, &store.load(c)?)?)),
        }
    }

    fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        match self {
            VecChild::Stored(c) => Ok(c.clone()),
            VecChild::Mem(n) => n.flush(flusher),
        }
    }
}

/// A node of the trie: a leaf of items or an interior node of children.
#[derive(Clone, Debug)]
pub enum VecNode {
    /// A leaf of exactly 32 items (fewer only while building).
    Leaf(Vec<Slot>),
    /// An interior node of 1 to 32 children.
    Interior(Vec<VecChild>),
}

impl VecNode {
    fn encode(&self, flusher: &mut Flusher<'_>) -> Result<Vec<u8>> {
        let node = match self {
            VecNode::Leaf(items) => {
                let mut e = Vec::with_capacity(items.len());
                for s in items {
                    e.push(s.embed(flusher)?);
                }
                Node::new(KIND_V).with("e", Field::Embeddeds(e))
            }
            VecNode::Interior(children) => {
                let mut c = Vec::with_capacity(children.len());
                for child in children {
                    c.push(child.flush(flusher)?);
                }
                Node::new(KIND_V).with("c", Field::Links(c))
            }
        };
        Ok(node::encode(&node)?)
    }

    fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        let bytes = self.encode(flusher)?;
        Ok(flusher.write(bytes, cid::DAG_CBOR))
    }

    /// A trie node from its bytes; a leaf in the trie holds exactly 32 items.
    pub fn decode(c: &str, data: &[u8]) -> Result<VecNode> {
        let n = node::decode(data, Some(c))?;
        if n.kind != KIND_V {
            return Err(NodeError::at(format!("expected a vector node, found kind '{}'", n.kind), c).into());
        }
        let (has_c, has_e) = (n.get("c").is_some(), n.get("e").is_some());
        if has_c == has_e {
            return Err(NodeError::at("a vector node holds either 'c' or 'e'", c).into());
        }
        let len = if has_c { n.links("c").len() } else { n.embeddeds("e").len() };
        if len == 0 || len > WIDTH {
            return Err(NodeError::at(format!("vector node with {len} slots; 1 to 32 expected"), c).into());
        }
        if has_c {
            return Ok(VecNode::Interior(n.links("c").iter().cloned().map(VecChild::Stored).collect()));
        }
        if len != WIDTH {
            return Err(NodeError::at(format!("vector leaf with {len} items; a leaf in the trie holds exactly 32"), c).into());
        }
        let mut items = Vec::with_capacity(len);
        for e in n.embeddeds("e") {
            items.push(value::ref_of(e)?);
        }
        Ok(VecNode::Leaf(items))
    }

    fn children(&self) -> &[VecChild] {
        match self {
            VecNode::Interior(c) => c,
            VecNode::Leaf(_) => &[],
        }
    }
}

fn new_path(level: u32, node: VecNode) -> VecNode {
    if level == 0 {
        return node;
    }
    VecNode::Interior(vec![VecChild::Mem(Arc::new(new_path(level - BITS, node)))])
}

/// The root of a vector.
#[derive(Clone, Debug)]
pub struct VecRoot {
    n: u64,
    shift: u32,
    trie: Option<VecChild>,
    tail: Vec<Slot>,
    cid: Option<String>,
}

impl VecRoot {
    /// The empty vector.
    pub fn empty() -> Self {
        VecRoot {
            n: 0,
            shift: BITS,
            trie: None,
            tail: Vec::new(),
            cid: None,
        }
    }

    /// The number of elements.
    pub fn count(&self) -> u64 {
        self.n
    }

    fn leaf_for(&self, i: u64, store: &dyn Nodes) -> Result<Arc<VecNode>> {
        let mut node = self
            .trie
            .as_ref()
            .ok_or_else(|| PdtError::Invalid("vector trie is empty".to_string()))?
            .node(store)?;
        let mut level = self.shift;
        while level > 0 {
            let idx = ((i >> level) & MASK) as usize;
            let child = node
                .children()
                .get(idx)
                .ok_or_else(|| NodeError::new(format!("vector node lacks child {idx}")))?
                .node(store)?;
            node = child;
            level -= BITS;
        }
        Ok(node)
    }

    /// The slot of element `i`.
    pub fn nth(&self, i: u64, store: &dyn Nodes) -> Result<Slot> {
        if i >= self.n {
            return Err(PdtError::Invalid(format!("index {i} of a vector of {}", self.n)));
        }
        let off = tailoff(self.n);
        if i >= off {
            return Ok(self.tail[(i - off) as usize].clone());
        }
        match &*self.leaf_for(i, store)? {
            VecNode::Leaf(items) => items
                .get((i & MASK) as usize)
                .cloned()
                .ok_or_else(|| NodeError::new("vector leaf is short").into()),
            VecNode::Interior(_) => Err(NodeError::new("an interior node where a leaf belongs").into()),
        }
    }

    /// This vector with `item` appended.
    pub fn conj(&self, item: Slot, store: &dyn Nodes) -> Result<VecRoot> {
        if self.n >= MAX_COUNT {
            return Err(PdtError::Invalid("vector is full".to_string()));
        }
        let off = tailoff(self.n);
        if self.n - off < WIDTH as u64 {
            let mut tail = self.tail.clone();
            tail.push(item);
            return Ok(VecRoot {
                n: self.n + 1,
                shift: self.shift,
                trie: self.trie.clone(),
                tail,
                cid: None,
            });
        }
        let tail_node = VecNode::Leaf(self.tail.clone());
        let (trie, shift) = match &self.trie {
            None => (VecNode::Interior(vec![VecChild::Mem(Arc::new(tail_node))]), BITS),
            Some(t) if (self.n >> BITS) > (1u64 << self.shift) => (
                VecNode::Interior(vec![
                    t.clone(),
                    VecChild::Mem(Arc::new(new_path(self.shift, tail_node))),
                ]),
                self.shift + BITS,
            ),
            Some(t) => (self.push_tail(self.shift, &*t.node(store)?, tail_node, store)?, self.shift),
        };
        Ok(VecRoot {
            n: self.n + 1,
            shift,
            trie: Some(VecChild::Mem(Arc::new(trie))),
            tail: vec![item],
            cid: None,
        })
    }

    fn push_tail(&self, level: u32, parent: &VecNode, tail_node: VecNode, store: &dyn Nodes) -> Result<VecNode> {
        let subidx = (((self.n - 1) >> level) & MASK) as usize;
        let mut children = parent.children().to_vec();
        if level == BITS {
            children.push(VecChild::Mem(Arc::new(tail_node)));
            return Ok(VecNode::Interior(children));
        }
        if subidx < children.len() {
            let child = children[subidx].node(store)?;
            let next = self.push_tail(level - BITS, &child, tail_node, store)?;
            children[subidx] = VecChild::Mem(Arc::new(next));
            return Ok(VecNode::Interior(children));
        }
        children.push(VecChild::Mem(Arc::new(new_path(level - BITS, tail_node))));
        Ok(VecNode::Interior(children))
    }

    /// This vector with element `i` replaced.
    pub fn assoc_n(&self, i: u64, item: Slot, store: &dyn Nodes) -> Result<VecRoot> {
        if i >= self.n {
            return Err(PdtError::Invalid(format!("index {i} of a vector of {}", self.n)));
        }
        let off = tailoff(self.n);
        if i >= off {
            let mut tail = self.tail.clone();
            tail[(i - off) as usize] = item;
            return Ok(VecRoot { tail, cid: None, ..self.clone() });
        }
        let trie = self.trie.as_ref().ok_or_else(|| PdtError::Invalid("vector trie is empty".to_string()))?;
        let next = do_assoc(self.shift, &*trie.node(store)?, i, item, store)?;
        Ok(VecRoot {
            trie: Some(VecChild::Mem(Arc::new(next))),
            cid: None,
            ..self.clone()
        })
    }

    /// This vector without its last element.
    pub fn pop(&self, store: &dyn Nodes) -> Result<VecRoot> {
        if self.n == 0 {
            return Err(PdtError::Invalid("pop on an empty vector".to_string()));
        }
        let off = tailoff(self.n);
        if self.n - off > 1 {
            let mut tail = self.tail.clone();
            tail.pop();
            return Ok(VecRoot { n: self.n - 1, tail, cid: None, ..self.clone() });
        }
        if self.n == 1 {
            return Ok(VecRoot::empty());
        }
        let new_tail = match &*self.leaf_for(self.n - 2, store)? {
            VecNode::Leaf(items) => items.clone(),
            VecNode::Interior(_) => return Err(NodeError::new("an interior node where a leaf belongs").into()),
        };
        let trie = self.trie.as_ref().ok_or_else(|| PdtError::Invalid("vector trie is empty".to_string()))?;
        let mut new_trie = self.pop_tail(self.shift, &*trie.node(store)?, store)?;
        let mut shift = self.shift;
        match &new_trie {
            None => shift = BITS,
            Some(t) if self.shift > BITS && t.children().len() == 1 => {
                new_trie = Some((*t.children()[0].node(store)?).clone());
                shift = self.shift - BITS;
            }
            _ => {}
        }
        Ok(VecRoot {
            n: self.n - 1,
            shift,
            trie: new_trie.map(|t| VecChild::Mem(Arc::new(t))),
            tail: new_tail,
            cid: None,
        })
    }

    fn pop_tail(&self, level: u32, node: &VecNode, store: &dyn Nodes) -> Result<Option<VecNode>> {
        let subidx = (((self.n - 2) >> level) & MASK) as usize;
        let mut children = node.children().to_vec();
        if level > BITS {
            let next = self.pop_tail(level - BITS, &*children[subidx].node(store)?, store)?;
            return Ok(match next {
                None if subidx == 0 => None,
                None => {
                    children.pop();
                    Some(VecNode::Interior(children))
                }
                Some(n) => {
                    children[subidx] = VecChild::Mem(Arc::new(n));
                    Some(VecNode::Interior(children))
                }
            });
        }
        if subidx == 0 {
            return Ok(None);
        }
        children.pop();
        Ok(Some(VecNode::Interior(children)))
    }

    /// Writes every pending node and returns the root's CID.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        if let Some(c) = &self.cid {
            return Ok(c.clone());
        }
        let r = match &self.trie {
            None => Field::Null,
            Some(t) => Field::Link(t.flush(flusher)?),
        };
        let mut t = Vec::with_capacity(self.tail.len());
        for s in &self.tail {
            t.push(s.embed(flusher)?);
        }
        let bytes = node::encode(
            &Node::new(KIND_VR)
                .with("n", Field::Uint(self.n))
                .with("s", Field::Uint(u64::from(self.shift)))
                .with("r", r)
                .with("t", Field::Embeddeds(t)),
        )?;
        Ok(flusher.write(bytes, cid::DAG_CBOR))
    }

    /// A root from its bytes, checked against the count.
    pub fn decode(c: &str, data: &[u8]) -> Result<VecRoot> {
        let n = node::decode(data, Some(c))?;
        if n.kind == KIND_RR {
            return Err(NodeError::at("a relaxed vector (rr) is a level-2 form", c).into());
        }
        if n.kind != KIND_VR {
            return Err(NodeError::at(format!("expected a vector root, found kind '{}'", n.kind), c).into());
        }
        let count = n.uint("n").unwrap_or(0);
        let shift = n.uint("s").unwrap_or(u64::from(BITS));
        if count > MAX_COUNT || shift < u64::from(BITS) || shift > u64::from(MAX_SHIFT) || shift % u64::from(BITS) != 0 {
            return Err(NodeError::at(format!("vector root with count {count} and shift {shift}"), c).into());
        }
        let trie = match n.get("r") {
            Some(Field::Link(l)) => Some(l.clone()),
            _ => None,
        };
        let t = n.embeddeds("t");
        if t.len() > WIDTH {
            return Err(NodeError::at(format!("vector tail of {} elements", t.len()), c).into());
        }
        if t.len() as u64 != count - tailoff(count) || trie.is_none() != (tailoff(count) == 0) {
            return Err(NodeError::at(format!("vector tail and trie do not match the count {count}"), c).into());
        }
        if shift as u32 != shift_for(count) {
            return Err(NodeError::at(
                format!("vector root with shift {shift} where the count {count} implies {}", shift_for(count)),
                c,
            )
            .into());
        }
        let mut tail = Vec::with_capacity(t.len());
        for e in t {
            tail.push(value::ref_of(e)?);
        }
        Ok(VecRoot {
            n: count,
            shift: shift as u32,
            trie: trie.map(VecChild::Stored),
            tail,
            cid: Some(c.to_string()),
        })
    }
}

fn do_assoc(level: u32, node: &VecNode, i: u64, item: Slot, store: &dyn Nodes) -> Result<VecNode> {
    match node {
        VecNode::Leaf(items) if level == 0 => {
            let mut items = items.clone();
            items[(i & MASK) as usize] = item;
            Ok(VecNode::Leaf(items))
        }
        VecNode::Interior(children) if level > 0 => {
            let subidx = ((i >> level) & MASK) as usize;
            let mut children = children.clone();
            let next = do_assoc(level - BITS, &*children[subidx].node(store)?, i, item, store)?;
            children[subidx] = VecChild::Mem(Arc::new(next));
            Ok(VecNode::Interior(children))
        }
        _ => Err(NodeError::new("vector node of the wrong kind for its level").into()),
    }
}

/// A persistent vector of CBOR values over a node store.
#[derive(Clone, Debug)]
pub struct PVector {
    root: VecRoot,
}

impl Default for PVector {
    fn default() -> Self {
        Self::empty()
    }
}

impl PVector {
    /// The empty vector.
    pub fn empty() -> Self {
        PVector { root: VecRoot::empty() }
    }

    /// The vector whose root is `root` in `store`.
    pub fn load(store: &dyn Nodes, root: &str) -> Result<PVector> {
        Ok(PVector {
            root: VecRoot::decode(root, &store.load(root)?)?,
        })
    }

    /// The number of elements.
    pub fn count(&self) -> u64 {
        self.root.count()
    }

    /// Element `i`, reassembled.
    pub fn nth(&self, store: &dyn Nodes, i: u64) -> Result<Vec<u8>> {
        self.root.nth(i, store)?.resolve(store)
    }

    /// This vector with `item` (a canonical CBOR item) appended.
    pub fn conj(&self, store: &dyn Nodes, item: &[u8]) -> Result<PVector> {
        Ok(PVector {
            root: self.root.conj(value::spill(item)?, store)?,
        })
    }

    /// This vector with element `i` replaced by `item`.
    pub fn assoc_n(&self, store: &dyn Nodes, i: u64, item: &[u8]) -> Result<PVector> {
        Ok(PVector {
            root: self.root.assoc_n(i, value::spill(item)?, store)?,
        })
    }

    /// This vector without its last element.
    pub fn pop(&self, store: &dyn Nodes) -> Result<PVector> {
        Ok(PVector {
            root: self.root.pop(store)?,
        })
    }

    /// Every element, reassembled.
    pub fn items(&self, store: &dyn Nodes) -> Result<Vec<Vec<u8>>> {
        (0..self.count()).map(|i| self.nth(store, i)).collect()
    }

    /// Writes every pending node and returns the root's CID.
    pub fn flush(&self, flusher: &mut Flusher<'_>) -> Result<String> {
        self.root.flush(flusher)
    }

    /// Writes every pending node into `store`; returns the root and the nodes written.
    pub fn commit(&self, store: &dyn Nodes) -> Result<(String, Written)> {
        let mut flusher = Flusher::new(store);
        let root = self.flush(&mut flusher)?;
        Ok((root, flusher.into_written()))
    }
}
