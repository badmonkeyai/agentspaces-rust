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

//! `PBlob`, bytes as a prolly tree of FastCDC chunks (annex H, blobs; Python `pdt/blob.py`).
//!
//! Each chunk is a raw node (codec 0x55). A blob of zero or one chunk is that chunk, and its CID
//! is the root. Otherwise the chunks are level 0 of a prolly tree: level L+1 groups the entries
//! of level L into nodes `{k:"b", h: height, c:[links], z:[bytes under each child]}`, closing a
//! node after an entry whose sha2-256 digest's first four bytes, read big-endian, are below
//! 0x08000000, with at least 4 and at most 256 entries per node, until one node remains. A reader
//! seeks by the `z` sums and verifies every chunk by the path of CIDs from the root.

use std::io::Read;

use super::fastcdc::{self, Chunker};
use super::node::{self, Field, KIND_B, MAX_DEPTH, Node};
use super::store::{Flusher, Nodes};
use super::{NodeError, PdtError, Result, cid};

/// An entry closes a node when its digest's first four bytes are below this.
pub const BOUNDARY: u32 = 0x0800_0000;
/// The fewest entries a node closes with (except the last of a level).
pub const MIN_FANOUT: usize = 4;
/// The most entries a node holds.
pub const MAX_FANOUT: usize = 256;

/// One entry of a level: a node (or chunk) and the bytes under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The CID.
    pub cid: String,
    /// The bytes under it.
    pub length: u64,
}

impl Entry {
    fn boundary(&self) -> bool {
        cid::parse(&self.cid).is_ok_and(|p| u32::from_be_bytes([p.digest[0], p.digest[1], p.digest[2], p.digest[3]]) < BOUNDARY)
    }
}

/// A blob written: its root, its size, and its chunks in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The root CID (a raw chunk for a blob of zero or one chunk).
    pub root: String,
    /// The bytes.
    pub size: u64,
    /// The chunks, in order.
    pub chunks: Vec<Entry>,
    /// The tree height (0 for a single chunk).
    pub height: u64,
}

fn group(level: &[Entry]) -> Vec<&[Entry]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, entry) in level.iter().enumerate() {
        let len = i + 1 - start;
        if len >= MAX_FANOUT || (len >= MIN_FANOUT && entry.boundary()) {
            out.push(&level[start..=i]);
            start = i + 1;
        }
    }
    if start < level.len() {
        out.push(&level[start..]);
    }
    out
}

/// Builds the tree over chunks already written and writes the interior nodes.
pub fn build(chunks: Vec<Entry>, flusher: &mut Flusher<'_>) -> Result<Written> {
    let size: u64 = chunks.iter().map(|c| c.length).sum();
    if chunks.is_empty() {
        let root = flusher.write(Vec::new(), cid::RAW);
        return Ok(Written { root, size: 0, chunks, height: 0 });
    }
    let mut level = chunks.clone();
    let mut height = 0u64;
    while level.len() > 1 {
        height += 1;
        let mut next = Vec::new();
        for entries in group(&level) {
            let bytes = node::encode(
                &Node::new(KIND_B)
                    .with("h", Field::Uint(height))
                    .with("c", Field::Links(entries.iter().map(|e| e.cid.clone()).collect()))
                    .with("z", Field::Uints(entries.iter().map(|e| e.length).collect())),
            )?;
            let c = flusher.write(bytes, cid::DAG_CBOR);
            next.push(Entry {
                cid: c,
                length: entries.iter().map(|e| e.length).sum(),
            });
        }
        level = next;
    }
    Ok(Written {
        root: level[0].cid.clone(),
        size,
        chunks,
        height,
    })
}

/// Writes `data` as a blob.
pub fn write_bytes(data: &[u8], flusher: &mut Flusher<'_>) -> Result<Written> {
    let mut chunks = Vec::new();
    let mut start = 0;
    for end in fastcdc::cuts(data) {
        let c = flusher.write(data[start..end].to_vec(), cid::RAW);
        chunks.push(Entry {
            cid: c,
            length: (end - start) as u64,
        });
        start = end;
    }
    build(chunks, flusher)
}

/// Writes a stream as a blob, refusing it past `limit` bytes; `progress` hears the bytes so far.
pub fn write_stream<R: Read>(
    source: R,
    limit: u64,
    flusher: &mut Flusher<'_>,
    mut progress: impl FnMut(u64),
) -> Result<Written> {
    let mut chunker = Chunker::new(source);
    let mut chunks = Vec::new();
    let mut total = 0u64;
    while let Some(chunk) = chunker
        .next_chunk()
        .map_err(|e| PdtError::Invalid(format!("reading the source: {e}")))?
    {
        total += chunk.len() as u64;
        if total > limit {
            return Err(PdtError::Invalid(format!("the source grew beyond the {limit}-byte limit")));
        }
        let length = chunk.len() as u64;
        let c = flusher.write(chunk, cid::RAW);
        chunks.push(Entry { cid: c, length });
        progress(total);
    }
    build(chunks, flusher)
}

/// A blob interior node: height, child CIDs, and the bytes under each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BNode {
    /// The height (1 just above the chunks).
    pub height: u64,
    /// The children.
    pub children: Vec<String>,
    /// The bytes under each child.
    pub sizes: Vec<u64>,
}

impl BNode {
    /// A `b` node from its bytes.
    pub fn decode(c: &str, data: &[u8]) -> Result<BNode> {
        let n = node::decode(data, Some(c))?;
        if n.kind != KIND_B {
            return Err(NodeError::at(format!("kind '{}' where a blob node was expected", n.kind), c).into());
        }
        let (links, sizes) = (n.links("c"), n.uints("z"));
        if links.is_empty() || links.len() != sizes.len() {
            return Err(NodeError::at(format!("blob node with {} links and {} sizes", links.len(), sizes.len()), c).into());
        }
        let height = n.uint("h").filter(|h| *h >= 1).ok_or_else(|| NodeError::at("blob node without a height", c))?;
        Ok(BNode {
            height,
            children: links.to_vec(),
            sizes: sizes.to_vec(),
        })
    }

    /// The bytes under this node.
    pub fn size(&self) -> u64 {
        self.sizes.iter().sum()
    }
}

/// The size of the blob rooted at `root`.
pub fn size_of(store: &dyn Nodes, root: &str) -> Result<u64> {
    let data = store.load(root)?;
    if cid::codec_of(root) == Some(cid::RAW) {
        return Ok(data.len() as u64);
    }
    Ok(BNode::decode(root, &data)?.size())
}

/// The chunks of the blob rooted at `root`, in order, checking every node's size against its
/// parent's claim; every node must be in the store.
pub fn chunks(store: &dyn Nodes, root: &str) -> Result<Vec<Entry>> {
    let size = size_of(store, root)?;
    let mut out = Vec::new();
    collect(store, root, size, 1, &mut out)?;
    Ok(out)
}

fn collect(store: &dyn Nodes, c: &str, under: u64, depth: usize, out: &mut Vec<Entry>) -> Result<()> {
    if cid::codec_of(c) == Some(cid::RAW) {
        out.push(Entry { cid: c.to_string(), length: under });
        return Ok(());
    }
    if depth > MAX_DEPTH {
        return Err(NodeError::at(format!("tree deeper than {MAX_DEPTH} levels"), c).into());
    }
    let node = BNode::decode(c, &store.load(c)?)?;
    if node.size() != under {
        return Err(NodeError::at(format!("blob node holds {} bytes where its parent claims {under}", node.size()), c).into());
    }
    for (child, z) in node.children.iter().zip(&node.sizes) {
        collect(store, child, *z, depth + 1, out)?;
    }
    Ok(())
}

/// The bytes of one chunk, checked against the length the tree claims.
pub fn chunk(store: &dyn Nodes, entry: &Entry) -> Result<std::sync::Arc<[u8]>> {
    let data = store.load(&entry.cid)?;
    if data.len() as u64 != entry.length {
        return Err(NodeError::at(format!("chunk of {} bytes where the tree claims {}", data.len(), entry.length), &entry.cid).into());
    }
    Ok(data)
}

/// Every byte of the blob rooted at `root`.
pub fn read_all(store: &dyn Nodes, root: &str) -> Result<Vec<u8>> {
    let entries = chunks(store, root)?;
    let mut out = Vec::with_capacity(entries.iter().map(|e| e.length as usize).sum());
    for e in &entries {
        out.extend_from_slice(&chunk(store, e)?);
    }
    Ok(out)
}

/// The chunk that holds byte `offset`, and where it starts.
pub fn seek(store: &dyn Nodes, root: &str, offset: u64) -> Result<(Entry, u64)> {
    let size = size_of(store, root)?;
    if offset >= size {
        return Err(PdtError::Invalid(format!("offset {offset} outside a blob of {size} bytes")));
    }
    let (mut c, mut start, mut under, mut depth) = (root.to_string(), 0u64, size, 1usize);
    while cid::codec_of(&c) != Some(cid::RAW) {
        if depth > MAX_DEPTH {
            return Err(NodeError::at(format!("tree deeper than {MAX_DEPTH} levels"), &c).into());
        }
        let node = BNode::decode(&c, &store.load(&c)?)?;
        if node.size() != under {
            return Err(NodeError::at(format!("blob node holds {} bytes where its parent claims {under}", node.size()), &c).into());
        }
        let mut i = 0;
        while i < node.sizes.len() - 1 && offset >= start + node.sizes[i] {
            start += node.sizes[i];
            i += 1;
        }
        under = node.sizes[i];
        c = node.children[i].clone();
        depth += 1;
    }
    Ok((Entry { cid: c, length: under }, start))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdt::store::MemoryNodes;

    #[test]
    fn small_blobs_are_their_chunk() {
        let store = MemoryNodes::new();
        let mut f = Flusher::new(&store);
        let empty = write_bytes(&[], &mut f).unwrap();
        assert_eq!(empty.root, cid::of(&[], cid::RAW));
        let one = write_bytes(b"hello", &mut f).unwrap();
        assert_eq!(one.root, cid::of(b"hello", cid::RAW));
        assert_eq!(read_all(&store, &one.root).unwrap(), b"hello");
    }

    #[test]
    fn reads_back_and_seeks() {
        let data: Vec<u8> = (0..2_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
        let store = MemoryNodes::new();
        let mut f = Flusher::new(&store);
        let w = write_bytes(&data, &mut f).unwrap();
        assert!(w.height >= 1);
        assert_eq!(read_all(&store, &w.root).unwrap(), data);
        let (entry, start) = seek(&store, &w.root, 1_000_000).unwrap();
        assert!(start <= 1_000_000 && start + entry.length > 1_000_000);
        let streamed = write_stream(&data[..], u64::MAX, &mut Flusher::new(&MemoryNodes::new()), |_| {}).unwrap();
        assert_eq!(streamed.root, w.root);
        assert!(write_stream(&data[..], 1000, &mut Flusher::new(&MemoryNodes::new()), |_| {}).is_err());
    }
}
