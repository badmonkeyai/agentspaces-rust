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

//! The fingerprinted trie of a replicated space (SPEC annex I.6, v0.1.35, `wire.ae=2`): the
//! audited set of a space's stream, its sixteen-way trie over SHA-256 of each entry id, the leaf
//! and inner preimages, the 16-byte fingerprints, and the 32-byte stream hash.
//!
//! - *The audited set.* One *slot* per entry id with at least one line; a slot holds the entry's
//!   state line `e:<id>=<stateHash>` (or the line a tag-sharded replica remembered when it
//!   dropped the entry), its claim line `c:<id>=<claimHash>`, and each line the replica
//!   acknowledges for it, standing as the line itself ([`SlotSource::lines`]). A present entry
//!   whose write lease lapsed by the replica's clock contributes neither its state nor its claim
//!   line. An entry id holding a control character (U+0000 to U+001F, U+007F) never enters the
//!   set ([`is_audited_id`]).
//! - *The key and the path.* A slot's key is SHA-256 of its id's UTF-8 bytes, read as 64 nibbles,
//!   the most significant first ([`entry_key`]); a [`Path`] is 0 to 64 nibbles, the root's empty.
//! - *The canonical shape.* The node at a path is a leaf when it holds at most [`LEAF_MAX`]
//!   slots or sits at 64 nibbles, and an inner node otherwise; the shape is a function of the set
//!   alone.
//! - *Preimages and fingerprints.* A leaf's preimage is its lines, sorted by unsigned bytes, each
//!   once, joined by one LF with none after the last; an inner node's is 384 bytes, for each child
//!   in nibble order its fingerprint (16 zero bytes when empty) and its count as 8 bytes big
//!   endian. A node's fingerprint is the first 16 bytes of the SHA-256 of its preimage, and the
//!   stream hash the whole SHA-256 of the root's ([`EMPTY_STREAM_HASH`] for an empty set).
//!
//! [`AuditTrie`] stores the slots in key order and memoizes each node's hash by path, so a change
//! rehashes only the nodes on its key's path and an unchanged trie answers with no hashing. It
//! may store the slots in any form, since the fingerprints are defined over the set at every
//! path; this one keeps a sorted map and computes the shape on demand.
#![warn(missing_docs)]

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use crate::crypto;

/// Children per inner node: one per nibble.
pub const FANOUT: usize = 16;
/// The leaf threshold T: a node of at most this many slots is a leaf.
pub const LEAF_MAX: u64 = 32;
/// Nibbles in a key, the deepest path; a node there is a leaf whatever its count.
pub const KEY_NIBBLES: usize = 64;
/// Bytes of a fingerprint: the first 16 of its preimage's SHA-256.
pub const FINGERPRINT_BYTES: usize = 16;
/// Bytes one child takes in an inner preimage: its fingerprint and its count.
pub const CHILD_BYTES: usize = FINGERPRINT_BYTES + 8;
/// Bytes of an inner node's preimage.
pub const INNER_PREIMAGE_BYTES: usize = FANOUT * CHILD_BYTES;
/// The stream hash of an empty set: the SHA-256 of zero bytes.
pub const EMPTY_STREAM_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// The key of a slot: SHA-256 of its entry id's UTF-8 bytes.
pub fn entry_key(entry_id: &str) -> [u8; 32] {
    crypto::port().sha256(entry_id.as_bytes())
}

/// Nibble `index` (0 to 63) of a key: the high four bits of byte `index / 2` for an even index,
/// the low four for an odd one.
pub fn nibble(key: &[u8; 32], index: usize) -> u8 {
    let byte = key[index / 2];
    if index.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0F
    }
}

/// Whether a text holds a control character of annex I.6 (U+0000 to U+001F, or U+007F).
pub fn has_control(text: &str) -> bool {
    text.chars().any(|c| c < '\u{20}' || c == '\u{7f}')
}

/// Whether an entry id may enter the audited set: non-empty and free of control characters. Under
/// `wire.ae=2` a state or claim whose id holds one is dropped uncounted, and a write is refused.
pub fn is_audited_id(entry_id: &str) -> bool {
    !entry_id.is_empty() && !has_control(entry_id)
}

/// The first 16 bytes of the SHA-256 of a preimage.
pub fn fingerprint(preimage: &[u8]) -> [u8; FINGERPRINT_BYTES] {
    truncate(&crypto::port().sha256(preimage))
}

fn truncate(hash: &[u8; 32]) -> [u8; FINGERPRINT_BYTES] {
    let mut out = [0u8; FINGERPRINT_BYTES];
    out.copy_from_slice(&hash[..FINGERPRINT_BYTES]);
    out
}

/// The entry id a digest line names: the text between its `e:` or `c:` and its last `=` (a state
/// hash is hex and a claim hash holds no `=`); `None` for a line of another shape.
pub fn entry_id_of_line(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("e:")
        .or_else(|| line.strip_prefix("c:"))?;
    let eq = rest.rfind('=')?;
    (eq > 0).then(|| &rest[..eq])
}

// ---------------------------------------------------------------------------------------------
// Slots

/// What one entry contributes to the audited set, before the slot rules of annex I.6 apply.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlotSource<'a> {
    /// The entry id.
    pub id: &'a str,
    /// The hash of the state line `e:<id>=<state>` when the replica holds a state (a tombstone
    /// included).
    pub state: Option<&'a str>,
    /// The hash of the claim line `c:<id>=<claim>` when the replica holds a claim.
    pub claim: Option<&'a str>,
    /// The hash of the state line a tag-sharded replica remembered when it dropped the entry; a
    /// held state's line wins over it.
    pub dropped: Option<&'a str>,
    /// Whether the entry is present and its write lease lapsed by the replica's clock: a held
    /// state's line and the claim line then stay out of the set.
    pub lapsed: bool,
    /// The lines the replica acknowledges for the entry, each standing as itself (no `a:`).
    pub acks: &'a [String],
}

impl SlotSource<'_> {
    /// The slot's audited lines, sorted by their bytes, each once; empty when the slot has none
    /// or its id holds a control character.
    pub fn lines(&self) -> Vec<String> {
        if !is_audited_id(self.id) {
            return Vec::new();
        }
        let mut lines = Vec::with_capacity(2 + self.acks.len());
        if !(self.lapsed && self.state.is_some()) {
            if let Some(hash) = self.state.or(self.dropped) {
                lines.push(format!("e:{}={hash}", self.id));
            }
            if let Some(hash) = self.claim {
                lines.push(format!("c:{}={hash}", self.id));
            }
        }
        lines.extend(self.acks.iter().cloned());
        normalize(lines)
    }
}

/// Lines sorted by their bytes, each once, without any empty line or one holding a control
/// character (which no slot rule produces and which would break the leaf's joining).
fn normalize(mut lines: Vec<String>) -> Vec<String> {
    lines.retain(|line| !line.is_empty() && !has_control(line));
    lines.sort_unstable();
    lines.dedup();
    lines
}

// ---------------------------------------------------------------------------------------------
// Paths

/// A path of 0 to 64 nibbles, packed two to a byte; the root's is empty.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Path {
    len: u8,
    packed: [u8; 32],
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Path({})", self.hex())
    }
}

impl Path {
    /// The root's empty path.
    pub const ROOT: Path = Path {
        len: 0,
        packed: [0; 32],
    };

    /// The path of the given nibbles, one per byte, or `None` when one is above `0x0F` or there
    /// are more than 64.
    pub fn from_nibbles(nibbles: &[u8]) -> Option<Path> {
        if nibbles.len() > KEY_NIBBLES || nibbles.iter().any(|&n| n > 0x0F) {
            return None;
        }
        let mut path = Path::ROOT;
        for &n in nibbles {
            path = path.child(n)?;
        }
        Some(path)
    }

    /// The path of the first `len` nibbles of a key (`len` at most 64).
    pub fn prefix_of(key: &[u8; 32], len: usize) -> Path {
        let len = len.min(KEY_NIBBLES);
        let mut packed = [0u8; 32];
        packed[..len / 2].copy_from_slice(&key[..len / 2]);
        if len % 2 == 1 {
            packed[len / 2] = key[len / 2] & 0xF0;
        }
        Path {
            len: len as u8,
            packed,
        }
    }

    /// Its number of nibbles.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether it is the root's.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Nibble `index` (below [`Path::len`]).
    pub fn nibble(&self, index: usize) -> u8 {
        nibble(&self.packed, index)
    }

    /// Its nibbles, one per byte: the form a `TreeNode.path` carries.
    pub fn nibbles(&self) -> Vec<u8> {
        (0..self.len()).map(|i| self.nibble(i)).collect()
    }

    /// The path as lower-case hex digits, one per nibble.
    pub fn hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        (0..self.len())
            .map(|i| char::from(DIGITS[usize::from(self.nibble(i))]))
            .collect()
    }

    /// The child at `nibble`, or `None` at 64 nibbles or for a nibble above `0x0F`.
    pub fn child(&self, nibble: u8) -> Option<Path> {
        if self.len() >= KEY_NIBBLES || nibble > 0x0F {
            return None;
        }
        let mut child = *self;
        let at = self.len() / 2;
        if self.len().is_multiple_of(2) {
            child.packed[at] = nibble << 4;
        } else {
            child.packed[at] |= nibble;
        }
        child.len += 1;
        Some(child)
    }

    /// Whether a key begins with this path.
    pub fn holds(&self, key: &[u8; 32]) -> bool {
        Path::prefix_of(key, self.len()) == *self
    }

    /// The first key under the path, and the first key past it (`None` past the last key).
    fn bounds(&self) -> ([u8; 32], Option<[u8; 32]>) {
        let low = self.packed;
        let mut high = self.packed;
        let mut index = self.len();
        while index > 0 {
            index -= 1;
            let byte = &mut high[index / 2];
            let n = if index.is_multiple_of(2) {
                *byte >> 4
            } else {
                *byte & 0x0F
            };
            let shift = if index.is_multiple_of(2) { 4 } else { 0 };
            *byte &= !(0x0F << shift);
            if n < 0x0F {
                *byte |= (n + 1) << shift;
                return (low, Some(high));
            }
        }
        (low, None)
    }
}

// ---------------------------------------------------------------------------------------------
// Nodes

/// What a node is in the canonical shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// No slot under the path.
    Empty,
    /// At most [`LEAF_MAX`] slots, or 64 nibbles deep.
    Leaf,
    /// More than [`LEAF_MAX`] slots above 64 nibbles.
    Inner,
}

impl NodeKind {
    /// `empty`, `leaf`, or `inner`.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Empty => "empty",
            NodeKind::Leaf => "leaf",
            NodeKind::Inner => "inner",
        }
    }
}

/// One node of the trie, with its preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditNode {
    /// Empty, leaf, or inner.
    pub kind: NodeKind,
    /// The slots under the path.
    pub count: u64,
    /// The fingerprint; `None` for an empty node.
    pub fingerprint: Option<[u8; FINGERPRINT_BYTES]>,
    /// The leaf's joined lines or the inner node's 384 bytes; empty for an empty node.
    pub preimage: Vec<u8>,
}

/// A node's count, the full SHA-256 of its preimage, and its lines' byte total, memoized by
/// path.
#[derive(Debug, Clone, Copy)]
struct Summary {
    count: u64,
    hash: [u8; 32],
    inner: bool,
    /// The UTF-8 bytes of the lines under the node, each with one LF, so the joined lines are one
    /// byte shorter. Exact, since every line names its own slot's id and two slots therefore never
    /// share one: what a bounded line build measures ([`AuditTrie::joined_under`]).
    bytes: u64,
}

/// A slot's share of a node's byte total: each of its lines (distinct already) and one LF.
fn slot_bytes(lines: &[String]) -> u64 {
    lines.iter().map(|line| line.len() as u64 + 1).sum()
}

/// A child's fingerprint and count as an inner preimage lists them.
pub fn child_of(preimage: &[u8], child: usize) -> Option<([u8; FINGERPRINT_BYTES], u64)> {
    let at = child.checked_mul(CHILD_BYTES)?;
    let bytes = preimage.get(at..at + CHILD_BYTES)?;
    let mut fp = [0u8; FINGERPRINT_BYTES];
    fp.copy_from_slice(&bytes[..FINGERPRINT_BYTES]);
    let mut count = [0u8; 8];
    count.copy_from_slice(&bytes[FINGERPRINT_BYTES..]);
    Some((fp, u64::from_be_bytes(count)))
}

// ---------------------------------------------------------------------------------------------
// The trie

/// The audited set of one space stream as a fingerprinted trie (see the [module docs](self)).
#[derive(Debug, Clone, Default)]
pub struct AuditTrie {
    /// The slots by key, then id (two ids never share a key short of a SHA-256 collision).
    slots: BTreeMap<([u8; 32], String), Vec<String>>,
    /// The summaries of the non-empty nodes computed since their path last changed.
    memo: HashMap<Path, Summary>,
    /// Slots read by the line walks ([`AuditTrie::lines_under`], [`AuditTrie::joined_under`]),
    /// for the tests that bound them.
    #[cfg(test)]
    walked: std::cell::Cell<u64>,
}

impl AuditTrie {
    /// An empty trie.
    pub fn new() -> Self {
        AuditTrie::default()
    }

    /// The trie of the given slots ([`SlotSource::lines`] each).
    pub fn from_sources<'a>(sources: impl IntoIterator<Item = SlotSource<'a>>) -> Self {
        let mut trie = AuditTrie::new();
        for source in sources {
            trie.put(source.id, source.lines());
        }
        trie
    }

    /// Sets an entry's slot to `lines` (sorted, each once, empty and control-holding lines left
    /// out); no lines, or an id that may not enter the set, removes it. Whether the set changed.
    pub fn put(&mut self, entry_id: &str, lines: Vec<String>) -> bool {
        let lines = normalize(lines);
        if lines.is_empty() || !is_audited_id(entry_id) {
            return self.remove(entry_id);
        }
        let key = entry_key(entry_id);
        let slot = (key, entry_id.to_owned());
        if self.slots.get(&slot) == Some(&lines) {
            return false;
        }
        self.slots.insert(slot, lines);
        self.forget(&key);
        true
    }

    /// Removes an entry's slot; whether it held one.
    pub fn remove(&mut self, entry_id: &str) -> bool {
        let key = entry_key(entry_id);
        if self.slots.remove(&(key, entry_id.to_owned())).is_none() {
            return false;
        }
        self.forget(&key);
        true
    }

    /// Removes every slot.
    pub fn clear(&mut self) {
        self.slots.clear();
        self.memo.clear();
    }

    /// The slot of an entry id, its lines.
    pub fn slot(&self, entry_id: &str) -> Option<&[String]> {
        self.slots
            .get(&(entry_key(entry_id), entry_id.to_owned()))
            .map(Vec::as_slice)
    }

    /// The entry ids of every slot, in key order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.slots.keys().map(|(_, id)| id.as_str())
    }

    /// The set's count: its slots, not its lines.
    pub fn count(&self) -> u64 {
        self.slots.len() as u64
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Every line of the set, sorted by bytes, each once.
    pub fn lines(&self) -> Vec<String> {
        self.lines_under(&Path::ROOT)
    }

    /// The stream hash: the whole SHA-256 of the root's preimage.
    pub fn stream_hash(&mut self) -> [u8; 32] {
        self.summary(&Path::ROOT)
            .map_or(EMPTY_STREAM_HASH, |summary| summary.hash)
    }

    /// The count and fingerprint at a path (`(0, None)` for an empty node), memoized.
    pub fn fingerprint_at(&mut self, path: &Path) -> (u64, Option<[u8; FINGERPRINT_BYTES]>) {
        self.summary(path).map_or((0, None), |summary| {
            (summary.count, Some(truncate(&summary.hash)))
        })
    }

    /// The node at a path with its preimage.
    pub fn node(&mut self, path: &Path) -> AuditNode {
        let Some(summary) = self.summary(path) else {
            return AuditNode {
                kind: NodeKind::Empty,
                count: 0,
                fingerprint: None,
                preimage: Vec::new(),
            };
        };
        let preimage = if summary.inner {
            self.inner_preimage(path)
        } else {
            self.leaf_preimage(path)
        };
        AuditNode {
            kind: if summary.inner {
                NodeKind::Inner
            } else {
                NodeKind::Leaf
            },
            count: summary.count,
            fingerprint: Some(truncate(&summary.hash)),
            preimage,
        }
    }

    /// Every line under a path whatever its count, sorted by bytes, each once.
    pub fn lines_under(&self, path: &Path) -> Vec<String> {
        let mut lines: Vec<String> = self
            .range(path)
            .inspect(|_| self.note_walked())
            .flat_map(|(_, lines)| lines.iter().cloned())
            .collect();
        lines.sort_unstable();
        lines.dedup();
        lines
    }

    /// The bytes of the lines under a path, each with one LF (0 for an empty node): the joined
    /// lines hold one byte less. Read from the node's summary, memoized, never by a walk.
    pub fn line_bytes_at(&mut self, path: &Path) -> u64 {
        self.summary(path).map_or(0, |summary| summary.bytes)
    }

    /// [`AuditTrie::lines_under`] joined as a leaf's preimage, or `None` when the lines pass
    /// `max_bytes`: known from the node's byte total without a walk, so lines that would pass the
    /// bound are never gathered only to be thrown away (annex I.6, step 4).
    pub fn joined_under(&mut self, path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
        let joined = self.line_bytes_at(path).saturating_sub(1);
        if joined > max_bytes as u64 {
            return None;
        }
        let mut total = 0usize;
        let mut lines: Vec<&str> = Vec::new();
        for (_, slot) in self.range(path) {
            self.note_walked();
            for line in slot {
                total = total.saturating_add(line.len() + 1);
                if total > max_bytes.saturating_add(1) {
                    return None;
                }
                lines.push(line);
            }
        }
        lines.sort_unstable();
        lines.dedup();
        Some(lines.join("\n").into_bytes())
    }

    /// Whether `line` is in the set.
    pub fn holds_line(&self, line: &str) -> bool {
        self.holds_line_under(line, &Path::ROOT)
    }

    /// Whether `line` is among the lines under `path`: the slot of the entry id the line names
    /// lies under the path and lists the line. Every line names its own slot's id (a state or
    /// claim line by construction, an acknowledged line as [`SlotSource::lines`] keeps it), so
    /// this reads one slot and answers what a comparison with every line under the path answers,
    /// at the cost of the one line (Java `HashTrie.holdsLine`).
    pub fn holds_line_under(&self, line: &str, path: &Path) -> bool {
        let Some(id) = entry_id_of_line(line) else {
            return false;
        };
        let key = entry_key(id);
        path.holds(&key)
            && self.slots.get(&(key, id.to_owned())).is_some_and(|lines| {
                lines
                    .binary_search_by(|held| held.as_str().cmp(line))
                    .is_ok()
            })
    }

    // ---- internals

    /// Counts one slot read by a line walk (tests only).
    #[inline]
    fn note_walked(&self) {
        #[cfg(test)]
        self.walked.set(self.walked.get() + 1);
    }

    /// The slots read by line walks since the last call, and resets the count (tests only).
    #[cfg(test)]
    pub(crate) fn take_walked(&self) -> u64 {
        self.walked.replace(0)
    }

    /// The slots under a path, in key order.
    fn range(&self, path: &Path) -> impl Iterator<Item = (&([u8; 32], String), &Vec<String>)> {
        let (low, high) = path.bounds();
        let start = Bound::Included((low, String::new()));
        let end = match high {
            Some(high) => Bound::Excluded((high, String::new())),
            None => Bound::Unbounded,
        };
        self.slots.range((start, end))
    }

    /// Forgets the memo of every node on a key's path.
    fn forget(&mut self, key: &[u8; 32]) {
        if self.memo.is_empty() {
            return;
        }
        for len in 0..=KEY_NIBBLES {
            self.memo.remove(&Path::prefix_of(key, len));
        }
    }

    /// The summary at a path, `None` when the node is empty.
    fn summary(&mut self, path: &Path) -> Option<Summary> {
        if let Some(summary) = self.memo.get(path) {
            return Some(*summary);
        }
        // How many slots, up to one past the threshold: that decides leaf or inner.
        let probe = self.range(path).take(LEAF_MAX as usize + 1).count() as u64;
        if probe == 0 {
            return None;
        }
        let summary = if probe <= LEAF_MAX || path.len() >= KEY_NIBBLES {
            let (count, bytes) = self
                .range(path)
                .fold((0u64, 0u64), |(count, bytes), (_, lines)| {
                    (count + 1, bytes + slot_bytes(lines))
                });
            Summary {
                count,
                hash: crypto::port().sha256(&self.leaf_preimage(path)),
                inner: false,
                bytes,
            }
        } else {
            let mut preimage = Vec::with_capacity(INNER_PREIMAGE_BYTES);
            let mut count = 0u64;
            let mut bytes = 0u64;
            for c in 0..FANOUT as u8 {
                let child = path.child(c).unwrap_or(*path);
                match self.summary(&child) {
                    Some(summary) => {
                        preimage.extend_from_slice(&summary.hash[..FINGERPRINT_BYTES]);
                        preimage.extend_from_slice(&summary.count.to_be_bytes());
                        count += summary.count;
                        bytes += summary.bytes;
                    }
                    None => preimage.extend_from_slice(&[0u8; CHILD_BYTES]),
                }
            }
            Summary {
                count,
                hash: crypto::port().sha256(&preimage),
                inner: true,
                bytes,
            }
        };
        self.memo.insert(*path, summary);
        Some(summary)
    }

    fn leaf_preimage(&self, path: &Path) -> Vec<u8> {
        self.lines_under(path).join("\n").into_bytes()
    }

    fn inner_preimage(&mut self, path: &Path) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(INNER_PREIMAGE_BYTES);
        for c in 0..FANOUT as u8 {
            let child = path.child(c).unwrap_or(*path);
            match self.summary(&child) {
                Some(summary) => {
                    preimage.extend_from_slice(&summary.hash[..FINGERPRINT_BYTES]);
                    preimage.extend_from_slice(&summary.count.to_be_bytes());
                }
                None => preimage.extend_from_slice(&[0u8; CHILD_BYTES]),
            }
        }
        preimage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn one_line(id: &str, hash: &str) -> SlotSource<'static> {
        // Leaked for the test's brevity: a handful of short strings.
        let id: &'static str = Box::leak(id.to_owned().into_boxed_str());
        let hash: &'static str = Box::leak(hash.to_owned().into_boxed_str());
        SlotSource {
            id,
            state: Some(hash),
            ..SlotSource::default()
        }
    }

    #[test]
    fn the_annex_illustrations_hold() {
        // A slot `a` holding e:a=1 and c:a=2: key ca978112..., the 11-byte leaf preimage.
        let mut trie = AuditTrie::new();
        trie.put("a", vec!["e:a=1".into(), "c:a=2".into()]);
        assert_eq!(hex(&entry_key("a")[..4]), "ca978112");
        let root = trie.node(&Path::ROOT);
        assert_eq!(root.preimage, b"c:a=2\ne:a=1");
        assert_eq!(
            hex(&root.fingerprint.unwrap()),
            "b5af992c6ac029d376fa9dec750a5c4b"
        );
        // e00 to e32: an inner root with empty children at nibbles 2 and 7.
        let ids: Vec<String> = (0..33).map(|i| format!("e{i:02}")).collect();
        let mut big = AuditTrie::from_sources(ids.iter().map(|id| one_line(id, "0")));
        assert_eq!(
            hex(&big.stream_hash()),
            "988d034b3abe2292c17478e2f646d845710c3ce40c30dfd9732598be8c2560cb"
        );
        let root = big.node(&Path::ROOT);
        assert_eq!(root.kind, NodeKind::Inner);
        assert_eq!(child_of(&root.preimage, 2), Some(([0; 16], 0)));
        assert_eq!(child_of(&root.preimage, 7), Some(([0; 16], 0)));
        big.remove("e32");
        assert_eq!(
            hex(&big.stream_hash()),
            "fb7d5b769f66fc5abcc7636fe0bb14131574cac97d0feba9525ced60a95ac77e"
        );
        assert_eq!(big.node(&Path::ROOT).kind, NodeKind::Leaf);
        assert_eq!(
            hex(&AuditTrie::new().stream_hash()),
            hex(&EMPTY_STREAM_HASH)
        );
    }

    #[test]
    fn paths_pack_and_bound() {
        let path = Path::from_nibbles(&[0xc, 0xa, 0x9]).unwrap();
        assert_eq!(path.hex(), "ca9");
        assert_eq!(path.nibbles(), vec![0xc, 0xa, 0x9]);
        assert!(path.holds(&entry_key("a")));
        assert!(Path::from_nibbles(&[0x10]).is_none());
        assert!(Path::from_nibbles(&[0; 65]).is_none());
        let deep = Path::from_nibbles(&[0xF; 64]).unwrap();
        assert!(deep.child(0).is_none());
        assert_eq!(deep.bounds().1, None);
        let (low, high) = Path::from_nibbles(&[0x1, 0xF]).unwrap().bounds();
        assert_eq!(low[0], 0x1F);
        assert_eq!(high.unwrap()[0], 0x20);
    }

    /// A bounded line build whose node's lines are known to pass the bound reads no slot: the
    /// node's exact byte total answers it, so a body of requests whose lines a partner would only
    /// gather to throw away costs it nothing (annex I.6, step 4).
    #[test]
    fn a_line_build_known_to_pass_its_bound_reads_no_slot() {
        let ids: Vec<String> = (0..4_000).map(|i| format!("entry-{i:05}")).collect();
        let mut trie = AuditTrie::from_sources(ids.iter().map(|id| one_line(id, "0")));
        trie.stream_hash();
        for c in 0..FANOUT as u8 {
            let path = Path::ROOT.child(c).unwrap();
            let (count, _) = trie.fingerprint_at(&path);
            assert!(count > 100, "{count}");
            trie.take_walked();
            assert_eq!(trie.joined_under(&path, 1_000), None);
            assert_eq!(
                trie.take_walked(),
                0,
                "a walk known to pass its bound was made"
            );
        }
        // A bound the lines fit in still gathers them, exactly as a leaf joins them.
        let path = Path::from_nibbles(&[3, 1]).unwrap();
        let all = trie.joined_under(&path, usize::MAX).expect("unbounded");
        assert_eq!(
            trie.joined_under(&path, all.len()).as_deref(),
            Some(all.as_slice())
        );
        assert_eq!(trie.joined_under(&path, all.len() - 1), None);
    }

    #[test]
    fn slot_rules_apply() {
        let acks = vec!["e:x=9".to_owned()];
        let lapsed = SlotSource {
            id: "x",
            state: Some("1"),
            claim: Some("2"),
            lapsed: true,
            acks: &acks,
            ..SlotSource::default()
        };
        assert_eq!(lapsed.lines(), vec!["e:x=9"]);
        let dropped = SlotSource {
            id: "x",
            dropped: Some("5"),
            ..SlotSource::default()
        };
        assert_eq!(dropped.lines(), vec!["e:x=5"]);
        let control = SlotSource {
            id: "x\ny",
            state: Some("1"),
            ..SlotSource::default()
        };
        assert!(control.lines().is_empty());
        assert_eq!(entry_id_of_line("e:a=b=c"), Some("a=b"));
        assert_eq!(entry_id_of_line("a:e:a=1"), None);
        assert_eq!(entry_id_of_line("e:=1"), None);
    }
}
