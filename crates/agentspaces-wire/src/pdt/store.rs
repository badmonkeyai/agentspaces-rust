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

//! Where values read and write nodes: the [`Nodes`] trait, the in-memory [`MemoryNodes`], and
//! the [`Flusher`] that hashes new nodes bottom up and writes the ones a store lacks.
//!
//! A store holds verified bytes only. [`Nodes::put_verified`] checks the bytes against the CID
//! before it stores them; [`Flusher::write`] computes the CID itself. A reader that finds no node
//! gets [`PdtError::Missing`] and fetches it (the tree exchange), then reads again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{PdtError, Result, cid};

/// A store of nodes by CID. Implementations hold verified bytes and are shared across threads.
pub trait Nodes: Send + Sync {
    /// The bytes of a node, when held.
    fn get(&self, cid: &str) -> Option<Arc<[u8]>>;

    /// Whether a node is held.
    fn has(&self, cid: &str) -> bool {
        self.get(cid).is_some()
    }

    /// Stores bytes the caller already verified against `cid`; true when the node is new here.
    fn put(&self, cid: &str, data: &[u8]) -> bool;

    /// Stores bytes after verifying them against `cid`.
    fn put_verified(&self, cid: &str, data: &[u8]) -> Result<bool> {
        if !cid::verifies(cid, data) {
            return Err(PdtError::Invalid(format!(
                "bytes do not hash to {cid}"
            )));
        }
        Ok(self.put(cid, data))
    }

    /// The bytes of a node, or [`PdtError::Missing`].
    fn load(&self, cid: &str) -> Result<Arc<[u8]>> {
        self.get(cid).ok_or_else(|| PdtError::Missing(cid.to_string()))
    }
}

/// Nodes in memory.
#[derive(Debug, Default)]
pub struct MemoryNodes {
    nodes: Mutex<HashMap<String, Arc<[u8]>>>,
}

impl MemoryNodes {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of nodes held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store holds no node.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of every node held.
    pub fn total_bytes(&self) -> usize {
        self.lock().values().map(|v| v.len()).sum()
    }

    /// Removes a node; true when it was held.
    pub fn remove(&self, cid: &str) -> bool {
        self.lock().remove(cid).is_some()
    }

    /// The CIDs held.
    pub fn cids(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<[u8]>>> {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Nodes for MemoryNodes {
    fn get(&self, cid: &str) -> Option<Arc<[u8]>> {
        self.lock().get(cid).cloned()
    }

    fn has(&self, cid: &str) -> bool {
        self.lock().contains_key(cid)
    }

    fn put(&self, cid: &str, data: &[u8]) -> bool {
        let mut nodes = self.lock();
        if nodes.contains_key(cid) {
            return false;
        }
        nodes.insert(cid.to_string(), Arc::from(data));
        true
    }
}

/// The nodes a flush wrote, by CID, children before parents.
pub type Written = Vec<(String, Arc<[u8]>)>;

/// Hashes new nodes and writes those the store lacks, recording what it wrote (the delta).
pub struct Flusher<'a> {
    store: &'a dyn Nodes,
    written: Vec<(String, Arc<[u8]>)>,
}

impl<'a> Flusher<'a> {
    /// A flusher into `store`.
    pub fn new(store: &'a dyn Nodes) -> Self {
        Flusher {
            store,
            written: Vec::new(),
        }
    }

    /// The store written to.
    pub fn store(&self) -> &'a dyn Nodes {
        self.store
    }

    /// Writes `data` under `codec` when the store lacks it, and returns its CID.
    pub fn write(&mut self, data: Vec<u8>, codec: u8) -> String {
        let cid = cid::of(&data, codec);
        if !self.store.has(&cid) && self.store.put(&cid, &data) {
            self.written.push((cid.clone(), Arc::from(data)));
        }
        cid
    }

    /// The nodes this flusher wrote, in the order written (children before parents).
    pub fn written(&self) -> &[(String, Arc<[u8]>)] {
        &self.written
    }

    /// The nodes this flusher wrote, taken.
    pub fn into_written(self) -> Vec<(String, Arc<[u8]>)> {
        self.written
    }
}
