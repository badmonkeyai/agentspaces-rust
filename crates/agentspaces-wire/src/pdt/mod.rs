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

//! Persistent data trees (SPEC annex H), the pure half: nodes and their CIDs, the level-1
//! values (`PMap`, `PSet`, `PVector`, `PBlob`), spill, the `PRef` head record, the version-graph
//! node, and `FileEntry`. A port of `agentspaces-python/agentspaces/pdt` with Java's
//! `agentspaces-pdt` as the authority on bytes; the golden vectors `pdt_*` prove it.
//!
//! Nothing here touches the network or a disk. Values read and write nodes through the
//! [`store::Nodes`] trait, and [`store::MemoryNodes`] is the in-memory store. The peer crate
//! moves nodes between members (the tree exchange of SPEC §8) and the `agentspaces-pdt` crate
//! holds refs, the facade, and durable stores.
//!
//! Level 1 is what this module writes. A node of a level-2 kind (`db`, `dn`, `rr`, `rv`, `t`,
//! `vg`, `bo`) decodes, verifies, and yields its links, so a member stores and serves it, and the
//! level-1 value readers refuse it by name, as annex H requires of a level-1 member. The `vg`
//! node is written as well, since a ref writer names it in `pdt.ancestry` (v0.1.33).

pub mod blob;
pub mod champ;
pub mod cid;
pub mod fastcdc;
pub mod file_entry;
pub mod node;
pub mod pref;
pub mod store;
pub mod value;
pub mod vector;
pub mod vg;

use std::fmt;

/// Why a node, a value, or a record was refused: the rule broken and, when known, the CID of
/// the node that broke it (annex H: "names the CID and the rule").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeError {
    /// The rule, in words.
    pub rule: String,
    /// The node's CID, when the caller knew it.
    pub cid: Option<String>,
}

impl NodeError {
    /// A refusal under `rule`, with no CID yet.
    pub fn new(rule: impl Into<String>) -> Self {
        NodeError {
            rule: rule.into(),
            cid: None,
        }
    }

    /// A refusal under `rule` of the node `cid`.
    pub fn at(rule: impl Into<String>, cid: &str) -> Self {
        NodeError {
            rule: rule.into(),
            cid: Some(cid.to_string()),
        }
    }

    /// This refusal, naming `cid` when it named none.
    pub fn with_cid(mut self, cid: Option<&str>) -> Self {
        if self.cid.is_none() {
            self.cid = cid.map(str::to_string);
        }
        self
    }
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cid {
            Some(cid) => write!(f, "node {cid}: {}", self.rule),
            None => write!(f, "{}", self.rule),
        }
    }
}

impl std::error::Error for NodeError {}

/// Why a value operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdtError {
    /// A node broke a rule of annex H.
    Node(NodeError),
    /// A node the operation needs is not in the store (fetch it, then retry).
    Missing(String),
    /// The caller's input breaks a rule (a value too large, a bare link item, a bad index).
    Invalid(String),
}

impl fmt::Display for PdtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdtError::Node(e) => e.fmt(f),
            PdtError::Missing(cid) => write!(f, "node {cid} is not in the store"),
            PdtError::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for PdtError {}

impl From<NodeError> for PdtError {
    fn from(e: NodeError) -> Self {
        PdtError::Node(e)
    }
}

/// The result of a value operation.
pub type Result<T> = std::result::Result<T, PdtError>;

/// The sha2-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}
