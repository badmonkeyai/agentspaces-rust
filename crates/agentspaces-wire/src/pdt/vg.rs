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

//! The version-graph node (annex H, the version graph): `{k:"vg", r: the head's root as CID
//! text, b: [each base root as CID text], i: the issuer's agent id, t: the issued stamp,
//! p: [links to the vg nodes of the bases, in the order of b]}`. A writer stores one per head and
//! names it in the head's `pdt.ancestry`; a reader walks it when a base's entry is gone.

use super::node::{self, Field, KIND_VG, Node};
use super::{NodeError, Result, cid};

/// One version's chain node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgNode {
    /// The version's root.
    pub root: String,
    /// The roots of its bases.
    pub bases: Vec<String>,
    /// The issuer's agent id.
    pub issuer: String,
    /// The issued stamp.
    pub stamp: String,
    /// The chain nodes of the bases, in the order of `bases` (fewer when a base has none known).
    pub parents: Vec<String>,
}

impl VgNode {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(node::encode(
            &Node::new(KIND_VG)
                .with("r", Field::Text(self.root.clone()))
                .with("b", Field::Texts(self.bases.clone()))
                .with("i", Field::Text(self.issuer.clone()))
                .with("t", Field::Text(self.stamp.clone()))
                .with("p", Field::Links(self.parents.clone())),
        )?)
    }

    /// The CID of the canonical bytes.
    pub fn cid(&self) -> Result<String> {
        Ok(cid::of(&self.encode()?, cid::DAG_CBOR))
    }

    /// A chain node from its bytes.
    pub fn decode(c: &str, data: &[u8]) -> Result<VgNode> {
        let n = node::decode(data, Some(c))?;
        if n.kind != KIND_VG {
            return Err(NodeError::at(format!("expected a vg node, found kind '{}'", n.kind), c).into());
        }
        let text = |key: &str| match n.get(key) {
            Some(Field::Text(t)) => Ok(t.clone()),
            _ => Err(NodeError::at(format!("vg node lacks '{key}'"), c)),
        };
        let bases = match n.get("b") {
            Some(Field::Texts(t)) => t.clone(),
            _ => return Err(NodeError::at("vg node lacks 'b'", c).into()),
        };
        Ok(VgNode {
            root: text("r")?,
            bases,
            issuer: text("i")?,
            stamp: text("t")?,
            parents: n.links("p").to_vec(),
        })
    }
}
