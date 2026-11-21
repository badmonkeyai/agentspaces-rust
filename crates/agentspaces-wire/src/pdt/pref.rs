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

//! The `PRef` head (annex H, the ref; SPEC §7.1): `ai.badmonkey.agentspaces.agent.pdt.PRef#v1`,
//! a reserved entry type whose record names a version of a ref. [`PRef::decode`] reads the
//! record under its annex I.1 schema (the record rules P1 to P4 and R1, [`crate::schema`]) and
//! [`PRef::violation`] judges the bounds of annex H; a reader ignores a head that fails either
//! and counts it once in `headsIgnored`.

use crate::cbor::{self, Map, Value};
use crate::schema;

use super::cid;

/// The entry type of a head.
pub const PREF_TYPE: &str = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1";
/// The tag that carries the ref name.
pub const NAME_TAG: &str = "name";
/// The tag that carries the root.
pub const ROOT_TAG: &str = "root";
/// Version 1.
pub const VERSION: i64 = 1;
/// Version 2 (PDT 2).
pub const VERSION_2: i64 = 2;
/// A map ref.
pub const KIND_MAP: &str = "map";
/// A set ref.
pub const KIND_SET: &str = "set";
/// A vector ref.
pub const KIND_VECTOR: &str = "vector";
/// A blob ref.
pub const KIND_BLOB: &str = "blob";
/// A tree ref (a map from relative path to `FileEntry`).
pub const KIND_TREE: &str = "tree";
/// A DataScript ref (PDT 2).
pub const KIND_DB: &str = "db";
/// The kinds a head may name.
pub const KINDS: [&str; 6] = [KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE, KIND_DB];
/// Concurrent heads merge.
pub const MODE_MULTI: &str = "multi";
/// A take serves as the compare-and-set.
pub const MODE_LINEAR: &str = "linear";
/// No sealing.
pub const SEALING_NONE: &str = "none";
/// Sealed per `NODES` under the group key.
pub const SEALING_GROUP_KEY: &str = "group-key";
/// Each node sealed deterministically.
pub const SEALING_SEALED_NODES: &str = "sealed-nodes";
/// The longest name, in UTF-8 bytes.
pub const MAX_NAME_BYTES: usize = 256;
/// The most bases.
pub const MAX_BASE: usize = 8;
/// The largest seq (2^53).
pub const MAX_SEQ: i64 = 1 << 53;
/// The inline delta's bound.
pub const INLINE_DELTA_BYTES: usize = 32 * 1024;
/// The most attrs.
pub const MAX_ATTRS: usize = 32;
/// The bytes of attrs' keys and text values at most.
pub const MAX_ATTRS_BYTES: usize = 4 * 1024;
/// The longest `mode` or `sealing`.
pub const MAX_MODE_BYTES: usize = 32;
/// The advisory issued stamp.
pub const ISSUED_ATTR: &str = "pdt.issued";
/// The advisory issuer.
pub const ISSUER_ATTR: &str = "pdt.issuer";
/// The chain node of the version graph.
pub const ANCESTRY_ATTR: &str = "pdt.ancestry";

/// One head's record.
#[derive(Debug, Clone, PartialEq)]
pub struct PRef {
    /// 1, or 2 under PDT 2.
    pub v: i64,
    /// The ref name.
    pub name: String,
    /// The kind of value.
    pub kind: String,
    /// The root CID.
    pub root: String,
    /// The roots this version was computed from (0 to 8).
    pub base: Vec<String>,
    /// max(seq of the bases) + 1.
    pub seq: i64,
    /// Entries or bytes.
    pub size: i64,
    /// The inline delta, when carried.
    pub nodes: Option<Vec<Vec<u8>>>,
    /// `multi` or `linear` (an open set).
    pub mode: String,
    /// `none`, `group-key`, or `sealed-nodes` (an open set).
    pub sealing: String,
    /// The key epoch, when sealed.
    pub key_epoch: Option<i64>,
    /// The attributes in canonical key order; a value is text except under the reserved pair,
    /// where it may be any item (rule R1).
    pub attrs: Option<Vec<(String, Value)>>,
}

impl PRef {
    /// A version-1 head with no inline delta, attrs, or key epoch.
    pub fn new(name: &str, kind: &str, root: &str, base: Vec<String>, seq: i64, size: i64) -> PRef {
        PRef {
            v: VERSION,
            name: name.to_string(),
            kind: kind.to_string(),
            root: root.to_string(),
            base,
            seq,
            size,
            nodes: None,
            mode: MODE_MULTI.to_string(),
            sealing: SEALING_NONE.to_string(),
            key_epoch: None,
            attrs: None,
        }
    }

    /// The text attr under `key`.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.as_ref()?.iter().find(|(k, _)| k == key).and_then(|(_, v)| v.as_str())
    }

    /// Sets a text attr, keeping canonical order.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        let attrs = self.attrs.get_or_insert_with(Vec::new);
        attrs.retain(|(k, _)| k != key);
        attrs.push((key.to_string(), Value::from(value)));
        attrs.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    }

    /// The record as a CBOR value, fields in declared order, `nodes`, `keyEpoch`, and `attrs`
    /// omitted when absent.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("v", Value::Int(i128::from(self.v)));
        map.insert("name", self.name.as_str());
        map.insert("kind", self.kind.as_str());
        map.insert("root", self.root.as_str());
        map.insert("base", Value::Array(self.base.iter().map(Value::from).collect()));
        map.insert("seq", Value::Int(i128::from(self.seq)));
        map.insert("size", Value::Int(i128::from(self.size)));
        if let Some(nodes) = &self.nodes {
            map.insert("nodes", Value::Array(nodes.iter().map(|n| Value::Bytes(n.clone())).collect()));
        }
        map.insert("mode", self.mode.as_str());
        map.insert("sealing", self.sealing.as_str());
        if let Some(epoch) = self.key_epoch {
            map.insert("keyEpoch", Value::Int(i128::from(epoch)));
        }
        if let Some(attrs) = &self.attrs {
            let mut a = Map::new();
            for (k, v) in attrs {
                a.insert(k.as_str(), v.clone());
            }
            map.insert("attrs", Value::Map(cbor::canonical_map(&a)));
        }
        Value::Map(map)
    }

    /// The record's bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// The tags a head entry carries: `name` and `root`.
    pub fn tags(&self) -> Map {
        let mut tags = Map::new();
        tags.insert(NAME_TAG, self.name.as_str());
        tags.insert(ROOT_TAG, self.root.as_str());
        cbor::canonical_map(&tags)
    }

    /// The record the bytes hold under its schema, or `None` when undecodable.
    pub fn decode(bytes: &[u8]) -> Option<PRef> {
        let map = schema::decode_map(bytes, "PRef")?;
        Self::from_map(&map)
    }

    /// The record a decoded map holds, or `None` when a field is of another kind.
    pub fn from_map(map: &Map) -> Option<PRef> {
        let text = |k: &str| map.get(k).and_then(Value::as_str).map(str::to_string);
        let int = |k: &str| map.get(k).and_then(Value::as_i64);
        let base = map
            .get("base")?
            .as_array()?
            .iter()
            .map(|b| b.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?;
        let nodes = match map.get("nodes") {
            None => None,
            Some(v) => Some(v.as_array()?.iter().map(|n| n.as_bytes().map(<[u8]>::to_vec)).collect::<Option<Vec<_>>>()?),
        };
        let attrs = match map.get("attrs") {
            None => None,
            Some(v) => Some(
                v.as_map()?
                    .iter()
                    .map(|(k, v)| k.as_str().map(|k| (k.to_string(), v.clone())))
                    .collect::<Option<Vec<_>>>()?,
            ),
        };
        Some(PRef {
            v: int("v")?,
            name: text("name")?,
            kind: text("kind")?,
            root: text("root")?,
            base,
            seq: int("seq")?,
            size: int("size")?,
            nodes,
            mode: text("mode")?,
            sealing: text("sealing")?,
            key_epoch: match map.get("keyEpoch") {
                None => None,
                Some(v) => Some(v.as_i64()?),
            },
            attrs,
        })
    }

    /// The first broken bound of annex H, or `None`.
    pub fn violation(&self) -> Option<String> {
        if self.v != VERSION && self.v != VERSION_2 {
            return Some(format!("unsupported PRef version {}", self.v));
        }
        if self.kind == KIND_DB && self.v != VERSION_2 {
            return Some(format!("a db head is version {VERSION_2}, found {}", self.v));
        }
        if self.name.is_empty() {
            return Some("empty name".to_string());
        }
        if self.name.len() > MAX_NAME_BYTES {
            return Some(format!("name longer than {MAX_NAME_BYTES} bytes"));
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Some(format!("unknown kind {}", self.kind));
        }
        if !cid::is_cid(&self.root) {
            return Some("root is not a CID".to_string());
        }
        if self.base.len() > MAX_BASE {
            return Some(format!("more than {MAX_BASE} bases"));
        }
        if self.base.iter().any(|b| !cid::is_cid(b)) {
            return Some("base root is not a CID".to_string());
        }
        if self.seq < 0 {
            return Some("negative seq".to_string());
        }
        if self.seq > MAX_SEQ {
            return Some(format!("seq above {MAX_SEQ}"));
        }
        if self.size < 0 {
            return Some("negative size".to_string());
        }
        if let Some(nodes) = &self.nodes {
            if nodes.iter().any(Vec::is_empty) {
                return Some("empty inline node".to_string());
            }
            if nodes.iter().map(Vec::len).sum::<usize>() > INLINE_DELTA_BYTES {
                return Some(format!("inline nodes larger than {INLINE_DELTA_BYTES} bytes"));
            }
        }
        for (field, v) in [("mode", &self.mode), ("sealing", &self.sealing)] {
            if v.is_empty() {
                return Some(format!("empty {field}"));
            }
            if v.len() > MAX_MODE_BYTES {
                return Some(format!("{field} longer than {MAX_MODE_BYTES} bytes"));
            }
        }
        if self.key_epoch.is_some_and(|e| e < 0) {
            return Some("negative keyEpoch".to_string());
        }
        if let Some(attrs) = &self.attrs {
            if attrs.len() > MAX_ATTRS {
                return Some(format!("more than {MAX_ATTRS} attrs"));
            }
            let bytes: usize = attrs.iter().map(|(k, v)| k.len() + v.as_str().map_or(0, str::len)).sum();
            if bytes > MAX_ATTRS_BYTES {
                return Some(format!("attrs larger than {MAX_ATTRS_BYTES} bytes"));
            }
        }
        None
    }
}
