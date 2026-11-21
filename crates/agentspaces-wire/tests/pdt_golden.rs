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

//! The persistent-data-tree vectors of annex H, rebuilt from the inputs of Java's
//! `agentspaces-pdt` `golden/PdtVectors`, byte for byte.

mod common;

use agentspaces_wire::cbor::Value;
use agentspaces_wire::pdt::champ::PMap;
use agentspaces_wire::pdt::node::{self, KIND_SN};
use agentspaces_wire::pdt::pref::{self, PRef};
use agentspaces_wire::pdt::store::{Flusher, MemoryNodes, Nodes};
use agentspaces_wire::pdt::vector::PVector;
use agentspaces_wire::pdt::vg::VgNode;
use agentspaces_wire::pdt::{blob, cid, fastcdc};
use common::{hex, s};

/// `java.util.Random`, for the seeded streams of the vectors.
struct JavaRandom(u64);

impl JavaRandom {
    fn new(seed: u64) -> Self {
        JavaRandom((seed ^ 0x5DEE_CE66D) & ((1 << 48) - 1))
    }

    fn next_int(&mut self) -> i32 {
        self.0 = (self.0.wrapping_mul(0x5DEE_CE66D).wrapping_add(0xB)) & ((1 << 48) - 1);
        (self.0 >> 16) as i32
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let mut rnd = self.next_int();
            let n = (out.len() - i).min(4);
            for _ in 0..n {
                out[i] = rnd as u8;
                rnd >>= 8;
                i += 1;
            }
        }
    }
}

fn seeded(size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    JavaRandom::new(42).next_bytes(&mut out);
    out
}

fn text(t: &str) -> Vec<u8> {
    agentspaces_wire::cbor::encode(&Value::from(t))
}

fn int(n: i64) -> Vec<u8> {
    agentspaces_wire::cbor::encode(&Value::Int(i128::from(n)))
}

fn root_bytes(store: &MemoryNodes, root: &str) -> Vec<u8> {
    store.get(root).expect("root flushed").to_vec()
}

fn map_small(store: &MemoryNodes) -> String {
    let map = PMap::empty()
        .assoc(store, &text("a"), &int(1))
        .unwrap()
        .assoc(store, &text("b"), &text("two"))
        .unwrap();
    map.commit(store).unwrap().0
}

fn map_deep(store: &MemoryNodes) -> String {
    let mut map = PMap::empty();
    for i in 0..100 {
        map = map.assoc(store, &text(&format!("k{i}")), &int(i)).unwrap();
    }
    map.commit(store).unwrap().0
}

#[test]
fn map_vectors() {
    let store = MemoryNodes::new();
    let empty = PMap::empty().commit(&store).unwrap().0;
    assert_eq!(root_bytes(&store, &empty), hex("pdt_map_empty"));
    let small = map_small(&store);
    assert_eq!(root_bytes(&store, &small), hex("pdt_map_small"));
    assert_eq!(root_bytes(&store, &small), hex("pdt_node_dagcbor"));
    let deep = map_deep(&store);
    assert_eq!(root_bytes(&store, &deep), hex("pdt_map_deep"));

    let loaded = PMap::load(&store, &deep).unwrap();
    assert_eq!(loaded.count(), 100);
    assert_eq!(loaded.get(&store, &text("k42")).unwrap(), Some(int(42)));
    assert_eq!(loaded.get(&store, &text("k100")).unwrap(), None);
}

#[test]
fn map_layout_depends_only_on_the_key_set() {
    let store = MemoryNodes::new();
    let deep = map_deep(&store);
    let mut map = PMap::load(&store, &deep).unwrap();
    for i in 100..300 {
        map = map.assoc(&store, &text(&format!("k{i}")), &int(i)).unwrap();
    }
    for i in (100..300).rev() {
        map = map.dissoc(&store, &text(&format!("k{i}"))).unwrap();
    }
    assert_eq!(map.count(), 100);
    assert_eq!(map.commit(&store).unwrap().0, deep, "removal compacts back to the same root");
    let changed = map.assoc(&store, &text("k7"), &text("seven")).unwrap();
    let diff = changed.diff(&map, &store).unwrap();
    assert_eq!(diff.len(), 1);
    assert!(diff.contains_key(&text("k7")));
}

#[test]
fn embedded_items_keep_their_codec_form() {
    let store = MemoryNodes::new();
    // {"x": 1, "y": "two"} as Java's codec writes a LinkedHashMap, and 1.5f as a float32
    let rec = [0xBF, 0x61, b'x', 0x01, 0x61, b'y', 0x63, b't', b'w', b'o', 0xFF];
    let map = PMap::empty()
        .assoc(&store, &text("rec"), &rec)
        .unwrap()
        .assoc(&store, &text("f"), &[0xFA, 0x3F, 0xC0, 0x00, 0x00])
        .unwrap();
    let root = map.commit(&store).unwrap().0;
    assert_eq!(root_bytes(&store, &root), hex("pdt_node_embedded"));
}

#[test]
fn vector_vectors() {
    for (name, count) in [("pdt_vector_tail", 10), ("pdt_vector_deep", 1100)] {
        let store = MemoryNodes::new();
        let mut v = PVector::empty();
        for i in 0..count {
            v = v.conj(&store, &int(i)).unwrap();
        }
        let root = v.commit(&store).unwrap().0;
        assert_eq!(root_bytes(&store, &root), hex(name), "{name}");
        let loaded = PVector::load(&store, &root).unwrap();
        assert_eq!(loaded.count(), count as u64);
        assert_eq!(loaded.nth(&store, 700.min(count as u64 - 1)).unwrap(), int(700.min(count - 1)));
        let popped = loaded.pop(&store).unwrap();
        let mut rebuilt = PVector::empty();
        for i in 0..count - 1 {
            rebuilt = rebuilt.conj(&store, &int(i)).unwrap();
        }
        assert_eq!(popped.commit(&store).unwrap().0, rebuilt.commit(&store).unwrap().0, "{name} pop");
    }
}

#[test]
fn blob_and_cut_vectors() {
    let small = seeded(100 * 1024);
    let store = MemoryNodes::new();
    let written = blob::write_bytes(&small, &mut Flusher::new(&store)).unwrap();
    let mut expected = s("pdt_blob_small").split(',');
    assert_eq!(written.root, expected.next().unwrap());
    let chunks: Vec<&str> = expected.collect();
    assert_eq!(written.chunks.iter().map(|c| c.cid.as_str()).collect::<Vec<_>>(), chunks);
    assert_eq!(blob::read_all(&store, &written.root).unwrap(), small);

    let stream = seeded(8 * 1024 * 1024);
    let cuts: Vec<String> = fastcdc::cuts(&stream).iter().take(20).map(usize::to_string).collect();
    assert_eq!(cuts.join(","), s("pdt_fastcdc_cuts"));
}

fn golden_ref(store: &MemoryNodes) -> PRef {
    let deep = map_deep(store);
    let deep_node = root_bytes(store, &deep);
    let first_child = node::links(&deep_node, Some(&deep)).unwrap()[0].clone();
    let child_node = root_bytes(store, &first_child);
    let small = map_small(store);
    let mut r = PRef::new("facts", pref::KIND_MAP, &deep, vec![small], 2, 100);
    r.nodes = Some(vec![deep_node, child_node]);
    r.key_epoch = Some(3);
    r.set_attr("origin", "golden");
    r
}

#[test]
fn ref_vectors() {
    let store = MemoryNodes::new();
    let r = golden_ref(&store);
    assert_eq!(r.encode(), hex("pdt_ref_cbor"));
    let back = PRef::decode(&hex("pdt_ref_cbor")).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.violation(), None);

    let empty = PMap::empty().commit(&store).unwrap().0;
    let min = PRef::new("facts", pref::KIND_MAP, &empty, vec![], 1, 0);
    assert_eq!(min.encode(), hex("pdt_ref_min_cbor"));

    let v2 = PRef::decode(&hex("pdt_ref_v2_cbor")).unwrap();
    assert_eq!((v2.v, v2.kind.as_str()), (2, pref::KIND_DB));
    assert_eq!(v2.encode(), hex("pdt_ref_v2_cbor"));
}

#[test]
fn version_graph_vectors() {
    let chain = s("pdt_vg_chain");
    let mut parts = chain.split(',');
    let (deep_hex, small_hex) = (parts.next().unwrap(), parts.next().unwrap());
    let deep_bytes = ::hex::decode(deep_hex).unwrap();
    let small_bytes = ::hex::decode(small_hex).unwrap();
    let small_cid = cid::of(&small_bytes, cid::DAG_CBOR);
    let deep_cid = cid::of(&deep_bytes, cid::DAG_CBOR);
    let deep = VgNode::decode(&deep_cid, &deep_bytes).unwrap();
    let small = VgNode::decode(&small_cid, &small_bytes).unwrap();
    assert_eq!(deep.encode().unwrap(), deep_bytes);
    assert_eq!(small.encode().unwrap(), small_bytes);
    assert_eq!(deep.parents, vec![small_cid.clone()]);
    assert_eq!(deep.bases, vec![small.root.clone()]);

    let store = MemoryNodes::new();
    let r = golden_ref(&store);
    assert_eq!(deep.root, r.root);
    assert_eq!(small.root, r.base[0]);

    let merge_bytes = hex("pdt_vg_merge");
    let merge = VgNode::decode(&cid::of(&merge_bytes, cid::DAG_CBOR), &merge_bytes).unwrap();
    assert_eq!(merge.encode().unwrap(), merge_bytes);
    assert_eq!(merge.root, PMap::empty().commit(&store).unwrap().0);
    assert_eq!(merge.parents, vec![deep_cid.clone(), small_cid]);

    let ancestry = PRef::decode(&hex("pdt_ref_ancestry_cbor")).unwrap();
    assert_eq!(ancestry.attr(pref::ANCESTRY_ATTR), Some(deep_cid.as_str()));
    assert_eq!(ancestry.encode(), hex("pdt_ref_ancestry_cbor"));
}

#[test]
fn sealed_envelope_decodes_with_links_in_the_clear() {
    let bytes = hex("pdt_sealed_node");
    let n = node::decode(&bytes, None).unwrap();
    assert_eq!(n.kind, KIND_SN);
    assert!(node::links(&bytes, None).unwrap().is_empty(), "map_small has no links");
    assert_eq!(node::encode(&n).unwrap(), bytes);
}

/// Every node of the level-2 vectors decodes, re-encodes to its bytes, and yields its links, so a
/// level-1 member verifies, stores, and serves it.
#[test]
fn level_two_nodes_round_trip() {
    for name in [
        "pdt_db_root",
        "pdt_dn_leaf",
        "pdt_dn_branch",
        "pdt_dn_tail",
        "pdt_datom_values",
        "pdt_rr_relaxed",
        "pdt_rr_packed",
        "pdt_text_runs",
        "pdt_text_merge",
    ] {
        for part in s(name).split(',') {
            let Ok(bytes) = ::hex::decode(part) else { continue };
            if bytes.first().is_none_or(|b| b >> 5 != 5) {
                continue;
            }
            let n = node::decode(&bytes, None).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(node::encode(&n).unwrap(), bytes, "{name}");
            node::links(&bytes, None).unwrap();
        }
    }
    let sample = s("pdt_db_sample");
    let mut parts = sample.split(',');
    let root = parts.next().unwrap();
    let store = MemoryNodes::new();
    for part in parts {
        let bytes = ::hex::decode(part).unwrap();
        let c = cid::of(&bytes, cid::DAG_CBOR);
        store.put_verified(&c, &bytes).unwrap();
    }
    // every node reachable from the root is held, and its links resolve
    let mut stack = vec![root.to_string()];
    let mut seen = std::collections::HashSet::new();
    while let Some(c) = stack.pop() {
        if !seen.insert(c.clone()) {
            continue;
        }
        let bytes = store.get(&c).unwrap_or_else(|| panic!("{c} missing"));
        stack.extend(node::links(&bytes, Some(&c)).unwrap());
    }
    assert_eq!(seen.len(), store.len());
}
