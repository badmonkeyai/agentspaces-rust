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

//! The content swarm vectors of annex G and annex H (the tree messages), rebuilt from the
//! inputs of Java's `tools/golden/GoldenVectors.contentVectors`, byte for byte.

mod common;

use agentspaces_wire::content::{self, Dropped, Holding, Manifest, Message};
use agentspaces_wire::pdt::cid;
use common::{hex, s};

fn piece_table(pieces: usize, piece_size: usize, last: usize) -> Vec<u8> {
    let mut table = Vec::new();
    for i in 0..pieces {
        let piece = vec![(i + 1) as u8; if i == pieces - 1 { last } else { piece_size }];
        table.extend_from_slice(&agentspaces_wire::pdt::sha256(&piece));
    }
    table
}

fn root() -> String {
    s("content_root_cidv1").to_string()
}

#[test]
fn content_root_is_the_raw_cid_of_the_table() {
    assert_eq!(content::content_root(&piece_table(3, 65_536, 100)), root());
}

#[test]
fn manifests_round_trip_and_validate() {
    for name in ["content_manifest_inline_cbor", "content_manifest_tableref_cbor", "content_manifest_tree_cbor", "pdt_manifest_tree_cbor"] {
        let bytes = hex(name);
        let m = Manifest::decode(&bytes).unwrap_or_else(|| panic!("{name} decodes"));
        assert_eq!(m.encode(), bytes, "{name}");
        assert_eq!(m.violation(), None, "{name}");
    }
    let inline = Manifest::decode(&hex("content_manifest_inline_cbor")).unwrap();
    assert_eq!(inline.root, root());
    assert_eq!(inline.table.as_deref(), Some(&piece_table(3, 65_536, 100)[..]));
    let tree = Manifest::decode(&hex("content_manifest_tree_cbor")).unwrap();
    assert_eq!(tree.root, cid::of(&[0xA0], cid::DAG_CBOR));
    assert_eq!(tree.layout.as_deref(), Some(content::LAYOUT_TREE));
    let mut broken = inline.clone();
    broken.size += 1;
    assert!(broken.violation().is_none(), "size within the last piece still matches pieces");
    broken.pieces = 4;
    assert!(broken.violation().is_some());
}

#[test]
fn holdings_round_trip() {
    let partial = Holding::decode(&hex("content_holding_partial_cbor")).unwrap();
    assert_eq!(partial.encode(), hex("content_holding_partial_cbor"));
    assert_eq!(content::decode_have(partial.have.as_deref(), 3), vec![true, false, true]);
    assert_eq!(partial.via.as_deref(), Some(&["zB".to_string()][..]));
    let complete = Holding::decode(&hex("content_holding_complete_cbor")).unwrap();
    assert_eq!(complete.encode(), hex("content_holding_complete_cbor"));
    let rebuilt = Holding::complete_tree(&root(), &complete.holder, 3, None);
    assert_eq!(rebuilt.encode(), hex("content_holding_complete_cbor"));
}

#[test]
fn piece_messages_match() {
    let r = root();
    let range: Vec<u8> = (0..16).collect();
    let cases = [
        ("content_piece_want_cbor", Message::PieceWant { root: r.clone(), index: 2, offset: 65_536, length: 65_536, req: 42 }),
        ("content_piece_cbor", Message::Piece { root: r.clone(), index: 2, offset: 65_536, bytes: range, req: 42 }),
        ("content_have_cbor", Message::Have { root: r.clone(), have: Some(vec![0, 1, 1, 1]), complete: false }),
        ("content_cancel_cbor", Message::Cancel { root: r.clone(), index: 2, req: 42 }),
        ("content_reject_cbor", Message::Reject { root: r.clone(), index: 2, reason: 2 }),
        ("content_manifest_want_cbor", Message::ManifestWant { root: r.clone() }),
        ("content_manifest_cbor", Message::Manifest { root: r.clone(), record: hex("content_manifest_inline_cbor") }),
    ];
    for (name, message) in cases {
        assert_eq!(message.encode(), hex(name), "{name}");
        assert_eq!(content::decode(&hex(name)).unwrap(), message, "{name}");
    }
}

#[test]
fn tree_messages_match() {
    let tree_root = cid::of(&[0xA0], cid::DAG_CBOR);
    let empty_chunk = cid::of(&[], cid::RAW);
    let cases = [
        ("content_node_want_cbor", Message::NodeWant { req: 42, cids: vec![tree_root.clone(), empty_chunk.clone()] }),
        ("content_nodes_cbor", Message::Nodes { req: 42, nodes: Some(vec![vec![0xA0], vec![]]), sealed: None, epoch: None, missing: Some(vec![root()]) }),
        ("content_tree_want_cbor", Message::TreeWant { req: 43, root: tree_root, haves: Some(vec![empty_chunk.clone()]), budget: 64 * 1024 * 1024 }),
        ("content_tree_end_cbor", Message::TreeEnd { req: 43, frontier: vec![empty_chunk], reason: 2 }),
    ];
    for (name, message) in cases {
        assert_eq!(message.encode(), hex(name), "{name}");
        assert_eq!(content::decode(&hex(name)).unwrap(), message, "{name}");
    }
}

#[test]
fn level_two_forms_are_dropped() {
    for name in ["content_tree_want_sketch_cbor", "content_tree_end_sketch_cbor", "content_nodes_deltas_cbor", "content_challenge_cbor"] {
        let dropped = content::decode(&hex(name)).unwrap_err();
        assert!(!dropped.is_piece_message(), "{name}: {dropped:?}");
    }
    assert_eq!(content::decode(&hex("content_challenge_cbor")).unwrap_err(), Dropped::UnknownTag(12));
    // req 42 in a wider head than its shortest form (`18 2a` becomes `19 00 2a`)
    let mut relabel = hex("content_cancel_cbor");
    assert_eq!(&relabel[relabel.len() - 3..], &[0x18, 0x2A, 0xFF]);
    let at = relabel.len() - 3;
    relabel.splice(at..at + 2, [0x19, 0x00, 0x2A]);
    assert_eq!(content::decode(&relabel).unwrap_err(), Dropped::Undecodable(content::T_CANCEL));
}
