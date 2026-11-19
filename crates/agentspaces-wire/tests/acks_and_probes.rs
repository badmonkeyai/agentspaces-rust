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

//! The acknowledged lines of a space (SPEC §7.3, §9.2 R7, annex I.6) and the probe hashes of SPEC
//! §5.2:
//!
//! - a refused line is written `a:<line>` in the text digest after the entry and claim lines, and
//!   stands in its entry's audited slot as the line itself, so the trie's stream hash and the text
//!   digest move with it;
//! - at most 8192 per space, the least recently refused forgotten first, and each forgotten at its
//!   own time;
//! - a probe's `root` and `hashes` are read strictly, each refusal named, and the probe bodies of
//!   annex I.7 read as they were written; `root` is taken over the streams in Java string order.

mod common;

use std::collections::BTreeMap;

use agentspaces_wire::bodies::{
    self, KIND_ACK, KIND_PING, PROBE_HAVE_MAX, ProbeHashes, ProbeRefusal, decode_body,
    probe_hashes, probe_root,
};
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::fold::{ACK_CAP, SpaceStore};
use agentspaces_wire::serving;
use agentspaces_wire::trie::{AuditTrie, EMPTY_STREAM_HASH};
use common::hex;

fn trie_of(store: &SpaceStore) -> AuditTrie {
    let mut trie = AuditTrie::new();
    for (id, lines) in store.audit_slots(0) {
        trie.put(id, lines);
    }
    trie
}

#[test]
fn an_acknowledged_line_stands_in_the_digest_and_the_trie() {
    let mut store = SpaceStore::new();
    let empty = serving::space_digest_acked(store.states(), store.claims(), store.acknowledged());
    assert!(empty.is_empty());
    assert_eq!(trie_of(&store).stream_hash(), EMPTY_STREAM_HASH);
    let generation = store.generation();
    assert!(store.acknowledge("b", "e:b=2", 100));
    assert!(store.acknowledge("a", "c:a=1", 100));
    assert!(store.generation() != generation, "the audited set moved");
    let digest = serving::space_digest_acked(store.states(), store.claims(), store.acknowledged());
    assert_eq!(digest, b"a:c:a=1\na:e:b=2\n");
    // A partner reads an acknowledged line as held.
    let lines = serving::digest_lines(&digest);
    assert!(serving::names_line(&lines, "e:b=2"));
    assert!(!serving::names_line(&lines, "e:b=3"));
    // The trie holds the lines themselves, in their entries' slots.
    let mut trie = trie_of(&store);
    assert_eq!(trie.slot("a"), Some(&["c:a=1".to_owned()][..]));
    assert_eq!(trie.slot("b"), Some(&["e:b=2".to_owned()][..]));
    assert_ne!(trie.stream_hash(), EMPTY_STREAM_HASH);
    // Refused again: no new line, and the set does not move.
    let generation = store.generation();
    assert!(!store.acknowledge("b", "e:b=2", 500));
    assert_eq!(store.generation(), generation);
    assert_eq!(store.acknowledged_count(), 2);
}

#[test]
fn acknowledgements_are_forgotten_at_their_time() {
    let mut store = SpaceStore::new();
    store.acknowledge("a", "e:a=1", 100);
    store.acknowledge("b", "e:b=1", 200);
    // Refusing `a` again moves its time.
    store.acknowledge("a", "e:a=1", 300);
    assert_eq!(store.forget_acknowledged(199), 0);
    assert_eq!(store.forget_acknowledged(200), 1);
    assert!(store.is_acknowledged("e:a=1"));
    assert!(!store.is_acknowledged("e:b=1"));
    assert_eq!(store.forget_acknowledged(i64::MAX), 1);
    assert_eq!(store.acknowledged_count(), 0);
    assert!(store.audit_slots(0).is_empty());
}

#[test]
fn a_space_keeps_at_most_8192_acknowledgements_the_least_recently_refused_going_first() {
    let mut store = SpaceStore::new();
    for index in 0..ACK_CAP {
        store.acknowledge(&format!("id-{index}"), &format!("e:id-{index}=1"), i64::MAX);
    }
    assert_eq!(store.acknowledged_count(), ACK_CAP);
    // Refuse the oldest again: it becomes the most recent, and the next oldest goes instead.
    store.acknowledge("id-0", "e:id-0=1", i64::MAX);
    store.acknowledge("extra", "e:extra=1", i64::MAX);
    assert_eq!(store.acknowledged_count(), ACK_CAP);
    assert!(store.is_acknowledged("e:id-0=1"));
    assert!(!store.is_acknowledged("e:id-1=1"));
    assert!(store.is_acknowledged("e:extra=1"));
    assert_eq!(store.audit_slots(0).len(), ACK_CAP);
}

#[test]
fn an_acknowledgement_stays_out_of_the_set_when_its_id_holds_a_control_character() {
    let mut store = SpaceStore::new();
    store.acknowledge("bad\nid", "e:bad\nid=1", i64::MAX);
    let slots = store.audit_slots(0);
    assert!(slots.iter().all(|(_, lines)| lines.is_empty()));
    assert_eq!(trie_of(&store).stream_hash(), EMPTY_STREAM_HASH);
}

// ------------------------------------------------------------------------- probe hashes (§5.2)

fn body(map: Value) -> Map {
    match map {
        Value::Map(map) => map,
        _ => unreachable!("a map"),
    }
}

#[test]
fn the_probe_bodies_of_annex_i7_read_strictly() {
    for (name, kind, hashes, have) in [
        ("ping_hashes_have_body_cbor", KIND_PING, Some(2), true),
        ("ping_hashes_body_cbor", KIND_PING, Some(2), false),
        ("ping_have_body_cbor", KIND_PING, None, true),
        (
            "ping_hashes_twenty_streams_body_cbor",
            KIND_PING,
            Some(20),
            false,
        ),
        ("ack_body_cbor", KIND_ACK, None, false),
        ("ack_hashes_have_body_cbor", KIND_ACK, Some(2), true),
        ("ack_hashes_body_cbor", KIND_ACK, Some(2), false),
        ("ack_have_body_cbor", KIND_ACK, None, true),
    ] {
        let decoded = decode_body(kind, &hex(name)).expect(name);
        let probe = probe_hashes(&decoded).unwrap_or_else(|refusal| panic!("{name}: {refusal:?}"));
        assert_eq!(probe.root, None, "{name}");
        assert_eq!(probe.hashes.as_ref().map(BTreeMap::len), hashes, "{name}");
        assert_eq!(decoded.contains_key("have"), have, "{name}");
        assert_eq!(probe.is_empty(), hashes.is_none(), "{name}");
    }
    // An ACK built from what a PING carried writes exactly the vector's ACK.
    let ping = decode_body(KIND_PING, &hex("ping_hashes_body_cbor")).expect("decodes");
    let probe = probe_hashes(&ping).expect("well formed");
    assert_eq!(
        bodies::ack_body_with(42, &probe),
        hex("ack_hashes_body_cbor")
    );
    assert_eq!(
        bodies::ack_body_with(42, &ProbeHashes::default()),
        hex("ack_body_cbor")
    );
    assert_eq!(
        bodies::ping_body_with(42, &probe),
        hex("ping_hashes_body_cbor")
    );
}

#[test]
fn a_malformed_piggyback_is_refused_with_its_reason() {
    let hash = vec![7u8; 32];
    let short = vec![7u8; 31];
    let refused = |map: Value| probe_hashes(&body(map)).err();
    assert_eq!(
        refused(cbor_map! { "nonce" => 1, "hashes" => cbor_map! { "space:a" => short.clone() } }),
        Some(ProbeRefusal::HashLength)
    );
    assert_eq!(
        refused(cbor_map! { "nonce" => 1, "root" => short.clone() }),
        Some(ProbeRefusal::RootLength)
    );
    assert_eq!(
        refused(cbor_map! {
            "nonce" => 1,
            "root" => hash.clone(),
            "hashes" => cbor_map! { "space:a" => hash.clone() },
        }),
        Some(ProbeRefusal::RootAndHashes)
    );
    assert_eq!(
        refused(cbor_map! { "nonce" => 1, "hashes" => cbor_map! { "" => hash.clone() } }),
        Some(ProbeRefusal::EmptyStream)
    );
    let item = cbor_map! { "streamId" => "space:a", "hash" => short };
    assert_eq!(
        refused(cbor_map! { "nonce" => 1, "have" => Value::Array(vec![item]) }),
        Some(ProbeRefusal::HaveHashLength)
    );
    let item = cbor_map! { "streamId" => "space:a", "hash" => hash.clone() };
    assert_eq!(
        refused(cbor_map! {
            "nonce" => 1,
            "have" => Value::Array(vec![item; PROBE_HAVE_MAX + 1]),
        }),
        Some(ProbeRefusal::HaveTooMany)
    );
    let probe = probe_hashes(&body(cbor_map! { "nonce" => 1, "root" => hash.clone() }))
        .expect("a root alone is well formed");
    assert_eq!(probe.root, Some([7u8; 32]));
    // Each refusal has its own name.
    let names: std::collections::BTreeSet<&str> = [
        ProbeRefusal::HashLength,
        ProbeRefusal::RootLength,
        ProbeRefusal::RootAndHashes,
        ProbeRefusal::EmptyStream,
        ProbeRefusal::HaveHashLength,
        ProbeRefusal::HaveTooMany,
    ]
    .iter()
    .map(|refusal| refusal.as_str())
    .collect();
    assert_eq!(names.len(), 6);
}

#[test]
fn hashes_go_one_by_one_up_to_the_bound_and_root_past_it() {
    let streams: BTreeMap<String, [u8; 32]> = (0..33)
        .map(|index| (format!("space:s{index:02}"), [index as u8; 32]))
        .collect();
    let mut first: BTreeMap<String, [u8; 32]> = streams.clone();
    first.retain(|stream, _| stream.as_str() < "space:s32");
    assert_eq!(first.len(), 32);
    let named = ProbeHashes::of(first.clone(), 32);
    assert_eq!(named.hashes.as_ref().map(BTreeMap::len), Some(32));
    assert_eq!(named.root, None);
    let rooted = ProbeHashes::of(streams.clone(), 32);
    assert_eq!(rooted.hashes, None);
    assert_eq!(rooted.root, Some(probe_root(&streams)));
    // A bound of zero always sends root.
    assert!(ProbeHashes::of(first, 0).root.is_some());
}

#[test]
fn the_root_is_taken_in_java_string_order() {
    // U+FFFD sorts after U+1F600 in UTF-16 units, before it in UTF-8 bytes.
    let mut hashes = BTreeMap::new();
    hashes.insert("space:\u{1F600}".to_owned(), [1u8; 32]);
    hashes.insert("space:\u{FFFD}".to_owned(), [2u8; 32]);
    let mut preimage = Vec::new();
    for (stream, byte) in [("space:\u{1F600}", 1u8), ("space:\u{FFFD}", 2u8)] {
        preimage.extend_from_slice(stream.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&[byte; 32]);
        preimage.push(0);
    }
    assert_eq!(
        probe_root(&hashes),
        agentspaces_wire::crypto::port().sha256(&preimage)
    );
    // An empty set's root is the SHA-256 of nothing.
    assert_eq!(probe_root(&BTreeMap::new()), EMPTY_STREAM_HASH);
}
