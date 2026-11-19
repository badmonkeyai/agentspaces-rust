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

//! Attacks on the replication-by-entry readers and the audit's state (SPEC §5.2, §7.3, annex
//! I.6), each a regression test of a hole that was closed or a bound that must hold:
//!
//! - a partner that answers the root of one opening again and again cannot keep the asker
//!   descending past the 64 answer bodies of one descent: each opening admits one root answer per
//!   stream;
//! - the `DIGEST`, `PULL_RESP`, `PING`, and `ACK` readers take arbitrary bytes and mutations of
//!   every golden carrier of v0.1.35 without panicking, and a carrier they accept is canonical:
//!   it encodes back to the bytes received;
//! - every form rule of the new fields is refused under its own name;
//! - the audit mirror, which derives again only what a store changed and what lapsed since,
//!   always holds the trie a pass over the whole store would build, through writes, renewals,
//!   withdrawals, claims, removals, acknowledgements and their forgetting, and lapses, its byte
//!   totals and bounded line builds included;
//! - a completion makes a holder whose claim displaced its signer's stand down only when that
//!   holder signed it, under a claim that verifies and names exactly the entry and space, and is
//!   not revoked (SPEC §7.4, the settle guarantee).

mod common;

use agentspaces_wire::audit::{
    self, DigestBody, FormError, IDS_MAX, SESSION_EXCHANGES_MAX, TREE_NODES_MAX, TreeNode,
};
use agentspaces_wire::bodies::{self, KIND_ACK, KIND_PING, ProbeRefusal};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::fold::{self, AuditMirror, FoldContext, SpaceStore};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::reconcile::{Asker, AuditRefusal};
use agentspaces_wire::records::{self, EntryWrite};
use agentspaces_wire::revocation::Registry;
use agentspaces_wire::trie::{AuditTrie, Path};
use common::hex;

/// A seeded xorshift64, so every run tries the same inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn trie_of(count: usize, hash: &str) -> AuditTrie {
    let mut trie = AuditTrie::new();
    for i in 0..count {
        let id = format!("entry-{i}");
        trie.put(&id, vec![format!("e:{id}={hash}")]);
    }
    trie
}

// ------------------------------------------------------------------------------- the descent

/// A partner answers one opening's root a hundred times. Each root used to start the stream's
/// descent afresh, its exchange count with it, so the partner held the asker descending (and
/// sending request bodies) for as long as it liked within the thirty seconds an opening lives.
/// One opening now admits one root per stream; another opening admits one more.
#[test]
fn a_replayed_root_cannot_restart_a_descent() {
    let mut partner = trie_of(400, "1");
    let mut own = trie_of(400, "2");
    let root = audit::answer_root(&mut partner);
    assert!(matches!(root.form, audit::TreeForm::Nodes(_)));
    let mut asker = Asker::new();
    asker.opening("p", 0);
    let mut bodies_with_requests = 0usize;
    let mut refused = 0usize;
    for _ in 0..100 {
        let step = asker.on_answers("p", "space:x", std::slice::from_ref(&root), &mut own, 0);
        if !step.requests.is_empty() {
            bodies_with_requests += 1;
        }
        refused += step
            .refusals
            .iter()
            .filter(|reason| **reason == AuditRefusal::UnsolicitedAnswer)
            .count();
    }
    assert_eq!(
        bodies_with_requests, 1,
        "one opening, one root answer per stream"
    );
    assert_eq!(refused, 99);
    // Another stream of the same opening has its own root.
    let step = asker.on_answers("p", "space:y", std::slice::from_ref(&root), &mut own, 0);
    assert!(!step.requests.is_empty());
    // The next opening admits the root again.
    asker.opening("p", 1);
    let step = asker.on_answers("p", "space:x", std::slice::from_ref(&root), &mut own, 1);
    assert!(!step.requests.is_empty());
    assert!(step.refusals.is_empty(), "{:?}", step.refusals);
}

/// Across a whole descent with a consistent partner the asker sends at most 64 request bodies
/// per stream for one opening, whatever the partner does in between.
#[test]
fn one_opening_draws_at_most_one_descent_per_stream() {
    let mut partner = trie_of(3_000, "1");
    let mut own = trie_of(3_000, "2");
    let mut asker = Asker::new();
    asker.opening("p", 0);
    let root = audit::answer_root(&mut partner);
    let mut sent = 0u32;
    let mut step = asker.on_answers("p", "space:x", std::slice::from_ref(&root), &mut own, 0);
    while !step.requests.is_empty() {
        sent += 1;
        assert!(step.requests.len() <= TREE_NODES_MAX);
        let (answers, _) = audit::answer_requests(&mut partner, "space:x", &step.requests, None);
        // Between answers the partner slips the root in again.
        let replay = asker.on_answers("p", "space:x", std::slice::from_ref(&root), &mut own, 0);
        assert!(replay.requests.is_empty(), "a replayed root restarted it");
        step = asker.on_answers("p", "space:x", &answers, &mut own, 0);
        assert!(
            sent <= SESSION_EXCHANGES_MAX,
            "the descent ran past its bound"
        );
    }
}

/// Two openings sent close together (a round, then the opening a probe or a continuation sent
/// just after it) are each owed their root answer, and no more than the last two openings are:
/// a burst of openings gives a partner no credit for a burst of roots later.
#[test]
fn the_last_two_openings_are_owed_a_root_each_and_no_more() {
    let mut partner = trie_of(400, "1");
    let mut own = trie_of(400, "2");
    let root = audit::answer_root(&mut partner);
    let roots_admitted = |asker: &mut Asker, own: &mut AuditTrie, bodies: usize| -> usize {
        (0..bodies)
            .filter(|_| {
                let step = asker.on_answers("p", "space:x", std::slice::from_ref(&root), own, 0);
                !step.requests.is_empty()
            })
            .count()
    };
    let mut asker = Asker::new();
    asker.opening("p", 0);
    asker.opening("p", 0);
    assert_eq!(
        roots_admitted(&mut asker, &mut own, 10),
        2,
        "both openings answered"
    );
    let mut asker = Asker::new();
    for _ in 0..5 {
        asker.opening("p", 0);
    }
    assert_eq!(
        roots_admitted(&mut asker, &mut own, 10),
        audit_roots_owed(),
        "five openings owe the last two"
    );
    // One root taken, then a new opening: the new opening is owed its own.
    let mut asker = Asker::new();
    asker.opening("p", 0);
    assert_eq!(roots_admitted(&mut asker, &mut own, 3), 1);
    asker.opening("p", 1);
    assert_eq!(roots_admitted(&mut asker, &mut own, 3), 1);
}

fn audit_roots_owed() -> usize {
    usize::try_from(agentspaces_wire::reconcile::ROOTS_OWED_MAX).expect("small")
}

/// A body whose every answer is refused (a path nobody asked for, a root no opening is owed)
/// moves nothing: it draws no request body, re-sends none of the requests in flight, and counts
/// no exchange, so the descent still runs its 64 bodies to the end afterwards.
#[test]
fn a_body_of_refused_answers_moves_nothing() {
    let mut partner = trie_of(3_000, "1");
    let mut own = trie_of(3_000, "2");
    let mut asker = Asker::new();
    asker.opening("p", 0);
    let root = audit::answer_root(&mut partner);
    let mut step = asker.on_answers("p", "space:x", std::slice::from_ref(&root), &mut own, 0);
    assert!(!step.requests.is_empty());
    let junk: Vec<TreeNode> = vec![
        root.clone(),
        TreeNode::lines(&Path::from_nibbles(&[1, 2, 3]).unwrap(), String::new()),
        TreeNode::lines(
            &Path::from_nibbles(&[15, 15, 15, 15]).unwrap(),
            "e:x=1".into(),
        ),
    ];
    let mut bodies = 1u32;
    let mut ids = 0usize;
    while !step.requests.is_empty() {
        // Before each honest answer, 50 bodies of refused answers.
        for _ in 0..50 {
            let stray = asker.on_answers("p", "space:x", &junk, &mut own, 0);
            assert!(stray.requests.is_empty(), "a refused body drew requests");
            assert!(stray.ids.is_empty());
            assert_eq!(stray.refusals.len(), junk.len(), "{:?}", stray.refusals);
        }
        let (answers, _) = audit::answer_requests(&mut partner, "space:x", &step.requests, None);
        step = asker.on_answers("p", "space:x", &answers, &mut own, 0);
        ids += step.ids.len();
        bodies += 1;
        assert!(
            bodies <= SESSION_EXCHANGES_MAX,
            "the descent ran past its bound"
        );
    }
    assert_eq!(ids, 3_000, "the descent ran to its end, every entry found");
}

// ------------------------------------------------------------------------------- the readers

const CARRIERS: &[&str] = &[
    "digest_body_cbor",
    "digest_tree_request_body_cbor",
    "digest_tree_nodes_body_cbor",
    "digest_tree_lines_body_cbor",
    "digest_ids_body_cbor",
    "digest_get_space_budget_body_cbor",
    "pull_resp_body_cbor",
    "pull_resp_remainder_body_cbor",
    "ping_body_cbor",
    "ping_hashes_have_body_cbor",
    "ping_hashes_body_cbor",
    "ping_have_body_cbor",
    "ping_hashes_twenty_streams_body_cbor",
    "ack_body_cbor",
    "ack_hashes_have_body_cbor",
    "ack_hashes_body_cbor",
    "ack_have_body_cbor",
    "adv_digest_tree_path_nibble_body",
    "adv_digest_tree_path_long_body",
    "adv_digest_tree_nodes_length_body",
    "adv_digest_tree_nodes_few_body",
    "adv_digest_tree_two_forms_body",
    "adv_digest_tree_no_form_body",
    "adv_digest_tree_lines_order_body",
    "adv_digest_tree_lines_empty_line_body",
    "adv_digest_ids_twice_body",
    "adv_digest_budget_zero_body",
    "adv_pull_resp_remainder_negative_body",
];

/// Every reader of the new fields over one input: none may panic, and a `DIGEST` or `PULL_RESP`
/// it accepts must be the canonical bytes of what it read.
fn read_all(input: &[u8]) {
    if let Ok(digest) = audit::parse_digest(input) {
        assert_eq!(
            digest.encode(),
            input,
            "a DIGEST accepted in a form it does not write"
        );
        for (_, nodes) in digest.tree.iter().flatten() {
            assert!(nodes.len() <= TREE_NODES_MAX);
            for node in nodes {
                assert!(node.trie_path().is_some(), "a path that is not nibbles");
            }
        }
        for (_, ids) in digest.ids.iter().flatten() {
            assert!(ids.len() <= IDS_MAX);
        }
        assert!(digest.budget.is_none_or(|budget| budget > 0));
    }
    if let Ok(resp) = audit::parse_pull_resp(input) {
        assert_eq!(
            resp.encode(),
            input,
            "a PULL_RESP accepted in a form it does not write"
        );
        assert!(resp.remainder.iter().flatten().all(|(_, left)| *left >= 0));
    }
    for kind in [KIND_PING, KIND_ACK] {
        if let Some(body) = bodies::decode_body(kind, input)
            && let Ok(probe) = bodies::probe_hashes(&body)
        {
            assert!(!(probe.root.is_some() && probe.hashes.is_some()));
        }
    }
    let _ = bodies::parse_ping(input);
    let _ = bodies::parse_ack(input);
}

#[test]
fn arbitrary_bytes_never_panic_the_readers() {
    let mut rng = Rng(0x5eed_0007_a11d_0017);
    for round in 0..20_000 {
        let len = rng.below(if round % 10 == 0 { 2_048 } else { 96 });
        let input = rng.bytes(len);
        read_all(&input);
    }
    // Length heads that claim far more than the input holds: no allocation follows them.
    for head in [
        vec![0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![
            0xbf, 0x64, b't', b'r', b'e', b'e', 0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff,
        ],
    ] {
        read_all(&head);
    }
}

#[test]
fn mutated_golden_carriers_never_panic_the_readers() {
    let mut rng = Rng(0x0dd_ba11_2026_1115);
    for name in CARRIERS {
        let golden = hex(name);
        read_all(&golden);
        for _ in 0..1_500 {
            let mut input = golden.clone();
            match rng.below(5) {
                0 => {
                    // Flip a few bytes.
                    for _ in 0..1 + rng.below(3) {
                        let at = rng.below(input.len());
                        input[at] ^= 1 << rng.below(8);
                    }
                }
                1 => input.truncate(rng.below(input.len())),
                2 => {
                    let at = rng.below(input.len() + 1);
                    let n = 1 + rng.below(8);
                    let extra = rng.bytes(n);
                    input.splice(at..at, extra);
                }
                3 => {
                    // Set one byte to a boundary value.
                    let at = rng.below(input.len());
                    input[at] = [0x00, 0x0f, 0x10, 0x1f, 0x7f, 0x80, 0xff, 0x0a][rng.below(8)];
                }
                _ => {
                    let at = rng.below(input.len());
                    let len = rng.below(input.len() - at + 1);
                    input.drain(at..at + len);
                }
            }
            read_all(&input);
        }
    }
}

// ------------------------------------------------------------------------------- named reasons

fn digest_with(field: &str, value: Value) -> Vec<u8> {
    let mut body = Map::new();
    body.insert("digests", Value::Null);
    body.insert(field, value);
    cbor::encode(&Value::Map(body))
}

fn tree_of(node: Map) -> Value {
    let mut tree = Map::new();
    tree.insert("space:tasks", Value::Array(vec![Value::Map(node)]));
    Value::Map(tree)
}

fn node(path: &[u8], field: &str, value: Value) -> Map {
    let mut node = Map::new();
    node.insert("path", path.to_vec());
    node.insert(field, value);
    node
}

#[test]
fn every_form_rule_of_the_new_fields_is_refused_by_name() {
    let refused = |body: Vec<u8>| audit::parse_digest(&body).err();
    assert_eq!(
        refused(digest_with("budget", Value::Int(-5))),
        Some(FormError::BudgetNotPositive)
    );
    assert_eq!(
        refused(digest_with(
            "tree",
            tree_of(node(&[0; 65], "count", Value::Int(1)))
        )),
        Some(FormError::PathLong)
    );
    assert_eq!(
        refused(digest_with(
            "tree",
            tree_of(node(&[0x10], "count", Value::Int(1)))
        )),
        Some(FormError::PathNibble)
    );
    assert_eq!(
        refused(digest_with(
            "tree",
            tree_of(node(&[1], "count", Value::Int(-1)))
        )),
        Some(FormError::CountNegative)
    );
    assert_eq!(
        refused(digest_with(
            "tree",
            tree_of(node(&[1], "lines", Value::from("e:a=1\u{0}")))
        )),
        Some(FormError::LinesControl)
    );
    let mut nodes = vec![0u8; 384];
    nodes[16..24].copy_from_slice(&40u64.to_be_bytes());
    nodes[24..40].copy_from_slice(&[7u8; 16]);
    assert_eq!(
        refused(digest_with(
            "tree",
            tree_of(node(&[1], "nodes", Value::Bytes(nodes)))
        )),
        Some(FormError::NodesEmptyChild)
    );
    let many: Vec<Value> = (0..=TREE_NODES_MAX)
        .map(|i| Value::Map(node(&[(i % 16) as u8], "count", Value::Int(0))))
        .collect();
    let mut tree = Map::new();
    tree.insert("space:tasks", Value::Array(many));
    assert_eq!(
        refused(digest_with("tree", Value::Map(tree))),
        Some(FormError::TreeTooMany)
    );
    let ids: Vec<Value> = (0..=IDS_MAX)
        .map(|i| Value::from(format!("id-{i}")))
        .collect();
    let mut named = Map::new();
    named.insert("space:tasks", Value::Array(ids));
    assert_eq!(
        refused(digest_with("ids", Value::Map(named))),
        Some(FormError::IdsTooMany)
    );
    // A field the record does not name: the whole carrier is undecodable.
    assert_eq!(
        refused(digest_with("forest", Value::Int(1))),
        Some(FormError::Undecodable)
    );
    // A request node that names a path but no form, inside an otherwise good body.
    let mut bare = Map::new();
    bare.insert("path", vec![1u8]);
    assert_eq!(
        refused(digest_with("tree", tree_of(bare))),
        Some(FormError::NoForm)
    );

    // Probe piggybacks.
    let ping = |field: &str, value: Value| {
        let mut body = Map::new();
        body.insert("nonce", 1);
        body.insert(field, value);
        bodies::decode_body(KIND_PING, &cbor::encode(&Value::Map(body)))
            .map(|body| bodies::probe_hashes(&body))
    };
    assert_eq!(
        ping("root", Value::Bytes(vec![0; 33])),
        Some(Err(ProbeRefusal::RootLength))
    );
    let mut hashes = Map::new();
    hashes.insert("space:tasks", vec![0u8; 31]);
    assert_eq!(
        ping("hashes", Value::Map(hashes)),
        Some(Err(ProbeRefusal::HashLength))
    );
    let mut empty_stream = Map::new();
    empty_stream.insert("", vec![0u8; 32]);
    assert_eq!(
        ping("hashes", Value::Map(empty_stream)),
        Some(Err(ProbeRefusal::EmptyStream))
    );
    // The encoder writes what the reader reads, the null `digests` of an audit body included.
    let body = DigestBody {
        tree: Some(vec![(
            "space:tasks".to_owned(),
            vec![TreeNode::request(&Path::ROOT, 3)],
        )]),
        budget: Some(1 << 20),
        ..DigestBody::default()
    };
    assert_eq!(audit::parse_digest(&body.encode()), Ok(body));
}

// ------------------------------------------------------------------------------- the mirror

fn fresh_trie(store: &SpaceStore, now: i64) -> AuditTrie {
    let mut trie = AuditTrie::new();
    for (id, lines) in store.audit_slots(now) {
        trie.put(id, lines);
    }
    trie
}

fn resigned(dto: &Map, identity: &Identity) -> Map {
    records::sign_state(dto, identity, None).expect("signed")
}

/// Random writes, renewals, withdrawals, claims, removals, acknowledgements, forgetting, and
/// clock moves over a store: after each sync the mirror's trie is the one a pass over the whole
/// store builds, and a sync derives only a few slots, never the whole space.
#[test]
fn the_audit_mirror_always_holds_the_whole_store_s_trie() {
    let identity = Identity::generate().expect("identity");
    let peer = identity.peer_id().to_owned();
    let registry = Registry::new(None, None);
    let payload = cbor::encode(&Value::from("p"));
    let mut rng = Rng(0xa0d1_7e55_0000_0042);
    let mut store = SpaceStore::new();
    let mut mirror = AuditMirror::new();
    let mut now: i64 = 1_800_000_000_000;
    let mut logical = 0i64;
    let mut counter = 0i64;
    let ids: Vec<String> = (0..60).map(|i| format!("entry-{i:02}")).collect();
    let mut synced = 0u32;
    let mut applied = [0u32; 3];
    let mut lapsed_seen = 0u32;
    for step in 0..3_000 {
        let id = ids[rng.below(ids.len())].clone();
        let ctx = FoldContext::new(now, &registry);
        logical += 1;
        let stamp = format!("{now}:{logical}:{peer}");
        match rng.below(10) {
            0 | 1 => {
                counter += 1;
                let write = EntryWrite {
                    entry_id: &id,
                    space_id: "space-id",
                    type_name: "T#v1",
                    payload: Some(&payload),
                    payload_ref: None,
                    tags: None,
                    key_epoch: None,
                    issued: &stamp,
                    expires_at_millis: now + 1 + rng.below(20 * 60_000) as i64,
                    counter,
                };
                if store.state(&id).is_none() {
                    let state = records::entry_state(&write, &identity, "a", None).expect("w");
                    if store.fold_state(&state, &ctx).is_applied() {
                        applied[0] += 1;
                    }
                }
            }
            2 => {
                if let Some(mut dto) = store.signed_state(&id).cloned() {
                    let expiry = now + rng.below(20 * 60_000) as i64;
                    dto.insert("leaseStamp", stamp.as_str());
                    let mut lease = Map::new();
                    lease.insert("holder", format!("{peer}/a"));
                    lease.insert("expiresAtMillis", expiry);
                    lease.insert("kind", "WRITE");
                    dto.insert("leaseValue", lease);
                    if store
                        .fold_state(&resigned(&dto, &identity), &ctx)
                        .is_applied()
                    {
                        applied[1] += 1;
                    }
                }
            }
            3 => {
                if let Some(mut dto) = store.signed_state(&id).cloned() {
                    let removes = fold::union_dots(dto.get("removes"), dto.get("adds"));
                    dto.insert("removes", removes);
                    if store
                        .fold_state(&resigned(&dto, &identity), &ctx)
                        .is_applied()
                    {
                        applied[2] += 1;
                    }
                }
            }
            4 => {
                let claim = records::take_claim(
                    &id,
                    "space-id",
                    1 + rng.below(3) as i64,
                    &stamp,
                    &peer,
                    0.0,
                    now + rng.below(10 * 60_000) as i64,
                );
                let signed = records::signed_claim(&claim, &identity, None).expect("c");
                store.merge_own_claim(&id, &signed);
            }
            5 => {
                store.remove(&id);
            }
            6 => {
                let line = format!("e:{id}={}", rng.below(4));
                store.acknowledge(&id, &line, now + rng.below(10 * 60_000) as i64);
            }
            7 => {
                store.forget_acknowledged(now);
            }
            _ => {
                now += rng.below(4 * 60_000) as i64;
            }
        }
        // Sync now and then, so changes accumulate between syncs too.
        if rng.below(3) == 0 || step == 2_999 {
            let before = mirror.slots_derived();
            let trie = mirror.sync(&mut store, now);
            let hash = trie.stream_hash();
            let mut fresh = fresh_trie(&store, now);
            assert_eq!(
                hash,
                fresh.stream_hash(),
                "the mirror drifted from the store at step {step}"
            );
            // The memoized byte totals a bounded line build trusts match a fresh count at the
            // root and a node below it, and so does the build itself.
            let below = Path::ROOT.child(rng.below(16) as u8).expect("a child");
            for path in [Path::ROOT, below] {
                assert_eq!(
                    trie.line_bytes_at(&path),
                    fresh.line_bytes_at(&path),
                    "the byte total drifted at step {step}"
                );
                let joined = fresh.lines_under(&path).join("\n").into_bytes();
                assert_eq!(
                    trie.joined_under(&path, joined.len()),
                    Some(joined.clone()),
                    "step {step}"
                );
                if !joined.is_empty() {
                    assert_eq!(
                        trie.joined_under(&path, joined.len() - 1),
                        None,
                        "step {step}"
                    );
                }
            }
            if synced > 0 {
                assert!(
                    mirror.slots_derived() - before <= 40,
                    "a sync derived {} slots",
                    mirror.slots_derived() - before
                );
            }
            synced += 1;
            lapsed_seen += store
                .states()
                .filter(|(_, state)| fold::write_lease_lapsed(state, now))
                .count() as u32;
        }
    }
    assert!(
        applied.iter().all(|count| *count > 20) && lapsed_seen > 100,
        "a vacuous run: {applied:?} {lapsed_seen}"
    );
    // A store that replaced the one mirrored is derived whole.
    let mut other = SpaceStore::new();
    other.acknowledge("x", "e:x=1", i64::MAX);
    let hash = mirror.sync(&mut other, now).stream_hash();
    assert_eq!(hash, fresh_trie(&other, now).stream_hash());
}

// ------------------------------------------------------------------------------- the settle guarantee

/// A completion a replica's own claim displaced makes that replica's take stand down only when
/// it is the authentic completion of the displaced claim's holder (SPEC §7.4): signed by that
/// holder, under a claim that verifies and names exactly this entry and space, for a record that
/// verifies, by a holder not revoked. Every forgery, transplant, and revoked holder is refused, so
/// no member can make an honest holder stand down with evidence it could not have signed.
#[test]
fn only_a_displaced_holder_s_own_completion_is_evidence_that_the_work_is_done() {
    const SPACE_ID: &str = "space-id";
    const GROUP: &str = "group-for-settle";
    let issued_ms = revocation_instant("2026-06-01T00:00:00Z");
    let now = issued_ms + 1_000;
    let founder = Identity::generate().expect("identity");
    let writer = Identity::generate().expect("identity");
    let displaced = Identity::generate().expect("identity");
    let stranger = Identity::generate().expect("identity");
    let payload = cbor::encode(&Value::from("p"));
    let stamp = format!("{now}:0:{}", writer.peer_id());
    let write = |entry_id: &'static str| EntryWrite {
        entry_id,
        space_id: SPACE_ID,
        type_name: "T#v1",
        payload: Some(&payload),
        payload_ref: None,
        tags: None,
        key_epoch: None,
        issued: &stamp,
        expires_at_millis: now + 60_000,
        counter: 1,
    };
    let state = records::entry_state(&write("e1"), &writer, "w", None).expect("state");
    let other_state = records::entry_state(&write("e2"), &writer, "w", None).expect("state");
    let claim_of = |entry_id: &str, space_id: &str| {
        let claim = records::take_claim(
            entry_id,
            space_id,
            1,
            &format!("{now}:1:{}", displaced.peer_id()),
            &displaced.agent("rust"),
            0.0,
            now + 30_000,
        );
        records::signed_claim(&claim, &displaced, None).expect("claim")
    };
    let completed = |dto: &Map, by: &Identity| {
        let mut dto = dto.clone();
        dto.insert("completed", true);
        records::sign_state(&dto, by, None).expect("signed")
    };
    let registry = Registry::new(Some(founder.peer_id().to_owned()), Some(GROUP.to_owned()));
    let ctx = FoldContext::new(now, &registry).with_space(SPACE_ID);
    let mut store = SpaceStore::new();
    assert!(store.fold_state(&state, &ctx).is_applied());
    let claim = claim_of("e1", SPACE_ID);
    let done = completed(&state, &displaced);

    // The authentic completion, with its record and without it (over the record held here).
    assert!(store.authenticates_completion_under(&done, &claim, &ctx));
    let recordless = records::without_record(&done).expect("recordless");
    assert!(store.authenticates_completion_under(&recordless, &claim, &ctx));
    // A recordless completion of an entry this store holds no record of is no evidence.
    assert!(!SpaceStore::new().authenticates_completion_under(&recordless, &claim, &ctx));
    // A state that is not a completion.
    assert!(!store.authenticates_completion_under(&state, &claim, &ctx));
    // Signed by a stranger, or by the writer, rather than the claim's holder.
    assert!(!store.authenticates_completion_under(&completed(&state, &stranger), &claim, &ctx));
    assert!(!store.authenticates_completion_under(&completed(&state, &writer), &claim, &ctx));
    // A claim for another entry, or another space, transplanted onto this completion.
    assert!(!store.authenticates_completion_under(&done, &claim_of("e2", SPACE_ID), &ctx));
    assert!(!store.authenticates_completion_under(&done, &claim_of("e1", "elsewhere"), &ctx));
    // The holder's completion of another entry, offered under this entry's claim.
    let other_done = completed(&other_state, &displaced);
    assert!(!store.authenticates_completion_under(&other_done, &claim, &ctx));
    // A completion of the same entry in another space.
    let foreign = FoldContext::new(now, &registry).with_space("elsewhere");
    assert!(!store.authenticates_completion_under(&done, &claim, &foreign));
    // A claim whose signature no longer covers it (its holder or epoch edited).
    for (field, value) in [
        ("holder", Value::from(stranger.agent("rust"))),
        ("epoch", Value::from(7)),
    ] {
        let mut forged = claim.clone();
        let mut inner = forged
            .get("claim")
            .and_then(Value::as_map)
            .expect("claim")
            .clone();
        inner.insert(field, value);
        forged.insert("claim", inner);
        assert!(
            !store.authenticates_completion_under(&done, &forged, &ctx),
            "{field}"
        );
    }
    // A completion signed by a stranger under a claim the stranger signed for the holder's name.
    let mut stolen = claim.clone();
    stolen.insert("holderKey", Value::Bytes(stranger.public_raw().to_vec()));
    assert!(!store.authenticates_completion_under(&completed(&state, &stranger), &stolen, &ctx));
    // Once the founder revokes the displaced holder, its completion is no evidence.
    let mut revoked = registry.clone();
    let ad = agentspaces_wire::revocation::peer_revocation(
        founder.peer_id(),
        GROUP,
        "2026-06-01T00:00:00Z",
        "PT720H",
        displaced.peer_id(),
        "KEY_COMPROMISE",
        None,
    );
    let signed = agentspaces_wire::revocation::sign_revocation(&ad, &founder);
    assert!(revoked.accept(
        agentspaces_wire::revocation::PEER_STREAM,
        &cbor::encode(&Value::Map(signed)),
        now,
    ));
    let ctx = FoldContext::new(now, &revoked).with_space(SPACE_ID);
    assert!(!store.authenticates_completion_under(&done, &claim, &ctx));
}

fn revocation_instant(iso: &str) -> i64 {
    agentspaces_wire::time::parse_instant_millis(iso).expect("an instant")
}
