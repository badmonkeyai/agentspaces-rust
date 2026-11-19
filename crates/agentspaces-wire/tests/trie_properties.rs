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

//! Seeded property tests of the fingerprinted trie (SPEC annex I.6) and the descent over it:
//!
//! - every node of a random set equals an independent fold of the annex's text (written here
//!   from the annex alone, over `sha2`), at every path the trie has, deep sets included;
//! - the shape and the fingerprints are a function of the set alone, whatever the history of
//!   inserts, removals and replaced slots, and the memo never serves a stale node;
//! - two sets have the same stream hash exactly when they hold the same lines;
//! - every node's byte total is exactly its lines joined plus one, so a bounded line build
//!   answers `None` exactly when the joined lines pass its bound;
//! - a descent between two random sets fetches exactly the entries of which the partner holds a
//!   line the asker lacks, within the exchange bound.

use std::collections::{BTreeMap, BTreeSet};

use agentspaces_wire::audit::{self, TreeForm};
use agentspaces_wire::reconcile::Asker;
use agentspaces_wire::trie::{AuditTrie, NodeKind, Path, entry_key};
use sha2::{Digest, Sha256};

/// xorshift64*, seeded per case so a failure names its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

type Set = BTreeMap<String, Vec<String>>;

fn random_set(rng: &mut Rng, size: usize) -> Set {
    let mut set = Set::new();
    while set.len() < size {
        let id = format!(
            "id-{}-{}",
            rng.below(1 << 20),
            "é".repeat(rng.below(2) as usize)
        );
        let mut lines = vec![format!("e:{id}={:x}", rng.below(1 << 16))];
        if rng.below(4) == 0 {
            lines.push(format!("c:{id}={}:{}", rng.below(9), rng.below(1 << 10)));
        }
        if rng.below(8) == 0 {
            lines.push(format!("e:{id}={:x}", rng.below(1 << 16)));
        }
        set.insert(id, lines);
    }
    set
}

fn build(set: &Set) -> AuditTrie {
    let mut trie = AuditTrie::new();
    for (id, lines) in set {
        trie.put(id, lines.clone());
    }
    trie
}

// ---- the independent fold, from the annex's text alone

fn nib(key: &[u8], i: usize) -> u8 {
    if i.is_multiple_of(2) {
        key[i / 2] >> 4
    } else {
        key[i / 2] & 0x0F
    }
}

fn under<'a>(set: &'a Set, path: &[u8]) -> Vec<(&'a String, &'a Vec<String>)> {
    set.iter()
        .filter(|(id, _)| {
            let key = Sha256::digest(id.as_bytes());
            path.iter().enumerate().all(|(i, n)| nib(&key, i) == *n)
        })
        .collect()
}

/// (count, preimage, inner) of the node at a path, empty when count is 0.
fn reference(set: &Set, path: &[u8]) -> (u64, Vec<u8>, bool) {
    let slots = under(set, path);
    let count = slots.len() as u64;
    if count == 0 {
        return (0, Vec::new(), false);
    }
    if count <= 32 || path.len() == 64 {
        let lines: BTreeSet<&[u8]> = slots
            .iter()
            .flat_map(|(_, lines)| lines.iter().map(String::as_bytes))
            .collect();
        return (
            count,
            lines.into_iter().collect::<Vec<_>>().join(&b'\n'),
            false,
        );
    }
    let mut preimage = Vec::with_capacity(384);
    for c in 0..16u8 {
        let mut child = path.to_vec();
        child.push(c);
        let (n, pre, _) = reference(set, &child);
        if n == 0 {
            preimage.extend_from_slice(&[0u8; 24]);
        } else {
            preimage.extend_from_slice(&Sha256::digest(&pre)[..16]);
            preimage.extend_from_slice(&n.to_be_bytes());
        }
    }
    (count, preimage, true)
}

fn assert_matches_reference(trie: &mut AuditTrie, set: &Set, path: &Path, seed: u64) {
    // The node's byte total is exactly its lines joined as a leaf joins them, plus one, whatever
    // its count: what lets a bounded line build skip a walk known to pass its bound.
    let lines: BTreeSet<&[u8]> = under(set, &path.nibbles())
        .iter()
        .flat_map(|(_, lines)| lines.iter().map(String::as_bytes))
        .collect();
    let joined = lines.into_iter().collect::<Vec<_>>().join(&b'\n');
    let want = if joined.is_empty() {
        0
    } else {
        joined.len() as u64 + 1
    };
    assert_eq!(trie.line_bytes_at(path), want, "seed {seed} path {path:?}");
    assert_eq!(
        trie.joined_under(path, joined.len()).as_deref(),
        Some(joined.as_slice()),
        "seed {seed} path {path:?}"
    );
    if !joined.is_empty() {
        assert_eq!(trie.joined_under(path, joined.len() - 1), None);
    }
    let node = trie.node(path);
    let (count, preimage, inner) = reference(set, &path.nibbles());
    assert_eq!(node.count, count, "seed {seed} path {path:?}");
    assert_eq!(node.preimage, preimage, "seed {seed} path {path:?}");
    if count == 0 {
        assert_eq!(node.kind, NodeKind::Empty);
        return;
    }
    assert_eq!(
        node.kind == NodeKind::Inner,
        inner,
        "seed {seed} path {path:?}"
    );
    assert_eq!(
        node.fingerprint.unwrap()[..],
        Sha256::digest(&preimage)[..16]
    );
    // A leaf's preimage holds no zero byte and an inner one always does: never the same.
    assert_eq!(preimage.contains(&0), inner);
    if inner {
        for c in 0..16 {
            assert_matches_reference(trie, set, &path.child(c).unwrap(), seed);
        }
    }
}

#[test]
fn every_node_equals_the_annex_fold() {
    for seed in 1..=12u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let size = [0, 1, 2, 31, 32, 33, 34, 64, 120, 300, 520, 700][seed as usize - 1];
        let set = random_set(&mut rng, size);
        let mut trie = build(&set);
        assert_matches_reference(&mut trie, &set, &Path::ROOT, seed);
        let root = reference(&set, &[]);
        let expected: [u8; 32] = Sha256::digest(&root.1).into();
        assert_eq!(trie.stream_hash(), expected, "seed {seed}");
    }
}

#[test]
fn a_deep_set_folds_several_nibbles_down() {
    // Ids whose keys share their first three nibbles: the trie runs past the third level.
    let mut set = Set::new();
    let mut n = 0u64;
    while set.len() < 40 {
        let id = format!("deep-{n}");
        n += 1;
        let key = entry_key(&id);
        if key[0] == 0xAB && key[1] >> 4 == 0xC {
            set.insert(id.clone(), vec![format!("e:{id}=1")]);
        }
    }
    let mut trie = build(&set);
    let abc = Path::from_nibbles(&[0xA, 0xB, 0xC]).unwrap();
    assert_eq!(trie.node(&abc).kind, NodeKind::Inner);
    assert_matches_reference(&mut trie, &set, &Path::ROOT, 0);
}

#[test]
fn the_shape_is_a_function_of_the_set_alone() {
    for seed in 1..=8u64 {
        let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
        let set = {
            let size = 40 + rng.below(400) as usize;
            random_set(&mut rng, size)
        };
        let mut fresh = build(&set);
        let want = fresh.stream_hash();
        // Another history: shuffled inserts, noise slots added and removed, slots replaced,
        // and the hash asked for along the way so the memo sees every intermediate trie.
        let mut order: Vec<(&String, &Vec<String>)> = set.iter().collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let mut trie = AuditTrie::new();
        let noise = random_set(&mut rng, 80);
        for (step, (id, lines)) in order.iter().enumerate() {
            if step % 3 == 0 {
                trie.put(id, vec![format!("e:{id}=stale")]);
                trie.stream_hash();
            }
            trie.put(id, (*lines).clone());
            if let Some((noise_id, noise_lines)) = noise.iter().nth(step % noise.len())
                && !set.contains_key(noise_id)
            {
                trie.put(noise_id, noise_lines.clone());
                if step % 5 == 0 {
                    trie.stream_hash();
                }
            }
        }
        for noise_id in noise.keys() {
            if !set.contains_key(noise_id) {
                trie.remove(noise_id);
            }
        }
        assert_eq!(trie.stream_hash(), want, "seed {seed}");
        assert_eq!(trie.count(), set.len() as u64);
        for c in 0..16 {
            let child = Path::ROOT.child(c).unwrap();
            assert_eq!(
                trie.fingerprint_at(&child),
                fresh.fingerprint_at(&child),
                "seed {seed}"
            );
        }
        assert_matches_reference(&mut trie, &set, &Path::ROOT, seed);
    }
}

#[test]
fn equal_hashes_exactly_when_equal_lines() {
    for seed in 1..=10u64 {
        let mut rng = Rng(seed ^ 0xABCD_EF01_2345_6789);
        let set = {
            let size = 1 + rng.below(200) as usize;
            random_set(&mut rng, size)
        };
        let mut a = build(&set);
        let mut b = build(&set);
        assert_eq!(a.stream_hash(), b.stream_hash());
        // One line added, changed, or removed anywhere changes the hash.
        let victim = set
            .keys()
            .nth(rng.below(set.len() as u64) as usize)
            .unwrap()
            .clone();
        let mut lines = set[&victim].clone();
        match seed % 3 {
            0 => lines.push(format!("c:{victim}=extra")),
            1 => lines[0].push('0'),
            _ => {
                b.remove(&victim);
                assert_ne!(a.stream_hash(), b.stream_hash(), "seed {seed}");
                continue;
            }
        }
        b.put(&victim, lines);
        assert_ne!(a.stream_hash(), b.stream_hash(), "seed {seed}");
        // The same lines reached through an acknowledgement standing as itself: equal again.
        b.put(&victim, set[&victim].clone());
        assert_eq!(a.stream_hash(), b.stream_hash(), "seed {seed}");
    }
}

#[test]
fn a_descent_fetches_exactly_what_the_asker_lacks() {
    for seed in 1..=10u64 {
        let mut rng = Rng(seed.wrapping_mul(0x1234_5678_9ABC_DEF1) | 1);
        let base = {
            let size = 30 + rng.below(600) as usize;
            random_set(&mut rng, size)
        };
        let mut asker_set = base.clone();
        let mut partner_set = base.clone();
        for _ in 0..rng.below(40) {
            let pick = base
                .keys()
                .nth(rng.below(base.len() as u64) as usize)
                .unwrap()
                .clone();
            match rng.below(3) {
                0 => {
                    asker_set.remove(&pick);
                }
                1 => {
                    partner_set.insert(pick.clone(), vec![format!("e:{pick}=new")]);
                }
                _ => {
                    let extra = format!("only-{}", rng.below(1 << 30));
                    partner_set.insert(extra.clone(), vec![format!("e:{extra}=1")]);
                }
            }
        }
        let mut asker = build(&asker_set);
        let mut partner = build(&partner_set);
        let held: BTreeSet<String> = asker.lines().into_iter().collect();
        let expected: BTreeSet<String> = partner_set
            .iter()
            .filter(|(_, lines)| lines.iter().any(|line| !held.contains(line)))
            .map(|(id, _)| id.clone())
            .collect();
        let mut descents = Asker::new();
        descents.opening("p", 0);
        let mut found = BTreeSet::new();
        let mut step = descents.on_answers(
            "p",
            "space:x",
            &[audit::answer_root(&mut partner)],
            &mut asker,
            0,
        );
        let mut exchanges = 1;
        loop {
            assert!(step.refusals.is_empty(), "seed {seed}: {:?}", step.refusals);
            found.extend(step.ids.iter().cloned());
            if step.requests.is_empty() {
                break;
            }
            assert!(step.requests.len() <= audit::TREE_NODES_MAX);
            let (answers, _) =
                audit::answer_requests(&mut partner, "space:x", &step.requests, None);
            assert!(
                answers
                    .iter()
                    .all(|a| matches!(a.form, TreeForm::Nodes(_) | TreeForm::Lines(_)))
            );
            step = descents.on_answers("p", "space:x", &answers, &mut asker, 0);
            exchanges += 1;
            assert!(
                exchanges <= 64,
                "seed {seed}: the descent ends within its bound"
            );
        }
        assert_eq!(found, expected, "seed {seed}");
    }
}

#[test]
fn a_small_budget_leaves_nodes_out_and_the_asker_asks_them_again() {
    let mut rng = Rng(77);
    let base = random_set(&mut rng, 900);
    let mut asker_set = base.clone();
    for id in base.keys().step_by(9) {
        asker_set.remove(id);
    }
    let mut asker = build(&asker_set);
    let mut partner = build(&base);
    let mut descents = Asker::new();
    descents.opening("p", 0);
    let mut step = descents.on_answers(
        "p",
        "space:x",
        &[audit::answer_root(&mut partner)],
        &mut asker,
        0,
    );
    let mut found = BTreeSet::new();
    let mut cut = false;
    while !step.requests.is_empty() {
        found.extend(step.ids.iter().cloned());
        let (answers, _) =
            audit::answer_requests(&mut partner, "space:x", &step.requests, Some(4096));
        cut |= answers.len() < step.requests.len();
        assert!(!answers.is_empty(), "the first node is always answered");
        step = descents.on_answers("p", "space:x", &answers, &mut asker, 0);
    }
    found.extend(step.ids);
    assert!(cut, "the budget cut an answer");
    let expected: BTreeSet<String> = base.keys().step_by(9).cloned().collect();
    assert_eq!(found, expected);
}
