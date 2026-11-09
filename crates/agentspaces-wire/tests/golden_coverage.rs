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

//! The golden coverage gate: every vector Java's `tools/golden/GoldenVectors.java` wrote into
//! `golden.json`, and every vector of `social-golden.json`, is named by at least one other test
//! of this crate, or is listed in [`SKIPPED`] with what it is and the future work that will
//! cover it, or why none will.
//!
//! A vector is *named* when a test file other than this one spells its key as a string literal
//! (`"peer_id"`), or builds it from a format string listed in [`TEMPLATES`]. The sources are read
//! from `tests/` at run time, so a new test file counts without touching this one.
//!
//! The skip table cannot go stale: a skip pattern that matches no vector, or that matches a
//! vector some test names, fails the gate, so covering a skipped vector means deleting its skip.
//! Run with `--nocapture` to see the coverage figures.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// This file, which names skipped keys and so never counts as naming one.
const THIS_FILE: &str = "golden_coverage.rs";

/// A golden key a test builds with `format!` rather than spelling out.
struct Template {
    /// The test file, under `tests/`.
    file: &'static str,
    /// The format string exactly as the file spells it, quotes included.
    template: &'static str,
    /// The placeholder in it, braces included.
    placeholder: &'static str,
    /// What the test substitutes for the placeholder.
    values: &'static [&'static str],
    /// Source text of the file listing those values, so the test is seen to iterate them.
    evidence: &'static [&'static str],
}

/// The keys tests build from format strings.
const TEMPLATES: &[Template] = &[
    Template {
        file: "records_golden.rs",
        template: "\"state_sign_view_agent_{name}_cbor\"",
        placeholder: "{name}",
        values: &["renew", "cancel", "complete"],
        evidence: &["\"renew\",", "\"cancel\",", "\"complete\","],
    },
    Template {
        file: "records_golden.rs",
        template: "\"entry_state_agent_{name}_cbor\"",
        placeholder: "{name}",
        values: &["renew", "cancel", "complete"],
        evidence: &["\"renew\",", "\"cancel\",", "\"complete\","],
    },
    Template {
        file: "revocation_golden.rs",
        template: "\"credential_revocation_{kind}_cbor\"",
        placeholder: "{kind}",
        values: &["agent", "agent_key", "x509_leaf", "join_credential"],
        evidence: &[
            "const GOLDEN_KINDS: [&str; 4] = [\"agent\", \"agent_key\", \"x509_leaf\", \"join_credential\"];",
            "for kind in GOLDEN_KINDS {",
        ],
    },
    Template {
        file: "revocation_golden.rs",
        template: "\"signed_credential_revocation_{kind}_cbor\"",
        placeholder: "{kind}",
        values: &["agent", "agent_key", "x509_leaf", "join_credential"],
        evidence: &[
            "const GOLDEN_KINDS: [&str; 4] = [\"agent\", \"agent_key\", \"x509_leaf\", \"join_credential\"];",
            "for kind in GOLDEN_KINDS {",
        ],
    },
    Template {
        file: "fold_golden.rs",
        template: "\"vote_three_names_one_peer_delta_{i}\"",
        placeholder: "{i}",
        values: &["1", "2", "3"],
        evidence: &["let order = [3, 1, 2];", "for i in order {"],
    },
];

/// Vectors no test of this crate names yet, by what they are and who will cover them.
struct SkipGroup {
    /// Exact keys, or prefixes ending in `*`.
    patterns: &'static [&'static str],
    /// What the vectors are, in one line.
    what: &'static str,
    /// The future work that will cover them, or why none will, in one line.
    phase: &'static str,
}

/// The skipped vectors. Each reason was checked against the generator (`GoldenVectors.java`) and
/// the Java code it encodes.
const SKIPPED: &[SkipGroup] = &[
    SkipGroup {
        patterns: &["dtls_pdu_*"],
        what: "the DTLS recovery sublayer's PDUs, laid out byte by byte in SPEC §5.5",
        phase: "future work: a dtls dialer, once a maintained Rust DTLS crate offers Connection ID",
    },
    SkipGroup {
        patterns: &["rtc_*"],
        what: "WebRTC signalling bodies OFFER, ANSWER, CAND, END (SPEC annex B)",
        phase: "not planned: the Rust peer skips webrtc seeds",
    },
    SkipGroup {
        patterns: &["raft_*"],
        what: "the ordered log's Raft frame union (RequestVote, VoteReply, AppendEntries, ...)",
        phase: "future work: an optional ordered-log client, and after it a Raft voter",
    },
    SkipGroup {
        patterns: &["pdt_*"],
        what: "Java's persistent data tree nodes and chunk cuts (agentspaces-pdt PdtVectors)",
        phase: "not planned: only Java's own PdtVectorsConformanceTest reads them, no client consumes the tree",
    },
    SkipGroup {
        patterns: &[
            "content_root_cidv1",
            "content_manifest*",
            "content_holding_*",
            "content_piece*",
            "content_have_cbor",
            "content_cancel_cbor",
            "content_reject_cbor",
            "content_node*",
            "content_tree_*",
        ],
        what: "the content swarm's root, Manifest, Holding, and piece-exchange bodies (annex G)",
        phase: "future work: the content swarm client",
    },
    SkipGroup {
        patterns: &["data_query_*", "data_result_cbor", "asset_*"],
        what: "connector entries: aspace:cap/data-query records, its canonical hash, asset invocations",
        phase: "future work: the connector clients",
    },
    SkipGroup {
        patterns: &["beacon_seal_*"],
        what: "the sealed multicast bootstrap-beacon datagram (SPEC §10.1 v0.1.19, HKDF and AES-256-GCM)",
        phase: "future work: an optional multicast beacon locator",
    },
    SkipGroup {
        patterns: &["space_state_hash", "space_claim_hash"],
        what: "ReplicatedSpace stateHash and claimHash, the lines a serving host answers a DIGEST with",
        phase: "future work: a Rust serving host (the TypeScript client's serving tests use them)",
    },
];

/// Whether a skip pattern names a key.
fn matches(pattern: &str, key: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => key == pattern,
    }
}

/// The source of every test file under `tests/` but this one, by file name.
fn test_sources() -> BTreeMap<String, String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = BTreeMap::new();
    for entry in fs::read_dir(&dir).expect("tests/ is readable") {
        let path = entry.expect("a directory entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.extension().is_some_and(|ext| ext == "rs") && name != THIS_FILE {
            let source = fs::read_to_string(&path).expect("a test file is UTF-8");
            sources.insert(name.to_owned(), source);
        }
    }
    assert!(sources.len() > 10, "the test sources were found");
    sources
}

/// The keys of a vector file.
fn keys_of(vectors: &'static serde_json::Value) -> Vec<&'static str> {
    vectors
        .as_object()
        .expect("a vector file is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// For each key some test names, the files that name it (a template's file reads
/// `file (template)`).
fn named(keys: &[&str], sources: &BTreeMap<String, String>) -> BTreeMap<String, Vec<String>> {
    let mut named: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for key in keys {
        let literal = format!("\"{key}\"");
        for (file, source) in sources {
            if source.contains(&literal) {
                named
                    .entry((*key).to_owned())
                    .or_default()
                    .push(file.clone());
            }
        }
    }
    for template in TEMPLATES {
        for value in template.values {
            let key = template
                .template
                .trim_matches('"')
                .replace(template.placeholder, value);
            named
                .entry(key)
                .or_default()
                .push(format!("{} (template)", template.file));
        }
    }
    named
}

/// The index in [`SKIPPED`] of the group that skips a key, when one does.
fn skip_of(key: &str) -> Option<usize> {
    SKIPPED
        .iter()
        .position(|group| group.patterns.iter().any(|pattern| matches(pattern, key)))
}

#[test]
fn every_golden_vector_is_tested_or_skipped_with_a_reason() {
    let sources = test_sources();
    let keys = keys_of(common::golden());
    let named = named(&keys, &sources);
    let mut covered = 0usize;
    let mut skipped: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    let mut missing = Vec::new();
    for key in &keys {
        if named.contains_key(*key) {
            covered += 1;
        } else if let Some(group) = skip_of(key) {
            skipped.entry(group).or_default().push(key);
        } else {
            missing.push(*key);
        }
    }
    assert!(
        missing.is_empty(),
        "golden vectors no test names and no skip lists (name each in a test, or add it to \
         SKIPPED with what it is and the work that will cover it): {missing:?}"
    );

    let total = keys.len();
    let skipped_total: usize = skipped.values().map(Vec::len).sum();
    assert_eq!(covered + skipped_total, total);
    let percent = |part: usize| 100.0 * part as f64 / total as f64;
    println!(
        "golden.json: {covered} of {total} vectors named by a test ({:.1}%), {skipped_total} \
         skipped ({:.1}%)",
        percent(covered),
        percent(skipped_total),
    );
    for (index, group) in SKIPPED.iter().enumerate() {
        let keys = skipped.get(&index).map_or(0, Vec::len);
        println!("  skipped {keys:>2} {:?}: {}", group.patterns, group.phase);
    }
}

#[test]
fn no_skip_names_a_covered_vector_and_none_is_dead() {
    let sources = test_sources();
    let keys = keys_of(common::golden());
    let named = named(&keys, &sources);
    for group in SKIPPED {
        assert!(!group.what.is_empty() && !group.what.contains('\n'));
        assert!(!group.phase.is_empty() && !group.phase.contains('\n'));
        for pattern in group.patterns {
            let hits: Vec<&str> = keys
                .iter()
                .copied()
                .filter(|key| matches(pattern, key))
                .collect();
            assert!(!hits.is_empty(), "skip {pattern} matches no golden vector");
            for key in hits {
                assert!(
                    !named.contains_key(key),
                    "skip {pattern} names {key}, which {:?} test: delete the skip",
                    named[key]
                );
                let groups = SKIPPED
                    .iter()
                    .filter(|other| other.patterns.iter().any(|p| matches(p, key)))
                    .count();
                assert_eq!(groups, 1, "{key} is skipped by more than one group");
            }
        }
    }
}

#[test]
fn templates_name_real_vectors_the_tests_iterate() {
    let sources = test_sources();
    let keys: BTreeSet<&str> = keys_of(common::golden()).into_iter().collect();
    for template in TEMPLATES {
        let source = sources
            .get(template.file)
            .unwrap_or_else(|| panic!("no test file {}", template.file));
        assert!(
            source.contains(template.template),
            "{} no longer builds {}",
            template.file,
            template.template
        );
        assert!(template.template.contains(template.placeholder));
        for evidence in template.evidence {
            assert!(
                source.contains(evidence),
                "{} no longer lists the values of {}: {evidence}",
                template.file,
                template.template
            );
        }
        for value in template.values {
            let key = template
                .template
                .trim_matches('"')
                .replace(template.placeholder, value);
            assert!(keys.contains(key.as_str()), "{key} is not a golden vector");
        }
    }
}

#[test]
fn every_social_vector_is_tested() {
    let sources = test_sources();
    let keys = keys_of(common::social_golden());
    let named = named(&keys, &sources);
    let missing: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| !named.contains_key(*key))
        .collect();
    assert!(
        missing.is_empty(),
        "social vectors no test names: {missing:?}"
    );
    println!(
        "social-golden.json: {} of {} vectors named by a test (100.0%)",
        keys.len(),
        keys.len()
    );
}
