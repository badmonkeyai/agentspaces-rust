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

//! The heads of a persistent-data-tree ref (SPEC annex H, the ref): which of a ref's live
//! versions are its heads, including while some of them are still loading.
//!
//! - *The rule.* A ref's heads are the live versions that no other live version with a larger
//!   `seq` lists in its `base`, equal roots folded into one. Seq grows along every base link, so
//!   a base link supersedes only the versions below it, and a version at [`MAX_SEQ`] supersedes
//!   whatever it lists. A version that recreates an ancestor's content (and with it the
//!   ancestor's root) therefore stays a head over the versions it was computed from.
//! - *Versions still loading.* A reader judges heads among the versions it has loaded. When a
//!   version in the middle of a chain is still loading, the base link that supersedes an older
//!   loaded version runs through it, so the older version would read as a head and its keys
//!   would come back in a merge. [`superseded_by`] walks from each loaded version over every
//!   live version, transitively, and names the older versions the loaded ones supersede through
//!   versions not yet loaded; [`loaded_heads`] removes those before applying the rule.
//!
//! Nothing here touches the network or a store: the caller supplies the versions.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// The largest `seq` a version may carry (2^53): a version at it is a revert that supersedes
/// whatever its `base` lists, whatever their seq.
pub const MAX_SEQ: i64 = 1 << 53;

/// One live version of a ref, as a reader holds it: the fields the head rule reads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefVersion {
    /// The version's root (a CID).
    pub root: String,
    /// The roots it was computed from.
    pub base: Vec<String>,
    /// Its sequence number; [`MAX_SEQ`] for a revert.
    pub seq: i64,
    /// The physical part of its issued stamp, in milliseconds.
    pub issued_physical: i64,
    /// The logical part of its issued stamp.
    pub issued_logical: u32,
    /// The issuing peer's id.
    pub issuer: String,
    /// The id of the entry that carries it.
    pub entry_id: String,
}

impl RefVersion {
    /// The seq below which this version supersedes what its base lists.
    fn supersedes_below(&self) -> i64 {
        if self.seq >= MAX_SEQ {
            i64::MAX
        } else {
            self.seq
        }
    }
}

/// The order in which equal roots are folded: issued physical, then logical, then the issuer's
/// bytes, then the root, as the reference implementation orders a ref's heads.
pub fn merge_order(a: &RefVersion, b: &RefVersion) -> Ordering {
    a.issued_physical
        .cmp(&b.issued_physical)
        .then(a.issued_logical.cmp(&b.issued_logical))
        .then_with(|| a.issuer.as_bytes().cmp(b.issuer.as_bytes()))
        .then_with(|| a.root.cmp(&b.root))
}

/// The live versions that `loaded` supersede, directly or through other live versions: each
/// newer version folds every older live version (a smaller seq, or any seq under a revert at
/// [`MAX_SEQ`]) that its `base` names, and the walk continues from each version folded. The
/// answer names each folded version by its root and entry id.
pub fn superseded_by(loaded: &[RefVersion], live: &[RefVersion]) -> HashSet<(String, String)> {
    let mut superseded: HashSet<(String, String)> = HashSet::new();
    let mut frontier: VecDeque<&RefVersion> = loaded.iter().collect();
    while let Some(newer) = frontier.pop_front() {
        let below = newer.supersedes_below();
        for older in live {
            if older.seq < below
                && newer.base.contains(&older.root)
                && superseded.insert((older.root.clone(), older.entry_id.clone()))
            {
                frontier.push_back(older);
            }
        }
    }
    superseded
}

/// The heads among `versions`: those no other version with a larger seq lists in its base,
/// equal roots folded to the version with the largest seq (the earlier in [`merge_order`] among
/// equals). The heads come back in [`merge_order`].
pub fn heads_among(versions: &[RefVersion]) -> Vec<RefVersion> {
    let mut superseded_below: HashMap<&str, i64> = HashMap::new();
    for version in versions {
        let below = version.supersedes_below();
        for base in &version.base {
            let slot = superseded_below.entry(base.as_str()).or_insert(below);
            *slot = (*slot).max(below);
        }
    }
    let mut ordered: Vec<&RefVersion> = versions.iter().collect();
    ordered.sort_by(|a, b| merge_order(a, b));
    let mut by_root: BTreeMap<&str, (usize, &RefVersion)> = BTreeMap::new();
    for (position, version) in ordered.into_iter().enumerate() {
        if superseded_below
            .get(version.root.as_str())
            .is_some_and(|below| *below > version.seq)
        {
            continue;
        }
        match by_root.get_mut(version.root.as_str()) {
            Some(kept) if version.seq > kept.1.seq => *kept = (kept.0, version),
            Some(_) => {}
            None => {
                by_root.insert(version.root.as_str(), (position, version));
            }
        }
    }
    let mut heads: Vec<(usize, &RefVersion)> = by_root.into_values().collect();
    heads.sort_by_key(|(position, _)| *position);
    heads
        .into_iter()
        .map(|(_, version)| version.clone())
        .collect()
}

/// The heads a reader judges from the versions it has loaded: when every live version is
/// loaded, the rule of [`heads_among`] alone; when some are still loading, the loaded versions
/// that other loaded versions supersede through them ([`superseded_by`]) are removed first.
pub fn loaded_heads(
    live: &[RefVersion],
    is_loaded: impl Fn(&RefVersion) -> bool,
) -> Vec<RefVersion> {
    let loaded: Vec<RefVersion> = live
        .iter()
        .filter(|version| is_loaded(version))
        .cloned()
        .collect();
    if loaded.len() == live.len() {
        return heads_among(&loaded);
    }
    let folded = superseded_by(&loaded, live);
    let ready: Vec<RefVersion> = loaded
        .into_iter()
        .filter(|version| !folded.contains(&(version.root.clone(), version.entry_id.clone())))
        .collect();
    heads_among(&ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(label: &str, base: &[&str], seq: i64, at: i64) -> RefVersion {
        RefVersion {
            root: format!("r-{label}"),
            base: base.iter().map(|b| format!("r-{b}")).collect(),
            seq,
            issued_physical: at,
            issued_logical: 0,
            issuer: "zA".to_owned(),
            entry_id: format!("e-{label}"),
        }
    }

    fn labels(heads: &[RefVersion]) -> Vec<String> {
        let mut out: Vec<String> = heads.iter().map(|h| h.root[2..].to_owned()).collect();
        out.sort();
        out
    }

    #[test]
    fn a_late_middle_version_no_longer_resurrects_its_loaded_ancestor() {
        // a <- x(late) <- h, and f: a is superseded through x even while x loads.
        let live = vec![
            version("a", &[], 1, 1000),
            version("x", &["a"], 2, 1001),
            version("h", &["x"], 3, 1002),
            version("f", &[], 4, 1003),
        ];
        let without_fold = heads_among(
            &live
                .iter()
                .filter(|v| v.root != "r-x")
                .cloned()
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            labels(&without_fold),
            ["a", "f", "h"],
            "the defect: the rule alone keeps a"
        );
        assert_eq!(
            labels(&loaded_heads(&live, |v| v.root != "r-x")),
            ["f", "h"]
        );
    }

    #[test]
    fn equal_roots_fold_to_the_largest_seq() {
        let mut later = version("a", &["b"], 3, 1002);
        later.entry_id = "e-a2".to_owned();
        let live = vec![
            version("a", &[], 1, 1000),
            version("b", &["a"], 2, 1001),
            later,
        ];
        let heads = heads_among(&live);
        assert_eq!(heads.len(), 1);
        assert_eq!(
            heads[0].seq, 3,
            "the revert to a's content stays a head over b"
        );
    }

    #[test]
    fn a_revert_at_max_seq_supersedes_whatever_it_lists() {
        let live = vec![
            version("a", &[], 5, 1000),
            version("x", &["a"], 6, 1001),
            version("r", &["x"], MAX_SEQ, 1002),
        ];
        assert_eq!(labels(&loaded_heads(&live, |v| v.root != "r-x")), ["r"]);
    }
}
