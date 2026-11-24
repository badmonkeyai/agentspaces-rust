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

//! Issue instants for advertisements and cards a gossip item id names by issue millisecond (SPEC
//! v0.1.36 §9.5; the reference implementation's `IssueClock`). A changed
//! card or self-advertisement issued in the millisecond of the last one under its id would share
//! that one's item id, and a member that deduplicates by item id (every Java node) would drop it
//! until the next refresh. So a changed issue is at least a millisecond after the last one under
//! its id; the same content keeps its instant (a duplicate is harmless).

use std::collections::HashMap;

/// The most ids remembered; past it the least recently issued goes.
const MAX_IDS: usize = 4096;

/// The last issue under each id: its instant and a fingerprint of its content.
#[derive(Debug, Default)]
pub(super) struct IssueClock {
    last: HashMap<String, (i64, [u8; 32], u64)>,
    order: u64,
}

impl IssueClock {
    /// The issue instant (epoch milliseconds) for content `fingerprint` under `id`, asked at
    /// `wanted`: `wanted`, unless the last issue under `id` was at or after it with other content,
    /// then one millisecond after that one. Notes the answer as the last issue.
    pub fn next(&mut self, id: &str, wanted: i64, fingerprint: [u8; 32]) -> i64 {
        let issued = match self.last.get(id) {
            Some((last, seen, _)) if *seen != fingerprint && *last >= wanted => {
                last.saturating_add(1)
            }
            Some((last, seen, _)) if *seen == fingerprint && *last > wanted => *last,
            _ => wanted,
        };
        if !self.last.contains_key(id)
            && self.last.len() >= MAX_IDS
            && let Some(oldest) = self
                .last
                .iter()
                .min_by_key(|(_, (_, _, order))| *order)
                .map(|(id, _)| id.clone())
        {
            self.last.remove(&oldest);
        }
        self.order = self.order.wrapping_add(1);
        self.last
            .insert(id.to_owned(), (issued, fingerprint, self.order));
        issued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_issue_in_the_same_millisecond_is_a_millisecond_later() {
        let mut clock = IssueClock::default();
        assert_eq!(clock.next("card", 1_000, [1; 32]), 1_000);
        assert_eq!(clock.next("card", 1_000, [2; 32]), 1_001, "changed content");
        assert_eq!(clock.next("card", 1_000, [3; 32]), 1_002, "and again");
        assert_eq!(
            clock.next("card", 1_000, [3; 32]),
            1_002,
            "the same content keeps it"
        );
        assert_eq!(
            clock.next("card", 5_000, [4; 32]),
            5_000,
            "a later instant stands"
        );
        assert_eq!(clock.next("other", 1_000, [2; 32]), 1_000, "per id");
    }

    #[test]
    fn the_memory_is_bounded() {
        let mut clock = IssueClock::default();
        for n in 0..(MAX_IDS + 10) {
            clock.next(&format!("id-{n}"), 1, [0; 32]);
        }
        assert_eq!(clock.last.len(), MAX_IDS);
        assert!(!clock.last.contains_key("id-0"), "the oldest went");
    }
}
