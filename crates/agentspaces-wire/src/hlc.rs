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

//! Hybrid logical clock stamps (SPEC §7.1, §9), a port of `wire.py`'s `parse_hlc`,
//! `acceptable_hlc`, `hlc_now`, and `hlc_observe`, with Java `HlcTimestamp` and
//! `HybridLogicalClock` as the authority on what a stamp is, how stamps order, and how a clock
//! advances.
//!
//! A stamp is the text `physical:logical:node`: epoch milliseconds, a counter that orders stamps
//! within one millisecond, and the id of the node (a PeerID, or an agent id) that issued it.
//! Stamps order by physical time, then the counter, then the node in Java string order (UTF-16
//! code units, [`Stamp`]'s [`Ord`]).
//!
//! # The canonical stamp (SPEC §9, v0.1.30 and v0.1.31)
//!
//! A stamp has exactly one text, so the bytes a signer signed are always the re-encoding of the
//! stamp a receiver decodes, and every implementation verifies a signature over the same bytes.
//! [`Stamp::parse`] accepts exactly that text and refuses any other, wherever this crate decodes,
//! merges, orders, or deduplicates a stamp:
//!
//! - the physical and logical parts are each `0` or a non-zero ASCII digit followed by ASCII
//!   digits: no sign, no leading zero, no fraction, no exponent, no whitespace;
//! - the physical part fits a signed 64-bit integer and the logical part a signed 32-bit one;
//! - the node is non-empty and holds no `:` and no control character (U+0000 to U+001F, U+007F);
//!   a Rust string cannot hold a lone surrogate, so that rule holds by construction;
//! - the whole text holds at most [`MAX_STAMP_UNITS`] UTF-16 code units.
//!
//! | input                          | [`Stamp::parse`]          |
//! |--------------------------------|---------------------------|
//! | `5:0:n`, `5:65537:n`           | 5, 0 (65537), `n`         |
//! | `+5:0:n`, `05:0:n`, `5:00:n`   | refused (not canonical)   |
//! | `-5:0:n`, `5:-1:n`             | refused (a sign)          |
//! | `5`, `5:x`, `5:0:`, `5:0:a:b`  | refused (parts)           |
//! | `5:2147483648:n`               | refused (counter range)   |
//! | `5:0:a\u{7}b`                  | refused (control in node) |
//!
//! A counter above [`LOGICAL_LIMIT`] that is otherwise canonical parses, so the carrier that holds
//! it decodes and its signature verifies; every merge point then refuses it as not acceptable
//! ([`Stamp::is_acceptable`]), which names the signer. A text outside the grammar makes its
//! carrier undecodable before any signature check.
//!
//! # The clock
//!
//! [`Hlc`] is one node's clock. It has no global state and no clock of its own: the caller passes
//! its wall time to [`Hlc::now`] and [`Hlc::observe`], so tests are deterministic and one process
//! may run many nodes, each with its own `Hlc` (`wire.py` keys one global table by node instead).
//! It validates its node when it is built ([`Hlc::new`]), so it never issues a stamp a receiver
//! refuses for its node; it carries into the next millisecond where an increment would pass
//! [`LOGICAL_LIMIT`], so it never issues the same stamp twice; and it clamps a merged remote
//! physical part one millisecond inside the drift ceiling, so a carry after the merge lands at
//! most on the ceiling.
#![warn(missing_docs)]

use std::cmp::Ordering;
use std::fmt;

use crate::cbor::Value;
use crate::limits::{LOGICAL_LIMIT, MAX_DRIFT_MILLIS, MAX_NODE_UNITS, MAX_STAMP_UNITS};
use crate::util::java_order;

// ---------------------------------------------------------------------------------------------
// Stamps

/// A hybrid logical clock stamp in its canonical text, parsed as Java `HlcTimestamp.parse` parses
/// one and ordered as `HlcTimestamp.compareTo` orders them (physical, logical, then node in Java
/// string order).
///
/// The crate's one stamp parser: [`crate::records`], [`crate::fold`], [`crate::envelope`], and
/// the schemas of [`crate::schema`] judge every stamp with [`Stamp::parse`]. A `Stamp` borrows its
/// node from the text it was parsed from; its [`Display`](fmt::Display) form is that text again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp<'a> {
    /// Epoch milliseconds, the signing time; never negative in a parsed stamp.
    pub physical: i64,
    /// The logical counter; never negative in a parsed stamp, and above [`LOGICAL_LIMIT`] only in
    /// a stamp no merge point accepts.
    pub logical: i32,
    /// The node id; non-empty and free of `:` and control characters in a parsed stamp.
    pub node: &'a str,
}

impl<'a> Stamp<'a> {
    /// The canonical stamp `physical:logical:node` (SPEC §9; see the module rules), or `None`
    /// for any other text. Never panics.
    pub fn parse(text: &'a str) -> Option<Self> {
        if !within_units(text, MAX_STAMP_UNITS) {
            return None;
        }
        let mut parts = text.splitn(3, ':');
        let physical = canonical_digits(parts.next()?)?.parse().ok()?;
        let logical = canonical_digits(parts.next()?)?.parse().ok()?;
        let node = parts.next()?;
        is_canonical_node(node).then_some(Self {
            physical,
            logical,
            node,
        })
    }

    /// The stamp a field holds, when it is text that [`Stamp::parse`] accepts.
    pub fn of(value: Option<&'a Value>) -> Option<Self> {
        value.and_then(Value::as_str).and_then(Self::parse)
    }

    /// [`Stamp::parse`], kept under the name it had while the crate also read non-canonical
    /// stamps: every stamp it parses is canonical now.
    pub fn parse_canonical(text: &'a str) -> Option<Self> {
        Self::parse(text)
    }

    /// [`Stamp::of`], kept under the name it had while the crate also read non-canonical stamps.
    pub fn canonical_of(value: Option<&'a Value>) -> Option<Self> {
        Self::of(value)
    }

    /// The stamp `text` holds when it parses and is acceptable ([`Stamp::is_acceptable`]): what
    /// every merge and ordering point takes from a remote party (`wire.acceptable_hlc`).
    pub fn acceptable(text: &'a str) -> Option<Self> {
        Self::parse(text).filter(Stamp::is_acceptable)
    }

    /// Whether a remote stamp may merge into a clock, order a claim, or date a state: its logical
    /// counter is at most [`LOGICAL_LIMIT`] (Java `HybridLogicalClock.isAcceptable`, SPEC §9).
    pub fn is_acceptable(&self) -> bool {
        self.logical <= LOGICAL_LIMIT
    }
}

impl Ord for Stamp<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.physical
            .cmp(&other.physical)
            .then(self.logical.cmp(&other.logical))
            .then_with(|| java_order(self.node, other.node))
    }
}

impl PartialOrd for Stamp<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The canonical form `physical:logical:node` (Java `HlcTimestamp.encoded`).
impl fmt::Display for Stamp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.physical, self.logical, self.node)
    }
}

/// Whether `node` may be a stamp's node part (SPEC §9, Java `HlcTimestamp.canonicalNode`):
/// non-empty, with no `:` and no control character (U+0000 to U+001F, U+007F). A Rust string holds
/// no lone surrogate, the grammar's last rule.
pub fn is_canonical_node(node: &str) -> bool {
    !node.is_empty() && !node.chars().any(|c| c == ':' || c < ' ' || c == '\u{7F}')
}

/// `part` when it is `0` or a non-zero ASCII digit followed by ASCII digits.
fn canonical_digits(part: &str) -> Option<&str> {
    let digits = !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    (digits && (part == "0" || !part.starts_with('0'))).then_some(part)
}

/// Whether `text` holds at most `limit` UTF-16 code units. A UTF-8 text never has more code units
/// than bytes, so a short text is decided without counting.
fn within_units(text: &str, limit: usize) -> bool {
    text.len() <= limit || text.encode_utf16().count() <= limit
}

/// The physical milliseconds of a stamp, read leniently: the text before the first `:` (all of
/// it when there is none) as a signed decimal `i64` (Java `Long.parseLong`, an optional sign then
/// ASCII digits), or `None` when that part is not such a number. Nothing after the first `:` is
/// looked at, and a negative physical time is returned as it is.
///
/// No judgment in this crate reads a stamp this way any more: a stamp outside the canonical
/// grammar is no stamp (SPEC §9). It stays for callers that display a stamp's time. Never panics.
pub fn physical_lenient(stamp: &str) -> Option<i64> {
    stamp
        .split_once(':')
        .map_or(stamp, |(physical, _)| physical)
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------------------------
// The clock

/// Why a clock could not be built for a node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HlcError {
    /// The node is empty, or holds a `:` or a control character, so no stamp could carry it.
    #[error("a stamp node is non-empty and holds no ':' and no control character: {0:?}")]
    InvalidNode(String),
    /// The node is longer than [`MAX_NODE_UNITS`] UTF-16 code units, so a stamp it issued could
    /// pass [`MAX_STAMP_UNITS`].
    #[error("a stamp node holds at most {MAX_NODE_UNITS} UTF-16 code units")]
    NodeTooLong,
}

/// One node's hybrid logical clock (`wire.py`'s `hlc_now` and `hlc_observe`, per node, with Java
/// `HybridLogicalClock` as the authority): stamps it issues never run backwards, never repeat,
/// never carry a counter above [`LOGICAL_LIMIT`], and a stamp issued after an observed remote
/// stamp sorts after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hlc {
    node: String,
    physical: i64,
    /// The counter of the last stamp issued or observed; -1 before any, so the first stamp at
    /// physical 0 counts 0, as `wire.py`'s initial `(0, -1)` does.
    logical: i32,
}

impl Hlc {
    /// A clock for `node` that has issued and observed nothing. Refuses a node no stamp can carry
    /// ([`is_canonical_node`]) and one longer than [`MAX_NODE_UNITS`] UTF-16 code units, as Java's
    /// `HybridLogicalClock` constructor does (SPEC §9: a node validates its own node part where it
    /// builds a clock, so it never emits a stamp a receiver refuses for its node).
    pub fn new(node: impl Into<String>) -> Result<Self, HlcError> {
        let node = node.into();
        if !is_canonical_node(&node) {
            return Err(HlcError::InvalidNode(node));
        }
        if !within_units(&node, MAX_NODE_UNITS) {
            return Err(HlcError::NodeTooLong);
        }
        Ok(Self {
            node,
            physical: 0,
            logical: -1,
        })
    }

    /// The node this clock stamps.
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The physical time and counter of the last stamp issued or merged, or `None` before any.
    pub fn last(&self) -> Option<(i64, i32)> {
        (self.logical >= 0).then_some((self.physical, self.logical))
    }

    /// A fresh stamp `physical:logical:node` at `now_ms` on the caller's clock (`wire.hlc_now`):
    /// when `now_ms` is past the clock's physical time the stamp takes it with counter 0;
    /// otherwise (a clock that stood still or ran backwards, or a merged remote stamp ahead of
    /// it) the physical time stays and the counter advances by one. Where the counter would pass
    /// [`LOGICAL_LIMIT`] the clock carries instead: the physical time advances one millisecond and
    /// the counter starts at 0 (SPEC §9, Java `HybridLogicalClock.advance`), so the clock never
    /// returns the same stamp twice. Only a caller whose clock reads `i64::MAX` could exhaust the
    /// carry; the physical time then stays there.
    pub fn now(&mut self, now_ms: i64) -> String {
        if now_ms > self.physical {
            self.physical = now_ms;
            self.logical = 0;
        } else if self.logical < LOGICAL_LIMIT {
            self.logical += 1;
        } else {
            self.physical = self.physical.saturating_add(1);
            self.logical = 0;
        }
        format!("{}:{}:{}", self.physical, self.logical, self.node)
    }

    /// Merges a remote stamp observed at `now_ms` on the caller's clock (`wire.hlc_observe`), so
    /// later stamps from [`Hlc::now`] sort after it, and returns whether the clock advanced.
    ///
    /// Only an acceptable stamp merges ([`Stamp::acceptable`]): one that does not parse, or
    /// whose counter is above [`LOGICAL_LIMIT`], never reaches the clock. The remote physical
    /// time is clamped to `now_ms + MAX_DRIFT_MILLIS - 1`, one millisecond inside the drift
    /// ceiling (SPEC §9, v0.1.30), so a hostile far-future stamp cannot pin this clock and a
    /// carry after the merge lands at most on the ceiling. The clock then takes the clamped
    /// `(physical, logical)` pair when it is later than its own. The arithmetic saturates, so no
    /// stamp can overflow it.
    pub fn observe(&mut self, stamp: &str, now_ms: i64) -> bool {
        let Some(stamp) = Stamp::acceptable(stamp) else {
            return false;
        };
        let ceiling = now_ms.saturating_add(MAX_DRIFT_MILLIS - 1);
        let physical = stamp.physical.min(ceiling);
        let later = (physical, stamp.logical) > (self.physical, self.logical);
        if later {
            self.physical = physical;
            self.logical = stamp.logical;
        }
        later
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamp_has_one_text() {
        for text in [
            "5:0:n",
            "0:0:n",
            "1735689600000:3:zPeer",
            "5:0:a/b",
            "5:65537:n",
        ] {
            assert!(Stamp::parse(text).is_some(), "{text}");
            assert_eq!(Stamp::parse_canonical(text), Stamp::parse(text), "{text}");
            assert_eq!(
                Stamp::parse(text).map(|s| s.to_string()).as_deref(),
                Some(text)
            );
        }
        // Java's HlcTimestamp refuses each of these since v0.1.30.
        for text in [
            "+5:0:n",
            "05:0:n",
            "-0:0:n",
            "5:+0:n",
            "5:00:n",
            "5:-0:n",
            "00:0:n",
            "5:0:",
            "5:0:a\u{1}b",
            "5:0:a\u{7F}",
            "5:0:a:b",
            " 5:0:n",
            "5:0 :n",
            "5.0:0:n",
            "5e1:0:n",
        ] {
            assert_eq!(Stamp::parse(text), None, "{text:?}");
        }
        let value = Value::from("+5:0:n");
        assert_eq!(Stamp::of(Some(&value)), None);
        assert_eq!(Stamp::canonical_of(Some(&value)), None);
    }

    #[test]
    fn a_stamp_fits_one_definite_text() {
        let node = "n".repeat(MAX_STAMP_UNITS - 4);
        let longest = format!("5:0:{node}");
        assert_eq!(longest.encode_utf16().count(), MAX_STAMP_UNITS);
        assert!(Stamp::parse(&longest).is_some());
        assert_eq!(Stamp::parse(&format!("{longest}n")), None);
        // A character past U+FFFF is two code units.
        let wide = format!("5:0:{}{}", "n".repeat(MAX_STAMP_UNITS - 6), '\u{1F600}');
        assert_eq!(wide.encode_utf16().count(), MAX_STAMP_UNITS);
        assert!(Stamp::parse(&wide).is_some());
        assert_eq!(Stamp::parse(&format!("{wide}n")), None);
    }

    #[test]
    fn a_counter_above_the_limit_parses_and_is_not_acceptable() {
        let limit = format!("5:{LOGICAL_LIMIT}:n");
        let above = format!("5:{}:n", LOGICAL_LIMIT + 1);
        assert!(Stamp::acceptable(&limit).is_some());
        assert!(Stamp::parse(&above).is_some());
        assert_eq!(Stamp::acceptable(&above), None);
        assert_eq!(
            Stamp::parse(&format!("5:{}:n", i64::from(i32::MAX) + 1)),
            None
        );
    }

    #[test]
    fn a_clock_refuses_a_node_no_stamp_carries() {
        for node in ["", "a:b", "a\u{0}", "tab\t", "del\u{7F}"] {
            assert_eq!(
                Hlc::new(node),
                Err(HlcError::InvalidNode(node.into())),
                "{node:?}"
            );
        }
        assert!(Hlc::new("n".repeat(MAX_NODE_UNITS)).is_ok());
        assert_eq!(
            Hlc::new("n".repeat(MAX_NODE_UNITS + 1)),
            Err(HlcError::NodeTooLong)
        );
        // The longest node still issues a stamp that fits, whatever its parts grow to.
        let mut hlc = Hlc::new("n".repeat(MAX_NODE_UNITS)).expect("a node");
        let mut stamp = hlc.now(i64::MAX);
        for _ in 0..3 {
            stamp = hlc.now(i64::MAX);
        }
        assert!(Stamp::parse(&stamp).is_some());
    }
}
