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

//! Hybrid logical clock stamps (SPEC §7.1, §9), a port of `wire.py`'s
//! `hlc_now`, `hlc_observe`, and `hlc_physical`, with Java `HlcTimestamp` as the authority on what
//! a stamp is and how stamps order.
//!
//! A stamp is the text `physical:logical:node`: epoch milliseconds, a counter that orders stamps
//! within one millisecond, and the id of the node (a PeerID, or an agent id) that issued it.
//! Stamps order by physical time, then the counter, then the node in Java string order
//! ([`Stamp`]'s [`Ord`]).
//!
//! # Two parsers, two sets of rules
//!
//! The crate reads stamps two ways, on purpose, and each keeps the rules of the Java code it
//! mirrors:
//!
//! | input            | [`Stamp::parse`] (strict) | [`physical_lenient`] |
//! |------------------|---------------------------|----------------------|
//! | `5:0:n`, `+5:0:n` | 5, 0, `n`                | 5                    |
//! | `-5:0:n`         | refused (negative)         | -5                   |
//! | `5`, `5:x`       | refused (no logical/node)  | 5                    |
//! | `5:-1:n`, `5:2147483648:n` | refused          | 5                    |
//! | `5:0:`, `5:0:a:b` | refused (node empty / with `:`) | 5             |
//! | ` 5:0:n`, `x:0:n`, `9223372036854775808:0:n` | refused | refused   |
//!
//! - [`Stamp::parse`] is Java `HlcTimestamp.parse`: three parts split at the first two `:`, a
//!   non-negative `long`, a non-negative `int`, and a non-empty node free of `:`. Records, states,
//!   claims, and the space fold judge every stamp with it ([`crate::records`],
//!   [`crate::fold`]), so a stamp Java could not decode never verifies, and the fold admits
//!   exactly the stamps the verifiers accept.
//! - [`Stamp::parse_canonical`] is [`Stamp::parse`] restricted to the text Java writes a stamp
//!   back as (`5:0:n`, never `+5:0:n` or `05:0:n`). Java verifies a signature over its own
//!   re-encoding of a stamp, so every stamp a signature covers (a record's `issued`, a claim's
//!   `stamp`, a state's `leaseStamp` and `signedAt`, an envelope's `stamp`) is judged with it:
//!   the bytes this crate verifies are then the bytes Java verifies.
//! - [`physical_lenient`] reads only the physical milliseconds, as the Java frame filter and
//!   `wire.hlc_physical` read them: `Long.parseLong` of the text before the first `:`. The frame
//!   filter ([`crate::envelope::FrameFilter`]) judges a frame's age with it, and the fold reads
//!   the signing time of a `signedAt` with it.
//!
//! Both read an optional sign and ASCII digits only, with no surrounding space, and never panic.
//!
//! # The clock
//!
//! [`Hlc`] is one node's clock. It has no global state and no clock of its own: the caller passes
//! its wall time to [`Hlc::now`] and [`Hlc::observe`], so tests are deterministic and one process
//! may run many nodes, each with its own `Hlc` (`wire.py` keys one global table by node instead).
#![warn(missing_docs)]

use std::cmp::Ordering;
use std::fmt;

use crate::cbor::Value;
use crate::limits::MAX_HLC_SKEW_MILLIS;
use crate::util::java_order;

// ---------------------------------------------------------------------------------------------
// Stamps

/// A hybrid logical clock stamp, parsed as Java `HlcTimestamp.parse` parses one and ordered as
/// `HlcTimestamp.compareTo` orders them (physical, logical, then node in Java string order).
///
/// The crate's one strict stamp parser: [`crate::records`] and [`crate::fold`] judge every stamp
/// with [`Stamp::parse`]. A `Stamp` borrows its node from the text it was parsed from; its
/// [`Display`](fmt::Display) form is that text again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp<'a> {
    /// Epoch milliseconds, the signing time; never negative in a parsed stamp.
    pub physical: i64,
    /// The logical counter; never negative in a parsed stamp.
    pub logical: i32,
    /// The node id; non-empty and free of `:` in a parsed stamp.
    pub node: &'a str,
}

impl<'a> Stamp<'a> {
    /// `physical:logical:node` with a non-negative `long`, a non-negative `int`, and a non-empty
    /// node free of `:` (Java `HlcTimestamp.parse` and its constructor); `None` otherwise. Each
    /// number is an optional sign and ASCII digits (Java `Long.parseLong` and
    /// `Integer.parseInt`), with no surrounding space. Never panics.
    pub fn parse(text: &'a str) -> Option<Self> {
        let mut parts = text.splitn(3, ':');
        let physical: i64 = parts.next()?.parse().ok()?;
        let logical: i32 = parts.next()?.parse().ok()?;
        let node = parts.next()?;
        let valid = physical >= 0 && logical >= 0 && !node.is_empty() && !node.contains(':');
        valid.then_some(Self {
            physical,
            logical,
            node,
        })
    }

    /// The stamp a field holds, when it is text that [`Stamp::parse`] accepts.
    pub fn of(value: Option<&'a Value>) -> Option<Self> {
        value.and_then(Value::as_str).and_then(Self::parse)
    }

    /// [`Stamp::parse`], and only when `text` is already the canonical form Java writes the stamp
    /// back as (`HlcTimestamp.encoded`, this type's [`Display`](fmt::Display)): no `+` sign, no
    /// leading zeros, no `-0`. `None` otherwise. Never panics.
    ///
    /// Java decodes a signed stamp into an `HlcTimestamp` and verifies the signature over its
    /// re-encoding, so `+5:0:n` and `05:0:n` are signed as `5:0:n` there. A verifier here judges
    /// the bytes it received, so it accepts a stamp only in that canonical form: then both
    /// verify the same bytes ([`crate::records`], [`crate::envelope`]).
    pub fn parse_canonical(text: &'a str) -> Option<Self> {
        let stamp = Self::parse(text)?;
        let canonical = |part: &str| part == "0" || !(part.starts_with(['0', '+', '-']));
        let mut parts = text.splitn(3, ':');
        let physical = parts.next().is_some_and(canonical);
        let logical = parts.next().is_some_and(canonical);
        (physical && logical).then_some(stamp)
    }

    /// The stamp a field holds, when it is text that [`Stamp::parse_canonical`] accepts.
    pub fn canonical_of(value: Option<&'a Value>) -> Option<Self> {
        value
            .and_then(Value::as_str)
            .and_then(Self::parse_canonical)
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

/// The physical milliseconds of a stamp, read leniently: the text before the first `:` (all of
/// it when there is none) as a signed decimal `i64` (Java `Long.parseLong`, an optional sign then
/// ASCII digits), or `None` when that part is not such a number. Nothing after the first `:` is
/// looked at, and a negative physical time is returned as it is.
///
/// These are the Java frame filter's rules and `wire.hlc_physical`'s; see the module table for
/// how they differ from [`Stamp::parse`]. Never panics.
pub fn physical_lenient(stamp: &str) -> Option<i64> {
    stamp
        .split_once(':')
        .map_or(stamp, |(physical, _)| physical)
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------------------------
// The clock

/// One node's hybrid logical clock (`wire.py`'s `hlc_now` and `hlc_observe`, per node): stamps it
/// issues never run backwards, two stamps it issues never collide, and a stamp issued after an
/// observed remote stamp sorts after it.
///
/// The node should be a PeerID or an agent id (non-empty, free of `:`); otherwise the stamps it
/// issues are not stamps [`Stamp::parse`] accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hlc {
    node: String,
    physical: i64,
    /// The counter of the last stamp issued or observed; -1 before any, so the first stamp at
    /// physical 0 counts 0, as `wire.py`'s initial `(0, -1)` does.
    logical: i32,
}

impl Hlc {
    /// A clock for `node` that has issued and observed nothing.
    pub fn new(node: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            physical: 0,
            logical: -1,
        }
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
    /// it) the physical time stays and the counter advances by one. The counter saturates at
    /// `i32::MAX` rather than overflow (Java `HybridLogicalClock.incrementLogical`), so a stamp
    /// stays one Java can parse.
    pub fn now(&mut self, now_ms: i64) -> String {
        if now_ms > self.physical {
            self.physical = now_ms;
            self.logical = 0;
        } else {
            self.logical = self.logical.saturating_add(1);
        }
        format!("{}:{}:{}", self.physical, self.logical, self.node)
    }

    /// Merges a remote stamp observed at `now_ms` on the caller's clock (`wire.hlc_observe`), so
    /// later stamps from [`Hlc::now`] sort after it, and returns whether the clock advanced.
    ///
    /// A stamp that [`Stamp::parse`] refuses is ignored, as is one whose physical time is more
    /// than [`MAX_HLC_SKEW_MILLIS`] ahead of `now_ms`: a hostile far-future stamp cannot pin this
    /// clock. Otherwise the clock takes the stamp's `(physical, logical)` when that
    /// pair is later than its own. The arithmetic is exact, so no stamp can overflow it.
    pub fn observe(&mut self, stamp: &str, now_ms: i64) -> bool {
        let Some(stamp) = Stamp::parse(stamp) else {
            return false;
        };
        if i128::from(stamp.physical) > i128::from(now_ms) + i128::from(MAX_HLC_SKEW_MILLIS) {
            return false;
        }
        let later = (stamp.physical, stamp.logical) > (self.physical, self.logical);
        if later {
            self.physical = stamp.physical;
            self.logical = stamp.logical;
        }
        later
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_stamps_are_what_java_writes_back() {
        for text in ["5:0:n", "0:0:n", "1735689600000:3:zPeer", "5:0:a/b"] {
            assert_eq!(Stamp::parse_canonical(text), Stamp::parse(text), "{text}");
            assert!(Stamp::parse_canonical(text).is_some(), "{text}");
        }
        // Java's HlcTimestamp parses each of these and writes it back as `5:0:n` or `0:0:n`.
        for text in [
            "+5:0:n", "05:0:n", "-0:0:n", "5:+0:n", "5:00:n", "5:-0:n", "00:0:n",
        ] {
            assert!(Stamp::parse(text).is_some(), "{text}");
            assert_eq!(Stamp::parse_canonical(text), None, "{text}");
        }
        assert_eq!(Stamp::parse_canonical("5:0:"), None);
        let value = Value::from("+5:0:n");
        assert!(Stamp::of(Some(&value)).is_some());
        assert_eq!(Stamp::canonical_of(Some(&value)), None);
    }
}
