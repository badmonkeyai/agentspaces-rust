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

//! The lease and collection rules of SPEC §7.2 and §7.3 (v0.1.35): the renewal that never
//! shortens, the collection horizons with the drift floor, and the per-entry horizon under the
//! hint `wire.horizon=1` with both halves of its precondition. Pure functions of their inputs;
//! the replica supplies its clock, its view, and its longest observed lease.
//!
//! # Renewal (§7.2)
//!
//! [`renewed_expiry`] is `max(current, now + extension)`, the sum saturating: a renewal for less
//! than the lease has left leaves it as it was. The same rule covers a write lease, a take's hold,
//! and a subscription's lease. Only the issuer renews, and only an entry it holds present and
//! unexpired; the caller enforces those conditions.
//!
//! # Horizons (§7.3)
//!
//! A replica collects a state once its horizon has passed, the horizon being the expiry of the
//! state's lease (`L`) plus what [`keep_millis`] keeps for its [`Standing`]:
//!
//! | Standing | [`Rule::Legacy`] | [`Rule::PerEntry`] |
//! |---|---|---|
//! | present, its lease lapsed | `min(2 × maxLease, 5 min)` | the same |
//! | withdrawn | `max(2 × maxLease, MAX_DRIFT)` | `max(5 min, MAX_DRIFT)` |
//! | completed | `2 × maxLease` | the same |
//! | withdrawn and completed | `max(2 × maxLease, MAX_DRIFT)` | the same |
//!
//! A withdrawn entry is never collectable before `L + MAX_DRIFT` under either rule (the drift
//! floor): when the first replica collects, every conforming clock reads `L` or later, so no copy
//! of the entry can be live anywhere. A present entry is never collectable before its lease
//! lapses, and one whose lease is not a write lease never lapses.
//!
//! # The per-entry horizon (§7.3, normative under `wire.horizon=1`)
//!
//! The view's half: [`HorizonGate`] judges, at each sweep and at the door, whether this replica
//! and every member of its current view advertise the hint. It disengages at the first judgement
//! that finds a member without it, engages after [`DEFAULT_ENGAGE_ROUNDS`] fully hinted rounds,
//! and comes into force one `maxLease` plus five minutes after that ([`Mode`]).
//!
//! The writer's half: the rule applies to a withdrawal only when the replica vouches for every
//! writing node of the entry (the replica of each add dot, [`writers_vouched`]): this replica
//! itself, or a hinted member whose current stay in the view has lasted at least one `maxLease`
//! plus five minutes. A withdrawal by any other writer keeps the later of the two horizons
//! ([`collectable_here`]).
#![warn(missing_docs)]

use crate::cbor::{Map, Value};
use crate::fold;
use crate::limits::MAX_DRIFT_MILLIS;
use crate::records::WRITE_LEASE_KIND;

/// The hint a member that keeps the renewal rule and the per-entry horizon advertises, a key of
/// its resource hints (SPEC §7.3, §9).
pub const HINT_HORIZON: &str = "wire.horizon";
/// The value of [`HINT_HORIZON`] this crate implements.
pub const HORIZON_LEVEL: &str = "1";
/// How long a lapsed entry is kept past its lease at most, and the per-entry rule's grace: five
/// minutes.
pub const LAPSED_GRACE_MILLIS: i64 = 5 * 60 * 1000;
/// The least a withdrawn entry keeps past its lease under either rule: the clock drift ceiling of
/// SPEC §11, ten minutes (the drift floor).
pub const WITHDRAWN_DRIFT_FLOOR_MILLIS: i64 = MAX_DRIFT_MILLIS;
/// What a withdrawn entry keeps past its lease under the per-entry rule:
/// `max(5 min, MAX_DRIFT)`.
pub const PER_ENTRY_KEEP_MILLIS: i64 = if LAPSED_GRACE_MILLIS > WITHDRAWN_DRIFT_FLOOR_MILLIS {
    LAPSED_GRACE_MILLIS
} else {
    WITHDRAWN_DRIFT_FLOOR_MILLIS
};
/// The cap on the lease that feeds a space's longest observed lease (24 hours): one entry with a
/// century-long lease cannot stop collection.
pub const MAX_TRACKED_LEASE_MILLIS: i64 = 24 * 60 * 60 * 1000;
/// The fully hinted rounds the view holds before the per-entry rule engages, by default.
pub const DEFAULT_ENGAGE_ROUNDS: u32 = 3;
/// The fewest engage rounds a replica may be set to.
pub const ENGAGE_ROUNDS_MIN: u32 = 1;
/// The most engage rounds a replica may be set to.
pub const ENGAGE_ROUNDS_MAX: u32 = 64;

/// Whether a card's resource hints carry `wire.horizon=1`.
pub fn hints_horizon(hints: Option<&Value>) -> bool {
    hints
        .and_then(|hints| hints.get(HINT_HORIZON))
        .and_then(Value::as_str)
        == Some(HORIZON_LEVEL)
}

// ---------------------------------------------------------------------------------------------
// Renewal

/// The expiry a renewal sets (SPEC §7.2): at least `extension` from `now`, and never less than
/// the lease already had, `max(current, now + extension)`. The sum saturates, so a very long
/// extension never wraps into the past.
pub fn renewed_expiry(current: i64, now: i64, extension: i64) -> i64 {
    current.max(now.saturating_add(extension))
}

// ---------------------------------------------------------------------------------------------
// Horizons

/// Which collection rule a replica applies (SPEC §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Some member of the view lacks `wire.horizon=1`, or the replica keeps the old rule.
    Legacy,
    /// This replica and every member of its view advertise `wire.horizon=1`.
    PerEntry,
}

impl Rule {
    /// The name the golden vectors use: `legacy` or `per-entry`.
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Legacy => "legacy",
            Rule::PerEntry => "per-entry",
        }
    }

    /// The rule a golden vector names.
    pub fn parse(text: &str) -> Option<Rule> {
        match text {
            "legacy" => Some(Rule::Legacy),
            "per-entry" => Some(Rule::PerEntry),
            _ => None,
        }
    }
}

/// What a state is to the collector: what decides how long it is kept past its lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// Neither completed nor withdrawn; collectable only once its write lease lapsed (the vectors'
    /// `lapsed`).
    Present,
    /// Withdrawn by its issuer, not completed.
    Withdrawn,
    /// Completed, not withdrawn.
    Completed,
    /// Both withdrawn and completed.
    WithdrawnCompleted,
}

impl Standing {
    /// A state's standing, from its `completed` flag and its dot sets.
    pub fn of(state: &Map) -> Standing {
        let completed = state.get("completed").and_then(Value::as_bool) == Some(true);
        let withdrawn = fold::removes_cover_adds(state);
        match (completed, withdrawn) {
            (true, true) => Standing::WithdrawnCompleted,
            (true, false) => Standing::Completed,
            (false, _) if fold::is_present(state) => Standing::Present,
            (false, _) => Standing::Withdrawn,
        }
    }

    /// The name the golden vectors use: `lapsed`, `withdrawn`, `completed`, or
    /// `withdrawn_completed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Standing::Present => "lapsed",
            Standing::Withdrawn => "withdrawn",
            Standing::Completed => "completed",
            Standing::WithdrawnCompleted => "withdrawn_completed",
        }
    }

    /// The standing a golden vector names.
    pub fn parse(text: &str) -> Option<Standing> {
        match text {
            "lapsed" => Some(Standing::Present),
            "withdrawn" => Some(Standing::Withdrawn),
            "completed" => Some(Standing::Completed),
            "withdrawn_completed" => Some(Standing::WithdrawnCompleted),
            _ => None,
        }
    }
}

/// What a state keeps past its lease's expiry before it is collectable (SPEC §7.3, the table in
/// the [module docs](self)). A negative `max_lease` counts as zero.
pub fn keep_millis(standing: Standing, max_lease: i64, rule: Rule) -> i64 {
    let twice = max_lease.max(0).saturating_mul(2);
    match standing {
        Standing::Present => twice.min(LAPSED_GRACE_MILLIS),
        Standing::Completed => twice,
        Standing::WithdrawnCompleted => twice.max(WITHDRAWN_DRIFT_FLOOR_MILLIS),
        Standing::Withdrawn => match rule {
            Rule::Legacy => twice.max(WITHDRAWN_DRIFT_FLOOR_MILLIS),
            Rule::PerEntry => PER_ENTRY_KEEP_MILLIS,
        },
    }
}

/// The collection horizon of a state of `standing` whose lease expires at `expiry`: `None` when
/// the sum overflows, so the state is never collectable.
pub fn horizon(expiry: i64, standing: Standing, max_lease: i64, rule: Rule) -> Option<i64> {
    expiry.checked_add(keep_millis(standing, max_lease, rule))
}

/// Whether a state's lease is one that lapses: a `WRITE` lease, or one that names no kind. A
/// present entry under a lease of another kind is never collected.
fn lease_lapses(state: &Map) -> bool {
    fn kind(lease: Option<&Value>) -> Option<&str> {
        lease?.get("kind")?.as_str()
    }
    kind(state.get("leaseValue"))
        .or_else(|| kind(state.get("record")?.get("lease")))
        .is_none_or(|kind| kind == WRITE_LEASE_KIND)
}

/// A state's collection horizon under `rule`: `None` when it has no readable lease, when it is a
/// present entry under a lease that never lapses, or when the horizon overflows. For every state,
/// [`collectable`] is exactly `now >= state_horizon(...)`.
pub fn state_horizon(state: &Map, max_lease: i64, rule: Rule) -> Option<i64> {
    let expiry = fold::lease_expires_at(state)?;
    let standing = Standing::of(state);
    if standing == Standing::Present && !lease_lapses(state) {
        return None;
    }
    horizon(expiry, standing, max_lease, rule)
}

/// Whether a state is past its collection horizon at `now` under `rule` (SPEC §7.3). Every
/// horizon is at or after the lease's expiry, so a present entry is never collected while its
/// lease holds.
pub fn collectable(state: &Map, now: i64, max_lease: i64, rule: Rule) -> bool {
    state_horizon(state, max_lease, rule).is_some_and(|horizon| horizon <= now)
}

// ---------------------------------------------------------------------------------------------
// The writer's half

/// Where one writing node stands in a replica's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// The replica itself, which advertises the hint (its mode says so).
    This,
    /// A member of the current view whose current card carries the hint, in view since the given
    /// time on the replica's clock (the start of its current stay).
    InViewSince(i64),
    /// Out of the view, without the hint, or unreadable.
    Absent,
}

/// How long a writer must have been a hinted member of the view before the replica vouches for
/// it, and how long the per-entry rule waits after it engages: one `maxLease` plus five minutes.
pub fn settle_millis(max_lease: i64) -> i64 {
    max_lease.max(0).saturating_add(LAPSED_GRACE_MILLIS)
}

/// Whether the replica vouches for every writing node of `state` at `now` (SPEC §7.3): each is
/// [`Writer::This`], or [`Writer::InViewSince`] a time at least [`settle_millis`] before `now`.
/// A state with no add dot names no writer to vouch for, and is not vouched for.
pub fn writers_vouched(
    state: &Map,
    now: i64,
    max_lease: i64,
    mut writer: impl FnMut(&str) -> Writer,
) -> bool {
    let replicas = fold::add_replicas(state);
    if replicas.is_empty() {
        return false;
    }
    let settle = settle_millis(max_lease);
    replicas.into_iter().all(|replica| match writer(replica) {
        Writer::This => true,
        Writer::InViewSince(since) => since.checked_add(settle).is_some_and(|at| at <= now),
        Writer::Absent => false,
    })
}

/// The horizon a replica applies to a state under the rule its view allows (`mode`), given
/// whether it vouches for the state's writers: under [`Rule::PerEntry`] a withdrawal whose
/// writers it does not vouch for keeps the later of the legacy horizon and the per-entry one.
pub fn horizon_here(state: &Map, max_lease: i64, mode: Rule, vouched: bool) -> Option<i64> {
    let by_rule = |rule| state_horizon(state, max_lease, rule);
    if mode == Rule::PerEntry && Standing::of(state) == Standing::Withdrawn && !vouched {
        return Some(by_rule(Rule::Legacy)?.max(by_rule(Rule::PerEntry)?));
    }
    by_rule(mode)
}

/// Whether a replica collects a state at `now` ([`horizon_here`]): the sweep and the door both
/// judge by this, on the same clock.
pub fn collectable_here(state: &Map, now: i64, max_lease: i64, mode: Rule, vouched: bool) -> bool {
    horizon_here(state, max_lease, mode, vouched).is_some_and(|horizon| horizon <= now)
}

// ---------------------------------------------------------------------------------------------
// The view's half

/// Where a replica stands on the per-entry horizon (SPEC §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    /// This replica keeps the legacy rule, or a member of its view lacks the hint.
    #[default]
    Legacy,
    /// Every member advertises the hint; counting the rounds before it engages.
    Waiting,
    /// Engaged, and waiting one `maxLease` plus five minutes before withdrawals use the
    /// per-entry horizon, so that every copy a member renewed while its card lacked the hint has
    /// lapsed and is past its own lapse horizon first.
    Settling,
    /// In force.
    PerEntry,
}

impl Mode {
    /// The name the reference implementation reports: `LEGACY`, `WAITING`, `SETTLING`, or
    /// `PER_ENTRY`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Legacy => "LEGACY",
            Mode::Waiting => "WAITING",
            Mode::Settling => "SETTLING",
            Mode::PerEntry => "PER_ENTRY",
        }
    }

    /// The rule this mode applies.
    pub fn rule(self) -> Rule {
        if self == Mode::PerEntry {
            Rule::PerEntry
        } else {
            Rule::Legacy
        }
    }
}

/// The view's half of the per-entry horizon for one space: the mode and its hysteresis, judged
/// afresh at each sweep and at the door ([`HorizonGate::judge`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HorizonGate {
    mode: Mode,
    streak: u32,
    counted_at: Option<i64>,
    engaged_at: i64,
    engagements: u64,
    settlements: u64,
    disengagements: u64,
}

impl HorizonGate {
    /// A gate in [`Mode::Legacy`].
    pub fn new() -> Self {
        HorizonGate::default()
    }

    /// The mode as last judged.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// How many times the per-entry rule engaged (entered [`Mode::Settling`]).
    pub fn engagements(&self) -> u64 {
        self.engagements
    }

    /// How many times it came into force (entered [`Mode::PerEntry`]).
    pub fn settlements(&self) -> u64 {
        self.settlements
    }

    /// How many times a member without the hint disengaged it from settling or in force.
    pub fn disengagements(&self) -> u64 {
        self.disengagements
    }

    /// Judges the rule at `now` and moves the mode (SPEC §7.3):
    ///
    /// - `hinted` false (this replica keeps the legacy rule, or a member of its view lacks the
    ///   hint, a member whose card has not arrived included) disengages at once and resets the
    ///   count;
    /// - a fully hinted view counts one round per judgement at least `round_millis` after the
    ///   last counted one, and engages once it has counted `engage_rounds` (clamped to
    ///   [`ENGAGE_ROUNDS_MIN`] ..= [`ENGAGE_ROUNDS_MAX`]);
    /// - once engaged, the rule comes into force [`settle_millis`] of `max_lease` later.
    ///
    /// A clock that steps back restarts the wait it interrupts.
    pub fn judge(
        &mut self,
        now: i64,
        hinted: bool,
        round_millis: i64,
        max_lease: i64,
        engage_rounds: u32,
    ) -> Rule {
        if !hinted {
            if self.mode != Mode::Legacy {
                if matches!(self.mode, Mode::Settling | Mode::PerEntry) {
                    self.disengagements = self.disengagements.saturating_add(1);
                }
                self.mode = Mode::Legacy;
                self.streak = 0;
                self.counted_at = None;
            }
            return Rule::Legacy;
        }
        if matches!(self.mode, Mode::Legacy | Mode::Waiting) {
            let round = round_millis.max(1);
            match self.counted_at {
                Some(at) if now >= at => {
                    if now.saturating_sub(at) >= round {
                        self.streak = self.streak.saturating_add(1);
                        self.counted_at = Some(now);
                    }
                }
                _ => self.counted_at = Some(now),
            }
            let rounds = engage_rounds.clamp(ENGAGE_ROUNDS_MIN, ENGAGE_ROUNDS_MAX);
            if self.streak >= rounds {
                self.engaged_at = now;
                self.mode = Mode::Settling;
                self.engagements = self.engagements.saturating_add(1);
            } else {
                self.mode = Mode::Waiting;
            }
        }
        if self.mode == Mode::Settling {
            if now < self.engaged_at {
                self.engaged_at = now;
            } else if now.saturating_sub(self.engaged_at) >= settle_millis(max_lease) {
                self.mode = Mode::PerEntry;
                self.settlements = self.settlements.saturating_add(1);
            }
        }
        self.mode.rule()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_map;

    const L: i64 = 1_800_000_000_000;
    const MIN: i64 = 60_000;

    fn state(completed: bool, withdrawn: bool, kind: &str) -> Map {
        let dot = cbor_map! { "replica" => "z6Mkw", "counter" => 1 };
        map_of(cbor_map! {
            "adds" => Value::Array(vec![dot.clone()]),
            "removes" => Value::Array(if withdrawn { vec![dot] } else { vec![] }),
            "leaseValue" => cbor_map! { "holder" => "h", "expiresAtMillis" => L, "kind" => kind },
            "completed" => completed,
        })
    }

    fn map_of(value: Value) -> Map {
        match value {
            Value::Map(map) => map,
            _ => unreachable!("a map"),
        }
    }

    #[test]
    fn renewal_never_shortens_and_saturates() {
        assert_eq!(renewed_expiry(L + 10 * MIN, L, 2 * MIN), L + 10 * MIN);
        assert_eq!(renewed_expiry(L + 10 * MIN, L, 30 * MIN), L + 30 * MIN);
        assert_eq!(renewed_expiry(L, L, i64::MAX), i64::MAX);
        assert_eq!(renewed_expiry(L, L, 0), L);
    }

    #[test]
    fn standings_and_keeps_follow_the_table() {
        assert_eq!(
            Standing::of(&state(false, false, "WRITE")),
            Standing::Present
        );
        assert_eq!(
            Standing::of(&state(false, true, "WRITE")),
            Standing::Withdrawn
        );
        assert_eq!(
            Standing::of(&state(true, false, "WRITE")),
            Standing::Completed
        );
        assert_eq!(
            Standing::of(&state(true, true, "WRITE")),
            Standing::WithdrawnCompleted
        );
        for standing in [
            Standing::Present,
            Standing::Withdrawn,
            Standing::Completed,
            Standing::WithdrawnCompleted,
        ] {
            assert_eq!(Standing::parse(standing.as_str()), Some(standing));
        }
        // The drift floor under a short lease, both rules.
        assert_eq!(
            keep_millis(Standing::Withdrawn, MIN, Rule::Legacy),
            10 * MIN
        );
        assert_eq!(
            keep_millis(Standing::Withdrawn, MIN, Rule::PerEntry),
            10 * MIN
        );
        assert_eq!(
            keep_millis(Standing::Withdrawn, 60 * MIN, Rule::PerEntry),
            10 * MIN
        );
        assert_eq!(
            keep_millis(Standing::Withdrawn, 60 * MIN, Rule::Legacy),
            120 * MIN
        );
        assert_eq!(
            keep_millis(Standing::WithdrawnCompleted, MIN, Rule::PerEntry),
            10 * MIN
        );
        assert_eq!(
            keep_millis(Standing::Completed, MIN, Rule::PerEntry),
            2 * MIN
        );
        assert_eq!(
            keep_millis(Standing::Present, 60 * MIN, Rule::Legacy),
            5 * MIN
        );
        assert_eq!(keep_millis(Standing::Present, -5, Rule::Legacy), 0);
    }

    #[test]
    fn a_present_entry_under_a_take_lease_is_never_collected() {
        assert_eq!(
            state_horizon(&state(false, false, "TAKE"), MIN, Rule::Legacy),
            None
        );
        assert!(!collectable(
            &state(false, false, "TAKE"),
            i64::MAX,
            MIN,
            Rule::Legacy
        ));
        assert!(collectable(
            &state(false, false, "WRITE"),
            L + 2 * MIN,
            MIN,
            Rule::Legacy
        ));
        assert!(!collectable(
            &state(false, false, "WRITE"),
            L + 2 * MIN - 1,
            MIN,
            Rule::Legacy
        ));
    }

    #[test]
    fn an_unvouched_withdrawal_keeps_the_later_horizon() {
        let withdrawn = state(false, true, "WRITE");
        let long = 60 * MIN;
        assert_eq!(
            horizon_here(&withdrawn, long, Rule::PerEntry, true),
            Some(L + 10 * MIN)
        );
        assert_eq!(
            horizon_here(&withdrawn, long, Rule::PerEntry, false),
            Some(L + 120 * MIN)
        );
        // Completed states keep their horizon whatever the writer.
        let completed = state(true, false, "WRITE");
        assert_eq!(
            horizon_here(&completed, long, Rule::PerEntry, false),
            Some(L + 120 * MIN)
        );
    }

    #[test]
    fn writers_are_vouched_for_after_one_lease_and_the_grace() {
        let withdrawn = state(false, true, "WRITE");
        let since = |at: i64| move |_: &str| Writer::InViewSince(at);
        let settle = settle_millis(MIN);
        assert_eq!(settle, 6 * MIN);
        assert!(writers_vouched(&withdrawn, L, MIN, |_| Writer::This));
        assert!(writers_vouched(&withdrawn, L, MIN, since(L - settle)));
        assert!(!writers_vouched(&withdrawn, L, MIN, since(L - settle + 1)));
        assert!(!writers_vouched(&withdrawn, L, MIN, |_| Writer::Absent));
        let no_dots = map_of(cbor_map! { "adds" => Value::Array(vec![]), "completed" => false });
        assert!(!writers_vouched(&no_dots, L, MIN, |_| Writer::This));
    }

    #[test]
    fn the_gate_engages_after_three_rounds_and_disengages_at_once() {
        let mut gate = HorizonGate::new();
        let round = 1_000;
        let mut now = L;
        assert_eq!(gate.judge(now, true, round, MIN, 3), Rule::Legacy);
        assert_eq!(gate.mode(), Mode::Waiting);
        for _ in 0..2 {
            now += round;
            gate.judge(now, true, round, MIN, 3);
            assert_eq!(gate.mode(), Mode::Waiting);
        }
        // Judgements inside a round count nothing.
        gate.judge(now + round - 1, true, round, MIN, 3);
        assert_eq!(gate.mode(), Mode::Waiting);
        now += round;
        gate.judge(now, true, round, MIN, 3);
        assert_eq!(gate.mode(), Mode::Settling);
        assert_eq!(gate.engagements(), 1);
        assert_eq!(
            gate.judge(now + settle_millis(MIN) - 1, true, round, MIN, 3),
            Rule::Legacy
        );
        assert_eq!(
            gate.judge(now + settle_millis(MIN), true, round, MIN, 3),
            Rule::PerEntry
        );
        assert_eq!(gate.settlements(), 1);
        // One unhinted judgement: back to legacy, the count reset.
        assert_eq!(
            gate.judge(now + settle_millis(MIN), false, round, MIN, 3),
            Rule::Legacy
        );
        assert_eq!(gate.mode(), Mode::Legacy);
        assert_eq!(gate.disengagements(), 1);
        let again = now + settle_millis(MIN) + 1;
        gate.judge(again, true, round, MIN, 3);
        assert_eq!(gate.mode(), Mode::Waiting);
        // Waiting disengages without counting a disengagement.
        gate.judge(again, false, round, MIN, 3);
        assert_eq!(gate.disengagements(), 1);
    }

    #[test]
    fn engage_rounds_are_clamped() {
        let mut gate = HorizonGate::new();
        gate.judge(L, true, 1_000, MIN, 0);
        gate.judge(L + 1_000, true, 1_000, MIN, 0);
        assert_eq!(gate.mode(), Mode::Settling);
    }
}
