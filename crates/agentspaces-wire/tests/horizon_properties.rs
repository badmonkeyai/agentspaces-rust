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

//! Seeded property tests of the renewal rule (SPEC §7.2) and the collection horizons (SPEC
//! §7.3), with the invariants of the reference implementation's proof of the per-entry horizon
//! (its `docs/proofs/per-entry-horizon.md`) checked after every step of a randomized run:
//!
//! - *Renewal monotonicity*: `renewed_expiry` never shortens, reaches `now + extension`, and is
//!   idempotent; every horizon is at or after its lease's expiry.
//! - *LeaseBound*: once the issuer withdrew an entry with lease expiry `L`, no copy anywhere (held
//!   or in flight) carries an expiry past `L`.
//! - *NoResurrection*: a replica that held the entry withdrawn never again holds it present and
//!   unexpired by its own clock.
//! - *RefusedAtEveryDoor*: after a replica collected the entry, every copy the collected state
//!   covers is refused at its door.
//! - *NoLateLive* (the drift floor): once any replica collected the withdrawal, no replica, with
//!   its clock within the drift ceiling of every other, holds the entry present and unexpired.
//!
//! Three replicas with clocks skewed within plus or minus five minutes (so any two within
//! `MAX_DRIFT`) pass copies by pulls delayed up to 20 minutes (one in eight up to an hour) and
//! lost one in seven; the issuer writes, renews by the rule, and cancels; each replica's door and
//! sweep judge by this crate's functions on real state maps. The runs are checked not to be
//! vacuous (collections happen while a present copy is still about, and doors refuse such copies),
//! and the two breaks the proof names are shown to be caught: a writer that renews shorter (A2),
//! and a horizon without the drift floor under a skewed clock.

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::horizon::{
    self, Rule, Standing, collectable_here, keep_millis, renewed_expiry,
};
use agentspaces_wire::limits::MAX_DRIFT_MILLIS;

const MIN: i64 = 60_000;
const STEP: i64 = 30_000;
const REPLICAS: usize = 3;
const STEPS: usize = 400;

/// xorshift64*, seeded per run so a failure names its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

#[test]
fn renewal_never_shortens_reaches_the_extension_and_is_idempotent() {
    let mut rng = Rng::new(7);
    for _ in 0..100_000 {
        let current = (rng.next() >> 2) as i64 - (1 << 61);
        let now = (rng.next() >> 2) as i64 - (1 << 61);
        let extension = match rng.below(4) {
            0 => 0,
            1 => i64::MAX,
            _ => (rng.next() >> 20) as i64,
        };
        let expiry = renewed_expiry(current, now, extension);
        assert!(
            expiry >= current,
            "never shorter: {current} {now} {extension}"
        );
        assert!(
            expiry >= now.saturating_add(extension),
            "at least the extension: {current} {now} {extension}"
        );
        assert!(expiry == current || expiry == now.saturating_add(extension));
        assert_eq!(renewed_expiry(expiry, now, extension), expiry, "idempotent");
        // A chain of renewals is monotone, whatever order the extensions come in.
        let later = renewed_expiry(expiry, now.saturating_add(STEP), extension / 2);
        assert!(later >= expiry);
    }
}

#[test]
fn every_horizon_is_at_or_after_its_expiry_and_the_floors_hold() {
    let mut rng = Rng::new(11);
    for _ in 0..50_000 {
        let max_lease = rng.below(48 * 60) as i64 * MIN / 2;
        for standing in [
            Standing::Present,
            Standing::Withdrawn,
            Standing::Completed,
            Standing::WithdrawnCompleted,
        ] {
            for rule in [Rule::Legacy, Rule::PerEntry] {
                let keep = keep_millis(standing, max_lease, rule);
                assert!(keep >= 0);
                match standing {
                    Standing::Present => assert!(keep <= horizon::LAPSED_GRACE_MILLIS),
                    Standing::Withdrawn | Standing::WithdrawnCompleted => {
                        assert!(keep >= MAX_DRIFT_MILLIS, "the drift floor")
                    }
                    Standing::Completed => assert_eq!(keep, 2 * max_lease),
                }
                // A6: a withdrawn horizon is never shorter than the lapse horizon.
                assert!(
                    keep_millis(Standing::Withdrawn, max_lease, rule)
                        >= keep_millis(Standing::Present, max_lease, rule)
                );
            }
            // The per-entry rule never keeps longer than the legacy one, and changes only a
            // withdrawal.
            let legacy = keep_millis(standing, max_lease, Rule::Legacy);
            let per_entry = keep_millis(standing, max_lease, Rule::PerEntry);
            assert!(per_entry <= legacy);
            if standing != Standing::Withdrawn {
                assert_eq!(per_entry, legacy);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The model

/// One copy of the entry: the lease register (its stamp and expiry) and whether it is withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Copy {
    stamp: u64,
    expiry: i64,
    withdrawn: bool,
}

impl Copy {
    /// The CRDT join: removals union, the lease register by its stamp.
    fn join(self, other: Copy) -> Copy {
        let lease = if other.stamp > self.stamp {
            other
        } else {
            self
        };
        Copy {
            stamp: lease.stamp,
            expiry: lease.expiry,
            withdrawn: self.withdrawn || other.withdrawn,
        }
    }

    fn live(self, clock: i64) -> bool {
        !self.withdrawn && self.expiry > clock
    }

    fn state(self) -> Map {
        let dot = cbor_map! { "replica" => "z6MkIssuer", "counter" => 1 };
        let value = cbor_map! {
            "adds" => Value::Array(vec![dot.clone()]),
            "removes" => Value::Array(if self.withdrawn { vec![dot] } else { Vec::new() }),
            "leaseValue" => cbor_map! {
                "holder" => "z6MkIssuer/rust",
                "expiresAtMillis" => self.expiry,
                "kind" => "WRITE",
            },
            "completed" => false,
        };
        match value {
            Value::Map(map) => map,
            _ => unreachable!("a map"),
        }
    }
}

/// How a run's replicas judge horizons and renew.
#[derive(Debug, Clone, Copy)]
struct Config {
    rule: Rule,
    /// The issuer renews as `now + extension`, which can shorten (a release before v0.1.35).
    shortening: bool,
    /// The withdrawn horizon without the drift floor: `L + 5 min` under the per-entry rule.
    no_floor: bool,
    /// The largest clock offset either way, milliseconds.
    skew: i64,
}

struct Replica {
    offset: i64,
    held: Option<Copy>,
    collected: Option<Copy>,
    held_withdrawn: bool,
}

#[derive(Debug, Default)]
struct Tally {
    collected_withdrawals: u64,
    collected_with_present_about: u64,
    present_refused_after_collection: u64,
    violation: Option<String>,
}

fn collects(config: Config, copy: Copy, clock: i64, max_lease: i64) -> bool {
    if config.no_floor && copy.withdrawn && config.rule == Rule::PerEntry {
        return clock >= copy.expiry + horizon::LAPSED_GRACE_MILLIS;
    }
    collectable_here(&copy.state(), clock, max_lease, config.rule, true)
}

fn run(seed: u64, config: Config) -> Tally {
    let mut rng = Rng::new(seed);
    let mut tally = Tally::default();
    let max_lease = (1 + rng.below(20) as i64) * MIN;
    let mut replicas: Vec<Replica> = (0..REPLICAS)
        .map(|_| Replica {
            offset: rng.below(2 * config.skew as u64 + 1) as i64 - config.skew,
            held: None,
            collected: None,
            held_withdrawn: false,
        })
        .collect();
    let base: i64 = 1_800_000_000_000;
    let mut now = base;
    let mut stamp = 1u64;
    let first = Copy {
        stamp,
        expiry: now + replicas[0].offset + max_lease,
        withdrawn: false,
    };
    replicas[0].held = Some(first);
    let mut in_flight: Vec<(usize, Copy, i64)> = Vec::new();
    let mut withdrawn_at: Option<i64> = None;
    let mut any_collected = false;
    for step in 0..STEPS {
        now += STEP;
        let clock = |r: &Replica| now + r.offset;
        // The issuer renews (A1, A2) or cancels.
        let issuer_clock = clock(&replicas[0]);
        if let Some(held) = replicas[0].held
            && held.live(issuer_clock)
            && withdrawn_at.is_none()
        {
            if rng.one_in(4) {
                let extension = (1 + rng.below((max_lease / MIN) as u64)) as i64 * MIN;
                stamp += 1;
                let expiry = if config.shortening {
                    issuer_clock + extension
                } else {
                    renewed_expiry(held.expiry, issuer_clock, extension)
                };
                replicas[0].held = Some(Copy {
                    stamp,
                    expiry,
                    withdrawn: false,
                });
            } else if step > 10 && rng.one_in(12) {
                let withdrawn = Copy {
                    withdrawn: true,
                    ..held
                };
                replicas[0].held = Some(withdrawn);
                replicas[0].held_withdrawn = true;
                withdrawn_at = Some(withdrawn.expiry);
            }
        }
        // Pulls: a copy leaves for another replica, delayed, or is lost.
        for _ in 0..2 {
            let from = rng.below(REPLICAS as u64) as usize;
            let to = (from + 1 + rng.below(REPLICAS as u64 - 1) as usize) % REPLICAS;
            if let Some(copy) = replicas[from].held
                && !rng.one_in(7)
            {
                let delay = if rng.one_in(8) {
                    rng.below(120)
                } else {
                    rng.below(40)
                } as i64
                    * STEP;
                in_flight.push((to, copy, now + delay));
            }
        }
        // Deliveries meet the door, judged by the sweep's rule on the receiver's clock.
        let mut index = 0;
        while index < in_flight.len() {
            if in_flight[index].2 > now {
                index += 1;
                continue;
            }
            let (to, copy, _) = in_flight.swap_remove(index);
            let replica = &mut replicas[to];
            let at = now + replica.offset;
            let covered = replica
                .collected
                .is_some_and(|collected| collected.join(copy) == collected);
            if collects(config, copy, at, max_lease) {
                if replica.collected.is_some() && !copy.withdrawn {
                    tally.present_refused_after_collection += 1;
                }
                continue;
            }
            if covered && tally.violation.is_none() {
                tally.violation = Some(format!(
                    "RefusedAtEveryDoor: replica {to} took {copy:?} after collecting {:?}",
                    replica.collected
                ));
            }
            let joined = replica.held.map_or(copy, |held| held.join(copy));
            replica.held = Some(joined);
            replica.held_withdrawn |= joined.withdrawn;
        }
        // Sweeps.
        let present_about = replicas
            .iter()
            .any(|r| r.held.is_some_and(|c| !c.withdrawn))
            || in_flight.iter().any(|(_, c, _)| !c.withdrawn);
        for replica in &mut replicas {
            let at = now + replica.offset;
            if let Some(held) = replica.held
                && collects(config, held, at, max_lease)
            {
                replica.held = None;
                replica.collected = Some(held);
                if held.withdrawn {
                    any_collected = true;
                    tally.collected_withdrawals += 1;
                    if present_about {
                        tally.collected_with_present_about += 1;
                    }
                }
            }
        }
        // The invariants.
        if tally.violation.is_some() {
            break;
        }
        if let Some(limit) = withdrawn_at {
            let over = replicas
                .iter()
                .filter_map(|r| r.held)
                .chain(in_flight.iter().map(|(_, c, _)| *c))
                .find(|c| c.expiry > limit);
            if let Some(copy) = over {
                tally.violation = Some(format!("LeaseBound: {copy:?} past {limit}"));
                break;
            }
        }
        for (index, replica) in replicas.iter().enumerate() {
            let at = now + replica.offset;
            if let Some(held) = replica.held
                && held.live(at)
            {
                if replica.held_withdrawn {
                    tally.violation = Some(format!(
                        "NoResurrection: replica {index} holds {held:?} live at {at}"
                    ));
                }
                if any_collected {
                    tally.violation = Some(format!(
                        "NoLateLive: replica {index} holds {held:?} live at {at}"
                    ));
                }
            }
        }
        if tally.violation.is_some() {
            break;
        }
    }
    tally
}

fn sweep(config: Config, seeds: std::ops::Range<u64>) -> Tally {
    let mut total = Tally::default();
    for seed in seeds {
        let tally = run(seed, config);
        if let Some(violation) = tally.violation {
            total.violation = Some(format!("seed {seed}: {violation}"));
            return total;
        }
        total.collected_withdrawals += tally.collected_withdrawals;
        total.collected_with_present_about += tally.collected_with_present_about;
        total.present_refused_after_collection += tally.present_refused_after_collection;
    }
    total
}

const SKEW: i64 = MAX_DRIFT_MILLIS / 2;

#[test]
fn the_per_entry_horizon_keeps_every_invariant() {
    let config = Config {
        rule: Rule::PerEntry,
        shortening: false,
        no_floor: false,
        skew: SKEW,
    };
    let tally = sweep(config, 1..201);
    assert_eq!(tally.violation, None);
    assert!(tally.collected_withdrawals > 100, "{tally:?}");
    assert!(
        tally.collected_with_present_about > 10,
        "not vacuous: {tally:?}"
    );
    assert!(
        tally.present_refused_after_collection > 0,
        "not vacuous: {tally:?}"
    );
}

#[test]
fn the_legacy_horizon_keeps_every_invariant() {
    let config = Config {
        rule: Rule::Legacy,
        shortening: false,
        no_floor: false,
        skew: SKEW,
    };
    let tally = sweep(config, 1_001..1_201);
    assert_eq!(tally.violation, None);
    assert!(tally.collected_withdrawals > 100, "{tally:?}");
}

#[test]
fn a_writer_that_renews_shorter_breaks_the_per_entry_horizon() {
    let config = Config {
        rule: Rule::PerEntry,
        shortening: true,
        no_floor: false,
        skew: SKEW,
    };
    let tally = sweep(config, 1..2_001);
    let violation = tally
        .violation
        .expect("the model catches a shortening writer");
    assert!(
        [
            "LeaseBound",
            "NoResurrection",
            "NoLateLive",
            "RefusedAtEveryDoor"
        ]
        .iter()
        .any(|invariant| violation.contains(invariant)),
        "{violation}"
    );
}

#[test]
fn without_the_drift_floor_a_trailing_clock_shows_a_withdrawn_entry_live() {
    let config = Config {
        rule: Rule::PerEntry,
        shortening: false,
        no_floor: true,
        skew: SKEW,
    };
    let tally = sweep(config, 1..2_001);
    let violation = tally
        .violation
        .expect("the model catches the missing floor");
    assert!(violation.contains("NoLateLive"), "{violation}");
}
