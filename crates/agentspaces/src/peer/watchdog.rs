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

//! The loop's liveness check (SPEC v0.1.36 §9.5; the reference implementation's watchdog): one
//! thread per process, outside every peer's loop, that reads each loop's heartbeat
//! every [`PERIOD`] and judges it.
//!
//! Each peer runs one task whose loop selects over its job and frame channels and its per-concern
//! deadlines. The loop publishes a heartbeat ([`LoopBeat`]): the turns it finished, when the turn
//! in hand started, and the deadline it armed. The watchdog reads only those atomics (it does no
//! protocol work and takes no lock the loop can hold) and finds:
//!
//! - a **slow turn** (over [`SLOW_TURN`]): counted once per turn;
//! - a **wedged turn** (over [`WEDGED_TURN`]): counted once per turn and logged; the loop reads
//!   [`LoopStatus::Degraded`] while it lasts;
//! - a **missed fire**: the loop is idle, its armed deadline passed more than [`GRACE`] ago, and
//!   no turn ran since the last check: counted, logged, and the loop is nudged, which wakes its
//!   select so every overdue deadline fires on the next turn (the reference implementation
//!   re-initialises such a loop; this loop's deadlines are recomputed on every turn, so waking it
//!   is the whole repair);
//! - a **dead loop**: the loop ended by a panic while handles remain: [`LoopStatus::Down`];
//! - a **wall step**: (wall − monotonic) moved by more than [`WALL_STEP`] since the last check,
//!   an NTP step or a laptop sleep: every loop is nudged, so each reads the step on its next turn
//!   (its resume, its wall-anchored deadlines) within one check of the wake, rather than at
//!   whatever deadline it slept to (up to its re-lease, 30 s). The reference implementation's
//!   timer raises the same signal on its next wake;
//! - a **late tick**: the watchdog's own tick came back more than [`LATE_TICK`] (30 s) past its
//!   period, with the process frozen meanwhile (SIGSTOP, a long collection or VM pause): every
//!   loop is told and nudged, and takes it as a late wake (owner decision 3 of 2026-11-23), and
//!   that check judges no loop, since none could turn during the freeze.
//!
//! A panic inside one turn (a job, a frame, a deadline) is contained by the loop itself, which
//! counts it and goes on with its next turn; three within [`PANIC_WINDOW`] turn it
//! [`LoopStatus::Down`], one within it [`LoopStatus::Degraded`] (the reference implementation's
//! repeated-throw and escalation rules).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// How often the watchdog checks every loop (the reference implementation's default tick).
pub const PERIOD: Duration = Duration::from_secs(2);
/// A turn longer than this is slow.
pub const SLOW_TURN: Duration = Duration::from_millis(100);
/// A turn longer than this is wedged.
pub const WEDGED_TURN: Duration = Duration::from_secs(5);
/// How late past its armed deadline an idle loop may be before it counts as a missed fire.
pub const GRACE: Duration = Duration::from_millis(250);
/// The window over which contained panics count towards [`LoopStatus::Down`].
pub const PANIC_WINDOW: Duration = Duration::from_secs(600);
/// Contained panics within [`PANIC_WINDOW`] that turn the loop [`LoopStatus::Down`].
pub const PANICS_DOWN: usize = 3;
/// A move of (wall − monotonic) larger than this between two checks is a wall step (the
/// reference implementation's `WALL_STEP_THRESHOLD`).
pub const WALL_STEP: Duration = Duration::from_secs(1);
/// A watchdog tick this far past its period is a late wake: a frozen process (the peer loop's
/// `LATE_WAKE`, 30 s, as every implementation).
pub const LATE_TICK: Duration = Duration::from_secs(30);

/// Milliseconds on this process's monotonic clock (never 0, so 0 can mean "none").
fn mono_ms(at: Instant) -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = *BASE.get_or_init(|| Instant::now() - Duration::from_millis(1));
    u64::try_from(at.saturating_duration_since(base).as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// How a peer's loop is doing ([`LoopHealth::status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopStatus {
    /// Turning, and nothing wrong lately.
    Up,
    /// Turning, but a turn is wedged now, a turn panicked within [`PANIC_WINDOW`], or the last
    /// check found a missed fire.
    Degraded,
    /// The loop ended by a panic, or [`PANICS_DOWN`] turns panicked within [`PANIC_WINDOW`].
    Down,
}

/// A snapshot of a peer loop's heartbeat and the watchdog's findings
/// ([`crate::peer::Peer::loop_health`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoopHealth {
    /// The judgement.
    pub status: LoopStatus,
    /// Turns finished.
    pub turns: u64,
    /// Turns over [`SLOW_TURN`] the watchdog saw.
    pub slow_turns: u64,
    /// Turns over [`WEDGED_TURN`] the watchdog saw.
    pub wedged_turns: u64,
    /// Idle loops past their armed deadline the watchdog found, and nudged.
    pub missed_fires: u64,
    /// Turns that panicked and were contained.
    pub panics: u64,
    /// Whether the loop is running a turn now.
    pub in_turn: bool,
}

/// One loop's heartbeat: atomics the loop writes and the watchdog reads.
#[derive(Debug, Default)]
pub struct LoopBeat {
    name: String,
    turns: AtomicU64,
    /// When the turn in hand started (monotonic ms), 0 when idle.
    turn_started: AtomicU64,
    /// The deadline the loop armed (monotonic ms), 0 for none.
    armed: AtomicU64,
    slow_turns: AtomicU64,
    wedged_turns: AtomicU64,
    missed_fires: AtomicU64,
    panics: AtomicU64,
    /// The last turn counted slow, and wedged (each counts once per turn).
    slow_counted: AtomicU64,
    wedge_counted: AtomicU64,
    /// The turns the last check saw, and whether it found a missed fire.
    seen_turns: AtomicU64,
    missed_last: AtomicBool,
    /// Whether the loop ended, and whether by a panic.
    ended: AtomicBool,
    died: AtomicBool,
    /// When the contained panics happened (monotonic ms), the last [`PANICS_DOWN`] kept.
    panic_times: Mutex<Vec<u64>>,
    /// Wakes the loop's select (a missed fire's repair).
    nudge: tokio::sync::Notify,
    /// How late the watchdog's own tick came back (milliseconds past its period), when it was
    /// more than [`LATE_TICK`]: a frozen process. The loop takes it as a late wake
    /// ([`LoopBeat::take_late_wake`]); 0 for none.
    late_wake_ms: AtomicU64,
}

impl LoopBeat {
    /// A heartbeat for the loop named `name`, registered with the process's watchdog.
    pub(super) fn register(name: String) -> Arc<Self> {
        let beat = Arc::new(Self {
            name,
            // No check has seen the loop yet: a missed fire needs a whole period without a turn.
            seen_turns: AtomicU64::new(u64::MAX),
            ..Self::default()
        });
        watch(&beat);
        beat
    }

    /// The loop starts a turn.
    pub(super) fn start_turn(&self) {
        self.turn_started
            .store(mono_ms(Instant::now()), Ordering::SeqCst);
    }

    /// The loop finished a turn.
    pub(super) fn end_turn(&self) {
        self.turns.fetch_add(1, Ordering::SeqCst);
        self.turn_started.store(0, Ordering::SeqCst);
    }

    /// The loop armed `deadline` (in `remaining` from now), or none.
    pub(super) fn arm(&self, remaining: Option<Duration>) {
        let at = remaining
            .and_then(|remaining| Instant::now().checked_add(remaining))
            .map_or(0, mono_ms);
        self.armed.store(at, Ordering::SeqCst);
    }

    /// A turn panicked and was contained; answers whether the loop is now down.
    pub(super) fn note_panic(&self) -> bool {
        self.panics.fetch_add(1, Ordering::SeqCst);
        let now = mono_ms(Instant::now());
        let mut times = self
            .panic_times
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        times.push(now);
        let window = u64::try_from(PANIC_WINDOW.as_millis()).unwrap_or(u64::MAX);
        times.retain(|at| now.saturating_sub(*at) <= window);
        if times.len() > PANICS_DOWN {
            times.remove(0);
        }
        times.len() >= PANICS_DOWN
    }

    /// The loop ended; `panicking` when a panic ended it.
    pub(super) fn end(&self, panicking: bool) {
        self.ended.store(true, Ordering::SeqCst);
        if panicking {
            self.died.store(true, Ordering::SeqCst);
        }
    }

    /// Notes that the watchdog's tick came back `late` past its period (a frozen process) and
    /// nudges the loop, which takes it as a late wake on its next turn.
    fn note_late_tick(&self, late: Duration) {
        let late = u64::try_from(late.as_millis()).unwrap_or(u64::MAX);
        self.late_wake_ms.fetch_max(late, Ordering::SeqCst);
        // No check has seen the loop since the freeze: a missed fire needs a whole period
        // without a turn after it.
        self.seen_turns.store(u64::MAX, Ordering::SeqCst);
        self.nudge.notify_one();
    }

    /// How late the watchdog's last late tick was, once (zero when there was none since the last
    /// call): the loop's other signal of a freeze, for deadlines far off when it froze.
    pub(super) fn take_late_wake(&self) -> Duration {
        Duration::from_millis(self.late_wake_ms.swap(0, Ordering::SeqCst))
    }

    /// Resolves when the watchdog nudges the loop.
    pub(super) async fn nudged(&self) {
        self.nudge.notified().await;
    }

    /// The loop's health now.
    pub fn health(&self) -> LoopHealth {
        self.health_at(Instant::now())
    }

    fn health_at(&self, at: Instant) -> LoopHealth {
        let now = mono_ms(at);
        let started = self.turn_started.load(Ordering::SeqCst);
        let wedged =
            started != 0 && Duration::from_millis(now.saturating_sub(started)) > WEDGED_TURN;
        let window = u64::try_from(PANIC_WINDOW.as_millis()).unwrap_or(u64::MAX);
        let recent_panics = self
            .panic_times
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|t| now.saturating_sub(**t) <= window)
            .count();
        let status = if self.died.load(Ordering::SeqCst) || recent_panics >= PANICS_DOWN {
            LoopStatus::Down
        } else if wedged || recent_panics > 0 || self.missed_last.load(Ordering::SeqCst) {
            LoopStatus::Degraded
        } else {
            LoopStatus::Up
        };
        LoopHealth {
            status,
            turns: self.turns.load(Ordering::SeqCst),
            slow_turns: self.slow_turns.load(Ordering::SeqCst),
            wedged_turns: self.wedged_turns.load(Ordering::SeqCst),
            missed_fires: self.missed_fires.load(Ordering::SeqCst),
            panics: self.panics.load(Ordering::SeqCst),
            in_turn: started != 0,
        }
    }

    /// One check of this loop at `at` (the watchdog's, or a test's).
    fn check(&self, at: Instant) {
        let now = mono_ms(at);
        let turns = self.turns.load(Ordering::SeqCst);
        let started = self.turn_started.load(Ordering::SeqCst);
        if started != 0 {
            // The turn in hand is the next one: numbered from 1, so 0 means none counted.
            let turn = turns.wrapping_add(1);
            let running = Duration::from_millis(now.saturating_sub(started));
            if running > SLOW_TURN && self.slow_counted.swap(turn, Ordering::SeqCst) != turn {
                self.slow_turns.fetch_add(1, Ordering::SeqCst);
            }
            if running > WEDGED_TURN && self.wedge_counted.swap(turn, Ordering::SeqCst) != turn {
                self.wedged_turns.fetch_add(1, Ordering::SeqCst);
                tracing::warn!(
                    peer = %self.name,
                    running_ms = running.as_millis(),
                    "agentspaces: the peer's loop is wedged in one turn"
                );
            }
            self.missed_last.store(false, Ordering::SeqCst);
        } else {
            let armed = self.armed.load(Ordering::SeqCst);
            let grace = u64::try_from(GRACE.as_millis()).unwrap_or(u64::MAX);
            let idle_since_check = self.seen_turns.load(Ordering::SeqCst) == turns;
            let missed = !self.ended.load(Ordering::SeqCst)
                && armed != 0
                && now > armed.saturating_add(grace)
                && idle_since_check;
            self.missed_last.store(missed, Ordering::SeqCst);
            if missed {
                self.missed_fires.fetch_add(1, Ordering::SeqCst);
                tracing::warn!(
                    peer = %self.name,
                    late_ms = now.saturating_sub(armed),
                    "agentspaces: the peer's loop missed its deadline; nudged"
                );
                self.nudge.notify_one();
            }
        }
        self.seen_turns.store(turns, Ordering::SeqCst);
        if self.died.load(Ordering::SeqCst) {
            tracing::error!(peer = %self.name, "agentspaces: the peer's loop ended by a panic");
        }
    }
}

/// The process's watched loops.
struct Registry {
    beats: Vec<Weak<LoopBeat>>,
    running: bool,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            beats: Vec::new(),
            running: false,
        })
    })
}

/// Registers `beat`, starting the watchdog thread if none runs.
fn watch(beat: &Arc<LoopBeat>) {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.beats.push(Arc::downgrade(beat));
    if registry.running {
        return;
    }
    registry.running = std::thread::Builder::new()
        .name("agentspaces-watchdog".to_owned())
        .spawn(run)
        .is_ok();
}

/// The watchdog thread: checks every live loop each [`PERIOD`] (re-armed from the end of each
/// check, never at a fixed rate), and nudges them all on a wall step; stops when no loop is
/// left, to start again with the next.
fn run() {
    let last_offset = AtomicI64::new(i64::MIN);
    let mut last_tick = Instant::now();
    loop {
        std::thread::sleep(PERIOD);
        let now = Instant::now();
        let late = now
            .saturating_duration_since(last_tick)
            .saturating_sub(PERIOD);
        last_tick = now;
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            });
        let offset = wall.saturating_sub(i64::try_from(mono_ms(now)).unwrap_or(i64::MAX));
        nudge_on_wall_step(&last_offset, offset, &live_beats());
        if on_late_tick(late, &live_beats()) {
            // A frozen process: no loop could turn during the freeze, so this check judges
            // nobody (a turn in hand, or a deadline that passed, is the freeze's, not a fault).
            continue;
        }
        if check_all(now) == 0 {
            let mut registry = registry()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.beats.retain(|beat| beat.strong_count() > 0);
            if registry.beats.is_empty() {
                registry.running = false;
                return;
            }
        }
    }
}

/// The loops registered and still alive.
fn live_beats() -> Vec<Arc<LoopBeat>> {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.beats.retain(|beat| beat.strong_count() > 0);
    registry.beats.iter().filter_map(Weak::upgrade).collect()
}

/// Notes (wall − monotonic) `offset` (milliseconds) against `last`, the reading of the previous
/// check, and nudges every loop of `beats` when it moved by more than [`WALL_STEP`]. Answers
/// whether it did.
fn nudge_on_wall_step(last: &AtomicI64, offset: i64, beats: &[Arc<LoopBeat>]) -> bool {
    let previous = last.swap(offset, Ordering::SeqCst);
    let step = offset.saturating_sub(previous);
    let threshold = u64::try_from(WALL_STEP.as_millis()).unwrap_or(u64::MAX);
    if previous == i64::MIN || step.unsigned_abs() <= threshold {
        return false;
    }
    tracing::info!(
        step_ms = step,
        loops = beats.len(),
        "agentspaces: the wall clock stepped (an NTP step or a suspend); nudging every peer loop"
    );
    for beat in beats {
        beat.nudge.notify_one();
    }
    true
}

/// Checks every live loop at `at`; answers how many were checked.
/// The watchdog's tick came back `late` past its period. More than [`LATE_TICK`] is a frozen
/// process (SIGSTOP, a long collection or VM pause; owner decision 3 of 2026-11-23): every loop
/// is told, as a late wake, and nudged. Answers whether it was one.
fn on_late_tick(late: Duration, beats: &[Arc<LoopBeat>]) -> bool {
    if late <= LATE_TICK {
        return false;
    }
    tracing::info!(
        late_ms = u64::try_from(late.as_millis()).unwrap_or(u64::MAX),
        loops = beats.len(),
        "agentspaces: the watchdog woke late (a frozen process?); every peer loop takes it as a wake"
    );
    for beat in beats {
        beat.note_late_tick(late);
    }
    true
}

fn check_all(at: Instant) -> usize {
    let beats = live_beats();
    for beat in &beats {
        beat.check(at);
    }
    beats.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beat() -> LoopBeat {
        LoopBeat {
            name: "test".to_owned(),
            seen_turns: AtomicU64::new(u64::MAX),
            ..LoopBeat::default()
        }
    }

    /// A wall step (a suspend, an NTP step) nudges every loop at once, so each reads the step on
    /// its next turn; a slew under the threshold, and the first reading, nudge nobody.
    #[tokio::test]
    async fn a_wall_step_nudges_every_loop() {
        let beats = [Arc::new(beat()), Arc::new(beat())];
        let last = AtomicI64::new(i64::MIN);
        let nudged = |beat: &Arc<LoopBeat>| {
            let beat = Arc::clone(beat);
            async move {
                tokio::time::timeout(Duration::from_millis(20), beat.nudged())
                    .await
                    .is_ok()
            }
        };
        assert!(
            !nudge_on_wall_step(&last, 5_000, &beats),
            "the first reading"
        );
        assert!(!nudge_on_wall_step(&last, 5_900, &beats), "a slew");
        assert!(!nudged(&beats[0]).await);
        assert!(
            nudge_on_wall_step(&last, 605_900, &beats),
            "a ten-minute suspend"
        );
        assert!(
            nudged(&beats[0]).await && nudged(&beats[1]).await,
            "every loop"
        );
        assert!(nudge_on_wall_step(&last, 595_900, &beats), "a step back");
        assert!(nudged(&beats[1]).await);
    }

    /// Owner decision 3 of 2026-11-23: the watchdog's own tick back more than 30 s past its
    /// period is a frozen process. Every loop is told (once, as a late wake its loop takes) and
    /// nudged, and the first check after it finds no missed fire in a deadline that passed
    /// during the freeze; a tick merely slow is no late wake.
    #[tokio::test]
    async fn a_late_tick_is_a_late_wake_for_every_loop_and_no_missed_fire() {
        let beats = [Arc::new(beat()), Arc::new(beat())];
        assert!(
            !on_late_tick(Duration::from_secs(29), &beats),
            "slow, not frozen"
        );
        assert!(
            !on_late_tick(LATE_TICK, &beats),
            "30 s is not more than 30 s"
        );
        assert_eq!(beats[0].take_late_wake(), Duration::ZERO);
        let start = Instant::now();
        beats[0].arm(Some(Duration::from_millis(100)));
        beats[0].check(start);
        assert!(on_late_tick(Duration::from_secs(58), &beats), "frozen");
        for beat in &beats {
            tokio::time::timeout(Duration::from_millis(20), beat.nudged())
                .await
                .expect("nudged");
            assert_eq!(beat.take_late_wake(), Duration::from_secs(58));
            assert_eq!(beat.take_late_wake(), Duration::ZERO, "taken once");
        }
        // The deadline passed during the freeze, with no turn since: not a missed fire.
        beats[0].check(start + Duration::from_secs(60));
        assert_eq!(beats[0].health_at(start).missed_fires, 0);
        assert_eq!(beats[0].health_at(start).status, LoopStatus::Up);
    }

    #[test]
    fn a_slow_and_a_wedged_turn_count_once_per_turn() {
        let beat = beat();
        let start = Instant::now();
        beat.start_turn();
        beat.check(start + Duration::from_millis(50));
        assert_eq!(beat.health_at(start).slow_turns, 0);
        beat.check(start + Duration::from_millis(150));
        beat.check(start + Duration::from_millis(300));
        let health = beat.health_at(start + Duration::from_millis(300));
        assert_eq!((health.slow_turns, health.wedged_turns), (1, 0));
        assert_eq!(health.status, LoopStatus::Up);
        beat.check(start + Duration::from_secs(6));
        beat.check(start + Duration::from_secs(8));
        let health = beat.health_at(start + Duration::from_secs(8));
        assert_eq!(health.wedged_turns, 1, "once per turn");
        assert_eq!(health.status, LoopStatus::Degraded, "wedged now");
        beat.end_turn();
        let health = beat.health_at(start + Duration::from_secs(8));
        assert_eq!(
            (health.status, health.turns, health.in_turn),
            (LoopStatus::Up, 1, false)
        );
    }

    #[tokio::test]
    async fn an_idle_loop_past_its_deadline_is_a_missed_fire_and_is_nudged() {
        let beat = beat();
        let start = Instant::now();
        beat.arm(Some(Duration::from_millis(100)));
        beat.check(start);
        beat.check(start + Duration::from_millis(300));
        assert_eq!(beat.health_at(start).missed_fires, 0, "within the grace");
        beat.check(start + Duration::from_millis(400));
        assert_eq!(beat.health_at(start).missed_fires, 1);
        assert_eq!(beat.health_at(start).status, LoopStatus::Degraded);
        // The nudge is waiting for the loop's select.
        tokio::time::timeout(Duration::from_secs(1), beat.nudged())
            .await
            .expect("nudged");
        // A loop that turned since the last check missed nothing.
        beat.start_turn();
        beat.end_turn();
        beat.check(start + Duration::from_millis(500));
        assert_eq!(beat.health_at(start).missed_fires, 1);
        assert_eq!(beat.health_at(start).status, LoopStatus::Up);
        // No deadline armed: nothing to miss.
        beat.arm(None);
        beat.check(start + Duration::from_secs(10));
        beat.check(start + Duration::from_secs(12));
        assert_eq!(beat.health_at(start).missed_fires, 1);
    }

    #[test]
    fn three_contained_panics_within_ten_minutes_turn_the_loop_down() {
        let beat = beat();
        assert!(!beat.note_panic());
        assert_eq!(beat.health().status, LoopStatus::Degraded);
        assert!(!beat.note_panic());
        assert!(beat.note_panic());
        assert_eq!(beat.health().status, LoopStatus::Down);
        let died = self::beat();
        died.end(true);
        assert_eq!(died.health().status, LoopStatus::Down);
    }
}
