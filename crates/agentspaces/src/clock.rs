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

//! Wall-clock time for stamps and leases. Timers and timeouts use Tokio's clock; this trait
//! supplies the epoch milliseconds the protocol signs, so tests can pin it, and the local base
//! that the leases nobody else reads are judged on ([`Clock::local_ms`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock milliseconds since the Unix epoch.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;

    /// Milliseconds on this clock's local base: the time a period that only this process reads
    /// is judged on, such as a push subscription's lease (SPEC v0.1.36 §9.5: local periods on a
    /// monotonic clock, so a wall step or a laptop sleep neither cuts them short nor stretches
    /// them). Only differences between two readings mean anything. The default is
    /// [`Clock::now_ms`], so a clock a test moves by hand keeps those periods on that clock;
    /// [`SystemClock`] reads the monotonic clock (Tokio's, so paused-time tests drive it).
    fn local_ms(&self) -> i64 {
        self.now_ms()
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn local_ms(&self) -> i64 {
        monotonic_ms()
    }
}

/// Milliseconds on Tokio's monotonic clock from a base fixed at the first reading, offset so a
/// paused runtime's clock (which may start before that base) still reads positive.
fn monotonic_ms() -> i64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    const OFFSET: i64 = 1 << 40;
    let base = *BASE.get_or_init(std::time::Instant::now);
    let now = tokio::time::Instant::now().into_std();
    let millis = |span: std::time::Duration| i64::try_from(span.as_millis()).unwrap_or(i64::MAX);
    match now.checked_duration_since(base) {
        Some(ahead) => OFFSET.saturating_add(millis(ahead)),
        None => OFFSET.saturating_sub(millis(base.saturating_duration_since(now))),
    }
}

/// A clock the caller sets and advances; for tests and simulations.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// A clock reading `now_ms`.
    pub fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    /// Sets the reading.
    pub fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }

    /// Advances the reading by `millis`.
    pub fn advance(&self, millis: i64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The shared handle type the peer holds.
pub type SharedClock = Arc<dyn Clock>;
