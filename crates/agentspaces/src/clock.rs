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
//! supplies the epoch milliseconds the protocol signs, so tests can pin it.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock milliseconds since the Unix epoch.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
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
