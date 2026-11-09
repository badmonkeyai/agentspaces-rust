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

//! SIGINT, SIGTERM, SIGHUP, and SIGQUIT as a stop request: `watch` ends, `work` stops taking
//! (and a second signal ends what still runs).
//!
//! SIGHUP is what a closing terminal or ssh session sends, and SIGQUIT what a terminal's quit key
//! does: left at their default action they would end the process at once, and `work`'s programs,
//! which run in process groups of their own that the terminal's signals never reach, would be
//! orphaned, still working on tasks whose holds lapse and that another worker then runs again.
//! A SIGKILL of the process still leaves them running: nothing can catch it.
//!
//! The hangup is heard even when the process was started with SIGHUP ignored (`nohup`): a worker
//! that must outlive its terminal is started detached from it (`setsid`) or by a supervisor
//! (systemd, launchd), and then never receives one.

use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::exit::Failure;

/// The process's SIGINT, SIGTERM, SIGHUP, and SIGQUIT, from the moment it is made.
pub struct Stop {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
    quit: Signal,
}

impl Stop {
    /// Listens for SIGINT, SIGTERM, SIGHUP, and SIGQUIT (their default action, ending the
    /// process, is off from now on).
    pub fn new() -> Result<Self, Failure> {
        let listen = |kind: SignalKind, name: &str| {
            signal(kind)
                .map_err(|error| Failure::error(format!("cannot listen for {name}: {error}")))
        };
        Ok(Stop {
            interrupt: listen(SignalKind::interrupt(), "SIGINT")?,
            terminate: listen(SignalKind::terminate(), "SIGTERM")?,
            hangup: listen(SignalKind::hangup(), "SIGHUP")?,
            quit: listen(SignalKind::quit(), "SIGQUIT")?,
        })
    }

    /// Resolves at the next SIGINT, SIGTERM, SIGHUP, or SIGQUIT.
    pub async fn requested(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
            _ = self.quit.recv() => {}
        }
    }
}
