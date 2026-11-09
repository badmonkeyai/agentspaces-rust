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

//! What a handler is given beside its entry: the take it runs under ([`TakeContext`], Java
//! `TakeContext`) or the event it reacts to ([`NotifyContext`]).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::space::{EntryId, EntryView, EventKind, Lease, Space, SpaceError, Taken};

/// The shortest pause between two renewals of a [`TakeContext::keepalive`].
const MIN_RENEWAL: Duration = Duration::from_millis(10);

/// The take a worker's handler runs under (Java `TakeContext`, `TakeContext.java`): the taken
/// entry, its claim, the binding's lease, and the space, so long work can keep the take alive
/// ([`TakeContext::keepalive`], [`TakeContext::renew`]), key state by the task's entry id, or
/// write more entries as the agent. Cheap to clone; every clone renews the same take.
#[derive(Debug, Clone)]
pub struct TakeContext {
    taken: Arc<Mutex<Taken>>,
    entry: EntryView,
    epoch: i64,
    holder: String,
    lease: Lease,
    space: Space,
    produces: Option<String>,
}

impl TakeContext {
    pub(crate) fn new(taken: Taken, lease: Lease, produces: Option<String>) -> TakeContext {
        TakeContext {
            entry: taken.entry().clone(),
            epoch: taken.epoch(),
            holder: taken.holder().to_owned(),
            space: taken.space().clone(),
            taken: Arc::new(Mutex::new(taken)),
            lease,
            produces,
        }
    }

    pub(crate) fn taken(&self) -> &Arc<Mutex<Taken>> {
        &self.taken
    }

    /// The taken entry's id: a stable key for the task across workers and restarts.
    pub fn entry_id(&self) -> &EntryId {
        self.entry.entry_id()
    }

    /// The taken entry: its schema, raw payload, tags, issuer, and attestation.
    pub fn entry(&self) -> &EntryView {
        &self.entry
    }

    /// The claim's epoch: 1 for the first take of the entry, one more for each take after a
    /// hold lapsed (so a redelivered task reads more than 1).
    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    /// Which attempt at the entry this is ([`TakeContext::epoch`]).
    pub fn attempt(&self) -> i64 {
        self.epoch
    }

    /// The holder: the bound agent's AgentID.
    pub fn agent_id(&self) -> &str {
        &self.holder
    }

    /// The binding's take lease: what [`TakeContext::renew`] extends the hold by.
    pub fn lease(&self) -> Lease {
        self.lease
    }

    /// The space the entry was taken from, acting as the bound agent.
    pub fn space(&self) -> &Space {
        &self.space
    }

    /// The schema the binding declares it produces, when it declares exactly one
    /// ([`super::Reply::payload`] writes it).
    pub fn produces(&self) -> Option<&str> {
        self.produces.as_deref()
    }

    /// When the hold lapses unless renewed, epoch milliseconds.
    pub async fn expires_at_millis(&self) -> i64 {
        self.taken.lock().await.expires_at_millis()
    }

    /// How long the hold has left before it lapses unless renewed, on the peer's clock (the one
    /// that stamped the claim): less than the lease when the handler starts, since the claim was
    /// made a settle window and a pull before it (zero once lapsed).
    pub async fn hold_left(&self) -> Duration {
        let left = self
            .expires_at_millis()
            .await
            .saturating_sub(self.space.peer().clock().now_ms());
        Duration::from_millis(u64::try_from(left).unwrap_or(0))
    }

    /// When the first renewal of a hold with `left` to go is due, renewing every `half` after:
    /// at half of what is left when that comes before `half` (the claim was made a settle
    /// window before the handler started, so a short lease would lapse before a renewal a full
    /// half after the start), else at `half`.
    pub(crate) fn first_renewal(left: Duration, half: Duration) -> Duration {
        (left / 2).min(half)
    }

    /// Renews the hold by the binding's lease from now (Java `TakeContext.renew`); answers the
    /// new expiry.
    ///
    /// # Errors
    ///
    /// [`SpaceError::NotHeld`] once the hold lapsed or was lost, and the errors of
    /// [`Taken::renew`].
    pub async fn renew(&self) -> Result<i64, SpaceError> {
        self.taken.lock().await.renew(self.lease).await
    }

    /// Runs `work` while renewing the take's hold every half lease, the first renewal at half of
    /// what the hold has left when that is sooner ([`TakeContext::hold_left`]), and stops renewing
    /// when `work` ends, whatever it answers: long work keeps its task without the handler
    /// threading renewals through its code. A renewal that fails (the hold was lost) is logged and
    /// ends the renewals; `work` runs on.
    ///
    /// ```no_run
    /// # use agentspaces::agent::{HandlerError, Reply, TakeContext};
    /// # async fn ship(_: &str) -> Result<Reply, HandlerError> { Ok(Reply::none()) }
    /// async fn handle(order: String, ctx: TakeContext) -> Result<Reply, HandlerError> {
    ///     ctx.keepalive(ship(&order)).await
    /// }
    /// ```
    pub async fn keepalive<F: Future>(&self, work: F) -> F::Output {
        let half = (self.lease.duration() / 2).max(MIN_RENEWAL);
        // The first renewal comes while the hold still runs: the claim's lease started before
        // the handler did.
        let first = TakeContext::first_renewal(self.hold_left().await, half).max(MIN_RENEWAL);
        let mut renewing = true;
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + first, half);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(work);
        loop {
            tokio::select! {
                biased;
                output = &mut work => return output,
                _ = ticks.tick(), if renewing => {
                    if let Err(error) = self.renew().await {
                        tracing::warn!(
                            entry_id = %self.entry_id(),
                            %error,
                            "agentspaces: a keepalive renewal failed; renewals stop"
                        );
                        renewing = false;
                    }
                }
            }
        }
    }
}

/// The event a reaction runs for ([`super::AgentBuilder::notify`]): the entry as the peer held it
/// when the event was delivered, what happened to it, and the watched space (acting as the
/// bound agent).
#[derive(Debug, Clone)]
pub struct NotifyContext {
    pub(crate) entry: EntryView,
    pub(crate) kind: EventKind,
    pub(crate) space: Space,
    pub(crate) produces: Option<String>,
}

impl NotifyContext {
    /// The entry's id.
    pub fn entry_id(&self) -> &EntryId {
        self.entry.entry_id()
    }

    /// The entry.
    pub fn entry(&self) -> &EntryView {
        &self.entry
    }

    /// What happened to it.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// The watched space, acting as the bound agent.
    pub fn space(&self) -> &Space {
        &self.space
    }

    /// The schema the binding declares it produces, when it declares exactly one.
    pub fn produces(&self) -> Option<&str> {
        self.produces.as_deref()
    }
}
