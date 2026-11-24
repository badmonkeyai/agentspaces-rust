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

//! Watches: the bounded queue between the peer's actor and one watcher ([`SpaceEvents`]), and
//! the leased push subscription over it ([`Subscription`]).
//!
//! # Delivery
//!
//! The actor derives each transition once and offers it to every matching watch's queue without
//! waiting. Each queue holds at most its capacity
//! ([`DEFAULT_WATCH_CAPACITY`](crate::space::DEFAULT_WATCH_CAPACITY) unless
//! [`Space::with_watch_capacity`](crate::space::Space::with_watch_capacity) says otherwise); when
//! a watcher falls that far behind, its *oldest* queued event is dropped to make room and
//! counted ([`SpaceEvents::dropped`]). A slow watcher therefore never slows the peer or any other
//! watcher; it loses its own backlog, oldest first, and can tell that it did. Events carry the
//! entry id, so a watcher that must not miss state reads the space again ([`Space::get`],
//! [`Space::read_all`]) after a drop.
//!
//! [`Space::get`]: crate::space::Space::get
//! [`Space::read_all`]: crate::space::Space::read_all

#![warn(missing_docs)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use tokio::task::JoinHandle;

use super::types::{Lease, SpaceError, SpaceEvent};
use crate::clock::SharedClock;

/// Why a watch or subscription ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Its owner closed it (or dropped the [`SpaceEvents`]).
    Closed,
    /// Its lease lapsed before a renewal ([`Subscription`]), judged on the peer clock's local
    /// base ([`crate::clock::Clock::local_ms`]).
    Lapsed,
    /// The peer closed.
    PeerClosed,
}

#[derive(Debug, Default)]
struct QueueState {
    events: VecDeque<SpaceEvent>,
    closed: Option<CloseReason>,
    waker: Option<Waker>,
}

/// One watcher's queue: the actor pushes, the watcher pops. See the [module docs](self).
#[derive(Debug)]
pub(crate) struct WatchQueue {
    state: Mutex<QueueState>,
    capacity: usize,
    dropped: AtomicU64,
    /// When the watch lapses, milliseconds on the peer clock's local base
    /// ([`crate::clock::Clock::local_ms`], monotonic on the system clock: a subscription's lease
    /// is a local period, SPEC v0.1.36 §9.5); `i64::MAX` for none.
    expires_at: AtomicI64,
}

impl WatchQueue {
    /// A queue holding at most `capacity` events (at least one), lapsing at `expires_at`.
    pub(crate) fn new(capacity: usize, expires_at: i64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState::default()),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            expires_at: AtomicI64::new(expires_at),
        })
    }

    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues an event, dropping (and counting) the oldest when full; nothing once closed.
    pub(crate) fn push(&self, event: SpaceEvent) {
        let waker = {
            let mut state = self.lock();
            if state.closed.is_some() {
                return;
            }
            while state.events.len() >= self.capacity {
                state.events.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            state.events.push_back(event);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Ends the watch (the first reason stands). An owner's close discards what is queued; a
    /// lapse or the peer's close lets the watcher drain it first.
    pub(crate) fn close(&self, reason: CloseReason) {
        let waker = {
            let mut state = self.lock();
            if state.closed.is_some() {
                return;
            }
            state.closed = Some(reason);
            if reason == CloseReason::Closed {
                state.events.clear();
            }
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Why the watch ended, once it has.
    pub(crate) fn closed(&self) -> Option<CloseReason> {
        self.lock().closed
    }

    /// When the watch's lease lapses (on the local base); a renewal only moves it later.
    pub(crate) fn expires_at(&self) -> i64 {
        self.expires_at.load(Ordering::SeqCst)
    }

    /// Whether the watch's lease has lapsed at `now_ms` (on the local base).
    pub(crate) fn lapsed(&self, now_ms: i64) -> bool {
        self.expires_at.load(Ordering::SeqCst) <= now_ms
    }

    /// Moves the lapse to `expires_at` unless that is earlier than it already is (a renewal
    /// never shortens a lease, SPEC §7.2), unless the watch has ended or lapsed at `now_ms` (both
    /// on the local base). The
    /// read and the write are one step under the queue's lock, so two renewals at once cannot
    /// leave the shorter one in force.
    fn renew(&self, expires_at: i64, now_ms: i64) -> bool {
        let state = self.lock();
        if state.closed.is_some() || self.lapsed(now_ms) {
            return false;
        }
        self.expires_at.fetch_max(expires_at, Ordering::SeqCst);
        true
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn try_pop(&self) -> Option<SpaceEvent> {
        self.lock().events.pop_front()
    }

    fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Option<SpaceEvent>> {
        let mut state = self.lock();
        if let Some(event) = state.events.pop_front() {
            return Poll::Ready(Some(event));
        }
        if state.closed.is_some() {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// The events of one watch ([`Space::watch`](crate::space::Space::watch)): an async stream of
/// [`SpaceEvent`]s that ends when the watch is closed or the peer closes. It also implements
/// [`futures_core::Stream`].
///
/// See the [module docs](self) for delivery: a bounded queue that drops its oldest events when
/// the watcher falls behind ([`SpaceEvents::dropped`]). Dropping the value ends the watch.
#[derive(Debug)]
pub struct SpaceEvents {
    queue: Arc<WatchQueue>,
}

impl SpaceEvents {
    pub(crate) fn new(queue: Arc<WatchQueue>) -> Self {
        Self { queue }
    }

    /// The next event, waiting for one; `None` once the watch has ended and its queue is empty.
    pub async fn next(&mut self) -> Option<SpaceEvent> {
        std::future::poll_fn(|cx| self.queue.poll_pop(cx)).await
    }

    /// The next event already queued, without waiting.
    pub fn try_next(&mut self) -> Option<SpaceEvent> {
        self.queue.try_pop()
    }

    /// How many events were dropped because this watcher fell more than its queue's capacity
    /// behind (oldest first).
    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }

    /// Whether the watch still delivers.
    pub fn is_open(&self) -> bool {
        self.queue.closed().is_none()
    }

    /// Why the watch ended, once it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.queue.closed()
    }

    /// Ends the watch and discards what is queued. Idempotent.
    pub fn close(&mut self) {
        self.queue.close(CloseReason::Closed);
    }
}

impl futures_core::Stream for SpaceEvents {
    type Item = SpaceEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<SpaceEvent>> {
        self.queue.poll_pop(cx)
    }
}

impl Drop for SpaceEvents {
    fn drop(&mut self) {
        self.queue.close(CloseReason::Closed);
    }
}

/// A leased push subscription ([`Space::notify`](crate::space::Space::notify), Java
/// `Space.notify` and `Subscription`): its handler runs on a task of its own for each matching
/// event, until the lease lapses, the subscription is closed, or the peer closes.
/// [`Subscription::renew`] extends the lease from now. The lease is a local period, judged on the
/// peer clock's monotonic base ([`crate::clock::Clock::local_ms`]), so a laptop sleep or a wall
/// step lapses no subscription (SPEC v0.1.36 §9.5).
///
/// Dropping the handle does not end the subscription: its lease does, so a subscription that
/// outlives its owner never leaks (`space.py`'s `notify`). Delivery is the watch's ([module
/// docs](self)): a handler slower than the events loses the oldest of its backlog.
#[derive(Debug)]
pub struct Subscription {
    queue: Arc<WatchQueue>,
    clock: SharedClock,
    task: JoinHandle<()>,
}

impl Subscription {
    pub(crate) fn new(queue: Arc<WatchQueue>, clock: SharedClock, task: JoinHandle<()>) -> Self {
        Self { queue, clock, task }
    }

    /// Extends the lease to at least `lease` from now, never shortening it: the new lapse is
    /// `max(current, now + lease)` (SPEC §7.2; close the subscription to stop it sooner);
    /// [`SpaceError::SubscriptionClosed`] when it has already lapsed or been closed (Java
    /// `Subscription.renew`).
    pub fn renew(&self, lease: Lease) -> Result<(), SpaceError> {
        let now = self.clock.local_ms();
        let expires_at = now.saturating_add(lease.millis());
        if self.queue.renew(expires_at, now) {
            Ok(())
        } else {
            Err(SpaceError::SubscriptionClosed)
        }
    }

    /// When the subscription's lease lapses, epoch milliseconds on the peer's clock as it reads
    /// now (the lease runs on the local base: after a wall step this moves with the step).
    pub fn expires_at_millis(&self) -> i64 {
        let local = self.queue.expires_at.load(Ordering::SeqCst);
        if local == i64::MAX {
            return i64::MAX;
        }
        self.clock
            .now_ms()
            .saturating_add(local.saturating_sub(self.clock.local_ms()))
    }

    /// Ends the subscription at once; events still queued are not delivered. Idempotent.
    pub fn close(&self) {
        self.queue.close(CloseReason::Closed);
    }

    /// Whether the subscription still delivers. A lapse is noticed by the peer's sweep, which
    /// runs at the earliest lapse it tells, so this reads `true` for a moment after it.
    pub fn is_open(&self) -> bool {
        self.queue.closed().is_none() && !self.task.is_finished()
    }

    /// Why the subscription ended, once it has (`Lapsed` after its lease ran out).
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.queue.closed()
    }

    /// How many events were dropped because the handler fell behind.
    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }
}
