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

//! A blocking facade over the Space API ([`crate::space`]) for code without an async runtime:
//! [`Fleet`], [`Space`], [`Taken`], and [`SpaceEvents`] mirror the async verbs and run them on a
//! Tokio runtime the facade owns (two worker threads, so the peer keeps answering probes and
//! folding between calls). The typed verbs ([`crate::space::typed`]) are mirrored too:
//! [`Space::write`], [`Space::read_typed`], [`Space::take_typed`] with its [`TypedTaken`], and
//! [`Space::watch_typed`] with its [`TypedEvents`].
//!
//! ```no_run
//! # fn run(config: agentspaces::peer::PeerConfig) -> Result<(), agentspaces::space::SpaceError> {
//! use std::time::Duration;
//! use agentspaces::blocking::Fleet;
//! use agentspaces::space::{Lease, Template};
//! use agentspaces::wire::cbor::Map;
//! use agentspaces::wire::cbor_map;
//!
//! let fleet = Fleet::join(config)?;
//! let tasks = fleet.space("tasks");
//! tasks.write_value("com.acme.Task#v1", cbor_map! { "topic" => "index" }, Lease::DEFAULT_WRITE, Map::new())?;
//! if let Some(taken) = tasks.take(&Template::new("com.acme.Task#v1"), Lease::DEFAULT_TAKE, Duration::from_secs(5))? {
//!     taken.complete(None, Lease::DEFAULT_RESULT, Map::new())?;
//! }
//! fleet.close()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Not inside a runtime
//!
//! Blocking a thread that drives asynchronous tasks would stall them (Tokio panics when asked
//! to). So every call here first checks for a Tokio runtime context on the calling thread and
//! answers [`SpaceError::InsideRuntime`] when there is one, instead of panicking: an async task,
//! and also a thread that entered a runtime, such as one of `spawn_blocking`'s. Use the async API
//! there, or a plain `std::thread`.
//!
//! The runtime ends when the last facade value holding it ([`Fleet`], [`Space`], [`Taken`],
//! [`SpaceEvents`], their typed forms, and a running subscription's handler thread) is dropped,
//! without waiting for its tasks.
//!
//! # Subscriptions
//!
//! [`Space::notify`] runs its handler on a thread of its own (`agentspaces-notify`), one event at
//! a time and outside the runtime: the handler may block, and may call this facade's verbs (it
//! is not inside a runtime), without holding the workers the peer answers on. A handler slower
//! than its events loses the oldest of its own backlog only ([`crate::space::watch`]).

#![warn(missing_docs)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::identity::AgentIdentity;
use tokio::runtime::{Builder, Handle, Runtime};

use crate::entry::Entry;
use crate::peer::{Peer, PeerConfig};
use crate::space::typed::{expect_schema, typed_handler};
use crate::space::{
    self, EntryId, EntryView, Lease, SpaceError, SpaceEvent, Template, TypedEvent, TypedView,
};

/// The facade's runtime, shut down without waiting when the last holder drops it (so dropping a
/// facade value is never a blocking call, wherever it happens).
#[derive(Debug)]
struct Owned(Option<Runtime>);

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// The shared runtime handle every facade value carries.
#[derive(Debug, Clone)]
struct Blocker(Arc<Owned>);

impl Blocker {
    fn start() -> Result<Blocker, SpaceError> {
        outside_runtime()?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("agentspaces")
            .enable_all()
            .build()
            .map_err(|error| SpaceError::Runtime(error.to_string()))?;
        Ok(Blocker(Arc::new(Owned(Some(runtime)))))
    }

    /// Runs `future` to completion on the facade's runtime; [`SpaceError::InsideRuntime`] from a
    /// thread in a Tokio runtime context.
    fn run<F: Future>(&self, future: F) -> Result<F::Output, SpaceError> {
        outside_runtime()?;
        Ok(self.runtime()?.block_on(future))
    }

    fn runtime(&self) -> Result<&Runtime, SpaceError> {
        self.0
            .0
            .as_ref()
            .ok_or_else(|| SpaceError::Runtime("the runtime is shut down".to_owned()))
    }

    /// Subscribes to `template` on `space` for `lease` and runs `handler` for each event on a
    /// thread of its own, outside the runtime ([module docs](self#subscriptions)). The thread
    /// holds this runtime until the subscription ends (its lease lapses, it is closed, or the peer
    /// closes); the [`space::Subscription`]'s task ends with it.
    fn notify_on_thread<F>(
        &self,
        space: &space::Space,
        template: &Template,
        lease: Lease,
        mut handler: F,
    ) -> Result<space::Subscription, SpaceError>
    where
        F: FnMut(SpaceEvent) + Send + 'static,
    {
        let (mut events, queue, clock) = self.run(space.subscribe(template, lease))??;
        // The subscription's task lives as long as the thread: the thread holds the sender.
        let (alive, ended) = tokio::sync::oneshot::channel::<()>();
        let task = self.runtime()?.spawn(async move {
            let _ = ended.await;
        });
        let blocker = self.clone();
        std::thread::Builder::new()
            .name("agentspaces-notify".to_owned())
            .spawn(move || {
                let _alive = alive;
                while let Ok(Some(event)) = blocker.run(events.next()) {
                    handler(event);
                }
            })
            .map_err(|error| SpaceError::Runtime(format!("the handler thread: {error}")))?;
        Ok(space::Subscription::new(queue, clock, task))
    }
}

/// [`SpaceError::InsideRuntime`] when the calling thread is in a Tokio runtime context.
fn outside_runtime() -> Result<(), SpaceError> {
    if Handle::try_current().is_ok() {
        Err(SpaceError::InsideRuntime)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// The fleet

/// A fleet member driven from blocking code ([`space::Fleet`] over a runtime of its own). Cheap
/// to clone.
#[derive(Debug, Clone)]
pub struct Fleet {
    inner: space::Fleet,
    blocker: Blocker,
}

impl Fleet {
    /// Starts a runtime and a peer on it from `config` ([`space::Fleet::join`]).
    pub fn join(config: PeerConfig) -> Result<Fleet, SpaceError> {
        let blocker = Blocker::start()?;
        let inner = blocker.run(space::Fleet::join(config))??;
        Ok(Fleet { inner, blocker })
    }

    /// Starts a runtime and a peer on it from the `ASPACE_*` variables over the fleet YAML
    /// ([`space::Fleet::join_from_env`]).
    pub fn join_from_env() -> Result<Fleet, SpaceError> {
        let blocker = Blocker::start()?;
        let inner = blocker.run(space::Fleet::join_from_env())??;
        Ok(Fleet { inner, blocker })
    }

    /// A handle on space `name` of the fleet's group.
    pub fn space(&self, name: &str) -> Space {
        Space {
            inner: self.inner.space(name),
            blocker: self.blocker.clone(),
        }
    }

    /// The peer underneath (its async calls need a runtime of their own).
    pub fn peer(&self) -> &Peer {
        self.inner.peer()
    }

    /// The async fleet underneath.
    pub fn as_async(&self) -> &space::Fleet {
        &self.inner
    }

    /// Closes the peer for good ([`space::Fleet::close`]). Idempotent.
    pub fn close(&self) -> Result<(), SpaceError> {
        Ok(self.blocker.run(self.inner.close())??)
    }
}

// ---------------------------------------------------------------------------------------------
// The space

/// One space of the fleet's group, driven from blocking code: [`space::Space`]'s verbs, each
/// run to completion on the facade's runtime. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Space {
    inner: space::Space,
    blocker: Blocker,
}

impl Space {
    /// The space's name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// The async space underneath.
    pub fn as_async(&self) -> &space::Space {
        &self.inner
    }

    /// This space acting as `agent` ([`space::Space::as_agent`]).
    pub fn as_agent(&self, agent: AgentIdentity) -> Space {
        Space {
            inner: self.inner.as_agent(agent),
            blocker: self.blocker.clone(),
        }
    }

    /// The agent identity this handle acts as, if any.
    pub fn agent(&self) -> Option<&AgentIdentity> {
        self.inner.agent()
    }

    /// This space with another settle window for its takes ([`space::Space::with_settle`]).
    pub fn with_settle(&self, settle: Duration) -> Space {
        Space {
            inner: self.inner.with_settle(settle),
            blocker: self.blocker.clone(),
        }
    }

    /// This space with another capacity for its watches' queues
    /// ([`space::Space::with_watch_capacity`]).
    pub fn with_watch_capacity(&self, capacity: usize) -> Space {
        Space {
            inner: self.inner.with_watch_capacity(capacity),
            blocker: self.blocker.clone(),
        }
    }

    /// [`space::Space::pull`].
    pub fn pull(&self) -> Result<(), SpaceError> {
        self.blocker.run(self.inner.pull())?
    }

    /// [`space::Space::write_value`].
    pub fn write_value(
        &self,
        schema: &str,
        payload: Value,
        lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.blocker
            .run(self.inner.write_value(schema, payload, lease, tags))?
    }

    /// [`space::Space::renew_write`].
    pub fn renew_write(&self, entry_id: &EntryId, lease: Lease) -> Result<(), SpaceError> {
        self.blocker.run(self.inner.renew_write(entry_id, lease))?
    }

    /// [`space::Space::cancel`].
    pub fn cancel(&self, entry_id: &EntryId) -> Result<(), SpaceError> {
        self.blocker.run(self.inner.cancel(entry_id))?
    }

    /// [`space::Space::read_all`].
    pub fn read_all(
        &self,
        template: &Template,
        limit: usize,
    ) -> Result<Vec<EntryView>, SpaceError> {
        self.blocker.run(self.inner.read_all(template, limit))?
    }

    /// [`space::Space::read`].
    pub fn read(
        &self,
        template: &Template,
        timeout: Duration,
    ) -> Result<Option<EntryView>, SpaceError> {
        self.blocker.run(self.inner.read(template, timeout))?
    }

    /// [`space::Space::get`].
    pub fn get(&self, entry_id: &EntryId) -> Result<Option<EntryView>, SpaceError> {
        self.blocker.run(self.inner.get(entry_id))?
    }

    /// [`space::Space::take`].
    pub fn take(
        &self,
        template: &Template,
        lease: Lease,
        timeout: Duration,
    ) -> Result<Option<Taken>, SpaceError> {
        let taken = self
            .blocker
            .run(self.inner.take(template, lease, timeout))??;
        Ok(taken.map(|inner| Taken {
            inner,
            blocker: self.blocker.clone(),
        }))
    }

    /// [`space::Space::watch`].
    pub fn watch(&self, template: &Template) -> Result<SpaceEvents, SpaceError> {
        let inner = self.blocker.run(self.inner.watch(template))??;
        Ok(SpaceEvents {
            inner,
            blocker: self.blocker.clone(),
        })
    }

    /// [`space::Space::held`]: the take this handle's actor holds on `entry_id`, found by id.
    pub fn held(&self, entry_id: &EntryId, timeout: Duration) -> Result<Option<Taken>, SpaceError> {
        let taken = self.blocker.run(self.inner.held(entry_id, timeout))??;
        Ok(taken.map(|inner| Taken {
            inner,
            blocker: self.blocker.clone(),
        }))
    }

    /// [`space::Space::notify`], with the handler on a thread of its own, outside the runtime,
    /// one event at a time: it may block, and may call this facade's verbs ([module
    /// docs](self#subscriptions)).
    pub fn notify<F>(
        &self,
        template: &Template,
        lease: Lease,
        handler: F,
    ) -> Result<space::Subscription, SpaceError>
    where
        F: FnMut(SpaceEvent) + Send + 'static,
    {
        self.blocker
            .notify_on_thread(&self.inner, template, lease, handler)
    }

    // ------------------------------------------------------------------------- typed verbs

    /// [`space::Space::write`]: `value` as an entry of its type's schema.
    pub fn write<T: Entry>(
        &self,
        value: &T,
        lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.blocker.run(self.inner.write(value, lease, tags))?
    }

    /// [`space::Space::read_all_typed`].
    pub fn read_all_typed<T: Entry>(
        &self,
        template: &Template,
        limit: usize,
    ) -> Result<Vec<TypedView<T>>, SpaceError> {
        self.blocker
            .run(self.inner.read_all_typed(template, limit))?
    }

    /// [`space::Space::read_typed`].
    pub fn read_typed<T: Entry>(
        &self,
        template: &Template,
        timeout: Duration,
    ) -> Result<Option<TypedView<T>>, SpaceError> {
        self.blocker.run(self.inner.read_typed(template, timeout))?
    }

    /// [`space::Space::get_typed`].
    pub fn get_typed<T: Entry>(
        &self,
        entry_id: &EntryId,
    ) -> Result<Option<TypedView<T>>, SpaceError> {
        self.blocker.run(self.inner.get_typed(entry_id))?
    }

    /// [`space::Space::take_typed`].
    pub fn take_typed<T: Entry>(
        &self,
        template: &Template,
        lease: Lease,
        timeout: Duration,
    ) -> Result<Option<TypedTaken<T>>, SpaceError> {
        let taken = self
            .blocker
            .run(self.inner.take_typed::<T>(template, lease, timeout))??;
        Ok(taken.map(|typed| {
            let (inner, value) = typed.into_parts();
            TypedTaken {
                taken: Taken {
                    inner,
                    blocker: self.blocker.clone(),
                },
                value,
            }
        }))
    }

    /// [`space::Space::watch_typed`].
    pub fn watch_typed<T: Entry>(&self, template: &Template) -> Result<TypedEvents<T>, SpaceError> {
        let inner = self.blocker.run(self.inner.watch_typed::<T>(template))??;
        Ok(TypedEvents {
            inner,
            blocker: self.blocker.clone(),
        })
    }

    /// [`space::Space::notify_typed`], with the handler on a thread of its own as
    /// [`Space::notify`]'s.
    pub fn notify_typed<T, F>(
        &self,
        template: &Template,
        lease: Lease,
        handler: F,
    ) -> Result<space::Subscription, SpaceError>
    where
        T: Entry,
        F: FnMut(TypedEvent<T>) + Send + 'static,
    {
        expect_schema::<T>(template)?;
        self.blocker
            .notify_on_thread(&self.inner, template, lease, typed_handler(handler))
    }
}

// ---------------------------------------------------------------------------------------------
// A take

/// An entry held exclusively, driven from blocking code ([`space::Taken`]).
#[derive(Debug)]
pub struct Taken {
    inner: space::Taken,
    blocker: Blocker,
}

impl Taken {
    /// The taken entry.
    pub fn entry(&self) -> &EntryView {
        self.inner.entry()
    }

    /// The taken entry's id.
    pub fn entry_id(&self) -> &EntryId {
        self.inner.entry_id()
    }

    /// The holder: the AgentID the claim names.
    pub fn holder(&self) -> &str {
        self.inner.holder()
    }

    /// The claim's epoch.
    pub fn epoch(&self) -> i64 {
        self.inner.epoch()
    }

    /// When the hold lapses unless renewed, epoch milliseconds.
    pub fn expires_at_millis(&self) -> i64 {
        self.inner.expires_at_millis()
    }

    /// The async take underneath.
    pub fn as_async(&self) -> &space::Taken {
        &self.inner
    }

    /// [`space::Taken::complete`].
    pub fn complete(
        &self,
        result: Option<(&str, Value)>,
        result_lease: Lease,
        tags: Map,
    ) -> Result<Option<EntryId>, SpaceError> {
        self.blocker
            .run(self.inner.complete(result, result_lease, tags))?
    }

    /// [`space::Taken::complete_with`]: completes with a typed result; answers its id.
    pub fn complete_with<R: Entry>(
        &self,
        result: &R,
        result_lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.blocker
            .run(self.inner.complete_with(result, result_lease, tags))?
    }

    /// [`space::Taken::renew`].
    pub fn renew(&mut self, lease: Lease) -> Result<i64, SpaceError> {
        self.blocker.run(self.inner.renew(lease))?
    }

    /// [`space::Taken::release`]: no longer renewed; the hold lapses at its expiry.
    pub fn release(self) {
        self.inner.release();
    }
}

/// An entry held exclusively with its payload decoded as `T`, driven from blocking code
/// ([`space::TypedTaken`]): the [`Taken`] and the value. Dropping it is releasing it.
#[derive(Debug)]
pub struct TypedTaken<T> {
    taken: Taken,
    value: T,
}

impl<T> TypedTaken<T> {
    /// The decoded payload of the taken entry.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The take: its holder, epoch, and expiry.
    pub fn taken(&self) -> &Taken {
        &self.taken
    }

    /// The taken entry.
    pub fn entry(&self) -> &EntryView {
        self.taken.entry()
    }

    /// The taken entry's id.
    pub fn entry_id(&self) -> &EntryId {
        self.taken.entry_id()
    }

    /// The take and the decoded payload.
    pub fn into_parts(self) -> (Taken, T) {
        (self.taken, self.value)
    }

    /// [`space::Taken::complete`]: with an untyped result or none.
    pub fn complete(
        &self,
        result: Option<(&str, Value)>,
        result_lease: Lease,
        tags: Map,
    ) -> Result<Option<EntryId>, SpaceError> {
        self.taken.complete(result, result_lease, tags)
    }

    /// [`space::Taken::complete_with`]: with a typed result; answers its id.
    pub fn complete_with<R: Entry>(
        &self,
        result: &R,
        result_lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.taken.complete_with(result, result_lease, tags)
    }

    /// [`space::Taken::renew`].
    pub fn renew(&mut self, lease: Lease) -> Result<i64, SpaceError> {
        self.taken.renew(lease)
    }

    /// [`space::Taken::release`]: no longer renewed; the hold lapses at its expiry.
    pub fn release(self) {
        self.taken.release();
    }
}

// ---------------------------------------------------------------------------------------------
// Watches

/// The events of one watch, driven from blocking code ([`space::SpaceEvents`]). Dropping it ends
/// the watch.
#[derive(Debug)]
pub struct SpaceEvents {
    inner: space::SpaceEvents,
    blocker: Blocker,
}

impl SpaceEvents {
    /// The next event, blocking until one arrives; `None` once the watch has ended and its queue
    /// is empty.
    pub fn recv(&mut self) -> Result<Option<SpaceEvent>, SpaceError> {
        self.blocker.run(self.inner.next())
    }

    /// The next event, blocking at most `timeout`; `None` when none arrived in time or the watch
    /// has ended.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<SpaceEvent>, SpaceError> {
        let next = self
            .blocker
            .run(async { tokio::time::timeout(timeout, self.inner.next()).await })?;
        Ok(next.ok().flatten())
    }

    /// The next event already queued, without blocking.
    pub fn try_recv(&mut self) -> Option<SpaceEvent> {
        self.inner.try_next()
    }

    /// How many events were dropped because this watcher fell behind.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped()
    }

    /// Whether the watch still delivers.
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// Ends the watch. Idempotent.
    pub fn close(&mut self) {
        self.inner.close();
    }
}

/// The events of one typed watch, driven from blocking code ([`space::TypedEvents`]). Dropping
/// it ends the watch.
#[derive(Debug)]
pub struct TypedEvents<T> {
    inner: space::TypedEvents<T>,
    blocker: Blocker,
}

impl<T: Entry> TypedEvents<T> {
    /// The next event that decodes, blocking until one arrives; `None` once the watch has ended
    /// and its queue is empty.
    pub fn recv(&mut self) -> Result<Option<TypedEvent<T>>, SpaceError> {
        self.blocker.run(self.inner.next())
    }

    /// The next event that decodes, blocking at most `timeout`; `None` when none arrived in time
    /// or the watch has ended.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<TypedEvent<T>>, SpaceError> {
        let next = self
            .blocker
            .run(async { tokio::time::timeout(timeout, self.inner.next()).await })?;
        Ok(next.ok().flatten())
    }

    /// The next queued event that decodes, without blocking.
    pub fn try_recv(&mut self) -> Option<TypedEvent<T>> {
        self.inner.try_next()
    }
}

impl<T> TypedEvents<T> {
    /// How many events were passed over because their entry did not decode as `T`.
    pub fn skipped(&self) -> u64 {
        self.inner.skipped()
    }

    /// How many events were dropped because this watcher fell behind.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped()
    }

    /// Whether the watch still delivers.
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// Ends the watch. Idempotent.
    pub fn close(&mut self) {
        self.inner.close();
    }
}
