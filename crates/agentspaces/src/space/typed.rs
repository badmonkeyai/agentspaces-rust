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

//! The typed layer of the Space API: the verbs over Rust types that implement
//! [`Entry`] (usually `#[derive(Entry)]`) instead of CBOR [`Value`]s and
//! schema strings.
//!
//! ```no_run
//! # async fn run(space: agentspaces::space::Space) -> Result<(), agentspaces::space::SpaceError> {
//! use std::time::Duration;
//! use agentspaces::Entry;
//! use agentspaces::space::{Lease, Template, TypedView};
//! use agentspaces::wire::cbor::Map;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize, Entry)]
//! #[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
//! struct Task {
//!     topic: String,
//!     priority: i32,
//! }
//!
//! #[derive(Debug, Serialize, Deserialize, Entry)]
//! #[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Result#v1")]
//! struct Report {
//!     topic: String,
//!     summary: String,
//!     worker: String,
//! }
//!
//! space.write(&Task { topic: "index".into(), priority: 3 }, Lease::DEFAULT_WRITE, Map::new()).await?;
//!
//! let urgent = Template::of::<Task>().where_clause("priority>=3")?;
//! let all: Vec<TypedView<Task>> = space.read_all_typed(&urgent, 100).await?;
//! println!("{} urgent tasks", all.len());
//!
//! if let Some(taken) = space.take_typed::<Task>(&urgent, Lease::DEFAULT_TAKE, Duration::from_secs(15)).await? {
//!     let report = Report {
//!         topic: taken.value().topic.clone(),
//!         summary: "indexed".into(),
//!         worker: "rust".into(),
//!     };
//!     taken.complete_with(&report, Lease::DEFAULT_RESULT, Map::new()).await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Templates and decoding
//!
//! A typed verb takes a [`Template`] whose schema is the type's ([`Template::of`], then narrowed
//! with conditions as any template); a template of another schema is refused with
//! [`SpaceError::Entry`] ([`EntryError::WrongSchema`]) before anything is read.
//!
//! An entry of the right schema whose payload does not decode as the type (a writer with another
//! shape of the record) is invisible to the typed verbs, as it is to a Java template of that
//! class (`ReplicatedSpace.decodeIfMatches`): reads skip it, a take never claims it, and a watch
//! passes over its events ([`TypedEvents::skipped`]). The untyped verbs still see it, and
//! [`EntryView::decode`] says why it does not decode.

#![warn(missing_docs)]

use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use agentspaces_wire::cbor::{Map, Value};

use super::{
    CloseReason, EntryId, EntryView, EventKind, Lease, ResultWrite, Space, SpaceError, SpaceEvent,
    SpaceEvents, Subscription, Taken, Template,
};
use crate::entry::{Entry, EntryError};

// ---------------------------------------------------------------------------------------------
// Typed views and events

/// An entry as this peer holds it ([`EntryView`]) together with its payload decoded as `T`.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedView<T> {
    view: EntryView,
    value: T,
}

impl<T> TypedView<T> {
    /// The decoded payload.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The decoded payload, owned.
    pub fn into_value(self) -> T {
        self.value
    }

    /// The entry: its id, schema, raw payload, tags, issuer, lease, and state.
    pub fn view(&self) -> &EntryView {
        &self.view
    }

    /// The entry, owned.
    pub fn into_view(self) -> EntryView {
        self.view
    }

    /// The entry and its decoded payload.
    pub fn into_parts(self) -> (EntryView, T) {
        (self.view, self.value)
    }

    /// The entry's id.
    pub fn entry_id(&self) -> &EntryId {
        self.view.entry_id()
    }
}

impl<T: Entry> TypedView<T> {
    /// The view with its payload decoded as `T` ([`EntryView::decode`]).
    ///
    /// # Errors
    ///
    /// [`EntryError::WrongSchema`] when the entry is not of `T`'s schema, [`EntryError::Decode`]
    /// when its payload does not fit `T`.
    pub fn decode(view: EntryView) -> Result<Self, EntryError> {
        let value = view.decode::<T>()?;
        Ok(Self { view, value })
    }
}

/// One transition of one entry with its payload decoded as `T` ([`Space::watch_typed`]); the
/// typed [`SpaceEvent`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TypedEvent<T> {
    /// What happened.
    pub kind: EventKind,
    /// The entry, as this peer held it when the event was delivered, and its decoded payload.
    pub entry: TypedView<T>,
}

impl<T: Entry> TypedEvent<T> {
    /// The event with its entry's payload decoded as `T`.
    ///
    /// # Errors
    ///
    /// As [`TypedView::decode`].
    pub fn decode(event: SpaceEvent) -> Result<Self, EntryError> {
        Ok(Self {
            kind: event.kind,
            entry: TypedView::decode(event.entry)?,
        })
    }
}

/// The payload of `view` as `T`, or `None` (logged at debug) when it does not decode: a typed
/// verb passes over such an entry, as a Java template of the class does.
fn decoded<T: Entry>(view: &EntryView) -> Option<T> {
    match view.decode::<T>() {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::debug!(
                entry_id = %view.entry_id(),
                %error,
                "skipped an entry that does not decode as {}",
                std::any::type_name::<T>()
            );
            None
        }
    }
}

/// `view` decoded as `T`, or `None` when it does not decode ([`decoded`]).
fn typed<T: Entry>(view: EntryView) -> Option<TypedView<T>> {
    let value = decoded::<T>(&view)?;
    Some(TypedView { view, value })
}

/// `handler` over the events whose entry decodes as `T` ([`decoded`]): the handler of a typed
/// subscription ([`Space::notify_typed`], and the blocking facade's).
pub(crate) fn typed_handler<T, F>(mut handler: F) -> impl FnMut(SpaceEvent) + Send + 'static
where
    T: Entry,
    F: FnMut(TypedEvent<T>) + Send + 'static,
{
    move |event: SpaceEvent| {
        if let Some(value) = decoded::<T>(&event.entry) {
            handler(TypedEvent {
                kind: event.kind,
                entry: TypedView {
                    view: event.entry,
                    value,
                },
            });
        }
    }
}

/// [`EntryError::WrongSchema`] unless `template` selects `T`'s schema.
pub(crate) fn expect_schema<T: Entry>(template: &Template) -> Result<(), SpaceError> {
    if template.schema() == T::SCHEMA {
        Ok(())
    } else {
        Err(EntryError::WrongSchema {
            expected: T::SCHEMA,
            found: template.schema().to_owned(),
        }
        .into())
    }
}

// ---------------------------------------------------------------------------------------------
// The typed verbs

impl Space {
    /// Writes `value` as an entry of its type's schema ([`Entry::SCHEMA`]) for `lease`, with its
    /// `tags`, and answers its id: [`Space::write_value`] with the payload [`Entry::to_payload`]
    /// makes (Java `Space.write`).
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when the value has no payload form ([`EntryError::Encode`]), and the
    /// errors of [`Space::write_value`].
    pub async fn write<T: Entry>(
        &self,
        value: &T,
        lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        let payload = value.to_payload()?;
        self.write_value(T::SCHEMA, payload, lease, tags).await
    }

    /// The available entries matching `template` that decode as `T`, at most `limit`, in the
    /// order they first folded here ([`Space::read_all`], Java `readAll`). Never waits.
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when `template` is not of `T`'s schema, and the errors of
    /// [`Space::read_all`].
    pub async fn read_all_typed<T: Entry>(
        &self,
        template: &Template,
        limit: usize,
    ) -> Result<Vec<TypedView<T>>, SpaceError> {
        expect_schema::<T>(template)?;
        self.open().await?;
        self.find_decoded(template, limit, &mut typed::<T>).await
    }

    /// The first available entry matching `template` that decodes as `T`, waiting up to
    /// `timeout` for one ([`Space::read`]). `Ok(None)` at the timeout.
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when `template` is not of `T`'s schema, and the errors of
    /// [`Space::read`].
    pub async fn read_typed<T: Entry>(
        &self,
        template: &Template,
        timeout: Duration,
    ) -> Result<Option<TypedView<T>>, SpaceError> {
        expect_schema::<T>(template)?;
        self.read_decoded(template, timeout, typed::<T>).await
    }

    /// The entry `entry_id` as this peer holds it, whatever its state, decoded as `T`
    /// ([`Space::get`]); `None` when it is not held here.
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when the entry is of another schema ([`EntryError::WrongSchema`]) or
    /// its payload does not fit `T` ([`EntryError::Decode`]): an entry asked for by id is named,
    /// so a mismatch is reported rather than passed over. And the errors of [`Space::get`].
    pub async fn get_typed<T: Entry>(
        &self,
        entry_id: &EntryId,
    ) -> Result<Option<TypedView<T>>, SpaceError> {
        match self.get(entry_id).await? {
            Some(view) => Ok(Some(TypedView::decode(view)?)),
            None => Ok(None),
        }
    }

    /// Takes one available entry matching `template` that decodes as `T` exclusively, holding it
    /// for `lease`, waiting up to `timeout` for one ([`Space::take`], Java `take`): a candidate
    /// that does not decode is never claimed. `Ok(None)` when nothing could be taken in time.
    ///
    /// # Cancel safety
    ///
    /// Not cancel-safe once its claim is out, as [`Space::take`] (whose notes say what a dropped
    /// take costs, and how to avoid it).
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when `template` is not of `T`'s schema, and the errors of
    /// [`Space::take`].
    pub async fn take_typed<T: Entry>(
        &self,
        template: &Template,
        lease: Lease,
        timeout: Duration,
    ) -> Result<Option<TypedTaken<T>>, SpaceError> {
        expect_schema::<T>(template)?;
        let taken = self
            .take_decoded(template, lease, timeout, decoded::<T>)
            .await?;
        Ok(taken.map(|(taken, value)| TypedTaken { taken, value }))
    }

    /// Watches the entries matching `template` that decode as `T` ([`Space::watch`]): every
    /// transition from now on, its payload decoded. Events of entries that do not decode are
    /// passed over and counted ([`TypedEvents::skipped`]).
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when `template` is not of `T`'s schema, and the errors of
    /// [`Space::watch`].
    pub async fn watch_typed<T: Entry>(
        &self,
        template: &Template,
    ) -> Result<TypedEvents<T>, SpaceError> {
        expect_schema::<T>(template)?;
        Ok(TypedEvents {
            events: self.watch(template).await?,
            skipped: 0,
            entry: PhantomData,
        })
    }

    /// The leased push subscription over `T` ([`Space::notify`]): `handler` runs, on a task of
    /// its own, for each transition of a matching entry that decodes as `T`, until `lease`
    /// lapses unless renewed, the subscription is closed, or the peer closes. Must be called
    /// within a Tokio runtime.
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when `template` is not of `T`'s schema, and the errors of
    /// [`Space::notify`].
    pub async fn notify_typed<T, F>(
        &self,
        template: &Template,
        lease: Lease,
        handler: F,
    ) -> Result<Subscription, SpaceError>
    where
        T: Entry,
        F: FnMut(TypedEvent<T>) + Send + 'static,
    {
        expect_schema::<T>(template)?;
        self.notify(template, lease, typed_handler(handler)).await
    }
}

impl Taken {
    /// Completes the take with `result`, written into the same space as an entry of its type's
    /// schema under `result_lease` with `tags`, atomically ([`Taken::complete`], Java
    /// `Space.complete(taken, result, lease)`). Answers the result's id.
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] when the result has no payload form ([`EntryError::Encode`]), with
    /// the take still held; and the errors of [`Taken::complete`].
    pub async fn complete_with<R: Entry>(
        &self,
        result: &R,
        result_lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        let payload = result.to_payload()?;
        let written = self
            .finish(Some(ResultWrite {
                schema: R::SCHEMA.to_owned(),
                payload,
                lease_millis: result_lease.millis(),
                tags,
            }))
            .await?;
        // A completion given a result always answers the result's id (the actor's
        // `space_complete` writes it in the same turn).
        written.ok_or_else(|| SpaceError::NotHeld(self.entry_id().clone()))
    }
}

// ---------------------------------------------------------------------------------------------
// A typed take

/// An entry held exclusively with its payload decoded as `T` ([`Space::take_typed`], Java
/// `TakenEntry<T>`): the [`Taken`] and the value. Dropping it is releasing it.
#[derive(Debug)]
pub struct TypedTaken<T> {
    taken: Taken,
    value: T,
}

impl<T> TypedTaken<T> {
    /// The decoded payload of the taken entry (Java `TakenEntry.entry`).
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

    /// Completes the take, with an untyped result or none ([`Taken::complete`]).
    ///
    /// # Errors
    ///
    /// As [`Taken::complete`].
    pub async fn complete(
        &self,
        result: Option<(&str, Value)>,
        result_lease: Lease,
        tags: Map,
    ) -> Result<Option<EntryId>, SpaceError> {
        self.taken.complete(result, result_lease, tags).await
    }

    /// Completes the take with a typed result ([`Taken::complete_with`]); answers its id.
    ///
    /// # Errors
    ///
    /// As [`Taken::complete_with`].
    pub async fn complete_with<R: Entry>(
        &self,
        result: &R,
        result_lease: Lease,
        tags: Map,
    ) -> Result<EntryId, SpaceError> {
        self.taken.complete_with(result, result_lease, tags).await
    }

    /// Renews the hold to `lease` from now ([`Taken::renew`]); answers the new expiry.
    ///
    /// # Errors
    ///
    /// As [`Taken::renew`].
    pub async fn renew(&mut self, lease: Lease) -> Result<i64, SpaceError> {
        self.taken.renew(lease).await
    }

    /// Releases the take ([`Taken::release`]): the hold lapses at its expiry.
    pub fn release(self) {
        self.taken.release();
    }
}

// ---------------------------------------------------------------------------------------------
// A typed watch

/// The events of one typed watch ([`Space::watch_typed`]): an async stream of [`TypedEvent`]s
/// over a [`SpaceEvents`], with the same delivery (a bounded queue that drops its oldest events
/// when the watcher falls behind). It also implements [`futures_core::Stream`]. Dropping it ends
/// the watch.
pub struct TypedEvents<T> {
    events: SpaceEvents,
    skipped: u64,
    entry: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for TypedEvents<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedEvents")
            .field("entry", &std::any::type_name::<T>())
            .field("events", &self.events)
            .field("skipped", &self.skipped)
            .finish()
    }
}

impl<T: Entry> TypedEvents<T> {
    /// The event decoded, or `None` (counted) when its entry does not decode as `T`.
    fn accept(&mut self, event: SpaceEvent) -> Option<TypedEvent<T>> {
        match decoded::<T>(&event.entry) {
            Some(value) => Some(TypedEvent {
                kind: event.kind,
                entry: TypedView {
                    view: event.entry,
                    value,
                },
            }),
            None => {
                self.skipped = self.skipped.saturating_add(1);
                None
            }
        }
    }

    /// The next event that decodes, waiting for one; `None` once the watch has ended and its
    /// queue is empty.
    pub async fn next(&mut self) -> Option<TypedEvent<T>> {
        loop {
            let event = self.events.next().await?;
            if let Some(typed) = self.accept(event) {
                return Some(typed);
            }
        }
    }

    /// The next queued event that decodes, without waiting.
    pub fn try_next(&mut self) -> Option<TypedEvent<T>> {
        loop {
            let event = self.events.try_next()?;
            if let Some(typed) = self.accept(event) {
                return Some(typed);
            }
        }
    }
}

impl<T> TypedEvents<T> {
    /// How many events were passed over because their entry did not decode as `T`.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// How many events were dropped because this watcher fell more than its queue's capacity
    /// behind ([`SpaceEvents::dropped`]).
    pub fn dropped(&self) -> u64 {
        self.events.dropped()
    }

    /// Whether the watch still delivers.
    pub fn is_open(&self) -> bool {
        self.events.is_open()
    }

    /// Why the watch ended, once it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.events.close_reason()
    }

    /// Ends the watch and discards what is queued. Idempotent.
    pub fn close(&mut self) {
        self.events.close();
    }
}

impl<T: Entry> futures_core::Stream for TypedEvents<T> {
    type Item = TypedEvent<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<TypedEvent<T>>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.events).poll_next(cx) {
                Poll::Ready(Some(event)) => {
                    if let Some(typed) = this.accept(event) {
                        return Poll::Ready(Some(typed));
                    }
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
