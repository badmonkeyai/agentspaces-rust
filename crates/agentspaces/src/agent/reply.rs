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

//! What a handler answers ([`Reply`], [`Tagged`]) and how it fails ([`HandlerError`]): the return
//! conventions of the Java `AgentBinder` (`dispatch`, `AgentBinder.java` 1844-1930), its
//! `Tagged` (`Tagged.java`), and its `Entries` fork (`Entries.java`).

use std::fmt;

use agentspaces_wire::cbor::{Map, Value};

use crate::entry::Entry;

// ---------------------------------------------------------------------------------------------
// Replies

/// What a handler answers, as the Java binder reads a bound method's return
/// (`AgentBinder.dispatch`):
///
/// - an entry ([`Reply::entry`], `Ok(finding.into())`): a take completes with it, written into
///   the take's space atomically with the completion (or, with
///   [`AgentBuilder::result_space`](super::AgentBuilder::result_space), completed first and then
///   written there); a notify reaction writes it;
/// - [`Reply::none`] (`Ok(Reply::none())`, `Ok(().into())`, `Ok(None::<T>.into())`): a take
///   completes without a result; a reaction writes nothing;
/// - a fork ([`Reply::fork`], `Ok(vec![a, b].into())`): a take is completed once, without a
///   result, and then each element is written as if answered alone, in order (Java `Entries`).
///   Not atomic across the elements: a crash between two leaves the first written and the task
///   completed, so forked entries should carry the input's key for the stage downstream. A fork
///   inside a fork is refused when it is reached (logged; the elements before it stay written);
///   a [`Reply::none`] inside a fork writes nothing;
/// - a [`Tagged`] entry (or [`Reply::with_tags`]): the entry written with its tags;
/// - an error ([`HandlerError`]): no completion. The take's hold lapses and the entry reappears
///   for another worker (the crash idiom of SPEC §7.2); the failure is logged and counted.
///
/// An entry whose payload cannot be encoded is a handler failure too: the take lapses.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Reply {
    pub(crate) kind: ReplyKind,
}

/// The shapes of a [`Reply`].
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum ReplyKind {
    /// Nothing to write.
    #[default]
    None,
    /// An entry of a schema.
    Entry {
        schema: String,
        payload: Value,
        tags: Map,
    },
    /// An entry of the binding's produced schema.
    Payload { payload: Value, tags: Map },
    /// Several replies, each written as if answered alone.
    Fork(Vec<Reply>),
    /// A reply that cannot be written (an entry with no payload form, tags on a fork); a
    /// failure of the handler.
    Invalid(String),
}

impl Reply {
    /// Nothing: a take completes without a result, a reaction writes nothing.
    pub fn none() -> Reply {
        Reply {
            kind: ReplyKind::None,
        }
    }

    /// An entry of `T`'s schema with its payload ([`Entry::to_payload`]). A value with no
    /// payload form makes a reply that fails the handler when it is written.
    pub fn entry<T: Entry>(value: &T) -> Reply {
        match value.to_payload() {
            Ok(payload) => Reply::value(T::SCHEMA, payload),
            Err(error) => Reply {
                kind: ReplyKind::Invalid(format!("the result has no payload form: {error}")),
            },
        }
    }

    /// An entry of `schema` with `payload`: the value-level reply (the CLI, the bindings).
    pub fn value(schema: impl Into<String>, payload: Value) -> Reply {
        Reply {
            kind: ReplyKind::Entry {
                schema: schema.into(),
                payload,
                tags: Map::new(),
            },
        }
    }

    /// An entry of the binding's produced schema with `payload`: the one schema the binding
    /// declares (`produces`). A binding that declares none, or several, fails the handler when
    /// this is written.
    pub fn payload(payload: Value) -> Reply {
        Reply {
            kind: ReplyKind::Payload {
                payload,
                tags: Map::new(),
            },
        }
    }

    /// A fork: each reply written as if answered alone, in order (Java `Entries.of`). An empty
    /// fork writes nothing (a take still completes).
    pub fn fork<R: Into<Reply>>(replies: impl IntoIterator<Item = R>) -> Reply {
        Reply {
            kind: ReplyKind::Fork(replies.into_iter().map(Into::into).collect()),
        }
    }

    /// This entry with `tags` added (text to text, a later key replacing an earlier one): Java's
    /// `Tagged.of(entry, tags)`. Tags on [`Reply::none`] or a fork make a reply that fails the
    /// handler (Java refuses a `Tagged` of `Entries`): tag the fork's elements instead.
    pub fn with_tags<K: Into<String>, V: Into<String>>(
        mut self,
        tags: impl IntoIterator<Item = (K, V)>,
    ) -> Reply {
        let added: Vec<(String, String)> = tags
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        if added.is_empty() {
            return self;
        }
        match &mut self.kind {
            ReplyKind::Entry { tags, .. } | ReplyKind::Payload { tags, .. } => {
                for (key, value) in added {
                    tags.insert(key, value);
                }
                self
            }
            ReplyKind::None | ReplyKind::Fork(_) => Reply {
                kind: ReplyKind::Invalid(
                    "a reply that is not an entry carries no tags; tag the entries".to_owned(),
                ),
            },
            ReplyKind::Invalid(_) => self,
        }
    }

    /// This entry with one more tag ([`Reply::with_tags`]).
    pub fn with_tag(self, key: impl Into<String>, value: impl Into<String>) -> Reply {
        self.with_tags([(key.into(), value.into())])
    }

    /// Whether this reply writes nothing.
    pub fn is_none(&self) -> bool {
        matches!(self.kind, ReplyKind::None)
    }

    /// Whether this reply is a fork.
    pub fn is_fork(&self) -> bool {
        matches!(self.kind, ReplyKind::Fork(_))
    }

    /// The schema of an entry reply; `None` for nothing, a fork, or an entry of the binding's
    /// produced schema ([`Reply::payload`]).
    pub fn schema(&self) -> Option<&str> {
        match &self.kind {
            ReplyKind::Entry { schema, .. } => Some(schema),
            _ => None,
        }
    }

    /// The payload of an entry reply.
    pub fn payload_value(&self) -> Option<&Value> {
        match &self.kind {
            ReplyKind::Entry { payload, .. } | ReplyKind::Payload { payload, .. } => Some(payload),
            _ => None,
        }
    }

    /// The tags of an entry reply (empty otherwise).
    pub fn tags(&self) -> Map {
        match &self.kind {
            ReplyKind::Entry { tags, .. } | ReplyKind::Payload { tags, .. } => tags.clone(),
            _ => Map::new(),
        }
    }

    /// The elements of a fork.
    pub fn fork_elements(&self) -> Option<&[Reply]> {
        match &self.kind {
            ReplyKind::Fork(elements) => Some(elements),
            _ => None,
        }
    }
}

impl<T: Entry> From<T> for Reply {
    /// The entry ([`Reply::entry`]).
    fn from(value: T) -> Reply {
        Reply::entry(&value)
    }
}

impl<T: Entry> From<Option<T>> for Reply {
    /// The entry, or nothing.
    fn from(value: Option<T>) -> Reply {
        value.map_or_else(Reply::none, |value| Reply::entry(&value))
    }
}

impl<T: Entry> From<Tagged<T>> for Reply {
    /// The entry with its tags.
    fn from(tagged: Tagged<T>) -> Reply {
        let (entry, tags) = tagged.into_parts();
        let mut reply = Reply::entry(&entry);
        if let ReplyKind::Entry { tags: held, .. } = &mut reply.kind {
            *held = tags;
        }
        reply
    }
}

impl From<Vec<Reply>> for Reply {
    /// A fork ([`Reply::fork`]).
    fn from(replies: Vec<Reply>) -> Reply {
        Reply::fork(replies)
    }
}

impl<T: Entry> From<Vec<T>> for Reply {
    /// A fork of the entries ([`Reply::fork`]).
    fn from(entries: Vec<T>) -> Reply {
        Reply::fork(entries.iter().map(Reply::entry))
    }
}

impl From<()> for Reply {
    /// Nothing ([`Reply::none`]).
    fn from((): ()) -> Reply {
        Reply::none()
    }
}

// ---------------------------------------------------------------------------------------------
// Tagged

/// An entry together with the tags it is written with (Java `Tagged`, SPEC §10.3): a take's
/// result completes with them, a reaction's result is written with them. Tags are text to text.
///
/// ```
/// use agentspaces::agent::{Reply, Tagged};
/// use agentspaces::Entry;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, Entry)]
/// #[entry(schema = "com.acme.Finding#v1")]
/// struct Finding {
///     topic: String,
/// }
///
/// let reply: Reply = Tagged::new(Finding { topic: "rust".into() }, [("claimId", "c-1")]).into();
/// assert_eq!(reply.tags().get("claimId").and_then(|v| v.as_str()), Some("c-1"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Tagged<T> {
    entry: T,
    tags: Map,
}

impl<T> Tagged<T> {
    /// `entry` with `tags` (a later key replaces an earlier one).
    pub fn new<K: Into<String>, V: Into<String>>(
        entry: T,
        tags: impl IntoIterator<Item = (K, V)>,
    ) -> Tagged<T> {
        Tagged {
            entry,
            tags: Map::new(),
        }
        .tags_from(tags)
    }

    fn tags_from<K: Into<String>, V: Into<String>>(
        mut self,
        tags: impl IntoIterator<Item = (K, V)>,
    ) -> Tagged<T> {
        for (key, value) in tags {
            self.tags.insert(key.into(), value.into());
        }
        self
    }

    /// This tagged entry with one more tag.
    pub fn tag(self, key: impl Into<String>, value: impl Into<String>) -> Tagged<T> {
        self.tags_from([(key.into(), value.into())])
    }

    /// The entry.
    pub fn entry(&self) -> &T {
        &self.entry
    }

    /// The tags, text to text.
    pub fn tags(&self) -> &Map {
        &self.tags
    }

    /// The entry and its tags.
    pub fn into_parts(self) -> (T, Map) {
        (self.entry, self.tags)
    }
}

// ---------------------------------------------------------------------------------------------
// Handler errors

/// Why a handler failed: no completion follows, so a take's hold lapses and its entry reappears
/// for another worker (Java's "action failed; lease will lapse"). Any error converts with `?`;
/// [`HandlerError::msg`] makes one from text.
///
/// It deliberately does not implement [`std::error::Error`] itself, so that every error type
/// converts into it (the shape `anyhow::Error` takes).
pub struct HandlerError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl HandlerError {
    /// A failure described by `message`.
    pub fn msg(message: impl fmt::Display) -> HandlerError {
        HandlerError {
            source: message.to_string().into(),
        }
    }

    /// The underlying error.
    pub fn source(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.source.as_ref()
    }

    /// The underlying error, owned.
    pub fn into_source(self) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self.source
    }
}

impl<E> From<E> for HandlerError
where
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    fn from(error: E) -> HandlerError {
        HandlerError {
            source: error.into(),
        }
    }
}

impl fmt::Debug for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.source, f)
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::cbor_map;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Finding {
        topic: String,
    }

    impl Entry for Finding {
        const SCHEMA: &'static str = "com.acme.Finding#v1";
    }

    fn finding(topic: &str) -> Finding {
        Finding {
            topic: topic.to_owned(),
        }
    }

    #[test]
    fn entries_tags_forks_and_nothing_convert() {
        let reply: Reply = finding("a").into();
        assert_eq!(reply.schema(), Some("com.acme.Finding#v1"));
        assert_eq!(reply.payload_value(), Some(&cbor_map! { "topic" => "a" }));
        assert!(Reply::from(None::<Finding>).is_none());
        assert!(Reply::from(()).is_none());
        assert!(Reply::default().is_none());
        let tagged: Reply = Tagged::new(finding("b"), [("k", "v")]).tag("x", "y").into();
        assert_eq!(tagged.tags().get("k").and_then(Value::as_str), Some("v"));
        assert_eq!(tagged.tags().get("x").and_then(Value::as_str), Some("y"));
        let fork: Reply = vec![finding("c"), finding("d")].into();
        assert_eq!(fork.fork_elements().map(<[Reply]>::len), Some(2));
        let mixed = Reply::fork([Reply::entry(&finding("e")), Reply::none()]);
        assert!(mixed.is_fork());
        let value = Reply::value("x#v1", Value::Int(3)).with_tag("a", "b");
        assert_eq!(value.schema(), Some("x#v1"));
        assert_eq!(value.tags().len(), 1);
    }

    #[test]
    fn tags_on_nothing_or_a_fork_are_refused() {
        assert!(matches!(
            Reply::none().with_tag("a", "b").kind,
            ReplyKind::Invalid(_)
        ));
        assert!(matches!(
            Reply::fork(Vec::<Reply>::new()).with_tag("a", "b").kind,
            ReplyKind::Invalid(_)
        ));
        // No tags at all is no change.
        assert!(
            Reply::none()
                .with_tags(Vec::<(String, String)>::new())
                .is_none()
        );
    }

    #[test]
    fn handler_errors_convert_from_any_error() {
        fn fails() -> Result<(), HandlerError> {
            let parsed: Result<i32, _> = "x".parse::<i32>();
            parsed?;
            Ok(())
        }
        assert!(fails().is_err());
        let error = HandlerError::msg("boom");
        assert_eq!(error.to_string(), "boom");
        let from_text: HandlerError = "plain".into();
        assert_eq!(format!("{from_text}"), "plain");
    }
}
