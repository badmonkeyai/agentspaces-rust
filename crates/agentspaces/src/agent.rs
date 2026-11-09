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

//! Workers and cards: an agent binds `take` and `notify` handlers as closures, runs them over the
//! fleet's spaces under an agent identity of its own, and advertises what it does on an AgentCard.
//! The Java `AgentBinder` is the authority; the Ruby (`binder.rb`) and Python (`agents.py`) binders
//! are its siblings.
//!
//! ```no_run
//! # async fn run(fleet: agentspaces::space::Fleet) -> Result<(), Box<dyn std::error::Error>> {
//! use agentspaces::agent::{HandlerError, Reply, TakeContext};
//! use agentspaces::space::Lease;
//! use agentspaces::Entry;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, Entry)]
//! #[entry(schema = "shop.Order#v1")]
//! #[serde(rename_all = "camelCase")]
//! struct Order { order_id: String, item: String }
//!
//! #[derive(Serialize, Deserialize, Entry)]
//! #[entry(schema = "shop.Shipment#v1")]
//! #[serde(rename_all = "camelCase")]
//! struct Shipment { order_id: String, by: String }
//!
//! async fn ship(order: Order) -> Result<Shipment, HandlerError> {
//!     Ok(Shipment { order_id: order.order_id, by: "rust".into() })
//! }
//!
//! let bound = fleet
//!     .agent("fulfiller")
//!     .describe("Ships orders")
//!     .take("orders", Lease::parse("30s")?, |order: Order, ctx: TakeContext| async move {
//!         // renews the take's hold every 15 s while the shipment is made
//!         let shipment = ctx.keepalive(ship(order)).await?;
//!         Ok(Reply::from(shipment))
//!     })
//!     .action("ship")
//!     .produces::<Shipment>()
//!     .bind()
//!     .await?;
//! bound.stop_on_signals().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Binding
//!
//! [`Fleet::agent`] starts an [`AgentBuilder`]. Each `take` or `notify` adds a binding; the
//! modifiers that follow it ([`AgentBuilder::action`], [`AgentBuilder::parallel`],
//! [`AgentBuilder::produces`], [`AgentBuilder::where_clause`], ...) shape that binding.
//! [`AgentBuilder::bind`] checks everything, registers the reactions' watches, publishes the
//! card, and starts the loops; it answers a [`Bound`] handle.
//!
//! - The agent acts as `<peerId>/<name>` under a renewing subordinate identity of the peer
//!   ([`Peer::agent_identity`], 24-hour certificates as Java's binders mint them), so every
//!   record, claim, and completion it signs is AGENT_ATTESTED; [`AgentBuilder::identity`] gives
//!   it one made elsewhere.
//! - A take binding runs [`AgentBuilder::parallel`] loops (1 by default, Java's one thread per
//!   method), each taking with the poll timeout (1 s, Java `pollTimeout`) so a stop is seen, and
//!   running the handler on a task of its own with a [`TakeContext`].
//! - A notify binding watches its space and runs the handler once per entry (per kind, when
//!   several kinds are wanted) for each `Written` event by default, deduplicating redeliveries
//!   against the last 4096 ids (Java `AgentBinder.watch`), with at most 64 reactions at once
//!   unless [`AgentBuilder::parallel`] says otherwise; the others wait in a backlog of up to
//!   4096 while the watch is read on, and when the watch still falls behind and drops events,
//!   the space is read again so every entry written gets its reaction.
//!
//! What a handler answers follows the Java binder's return conventions ([`Reply`]): an entry,
//! nothing, a fork, a [`Tagged`] entry, or an error that lets the take lapse (logged at WARN
//! under [`HANDLER_LOG_TARGET`]).
//!
//! # The card
//!
//! Binding publishes the agent's AgentCard (SPEC §6.1) in Java's exact shape: the agent's key
//! and the certificate covering the card's issue instant, the flat `consumes` and `produces`
//! lists, the space bindings (a take's space for its schema, a reaction's only when no take
//! names the schema), and one declared action per binding (name, description, consumed schema,
//! produced schemas, space, kind), sorted by name with shared names disambiguated by their
//! consumed schemas (`AgentBinder.declared`). The card is signed by the peer, lives 15 minutes
//! (Java's TTL), and is republished every 5 minutes ([`AgentBuilder::card_refresh`]) with a
//! fresh issue instant. An agent found revoked stops (Java `unbind`) and its card lapses.
//!
//! Action names follow the Java rule: the handler's name ([`AgentBuilder::action`]). A closure
//! has none, so an unnamed binding is named as the Ruby binder names a block clause,
//! `<verb>_<index>` (`take_0`, `notify_1`): name the actions a fleet's callers see.
//!
//! # Stopping
//!
//! [`Bound::stop`] takes nothing new, lets running handlers finish within a grace period, and then
//! abandons them: an unfinished take is left to lapse and reappear. A take loop waiting for an
//! entry stops waiting at once and claims nothing more (Java's `Bound.close` interrupts it); a
//! claim it already made settles, and when it wins, its handler runs as a running one.
//! [`Bound::stop_on_signals`] does the same on SIGINT or SIGTERM (Ctrl-C elsewhere) with the
//! agent's grace (30 s by default, [`AgentBuilder::grace`]). Dropping the [`Bound`] does not
//! stop the agent: it runs until stopped or until the peer closes.

pub mod card;
pub mod context;
pub mod reply;
mod worker;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agentspaces_wire::ads::{self, AdError};
use agentspaces_wire::cbor::Map;
use agentspaces_wire::identity::AgentIdentity;
use tokio::task::{AbortHandle, JoinSet};

pub use card::{AgentCard, CardAction};
pub use context::{NotifyContext, TakeContext};
pub use reply::{HandlerError, Reply, Tagged};

use crate::entry::Entry;
use crate::peer::{Peer, PeerError};
use crate::space::{EntryView, EventKind, Fleet, Lease, Space, SpaceError, Template};
use worker::{
    BoxFuture, CardKeeper, Control, HandlerResult, NotifyFn, NotifyJob, NotifyRun, Results, TakeFn,
    TakeJob, TakeRun,
};

/// How long a stopping agent lets running handlers finish.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(30);

/// How often a bound agent republishes its card.
pub const DEFAULT_CARD_REFRESH: Duration = Duration::from_secs(5 * 60);

/// How long a published card lives (Java `AgentBinder.buildCard`, 15 minutes).
pub const DEFAULT_CARD_TTL: Duration = Duration::from_secs(15 * 60);

/// The lifetime of each certificate of a minted agent identity (Java's binders, 24 hours).
pub const DEFAULT_IDENTITY_TTL: &str = "PT24H";

/// How long one take of a take loop waits for an entry before it looks at the stop signal again
/// (Java `@SpaceTake.pollTimeout`, 1 s).
pub const DEFAULT_POLL: Duration = Duration::from_secs(1);

/// The shortest poll a take loop is allowed, so an idle loop never spins.
const MIN_POLL: Duration = Duration::from_millis(50);

/// How many reactions of one notify binding run at once unless [`AgentBuilder::parallel`] says.
pub const DEFAULT_NOTIFY_PARALLEL: usize = 64;

/// The `tracing` target of the warning a failed take handler logs (its entry's lease lapses):
/// a host that reports handler failures itself, as `aspace work` does, can filter it.
pub const HANDLER_LOG_TARGET: &str = "agentspaces::agent::handler";

/// Why an agent could not be bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The peer refused (closed, a revoked agent, an identity of another peer).
    #[error(transparent)]
    Peer(#[from] PeerError),
    /// A space verb refused (a filter that does not parse, a template of another schema).
    #[error(transparent)]
    Space(#[from] SpaceError),
    /// The card could not be built.
    #[error("the agent's card cannot be built: {0}")]
    Card(#[from] AdError),
    /// The agent's definition is refused: what is wrong, naming the binding.
    #[error("{0}")]
    Invalid(String),
}

// ---------------------------------------------------------------------------------------------
// Building

/// The verb of a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Take,
    Notify,
}

impl Verb {
    fn as_str(self) -> &'static str {
        match self {
            Verb::Take => ads::ACTION_TAKE,
            Verb::Notify => ads::ACTION_NOTIFY,
        }
    }
}

/// How a binding's handler runs.
enum Handler {
    Take(TakeFn),
    Notify(NotifyFn),
}

/// One `take` or `notify` binding as declared.
struct Binding {
    verb: Verb,
    space: String,
    schema: String,
    /// `Some` for a typed binding: its template must stay of this schema.
    typed: bool,
    template: Option<Template>,
    clauses: Vec<String>,
    tags: Vec<(String, String)>,
    lease: Lease,
    poll: Duration,
    parallel: Option<usize>,
    action: Option<String>,
    description: String,
    produces: Vec<String>,
    result_space: Option<String>,
    result_lease: Lease,
    kinds: Vec<EventKind>,
    handler: Handler,
}

impl Binding {
    fn new(
        verb: Verb,
        space: &str,
        schema: &str,
        typed: bool,
        lease: Lease,
        handler: Handler,
    ) -> Self {
        Binding {
            verb,
            space: space.to_owned(),
            schema: schema.to_owned(),
            typed,
            template: None,
            clauses: Vec::new(),
            tags: Vec::new(),
            lease,
            poll: DEFAULT_POLL,
            parallel: None,
            action: None,
            description: String::new(),
            produces: Vec::new(),
            result_space: None,
            result_lease: Lease::DEFAULT_RESULT,
            kinds: vec![EventKind::Written],
            handler,
        }
    }
}

/// An agent being defined ([`Fleet::agent`]); see the [module docs](self). The `take` and
/// `notify` methods add a binding; the modifiers after one shape it (a modifier before any
/// binding, or one that does not apply to its verb, is reported by [`AgentBuilder::bind`]).
#[must_use = "an agent does nothing until it is bound"]
pub struct AgentBuilder {
    fleet: Fleet,
    name: String,
    description: String,
    goals: Vec<String>,
    identity: Option<AgentIdentity>,
    identity_ttl: String,
    settle: Option<Duration>,
    card_refresh: Duration,
    card_ttl: Duration,
    publish_card: bool,
    grace: Duration,
    bindings: Vec<Binding>,
    errors: Vec<String>,
}

impl std::fmt::Debug for AgentBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentBuilder")
            .field("name", &self.name)
            .field("bindings", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

impl Fleet {
    /// Starts defining the agent `<peerId>/<name>` of this fleet member ([`AgentBuilder`]).
    pub fn agent(&self, name: &str) -> AgentBuilder {
        AgentBuilder {
            fleet: self.clone(),
            name: name.to_owned(),
            description: String::new(),
            goals: Vec::new(),
            identity: None,
            identity_ttl: DEFAULT_IDENTITY_TTL.to_owned(),
            settle: None,
            card_refresh: DEFAULT_CARD_REFRESH,
            card_ttl: DEFAULT_CARD_TTL,
            publish_card: true,
            grace: DEFAULT_GRACE,
            bindings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl AgentBuilder {
    // ------------------------------------------------------------------------- the agent

    /// The agent's description on its card (Java `@AgentSpec.description`).
    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// A goal the agent pursues, listed on its card (Java `@AgentSpec.goals`).
    pub fn goal(mut self, goal: impl Into<String>) -> Self {
        self.goals.push(goal.into());
        self
    }

    /// Acts under `identity` (an agent identity of this peer named `<peerId>/<name>`, as
    /// [`Peer::agent_identity`] mints them) instead of a freshly minted one: Java's
    /// `AgentIdentityFactory`. An identity of another name or peer is refused at bind.
    pub fn identity(mut self, identity: AgentIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The lifetime of each certificate of the minted identity (`java.time.Duration` text,
    /// [`DEFAULT_IDENTITY_TTL`]).
    pub fn identity_ttl(mut self, ttl_iso: impl Into<String>) -> Self {
        self.identity_ttl = ttl_iso.into();
        self
    }

    /// The settle window of the agent's takes ([`Space::with_settle`]; the space's default
    /// otherwise).
    pub fn settle(mut self, settle: Duration) -> Self {
        self.settle = Some(settle);
        self
    }

    /// How often the card is republished ([`DEFAULT_CARD_REFRESH`]).
    pub fn card_refresh(mut self, every: Duration) -> Self {
        self.card_refresh = every;
        self
    }

    /// How long each published card lives ([`DEFAULT_CARD_TTL`]); keep it longer than the
    /// refresh interval.
    pub fn card_ttl(mut self, ttl: Duration) -> Self {
        self.card_ttl = ttl;
        self
    }

    /// Publishes no card (Java's binder without a discovery service): the agent works, and no
    /// caller finds it.
    pub fn without_card(mut self) -> Self {
        self.publish_card = false;
        self
    }

    /// The grace period [`Bound::stop_on_signals`] gives running handlers ([`DEFAULT_GRACE`]).
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    // ------------------------------------------------------------------------- bindings

    /// Takes entries of `T`'s schema from `space`, holding each for `lease`, and runs `handler`
    /// on each with its [`TakeContext`] (Java `@SpaceTake`). Entries that do not decode as `T`
    /// are never claimed. What the handler answers completes the take ([`Reply`]).
    pub fn take<T, F, Fut>(mut self, space: &str, lease: Lease, handler: F) -> Self
    where
        T: Entry,
        F: Fn(T, TakeContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Reply, HandlerError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let take: TakeFn = Arc::new(move |space: Space, template: Template, lease, poll| {
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                let taken = space.take_typed::<T>(&template, lease, poll).await?;
                Ok(taken.map(|typed| {
                    let (taken, value) = typed.into_parts();
                    let job: TakeJob = Box::new(move |context| {
                        let run: BoxFuture<HandlerResult> = Box::pin(handler(value, context));
                        run
                    });
                    (taken, job)
                }))
            })
        });
        self.bindings.push(Binding::new(
            Verb::Take,
            space,
            T::SCHEMA,
            true,
            lease,
            Handler::Take(take),
        ));
        self
    }

    /// Takes entries of `schema` from `space` and runs `handler` on each entry as it is held
    /// (its raw payload, tags, and issuer) with its [`TakeContext`]: the value-level twin of
    /// [`AgentBuilder::take`] for the CLI and the bindings. `produces` declares the result
    /// schema on the card, and is the schema [`Reply::payload`] writes.
    pub fn take_value<F, Fut>(
        mut self,
        space: &str,
        schema: &str,
        produces: Option<String>,
        lease: Lease,
        handler: F,
    ) -> Self
    where
        F: Fn(EntryView, TakeContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Reply, HandlerError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let take: TakeFn = Arc::new(move |space: Space, template: Template, lease, poll| {
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                let taken = space.take(&template, lease, poll).await?;
                Ok(taken.map(|taken| {
                    let entry = taken.entry().clone();
                    let job: TakeJob = Box::new(move |context| {
                        let run: BoxFuture<HandlerResult> = Box::pin(handler(entry, context));
                        run
                    });
                    (taken, job)
                }))
            })
        });
        let mut binding =
            Binding::new(Verb::Take, space, schema, false, lease, Handler::Take(take));
        binding.produces.extend(produces);
        self.bindings.push(binding);
        self
    }

    /// Reacts to the entries of `T`'s schema written to `space` (Java `@SpaceNotify`): `handler`
    /// runs once per entry with its [`NotifyContext`], and what it answers is written into the
    /// space ([`Reply`]). Entries that do not decode as `T` are passed over.
    pub fn notify<T, F, Fut>(mut self, space: &str, handler: F) -> Self
    where
        T: Entry,
        F: Fn(T, NotifyContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Reply, HandlerError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let react: NotifyFn = Arc::new(move |entry: &EntryView| {
            let value = match entry.decode::<T>() {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(entry_id = %entry.entry_id(), %error, "a reaction passed over an entry that does not decode");
                    return None;
                }
            };
            let handler = Arc::clone(&handler);
            let job: NotifyJob = Box::new(move |context| {
                let run: BoxFuture<HandlerResult> = Box::pin(handler(value, context));
                run
            });
            Some(job)
        });
        self.bindings.push(Binding::new(
            Verb::Notify,
            space,
            T::SCHEMA,
            true,
            Lease::DEFAULT_NOTIFY,
            Handler::Notify(react),
        ));
        self
    }

    /// Reacts to the entries of `schema` written to `space`, each as it is held: the
    /// value-level twin of [`AgentBuilder::notify`]. `produces` declares the result schema.
    pub fn notify_value<F, Fut>(
        mut self,
        space: &str,
        schema: &str,
        produces: Option<String>,
        handler: F,
    ) -> Self
    where
        F: Fn(EntryView, NotifyContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Reply, HandlerError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let react: NotifyFn = Arc::new(move |entry: &EntryView| {
            let entry = entry.clone();
            let handler = Arc::clone(&handler);
            let job: NotifyJob = Box::new(move |context| {
                let run: BoxFuture<HandlerResult> = Box::pin(handler(entry, context));
                run
            });
            Some(job)
        });
        let mut binding = Binding::new(
            Verb::Notify,
            space,
            schema,
            false,
            Lease::DEFAULT_NOTIFY,
            Handler::Notify(react),
        );
        binding.produces.extend(produces);
        self.bindings.push(binding);
        self
    }

    // ------------------------------------------------------------------------- modifiers

    /// Applies `change` to the last binding, or records that `what` has no binding to apply to.
    fn last(mut self, what: &str, change: impl FnOnce(&mut Binding) -> Result<(), String>) -> Self {
        match self.bindings.last_mut() {
            Some(binding) => {
                if let Err(why) = change(binding) {
                    self.errors.push(why);
                }
            }
            None => self
                .errors
                .push(format!("{what} follows no take or notify binding")),
        }
        self
    }

    /// Names the last binding's action on the card (Java: the method's name). Unnamed bindings
    /// are `<verb>_<index>`.
    pub fn action(self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.last("action", |binding| {
            binding.action = Some(name);
            Ok(())
        })
    }

    /// Describes the last binding's action on the card (Java `@SpaceTake.description`, at most
    /// 512 characters); empty means the agent's description stands in.
    pub fn action_description(self, description: impl Into<String>) -> Self {
        let description = description.into();
        self.last("action_description", |binding| {
            binding.description = description;
            Ok(())
        })
    }

    /// Declares that the last binding produces entries of `O`'s schema (Java `produces`, or the
    /// method's return type): the card's action says so, so callers and catalogues find it.
    pub fn produces<O: Entry>(self) -> Self {
        self.produces_schema(O::SCHEMA)
    }

    /// Declares that the last binding produces entries of `schema`.
    pub fn produces_schema(self, schema: impl Into<String>) -> Self {
        let schema = schema.into();
        self.last("produces", |binding| {
            if !binding.produces.contains(&schema) {
                binding.produces.push(schema);
            }
            Ok(())
        })
    }

    /// How many entries the last binding handles at once: take loops for a take (1 by default),
    /// concurrent reactions for a notify ([`DEFAULT_NOTIFY_PARALLEL`]). At least 1.
    pub fn parallel(self, n: usize) -> Self {
        self.last("parallel", |binding| {
            if n == 0 {
                return Err("parallel needs at least 1".to_owned());
            }
            binding.parallel = Some(n);
            Ok(())
        })
    }

    /// How long each take of the last (take) binding waits before it looks at the stop signal
    /// again ([`DEFAULT_POLL`], at least 50 ms).
    pub fn poll(self, poll: Duration) -> Self {
        self.last("poll", |binding| {
            if binding.verb != Verb::Take {
                return Err("poll applies to a take binding".to_owned());
            }
            binding.poll = poll.max(MIN_POLL);
            Ok(())
        })
    }

    /// The write lease of the last binding's results ([`Lease::DEFAULT_RESULT`], 1 hour).
    pub fn result_lease(self, lease: Lease) -> Self {
        self.last("result_lease", |binding| {
            binding.result_lease = lease;
            Ok(())
        })
    }

    /// Writes the last binding's results into `space` (Java `resultSpace`): a take is then
    /// completed first and its result written there, not atomically.
    pub fn result_space(self, space: impl Into<String>) -> Self {
        let space = space.into();
        self.last("result_space", |binding| {
            binding.result_space = Some(space);
            Ok(())
        })
    }

    /// The template of the last binding, for conditions beyond its schema; it must be of the
    /// binding's schema.
    pub fn template(self, template: Template) -> Self {
        self.last("template", |binding| {
            binding.template = Some(template);
            Ok(())
        })
    }

    /// Narrows the last binding with a clause of the portable filter grammar (`"priority>=3"`,
    /// Java `where`); a clause that does not parse is reported at bind.
    pub fn where_clause(self, clause: impl Into<String>) -> Self {
        let clause = clause.into();
        self.last("where_clause", |binding| {
            binding.clauses.push(clause);
            Ok(())
        })
    }

    /// Narrows the last binding to entries whose tag `key` equals `value` (Java `tags`).
    pub fn tag_eq(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let pair = (key.into(), value.into());
        self.last("tag_eq", |binding| {
            binding.tags.push(pair);
            Ok(())
        })
    }

    /// The event kinds the last (notify) binding reacts to (Java `@SpaceNotify.on`; `Written`
    /// by default).
    pub fn on(self, kinds: &[EventKind]) -> Self {
        let kinds = kinds.to_vec();
        self.last("on", |binding| {
            if binding.verb != Verb::Notify {
                return Err("on applies to a notify binding".to_owned());
            }
            if kinds.is_empty() {
                return Err("a notify binding reacts to at least one event kind".to_owned());
            }
            binding.kinds = kinds;
            Ok(())
        })
    }

    // ------------------------------------------------------------------------- binding

    /// Binds the agent: checks the definition, takes its identity, registers the reactions'
    /// watches, publishes its card, and starts its loops.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for a definition Java's binder refuses (a modifier with no
    /// binding, more than 64 actions, action names that are not unique, a description over 512
    /// characters, a template of another schema, an identity of another agent) and for a take
    /// lease over [`Lease::MAX_TAKE`], which every take would refuse;
    /// [`AgentError::Space`] for a filter clause that does not parse; [`AgentError::Peer`] when
    /// the peer is closed or the agent revoked; [`AgentError::Card`] when the card cannot be
    /// built.
    pub async fn bind(self) -> Result<Bound, AgentError> {
        if let Some(first) = self.errors.first() {
            return Err(AgentError::Invalid(format!("agent {}: {first}", self.name)));
        }
        let peer = self.fleet.peer().clone();
        let expected = format!("{}/{}", peer.peer_id(), self.name);
        let identity = match self.identity {
            Some(identity) if identity.agent_id() == expected => identity,
            Some(identity) => {
                return Err(AgentError::Invalid(format!(
                    "the identity given is {}, not {expected}",
                    identity.agent_id()
                )));
            }
            None => peer.agent_identity(&self.name, &self.identity_ttl).await?,
        };
        if peer.is_revoked(identity.agent_id()).await {
            return Err(PeerError::Revoked(identity.agent_id().to_owned()).into());
        }
        let agent_id = identity.agent_id().to_owned();
        let local = identity.local_name().to_owned();
        let space_of = |name: &str| -> Space {
            let space = self.fleet.space(name).as_agent(identity.clone());
            match self.settle {
                Some(settle) => space.with_settle(settle),
                None => space,
            }
        };

        // The card's lists and actions, and each binding ready to run.
        let mut consumes: Vec<String> = Vec::new();
        let mut produces: Vec<String> = Vec::new();
        let mut space_bindings: Vec<(String, String)> = Vec::new();
        let mut actions: Vec<CardAction> = Vec::new();
        let mut takes: Vec<(Arc<TakeRun>, usize)> = Vec::new();
        let mut reactions: Vec<Arc<NotifyRun>> = Vec::new();
        for (index, binding) in self.bindings.into_iter().enumerate() {
            let name = binding
                .action
                .clone()
                .unwrap_or_else(|| format!("{}_{index}", binding.verb.as_str()));
            let label = format!("{local}.{name}");
            let template = template_of(&binding, &label)?;
            if binding.verb == Verb::Take && binding.lease > Lease::MAX_TAKE {
                // Every take would be refused: the agent would advertise work it never does.
                return Err(AgentError::Invalid(format!(
                    "{label}: a take may hold for {} at most, not {}",
                    Lease::MAX_TAKE,
                    binding.lease
                )));
            }
            push_unique(&mut consumes, &binding.schema);
            for schema in &binding.produces {
                push_unique(&mut produces, schema);
            }
            match binding.verb {
                // A take's space wins for its schema; a reaction's only when none names it.
                Verb::Take => {
                    space_bindings.retain(|(schema, _)| *schema != binding.schema);
                    space_bindings.push((binding.schema.clone(), binding.space.clone()));
                }
                Verb::Notify => {
                    if !space_bindings
                        .iter()
                        .any(|(schema, _)| *schema == binding.schema)
                    {
                        space_bindings.push((binding.schema.clone(), binding.space.clone()));
                    }
                }
            }
            actions.push(CardAction {
                name,
                description: binding.description.clone(),
                consumes: vec![binding.schema.clone()],
                produces: binding.produces.clone(),
                space: Some(binding.space.clone()),
                kind: binding.verb.as_str().to_owned(),
            });
            let results = Results {
                space: binding.result_space.as_deref().map(space_of),
                lease: binding.result_lease,
                produces: binding.produces.clone(),
            };
            match binding.handler {
                Handler::Take(take) => takes.push((
                    Arc::new(TakeRun {
                        label,
                        space: space_of(&binding.space),
                        template,
                        lease: binding.lease,
                        poll: binding.poll.max(MIN_POLL),
                        take,
                        results,
                    }),
                    binding.parallel.unwrap_or(1),
                )),
                Handler::Notify(react) => reactions.push(Arc::new(NotifyRun {
                    label,
                    space: space_of(&binding.space),
                    template,
                    kinds: binding.kinds,
                    parallel: binding.parallel.unwrap_or(DEFAULT_NOTIFY_PARALLEL),
                    react,
                    results,
                })),
            }
        }
        let actions = card::declared(actions)
            .map_err(|why| AgentError::Invalid(format!("agent {agent_id}: {why}")))?;
        let spec = card::CardSpec {
            group: peer.group_id().to_owned(),
            description: self.description,
            goals: self.goals,
            consumes,
            produces,
            space_bindings: space_bindings.into_iter().collect(),
            actions,
            ttl_iso: java_duration(self.card_ttl),
        };

        // The reactions watch from now on, before the agent is announced.
        let mut watches = Vec::with_capacity(reactions.len());
        for run in &reactions {
            watches.push(run.space.watch(&run.template).await?);
        }
        let keeper = Arc::new(CardKeeper {
            peer: peer.clone(),
            agent: identity.clone(),
            spec,
            refresh: self.card_refresh.max(Duration::from_millis(10)),
            card: std::sync::Mutex::new(None),
        });
        if self.publish_card {
            keeper.publish().await?;
        }

        let control = Control::new();
        let mut tasks = JoinSet::new();
        let mut aborts: Vec<AbortHandle> = Vec::new();
        for (run, parallel) in takes {
            for _ in 0..parallel.max(1) {
                aborts.push(tasks.spawn(worker::take_loop(Arc::clone(&run), control.clone())));
            }
        }
        for (run, events) in reactions.into_iter().zip(watches) {
            aborts.push(tasks.spawn(worker::notify_loop(run, events, control.clone())));
        }
        if self.publish_card {
            aborts.push(tasks.spawn(worker::card_loop(Arc::clone(&keeper), control.clone())));
        }
        // The loops belong to a supervisor of their own, not to the handle: dropping every
        // `Bound` leaves the agent running (Java keeps its handle in the binder), and the
        // supervisor says when the last loop has ended.
        let (ended_tx, ended) = tokio::sync::watch::channel(false);
        let supervised = agent_id.clone();
        tokio::spawn(supervise(tasks, supervised, ended_tx));
        Ok(Bound {
            inner: Arc::new(BoundInner {
                agent_id,
                identity,
                peer,
                keeper,
                control,
                grace: self.grace,
                ended,
                aborts: std::sync::Mutex::new(aborts),
            }),
        })
    }
}

/// The binding's template: its own (of its schema) or its schema's, narrowed by its clauses and
/// tags.
fn template_of(binding: &Binding, label: &str) -> Result<Template, AgentError> {
    let mut template = match &binding.template {
        Some(template) if template.schema() != binding.schema => {
            return Err(AgentError::Invalid(format!(
                "{label}: the template selects {}, not the binding's {}{}",
                template.schema(),
                binding.schema,
                if binding.typed {
                    " (its type's schema)"
                } else {
                    ""
                }
            )));
        }
        Some(template) => template.clone(),
        None => Template::new(binding.schema.clone()),
    };
    for clause in &binding.clauses {
        template = template.where_clause(clause)?;
    }
    for (key, value) in &binding.tags {
        template = template.tag_eq(key.clone(), value.clone());
    }
    Ok(template)
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|held| held == item) {
        list.push(item.to_owned());
    }
}

/// A duration as `java.time.Duration.toString` prints it (`PT15M`, `PT1H30M`, `PT0.5S`), whole
/// milliseconds.
pub(crate) fn java_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis == 0 {
        return "PT0S".to_owned();
    }
    let hours = millis / 3_600_000;
    let minutes = millis % 3_600_000 / 60_000;
    let seconds = millis % 60_000 / 1000;
    let fraction = millis % 1000;
    let mut text = String::from("PT");
    if hours > 0 {
        text.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        text.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 || fraction > 0 {
        text.push_str(&seconds.to_string());
        if fraction > 0 {
            let digits = format!("{fraction:03}");
            text.push('.');
            text.push_str(digits.trim_end_matches('0'));
        }
        text.push('S');
    }
    text
}

// ---------------------------------------------------------------------------------------------
// The bound agent

struct BoundInner {
    agent_id: String,
    identity: AgentIdentity,
    peer: Peer,
    keeper: Arc<CardKeeper>,
    control: Control,
    grace: Duration,
    /// Set by the supervisor once every loop has ended.
    ended: tokio::sync::watch::Receiver<bool>,
    aborts: std::sync::Mutex<Vec<AbortHandle>>,
}

/// Joins an agent's loops (each panic logged), then says they have all ended. Detached: the
/// loops run as long as it does, whoever still holds a [`Bound`].
async fn supervise(
    mut tasks: JoinSet<()>,
    agent_id: String,
    ended: tokio::sync::watch::Sender<bool>,
) {
    while let Some(done) = tasks.join_next().await {
        if let Err(error) = done
            && error.is_panic()
        {
            tracing::warn!("agentspaces: a loop of {agent_id} panicked");
        }
    }
    ended.send_replace(true);
}

/// A bound agent ([`AgentBuilder::bind`]): its loops, reactions, and card refresh, run until
/// [`Bound::stop`], a signal ([`Bound::stop_on_signals`]), the agent's revocation, or the peer's
/// close. Cheap to clone; every clone drives the same agent. Dropping it (every clone) does not
/// stop the agent: its loops run on until one of those, and only the handle to stop it is lost.
#[derive(Clone)]
pub struct Bound {
    inner: Arc<BoundInner>,
}

impl std::fmt::Debug for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bound")
            .field("agent_id", &self.inner.agent_id)
            .field("stopping", &self.inner.control.stopping())
            .finish()
    }
}

impl Bound {
    /// The agent's AgentID, `<peerId>/<name>`.
    pub fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }

    /// The identity the agent signs with.
    pub fn identity(&self) -> &AgentIdentity {
        &self.inner.identity
    }

    /// The peer underneath.
    pub fn peer(&self) -> &Peer {
        &self.inner.peer
    }

    /// The card last published (`None` for an agent bound [`AgentBuilder::without_card`]).
    pub fn card(&self) -> Option<AgentCard> {
        self.inner.keeper.current().and_then(AgentCard::parse)
    }

    /// The card last published, as its map.
    pub fn card_map(&self) -> Option<Map> {
        self.inner.keeper.current()
    }

    /// Publishes the card again now with a fresh issue instant (what the refresh does on its
    /// cadence).
    ///
    /// # Errors
    ///
    /// As [`AgentBuilder::bind`]'s card publication.
    pub async fn refresh_card(&self) -> Result<AgentCard, AgentError> {
        let card = self.inner.keeper.publish().await?;
        AgentCard::parse(card)
            .ok_or_else(|| AgentError::Invalid("the card published does not parse".to_owned()))
    }

    /// Whether the agent still takes and reacts: no stop was asked for (nor a revocation seen),
    /// and some loop still runs.
    pub fn is_running(&self) -> bool {
        !self.inner.control.stopping()
            && self
                .inner
                .aborts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|task| !task.is_finished())
    }

    /// How many takes completed and reactions were handled.
    pub fn handled(&self) -> u64 {
        self.inner.control.stats.handled.load(Ordering::Relaxed)
    }

    /// How many handlers failed (an error, a panic, or a reply that could not be written).
    pub fn failures(&self) -> u64 {
        self.inner.control.stats.failed.load(Ordering::Relaxed)
    }

    /// Asks the agent to take nothing new and returns at once; running handlers go on. A
    /// waiting take stops waiting and claims nothing more; a claim it already made settles (its
    /// settle window), and when it wins, its handler runs as a running one.
    pub fn request_stop(&self) {
        self.inner.control.request_stop();
    }

    /// Stops the agent: takes nothing new, lets running handlers finish within `grace`, then
    /// abandons the rest, whose takes lapse and reappear for other workers. Answers whether
    /// everything finished within `grace`. The card is no longer refreshed and lapses by its TTL.
    pub async fn stop(&self, grace: Duration) -> bool {
        self.request_stop();
        if tokio::time::timeout(grace, self.wait()).await.is_ok() {
            return true;
        }
        for task in self
            .inner
            .aborts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            task.abort();
        }
        self.wait().await;
        false
    }

    /// Waits until the agent has stopped: every loop ended (after [`Bound::stop`] or
    /// [`Bound::request_stop`], the agent's revocation, or the peer's close).
    pub async fn wait(&self) {
        let mut ended = self.inner.ended.clone();
        // An error means the supervisor is gone, which it only is once it said so (or the
        // runtime is shutting down): either way nothing runs any more.
        let _ = ended.wait_for(|ended| *ended).await;
    }

    /// Runs until SIGINT or SIGTERM (Ctrl-C where there are no Unix signals), then stops with
    /// the agent's grace ([`AgentBuilder::grace`], 30 s by default); returns early when the agent
    /// stops on its own. Answers whether everything finished within the grace.
    ///
    /// # Errors
    ///
    /// When the signal handlers cannot be installed.
    pub async fn stop_on_signals(&self) -> std::io::Result<bool> {
        tokio::select! {
            signalled = shutdown_signal() => {
                signalled?;
                tracing::info!("agentspaces: {} stopping on a signal", self.inner.agent_id);
                Ok(self.stop(self.inner.grace).await)
            }
            () = self.wait() => Ok(true),
        }
    }
}

/// Resolves on SIGINT or SIGTERM.
#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    Ok(())
}

/// Resolves on Ctrl-C.
#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::time;

    #[test]
    fn durations_print_as_java_prints_them() {
        for (millis, text) in [
            (15 * 60_000, "PT15M"),
            (5_400_000, "PT1H30M"),
            (24 * 3_600_000, "PT24H"),
            (2_000, "PT2S"),
            (500, "PT0.5S"),
            (61_250, "PT1M1.25S"),
            (0, "PT0S"),
        ] {
            let printed = java_duration(Duration::from_millis(millis));
            assert_eq!(printed, text);
            assert!(time::is_canonical_duration(&printed), "{printed}");
            if millis > 0 {
                assert_eq!(
                    time::parse_duration_millis(&printed).ok(),
                    i64::try_from(millis).ok()
                );
            }
        }
    }
}
