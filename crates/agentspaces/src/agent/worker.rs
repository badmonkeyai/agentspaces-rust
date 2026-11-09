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

//! The running half of a bound agent: the take loops (Java `AgentBinder.startTakeLoop`,
//! `AgentBinder.java` 860-904), the deduplicated reactions (`subscribe` and `watch`, 906-975),
//! the return dispatch (`dispatch`, 1854-1930), and the card refresh (`refreshCards`, 733-756).

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agentspaces_wire::ads::AD_TYPE_AGENT_CARD;
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::identity::AgentIdentity;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::{JoinError, JoinSet};

use super::card::CardSpec;
use super::context::{NotifyContext, TakeContext};
use super::reply::{HandlerError, Reply, ReplyKind};
use crate::peer::{Peer, PeerError};
use crate::space::{EntryView, EventKind, Lease, Space, SpaceError, SpaceEvents, Taken, Template};

/// How many entry ids a reaction remembers to drop redeliveries (Java
/// `AgentBinder.NOTIFY_DEDUP_CAPACITY`).
pub(crate) const NOTIFY_DEDUP_CAPACITY: usize = 4096;

/// The pause after a take that failed, before the next (`agents.py`'s half second).
const RETRY_PAUSE: Duration = Duration::from_millis(500);

/// A boxed, sendable future.
pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What a handler answers.
pub(crate) type HandlerResult = Result<Reply, HandlerError>;

/// One run of a take handler, over the take's context.
pub(crate) type TakeJob = Box<dyn FnOnce(TakeContext) -> BoxFuture<HandlerResult> + Send>;

/// One take of a binding: the take (typed or not) and the job its handler runs.
pub(crate) type TakeFn = Arc<
    dyn Fn(
            Space,
            Template,
            Lease,
            Duration,
        ) -> BoxFuture<Result<Option<(Taken, TakeJob)>, SpaceError>>
        + Send
        + Sync,
>;

/// One run of a reaction, over the event's context.
pub(crate) type NotifyJob = Box<dyn FnOnce(NotifyContext) -> BoxFuture<HandlerResult> + Send>;

/// A reaction of a binding: the job for an event's entry, or `None` when the entry does not
/// decode as the binding's type (passed over, as a Java template of the class passes it over).
pub(crate) type NotifyFn = Arc<dyn Fn(&EntryView) -> Option<NotifyJob> + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// The control every task of one bound agent shares

/// What a bound agent has counted.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    /// Takes completed and reactions dispatched.
    pub handled: AtomicU64,
    /// Handlers that failed (an error, a panic, a reply that could not be written).
    pub failed: AtomicU64,
}

/// The stop signal and counters of one bound agent.
#[derive(Debug, Clone)]
pub(crate) struct Control {
    stop: Arc<watch::Sender<bool>>,
    pub stats: Arc<Stats>,
}

impl Control {
    pub fn new() -> Control {
        Control {
            stop: Arc::new(watch::channel(false).0),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Asks every loop to take nothing new.
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    /// The stop signal, for the takes of the loops ([`Space::halting_on`]).
    pub fn halt(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Whether a stop was asked for.
    pub fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    /// Resolves once a stop is asked for.
    pub async fn stopped(&self) {
        let mut stop = self.stop.subscribe();
        let _ = stop.wait_for(|stopping| *stopping).await;
    }

    /// Waits `pause`, or less when a stop is asked for meanwhile.
    async fn pause(&self, pause: Duration) {
        let _ = tokio::time::timeout(pause, self.stopped()).await;
    }

    fn failed(&self) {
        self.stats.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn handled(&self) {
        self.stats.handled.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------------------------
// What a running binding knows

/// The result side of a binding: where and for how long its results are written, and what it
/// declares it produces.
#[derive(Debug, Clone)]
pub(crate) struct Results {
    /// The space results are written into when it is not the take's: `None` writes a take's
    /// result with its completion, atomically, and a reaction's into the watched space.
    pub space: Option<Space>,
    /// The results' write lease.
    pub lease: Lease,
    /// The schemas the binding declares it produces.
    pub produces: Vec<String>,
}

impl Results {
    /// The one schema the binding declares, when it declares exactly one.
    pub fn produced(&self) -> Option<&str> {
        match self.produces.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The schema, payload, and tags of an entry reply; `Err` for a [`Reply::payload`] with no
    /// single declared schema, or an invalid reply.
    fn entry_of(&self, kind: ReplyKind, label: &str) -> Result<(String, Value, Map), String> {
        match kind {
            ReplyKind::Entry {
                schema,
                payload,
                tags,
            } => {
                if !self.produces.is_empty() && !self.produces.contains(&schema) {
                    // Ruby's `check_produces`, not strict: the card says less than the write.
                    tracing::warn!(
                        "agentspaces: {label} wrote {schema}, which its binding does not declare it produces"
                    );
                }
                Ok((schema, payload, tags))
            }
            ReplyKind::Payload { payload, tags } => match self.produced() {
                Some(schema) => Ok((schema.to_owned(), payload, tags)),
                None => Err(format!(
                    "{label} answered a payload, but its binding declares {} produced schemas, \
                     not one",
                    self.produces.len()
                )),
            },
            ReplyKind::Invalid(why) => Err(format!("{label}: {why}")),
            ReplyKind::None | ReplyKind::Fork(_) => Err(format!("{label}: not an entry reply")),
        }
    }
}

/// A take binding, ready to run.
pub(crate) struct TakeRun {
    pub label: String,
    pub space: Space,
    pub template: Template,
    pub lease: Lease,
    pub poll: Duration,
    pub take: TakeFn,
    pub results: Results,
}

/// A reaction binding, ready to run.
pub(crate) struct NotifyRun {
    pub label: String,
    pub space: Space,
    pub template: Template,
    pub kinds: Vec<EventKind>,
    pub parallel: usize,
    pub react: NotifyFn,
    pub results: Results,
}

// ---------------------------------------------------------------------------------------------
// Takes

/// One take loop (Java `startTakeLoop`): take with the poll timeout so a stop is seen, run the
/// handler on a task of its own (a panic is a failure like an error), dispatch its reply. A
/// failed handler completes nothing, so the hold lapses and the entry reappears. Ends on a stop,
/// when the peer closes, or when the agent is revoked (which stops the whole agent, as Java's
/// `unbind` does).
pub(crate) async fn take_loop(run: Arc<TakeRun>, control: Control) {
    loop {
        if control.stopping() {
            return;
        }
        // The take heeds the stop: once asked, it claims nothing more and stops waiting
        // (Java's `Bound.close` interrupts a waiting take); a claim already made settles and its
        // handler runs, within the grace.
        let space = run.space.halting_on(control.halt());
        let taken = (run.take)(space, run.template.clone(), run.lease, run.poll).await;
        match taken {
            Ok(None) => {
                // An idle loop claims nothing, so it learns of a revocation here.
                if let Some(agent) = run.space.agent()
                    && run.space.peer().is_revoked(agent.agent_id()).await
                {
                    tracing::warn!(
                        "agentspaces: {}: {} is revoked; the agent stops",
                        run.label,
                        agent.agent_id()
                    );
                    control.request_stop();
                    return;
                }
            }
            Ok(Some((taken, job))) => {
                let context =
                    TakeContext::new(taken, run.lease, run.results.produced().map(str::to_owned));
                run_take(&run, &control, context, job).await;
            }
            Err(SpaceError::Peer(PeerError::Closed)) => return,
            Err(SpaceError::Peer(PeerError::Revoked(who))) => {
                tracing::warn!(
                    "agentspaces: {}: {who} is revoked; the agent stops",
                    run.label
                );
                control.request_stop();
                return;
            }
            Err(SpaceError::InvalidLease(why)) => {
                // No retry can succeed: the binding's own lease is refused.
                tracing::warn!("agentspaces: {}: {why}; the agent stops", run.label);
                control.request_stop();
                return;
            }
            Err(error) => {
                tracing::warn!("agentspaces: {}: take failed: {error}", run.label);
                control.pause(RETRY_PAUSE).await;
            }
        }
    }
}

/// Runs one taken entry's handler and dispatches what it answers.
async fn run_take(run: &TakeRun, control: &Control, context: TakeContext, job: TakeJob) {
    let entry_id = context.entry_id().clone();
    let mut handler = JoinSet::new();
    handler.spawn(job(context.clone()));
    let outcome = match handler.join_next().await {
        Some(Ok(outcome)) => outcome,
        Some(Err(error)) => Err(HandlerError::msg(join_failure(&error))),
        None => Err(HandlerError::msg("the handler did not run")),
    };
    match outcome {
        Err(error) => {
            // The crash idiom: no completion, the hold lapses, and the entry reappears for
            // another worker (SPEC §7.2).
            control.failed();
            tracing::warn!(
                target: super::HANDLER_LOG_TARGET,
                "agentspaces: {}: action failed on entry {entry_id}; lease will lapse: {error}",
                run.label
            );
        }
        Ok(reply) => match dispatch_take(run, &context, reply).await {
            Ok(()) => control.handled(),
            Err(error) => {
                control.failed();
                tracing::warn!("agentspaces: {}: entry {entry_id}: {error}", run.label);
            }
        },
    }
}

/// The return handling of a take (Java `dispatch` with a take): nothing completes without a
/// result; a fork completes once and then writes each element; an entry completes with it in
/// the same space (atomically) or, with another result space, completes and then writes it
/// there. A reply that cannot be written completes nothing (the hold lapses).
async fn dispatch_take(run: &TakeRun, context: &TakeContext, reply: Reply) -> Result<(), String> {
    let taken = context.taken().lock().await;
    let results = &run.results;
    match reply.kind {
        ReplyKind::None => {
            complete(&taken, None, results.lease).await?;
        }
        ReplyKind::Fork(elements) => {
            // The take is finished first, as Java's `AgentBinder.dispatch` completes a fork's
            // take once before it dispatches the elements: a failed element cannot make a
            // completed task reappear.
            complete(&taken, None, results.lease).await?;
            drop(taken);
            let target = results.space.clone().unwrap_or_else(|| run.space.clone());
            write_fork(&run.label, elements, &target, results).await?;
        }
        ReplyKind::Invalid(why) => return Err(format!("{why}; lease will lapse")),
        kind @ (ReplyKind::Entry { .. } | ReplyKind::Payload { .. }) => {
            let (schema, payload, tags) = results
                .entry_of(kind, &run.label)
                .map_err(|why| format!("{why}; lease will lapse"))?;
            match &results.space {
                None => {
                    taken
                        .complete(Some((&schema, payload)), results.lease, tags)
                        .await
                        .map_err(|error| format!("complete failed: {error}"))?;
                }
                Some(target) => {
                    complete(&taken, None, results.lease).await?;
                    drop(taken);
                    target
                        .write_value(&schema, payload, results.lease, tags)
                        .await
                        .map_err(|error| format!("result write failed: {error}"))?;
                }
            }
        }
    }
    Ok(())
}

async fn complete(
    taken: &Taken,
    result: Option<(&str, Value)>,
    lease: Lease,
) -> Result<(), String> {
    taken
        .complete(result, lease, Map::new())
        .await
        .map(|_| ())
        .map_err(|error| format!("complete failed: {error}"))
}

/// Writes each element of a fork into `target`, as if answered alone (Java `Entries`): nothing
/// for a [`Reply::none`], and a fork inside the fork refused when it is reached.
async fn write_fork(
    label: &str,
    elements: Vec<Reply>,
    target: &Space,
    results: &Results,
) -> Result<(), String> {
    for element in elements {
        match element.kind {
            ReplyKind::None => {}
            ReplyKind::Fork(_) => return Err(format!("{label} returned a fork inside a fork")),
            kind => {
                let (schema, payload, tags) = results.entry_of(kind, label)?;
                target
                    .write_value(&schema, payload, results.lease, tags)
                    .await
                    .map_err(|error| format!("a forked write failed: {error}"))?;
            }
        }
    }
    Ok(())
}

/// What a handler task's failure says.
fn join_failure(error: &JoinError) -> String {
    if error.is_panic() {
        "the handler panicked".to_owned()
    } else {
        "the handler was cancelled".to_owned()
    }
}

// ---------------------------------------------------------------------------------------------
// Reactions

/// The entry ids (or `id:kind` keys) a reaction has handled, the oldest forgotten first past
/// [`NOTIFY_DEDUP_CAPACITY`] (Java's bounded `seen` set).
#[derive(Debug, Default)]
struct Seen {
    keys: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    /// Whether `key` is new (and now remembered).
    fn insert(&mut self, key: String) -> bool {
        if self.keys.contains(&key) {
            return false;
        }
        if self.order.len() >= NOTIFY_DEDUP_CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.keys.remove(&oldest);
        }
        self.order.push_back(key.clone());
        self.keys.insert(key);
        true
    }
}

/// One reaction loop (Java `subscribe` over `watch`): each event of a wanted kind, once per
/// entry (per kind, when several are wanted), runs the handler on a task of its own, at most
/// `parallel` at once, and writes what it answers. On a stop the loop stops reading and lets
/// the reactions already running finish; reactions queued and not yet started are dropped.
///
/// The watch is read on, into a local backlog of up to [`NOTIFY_DEDUP_CAPACITY`] reactions,
/// while every permit is busy, so slow reactions do not make the watch's own queue overflow.
/// When it does overflow anyway (the backlog is full too), the dropped events are said at WARN
/// and, for a binding that reacts to `Written`, the space is read again and every available
/// entry not yet reacted to gets its reaction (Java runs each delivered event at once, so it
/// drops none).
pub(crate) async fn notify_loop(run: Arc<NotifyRun>, mut events: SpaceEvents, control: Control) {
    let mut seen = Seen::default();
    let permits = Arc::new(Semaphore::new(run.parallel.max(1)));
    let mut reactions: JoinSet<Result<(), String>> = JoinSet::new();
    let mut backlog: VecDeque<(NotifyJob, NotifyContext)> = VecDeque::new();
    let mut dropped = events.dropped();
    loop {
        // Start what the free permits allow, oldest first.
        while !backlog.is_empty() {
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                break;
            };
            let Some((job, context)) = backlog.pop_front() else {
                break;
            };
            spawn_reaction(&run, &mut reactions, job, context, permit);
        }
        let room = backlog.len() < NOTIFY_DEDUP_CAPACITY;
        tokio::select! {
            () = control.stopped() => break,
            Some(done) = reactions.join_next(), if !reactions.is_empty() => {
                reaction_done(&run.label, &control, done);
            }
            event = events.next(), if room => {
                let Some(event) = event else { break };
                if run.kinds.contains(&event.kind) {
                    queue_reaction(&run, &mut seen, &mut backlog, event.entry, event.kind);
                }
            }
        }
        let now_dropped = events.dropped();
        if now_dropped != dropped {
            let lost = now_dropped.wrapping_sub(dropped);
            dropped = now_dropped;
            recover(&run, &mut seen, &mut backlog, lost).await;
        }
    }
    drop(events);
    if !backlog.is_empty() {
        tracing::debug!(
            "agentspaces: {}: {} queued reactions were not started before the stop",
            run.label,
            backlog.len()
        );
    }
    while let Some(done) = reactions.join_next().await {
        reaction_done(&run.label, &control, done);
    }
}

/// Queues the reaction to `entry` for `kind`, unless it is a redelivery this binding already
/// reacted to, or the entry does not decode as the binding's type.
fn queue_reaction(
    run: &NotifyRun,
    seen: &mut Seen,
    backlog: &mut VecDeque<(NotifyJob, NotifyContext)>,
    entry: EntryView,
    kind: EventKind,
) {
    let key = if run.kinds.len() == 1 {
        entry.entry_id().to_string()
    } else {
        format!("{}:{kind}", entry.entry_id())
    };
    if !seen.insert(key) {
        return; // a redelivery of an event this agent already handled
    }
    let Some(job) = (run.react)(&entry) else {
        return;
    };
    let context = NotifyContext {
        entry,
        kind,
        space: run.space.clone(),
        produces: run.results.produced().map(str::to_owned),
    };
    backlog.push_back((job, context));
}

/// Runs one reaction on a task of its own, holding its permit until it ends.
fn spawn_reaction(
    run: &Arc<NotifyRun>,
    reactions: &mut JoinSet<Result<(), String>>,
    job: NotifyJob,
    context: NotifyContext,
    permit: OwnedSemaphorePermit,
) {
    let run = Arc::clone(run);
    reactions.spawn(async move {
        let _permit = permit;
        let reply = job(context)
            .await
            .map_err(|error| format!("notify failed: {error}"))?;
        let target = run
            .results
            .space
            .clone()
            .unwrap_or_else(|| run.space.clone());
        dispatch_reaction(&run.label, reply, &target, &run.results).await
    });
}

/// After the watch dropped `lost` events: says so, and for a binding that reacts to `Written`,
/// reads the space again and queues a reaction for each available entry not yet reacted to
/// (as far as the backlog has room).
async fn recover(
    run: &NotifyRun,
    seen: &mut Seen,
    backlog: &mut VecDeque<(NotifyJob, NotifyContext)>,
    lost: u64,
) {
    if !run.kinds.contains(&EventKind::Written) {
        tracing::warn!(
            "agentspaces: {}: the watch fell behind and dropped {lost} events; their reactions              are lost",
            run.label
        );
        return;
    }
    let room = NOTIFY_DEDUP_CAPACITY.saturating_sub(backlog.len());
    let present = match run
        .space
        .read_all(&run.template, NOTIFY_DEDUP_CAPACITY)
        .await
    {
        Ok(present) => present,
        Err(error) => {
            tracing::warn!(
                "agentspaces: {}: the watch fell behind and dropped {lost} events, and the                  space could not be read again: {error}",
                run.label
            );
            return;
        }
    };
    let before = backlog.len();
    for entry in present {
        if backlog.len() - before >= room {
            break;
        }
        queue_reaction(run, seen, backlog, entry, EventKind::Written);
    }
    tracing::warn!(
        "agentspaces: {}: the watch fell behind and dropped {lost} events; the space was read          again and {} entries not yet reacted to were queued",
        run.label,
        backlog.len() - before
    );
}

fn reaction_done(label: &str, control: &Control, done: Result<Result<(), String>, JoinError>) {
    match done {
        Ok(Ok(())) => control.handled(),
        Ok(Err(why)) => {
            control.failed();
            tracing::warn!("agentspaces: {label}: {why}");
        }
        Err(error) => {
            control.failed();
            tracing::warn!("agentspaces: {label}: {}", join_failure(&error));
        }
    }
}

/// The return handling of a reaction (Java `dispatch` without a take): nothing, each element of
/// a fork, or the entry written into `target` with its tags.
async fn dispatch_reaction(
    label: &str,
    reply: Reply,
    target: &Space,
    results: &Results,
) -> Result<(), String> {
    match reply.kind {
        ReplyKind::None => Ok(()),
        ReplyKind::Fork(elements) => write_fork(label, elements, target, results).await,
        kind => {
            let (schema, payload, tags) = results.entry_of(kind, label)?;
            target
                .write_value(&schema, payload, results.lease, tags)
                .await
                .map(|_| ())
                .map_err(|error| format!("result write failed: {error}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The card

/// The card a bound agent publishes and keeps fresh.
#[derive(Debug)]
pub(crate) struct CardKeeper {
    pub peer: Peer,
    pub agent: AgentIdentity,
    pub spec: CardSpec,
    pub refresh: Duration,
    pub card: Mutex<Option<Map>>,
}

impl CardKeeper {
    /// Builds the card at the peer's now, with the agent's certificate covering it (renewed at
    /// half-life first), and publishes it on the `ads` stream; keeps it as the current card.
    pub async fn publish(&self) -> Result<Map, super::AgentError> {
        let spec = self.spec.clone();
        let card = self
            .peer
            .with_signer(Some(self.agent.clone()), move |peer, agent, now| {
                agent
                    .ok_or(agentspaces_wire::ads::AdError::CertificateMismatch)
                    .and_then(|agent| spec.build(peer, agent, now))
            })
            .await??;
        self.peer
            .publish_ad(AD_TYPE_AGENT_CARD, card.clone())
            .await?;
        *self.card.lock().unwrap_or_else(PoisonError::into_inner) = Some(card.clone());
        Ok(card)
    }

    /// The card last published.
    pub fn current(&self) -> Option<Map> {
        self.card
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Republishes the card every `refresh` with a fresh issue instant (Java `refreshCards`) until
/// a stop; an agent found revoked stops instead (Java `unbind`: its card then lapses by TTL).
pub(crate) async fn card_loop(keeper: Arc<CardKeeper>, control: Control) {
    loop {
        if tokio::time::timeout(keeper.refresh, control.stopped())
            .await
            .is_ok()
        {
            return;
        }
        if keeper.peer.is_revoked(keeper.agent.agent_id()).await {
            tracing::warn!(
                "agentspaces: {} is revoked; the agent stops and its card lapses",
                keeper.agent.agent_id()
            );
            control.request_stop();
            return;
        }
        match keeper.publish().await {
            Ok(_) => {}
            Err(super::AgentError::Peer(PeerError::Closed)) => return,
            Err(super::AgentError::Peer(PeerError::Revoked(who))) => {
                tracing::warn!("agentspaces: {who} is revoked; the agent stops");
                control.request_stop();
                return;
            }
            Err(error) => {
                tracing::warn!(
                    "agentspaces: {}: card refresh failed: {error}",
                    keeper.agent.agent_id()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_forgets_the_oldest_past_its_capacity() {
        let mut seen = Seen::default();
        assert!(seen.insert("a".to_owned()));
        assert!(!seen.insert("a".to_owned()));
        for n in 0..NOTIFY_DEDUP_CAPACITY {
            assert!(seen.insert(format!("k{n}")));
        }
        // "a" was the oldest and is forgotten; the newest are still remembered.
        assert!(seen.insert("a".to_owned()));
        assert!(!seen.insert(format!("k{}", NOTIFY_DEDUP_CAPACITY - 1)));
        assert_eq!(seen.keys.len(), NOTIFY_DEDUP_CAPACITY);
    }
}
