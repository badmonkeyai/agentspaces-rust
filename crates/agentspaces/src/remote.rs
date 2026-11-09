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

//! Remote actions (SPEC §10.6, TECH-SPEC §9.3): the actions the fleet's live, unrevoked
//! AgentCards declare, each invocable by writing its input entry where the advertising agent
//! takes from and awaiting the result that correlates with it. The Java `RemoteActions`,
//! `RemoteAction`, and `Correlation` are the authority; Ruby's `Capabilities::RemoteActions` is
//! the sibling.
//!
//! ```no_run
//! # async fn run(fleet: agentspaces::space::Fleet) -> Result<(), agentspaces::space::SpaceError> {
//! use std::time::Duration;
//! use agentspaces::remote::RemoteActions;
//! use agentspaces::wire::cbor_map;
//!
//! let remote = RemoteActions::new(&fleet);
//! for action in remote.consuming("com.acme.Task#v1").await {
//!     let input = cbor_map! { "topic" => "rust", "priority" => 1 };
//!     match remote.invoke(&action, input.into(), Duration::from_secs(30)).await? {
//!         Some(result) => println!("{} answered {:?}", action.agent(), result.payload()),
//!         None => println!("no answer yet; the task stays leased"),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Which actions
//!
//! [`RemoteActions::available`] reads the cards the peer holds
//! ([`Peer::cards`](crate::peer::Peer::cards): live, verified, and without those of a revoked
//! peer, agent, or agent key), never this peer's own unless [`RemoteActions::include_own`] says
//! so, newest first (Java `RemoteActions.available`):
//!
//! - a card that declares actions yields one remote action per invocable declared action
//!   (`take`, `notify`, `ordered-take`, `embabel-action`) and pair of its consumed and produced
//!   schemas; a card from before v0.1.13 yields the cross product of its flat lists; either way
//!   at most [`MAX_SCHEMAS_PER_LIST`] schemas of a list and [`MAX_PAIRS_PER_CARD`] pairs of a
//!   card count, so a small hostile card cannot make every reader build millions of actions;
//! - the input goes to an explicit route for its schema ([`RemoteActions::route`]), else the
//!   space the action declares, else the card's space binding for the schema, a space a card
//!   names only among [`RemoteActions::spaces`] when set (card text is its publisher's); an
//!   action with none is not invocable and is passed over. Results are awaited in the input's
//!   space unless [`RemoteActions::results_in`] says otherwise, as a take completes there by
//!   default;
//! - an older refresh of the same capability (the same agent, action, and schemas) than one
//!   already listed is passed over (a newer card this caller cannot route does not hide it).
//!
//! Card text flows into planners' and tools' prompts, so [`RemoteAction::description`] is
//! stripped of control characters and capped at 500 characters, as Java does.
//!
//! # Invoking
//!
//! [`RemoteActions::invoke`] (Java `RemoteAction.invoke`): the results already present are
//! noted (a multiset of their payloads), a watch of the produced schema starts before the input
//! is written (so no result slips between them), the input is written for the write lease
//! (10 minutes), and the first result that correlates ([`Correlation::shared_fields`] by default)
//! is answered: the watch's `Written` events as they come, and the results present that were not
//! before the write when the watch fell behind and dropped events. The wait is the watch's; it
//! never polls. At the timeout the answer is `None` and the input stays where it was written,
//! leased (it is not cancelled): a worker may still answer it.
//!
//! One guard is added to Java's: a result issued before the input (by HLC stamp) cannot answer
//! it, so a result an earlier call left behind, which a peer that opened the space just now
//! learns of only after its baseline was read, is never taken for this call's answer. Every
//! member merges the stamps it folds into its clock, so a genuine answer is always issued after
//! its input.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::ads;
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::hlc::Stamp;
use agentspaces_wire::identity::AgentIdentity;
use tokio::time::Instant;

use crate::agent::{AgentCard, CardAction};
use crate::entry::{Entry, EntryError};
use crate::peer::PeerError;
use crate::space::{
    EntryId, EntryView, EventKind, Fleet, Lease, Space, SpaceError, Template, TypedView,
};

/// The longest card text surfaced to planners and tools (Java `RemoteAction.MAX_CARD_TEXT`).
pub const MAX_CARD_TEXT: usize = 500;

/// How many results present before an invocation are noted (Java's `readAll(..., 1_000)`).
const BASELINE_LIMIT: usize = 1000;

/// How often an invocation looks whether its watch fell behind and dropped events.
const BACKSTOP: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------------------------
// Correlation

/// Decides whether a result entry answers a request entry (Java `Correlation`): an invocation
/// is a write followed by a wait, and the space may carry results for other requests too.
#[derive(Clone)]
pub struct Correlation {
    matches: Arc<Matcher>,
}

/// A correlation's test over the input's and a candidate's payloads.
type Matcher = dyn Fn(&Value, &Value) -> bool + Send + Sync;

impl Correlation {
    /// The default (Java `Correlation.sharedFields`): every field the request and the candidate
    /// both carry holds equal values ([`shared_fields`]).
    pub fn shared_fields() -> Correlation {
        Correlation::new(shared_fields)
    }

    /// Any result observed after the write; the first one wins (Java `Correlation.any`).
    pub fn any() -> Correlation {
        Correlation::new(|_, _| true)
    }

    /// A correlation of the caller's: `matches(input payload, candidate payload)`.
    pub fn new(matches: impl Fn(&Value, &Value) -> bool + Send + Sync + 'static) -> Correlation {
        Correlation {
            matches: Arc::new(matches),
        }
    }

    /// Whether `candidate` answers `input` (both payloads).
    pub fn matches(&self, input: &Value, candidate: &Value) -> bool {
        (self.matches)(input, candidate)
    }
}

impl Default for Correlation {
    fn default() -> Self {
        Correlation::shared_fields()
    }
}

impl fmt::Debug for Correlation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Correlation")
    }
}

/// Java `Correlation.sharedFields` over payloads: the fields (map keys) both carry must hold
/// equal values; a field only one carries does not count. Payloads that share no field, or
/// that are not maps (Java: types that are not records), correlate, since nothing ties a result
/// to a request more specifically. A field carried as null on both sides is equal.
///
/// Values compare by meaning ([`same_value`]), as Java compares decoded record components and
/// maps: a nested map equals one with the same entries in another order (a JSON input keeps the
/// order it was typed in, a Java or serde map is written in its own), and an integer equals a
/// double of the same integral value (an untyped JSON `100` meets a Java `double` field's
/// `100.0`).
pub fn shared_fields(input: &Value, candidate: &Value) -> bool {
    let (Some(input), Some(candidate)) = (input.as_map(), candidate.as_map()) else {
        return true;
    };
    input.iter().all(|(field, value)| {
        candidate
            .get_value(field)
            .is_none_or(|other| same_value(other, value))
    })
}

/// How many entries a map may hold before [`same_value`] looks its keys up through a hash
/// table instead of scanning.
const SCANNED_MAP: usize = 16;

/// Whether two payload values mean the same: maps hold the same keys with values that mean the
/// same, whatever their order; arrays hold values that mean the same, in order; an integer and
/// a finite double mean the same when the double is integral and equal to it; anything else
/// compares as [`Value`] does (a double by its bits, as Java's `Double.equals`).
pub fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Map(a), Value::Map(b)) => {
            if a.len() != b.len() {
                return false;
            }
            if b.len() <= SCANNED_MAP {
                return a.iter().all(|(key, value)| {
                    b.get_value(key)
                        .is_some_and(|other| same_value(value, other))
                });
            }
            let held: std::collections::HashMap<&Value, &Value> = b.iter().collect();
            held.len() == b.len()
                && a.iter()
                    .all(|(key, value)| held.get(key).is_some_and(|other| same_value(value, other)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_value(a, b))
        }
        (Value::Int(n), Value::Float(x)) | (Value::Float(x), Value::Int(n)) => {
            integral_equals(*n, *x)
        }
        _ => a == b,
    }
}

/// Whether the double `x` is finite, integral, and equal to `n`.
#[allow(clippy::cast_possible_truncation, clippy::float_cmp)]
fn integral_equals(n: i128, x: f64) -> bool {
    // Every integer a payload carries is within 2^64 of zero, far inside what an i128 holds, so
    // the saturating cast only ever saturates for a double no payload integer equals.
    x.is_finite() && x.trunc() == x && x as i128 == n
}

// ---------------------------------------------------------------------------------------------
// Remote actions

/// One remote agent's advertised action as an invocable action (Java `RemoteAction`): the card
/// that advertises it, the action it declares, the schemas it consumes and produces, and where
/// an invocation writes and waits.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteAction {
    card: Arc<AgentCard>,
    /// Shared by every pairing of the action: a card's pairings never copy its lists.
    declared: Option<Arc<CardAction>>,
    consumes: String,
    produces: String,
    space: String,
    result_space: String,
}

impl RemoteAction {
    /// The advertising agent's card.
    pub fn card(&self) -> &AgentCard {
        &self.card
    }

    /// The advertising agent's AgentID.
    pub fn agent(&self) -> &str {
        self.card.agent()
    }

    /// The PeerID of the card's issuer.
    pub fn issuer(&self) -> &str {
        self.card.issuer()
    }

    /// The action the card declares for this pairing; `None` for a card from before v0.1.13.
    pub fn declared(&self) -> Option<&CardAction> {
        self.declared.as_deref()
    }

    /// The action's name: the declared action's, or `<agent local name>_<consumed schema>` for a
    /// card that declares none (Ruby `RemoteActions.actions`).
    pub fn name(&self) -> String {
        match &self.declared {
            Some(action) => action.name.clone(),
            None => format!("{}_{}", self.card.local_name(), self.consumes),
        }
    }

    /// The planner-friendly name, `<agent local name>_<input simple name>` (Java
    /// `RemoteAction.name`): stable across the v0.1.13 card change.
    pub fn planner_name(&self) -> String {
        format!("{}_{}", self.card.local_name(), simple_name(&self.consumes))
    }

    /// The declared kind (`take`, `notify`, ...); `None` for a card that declares no actions.
    pub fn kind(&self) -> Option<&str> {
        self.declared.as_ref().map(|action| action.kind.as_str())
    }

    /// What the action does: the declared action's description, else the card's, stripped of
    /// control characters and capped at [`MAX_CARD_TEXT`] characters, as Java does. Card text is
    /// written by whichever peer published the card: treat it as untrusted data.
    pub fn description(&self) -> String {
        let declared = self
            .declared
            .as_ref()
            .map(|action| action.description.as_str())
            .filter(|text| !text.trim().is_empty());
        sanitize(declared.unwrap_or(self.card.description()))
    }

    /// The advertising agent's goals, at most 16, each sanitized as the description.
    pub fn goals(&self) -> Vec<String> {
        self.card
            .goals()
            .iter()
            .take(16)
            .map(|goal| sanitize(goal))
            .collect()
    }

    /// The schema of the input entry.
    pub fn consumes(&self) -> &str {
        &self.consumes
    }

    /// The schema of the result entry.
    pub fn produces(&self) -> &str {
        &self.produces
    }

    /// The space an invocation writes its input into.
    pub fn space(&self) -> &str {
        &self.space
    }

    /// The space an invocation awaits its result in.
    pub fn result_space(&self) -> &str {
        &self.result_space
    }
}

impl fmt::Display for RemoteAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RemoteAction[{}: {} -> {} @ {}]",
            self.name(),
            self.consumes,
            self.produces,
            self.card.issuer()
        )
    }
}

/// A class's simple name from its schema: after the last `.` or `$`, before the `#`.
fn simple_name(schema: &str) -> &str {
    let class = schema.split_once('#').map_or(schema, |(class, _)| class);
    class
        .rsplit(['.', '$'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(class)
}

/// Java `RemoteAction.sanitize`: control characters become spaces, and text longer than
/// [`MAX_CARD_TEXT`] UTF-16 units is cut there with an ellipsis.
fn sanitize(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_ascii_control() { ' ' } else { c })
        .collect();
    if cleaned.encode_utf16().count() <= MAX_CARD_TEXT {
        return cleaned;
    }
    let mut units = 0;
    let mut cut = String::new();
    for c in cleaned.chars() {
        units += c.len_utf16();
        if units > MAX_CARD_TEXT {
            break;
        }
        cut.push(c);
    }
    cut.push('…');
    cut
}

/// What one invocation did: the input it wrote and the result it found, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    /// The id of the input entry written (still leased when no result came).
    pub input_id: EntryId,
    /// The correlated result; `None` at the timeout.
    pub result: Option<EntryView>,
}

/// The fleet's discovered capabilities as invocable actions (Java `RemoteActions`); see the
/// [module docs](self). Cheap to clone.
#[derive(Debug, Clone)]
pub struct RemoteActions {
    fleet: Fleet,
    include_own: bool,
    write_lease: Lease,
    routes: BTreeMap<String, String>,
    result_routes: BTreeMap<String, String>,
    spaces: Option<BTreeSet<String>>,
    agent: Option<AgentIdentity>,
    correlation: Correlation,
}

impl RemoteActions {
    /// The remote actions of the fleet's cards, as seen by this member.
    pub fn new(fleet: &Fleet) -> RemoteActions {
        RemoteActions {
            fleet: fleet.clone(),
            include_own: false,
            write_lease: Lease::DEFAULT_WRITE,
            routes: BTreeMap::new(),
            result_routes: BTreeMap::new(),
            spaces: None,
            agent: None,
            correlation: Correlation::shared_fields(),
        }
    }

    /// The fleet underneath.
    pub fn fleet(&self) -> &Fleet {
        &self.fleet
    }

    /// Also lists the actions of this peer's own cards (Java never does).
    pub fn include_own(mut self, include: bool) -> RemoteActions {
        self.include_own = include;
        self
    }

    /// The write lease of invocation inputs (10 minutes by default).
    pub fn write_lease(mut self, lease: Lease) -> RemoteActions {
        self.write_lease = lease;
        self
    }

    /// Writes the inputs of `schema` into `space` (Java `route`), whatever the cards say.
    pub fn route(mut self, schema: impl Into<String>, space: impl Into<String>) -> RemoteActions {
        self.routes.insert(schema.into(), space.into());
        self
    }

    /// Awaits the results of `schema` in `space` (Java `resultsIn`), when workers complete into
    /// another space than they take from.
    pub fn results_in(
        mut self,
        schema: impl Into<String>,
        space: impl Into<String>,
    ) -> RemoteActions {
        self.result_routes.insert(schema.into(), space.into());
        self
    }

    /// Follows only these spaces when a card names one (Java follows only registered spaces);
    /// by default any space the card names.
    pub fn spaces<S: Into<String>>(mut self, names: impl IntoIterator<Item = S>) -> RemoteActions {
        self.spaces = Some(names.into_iter().map(Into::into).collect());
        self
    }

    /// Writes inputs as `agent` (an agent identity of this peer) instead of the peer's default
    /// agent.
    pub fn as_agent(mut self, agent: AgentIdentity) -> RemoteActions {
        self.agent = Some(agent);
        self
    }

    /// Correlates results with `correlation` instead of [`Correlation::shared_fields`].
    pub fn correlation(mut self, correlation: Correlation) -> RemoteActions {
        self.correlation = correlation;
        self
    }

    /// The fleet's currently advertised, invocable actions, newest cards first; see the [module
    /// docs](self#which-actions).
    pub async fn available(&self) -> Vec<RemoteAction> {
        self.available_where(|_| true).await
    }

    /// [`RemoteActions::available`] of the declared actions `keep` answers true for (`None`:
    /// a card that declares no actions), passed over before their pairings are made: the
    /// catalogue asks for the actions it can offer only, as Ruby's gateway does.
    pub(crate) async fn available_where(
        &self,
        keep: impl Fn(Option<&CardAction>) -> bool,
    ) -> Vec<RemoteAction> {
        let own = self.fleet.peer().peer_id().to_owned();
        let mut cards: Vec<AgentCard> = self
            .fleet
            .peer()
            .cards()
            .await
            .into_iter()
            .filter_map(AgentCard::parse)
            .filter(|card| self.include_own || card.issuer() != own)
            .collect();
        cards.sort_by_key(|card| std::cmp::Reverse(card.issued_millis()));
        let mut actions = Vec::new();
        let mut seen: HashSet<(String, String, String, String)> = HashSet::new();
        for card in cards {
            let card = Arc::new(card);
            for (consumed, produced, declared) in pairs(&card, &keep) {
                let Some(space) = self.task_space(&card, declared.as_deref(), &consumed) else {
                    // Nowhere this caller writes the input: not invocable here, and no reason to
                    // pass over an older card of the same capability that names a space it does.
                    continue;
                };
                let key = (
                    card.agent().to_owned(),
                    declared
                        .as_ref()
                        .map_or_else(String::new, |action| action.name.clone()),
                    consumed.clone(),
                    produced.clone(),
                );
                if !seen.insert(key) {
                    continue; // an older refresh of the same capability
                }
                let result_space = self
                    .result_routes
                    .get(&produced)
                    .cloned()
                    .unwrap_or_else(|| space.clone());
                actions.push(RemoteAction {
                    card: Arc::clone(&card),
                    declared,
                    consumes: consumed,
                    produces: produced,
                    space,
                    result_space,
                });
            }
        }
        actions
    }

    /// The available actions consuming `schema` (Java `consuming`).
    pub async fn consuming(&self, schema: &str) -> Vec<RemoteAction> {
        let mut actions = self.available().await;
        actions.retain(|action| action.consumes == schema);
        actions
    }

    /// The available actions producing `schema` (Java `producing`).
    pub async fn producing(&self, schema: &str) -> Vec<RemoteAction> {
        let mut actions = self.available().await;
        actions.retain(|action| action.produces == schema);
        actions
    }

    /// The space an action's input goes to: an explicit route, the action's space, the card's
    /// binding for the schema; foreign names only among [`RemoteActions::spaces`] when set.
    fn task_space(
        &self,
        card: &AgentCard,
        declared: Option<&CardAction>,
        consumed: &str,
    ) -> Option<String> {
        if let Some(routed) = self.routes.get(consumed) {
            return Some(routed.clone());
        }
        let followed = |space: &&str| {
            !space.is_empty()
                && self
                    .spaces
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(*space))
        };
        declared
            .and_then(|action| action.space.as_deref())
            .filter(followed)
            .or_else(|| card.space_for(consumed).filter(followed))
            .map(str::to_owned)
    }

    fn space(&self, name: &str) -> Space {
        let space = self.fleet.space(name);
        match &self.agent {
            Some(agent) => space.as_agent(agent.clone()),
            None => space,
        }
    }

    /// Invokes `action` with `input` (its payload; written under the action's consumed schema)
    /// and awaits the correlated result for up to `timeout`; see the [module
    /// docs](self#invoking). `Ok(None)` at the timeout, the input left leased.
    ///
    /// # Errors
    ///
    /// The errors of [`Space::write_value`], [`Space::read_all`], and [`Space::watch`];
    /// [`PeerError::Closed`] when the peer closes while waiting.
    pub async fn invoke(
        &self,
        action: &RemoteAction,
        input: Value,
        timeout: Duration,
    ) -> Result<Option<EntryView>, SpaceError> {
        Ok(self.invoke_tracked(action, input, timeout).await?.result)
    }

    /// [`RemoteActions::invoke`], answering the input's entry id too.
    ///
    /// # Errors
    ///
    /// As [`RemoteActions::invoke`].
    pub async fn invoke_tracked(
        &self,
        action: &RemoteAction,
        input: Value,
        timeout: Duration,
    ) -> Result<Invocation, SpaceError> {
        let tasks = self.space(&action.space);
        let results = self.space(&action.result_space);
        let template = Template::new(action.produces.clone());
        // Entries equal to one already present are not answers to this request: how many of
        // each payload existed before the write (a multiset), so the backstop cannot resurrect a
        // stale result.
        let baseline: Vec<Value> = results
            .read_all(&template, BASELINE_LIMIT)
            .await?
            .into_iter()
            .map(EntryView::into_payload)
            .collect();
        // The watch starts before the write, so no result can slip between them.
        let mut events = results.watch(&template).await?;
        let input_id = tasks
            .write_value(
                &action.consumes,
                input.clone(),
                self.write_lease,
                Map::new(),
            )
            .await?;
        let written = tasks
            .get(&input_id)
            .await?
            .map(|view| view.issued().to_owned());
        let answers = |candidate: &EntryView| {
            issued_after(candidate.issued(), written.as_deref())
                && self.correlation.matches(&input, candidate.payload())
        };
        let found = |result: Option<EntryView>| Invocation {
            input_id: input_id.clone(),
            result,
        };
        let deadline = Instant::now().checked_add(timeout);
        let mut backstop = tokio::time::interval_at(Instant::now() + BACKSTOP, BACKSTOP);
        let mut dropped = events.dropped();
        loop {
            let expiry = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                event = events.next() => {
                    let Some(event) = event else {
                        return Err(PeerError::Closed.into());
                    };
                    if event.kind == EventKind::Written && answers(&event.entry) {
                        return Ok(found(Some(event.entry)));
                    }
                }
                _ = backstop.tick() => {
                    // The watch fell behind and lost events: look at what is present.
                    if events.dropped() != dropped {
                        dropped = events.dropped();
                        let current = results.read_all(&template, BASELINE_LIMIT).await?;
                        if let Some(result) = new_since(&baseline, current).into_iter().find(&answers) {
                            return Ok(found(Some(result)));
                        }
                    }
                }
                () = expiry => {
                    // One last look at what is present before giving up.
                    let current = results.read_all(&template, BASELINE_LIMIT).await?;
                    let result = new_since(&baseline, current).into_iter().find(&answers);
                    return Ok(found(result));
                }
            }
        }
    }

    /// [`RemoteActions::invoke`] with typed input and result (Java `invoke(input, resultType,
    /// timeout)`).
    ///
    /// # Errors
    ///
    /// [`SpaceError::Entry`] ([`EntryError::WrongSchema`]) when the action does not consume
    /// `I`'s schema or produce `O`'s, or the result does not decode as `O`; and the errors of
    /// [`RemoteActions::invoke`].
    pub async fn invoke_typed<I: Entry, O: Entry>(
        &self,
        action: &RemoteAction,
        input: &I,
        timeout: Duration,
    ) -> Result<Option<TypedView<O>>, SpaceError> {
        if action.consumes != I::SCHEMA {
            return Err(EntryError::WrongSchema {
                expected: I::SCHEMA,
                found: action.consumes.clone(),
            }
            .into());
        }
        if action.produces != O::SCHEMA {
            return Err(EntryError::WrongSchema {
                expected: O::SCHEMA,
                found: action.produces.clone(),
            }
            .into());
        }
        let payload = input.to_payload()?;
        match self.invoke(action, payload, timeout).await? {
            Some(view) => Ok(Some(TypedView::decode(view)?)),
            None => Ok(None),
        }
    }
}

/// The most schemas of one list (a declared action's `consumes` or `produces`, or a card's flat
/// lists) a card's pairings are made from; the rest of a longer list is passed over. Java's
/// binders declare one consumed schema per action and a few produced ones.
pub const MAX_SCHEMAS_PER_LIST: usize = 64;

/// The most (consumed, produced) pairings one card yields; the rest are passed over, so a card
/// of a few kilobytes cannot make every reader build millions of actions.
pub const MAX_PAIRS_PER_CARD: usize = 4096;

/// The (consumed, produced, declared action) pairs a card offers (Java `RemoteActions.pairs`):
/// its declared invocable actions `keep` keeps when it declares any, else the cross product of
/// its flat lists, within [`MAX_SCHEMAS_PER_LIST`] and [`MAX_PAIRS_PER_CARD`]. Every pairing of
/// a declared action shares it.
fn pairs(
    card: &AgentCard,
    keep: &dyn Fn(Option<&CardAction>) -> bool,
) -> Vec<(String, String, Option<Arc<CardAction>>)> {
    let mut pairs = Vec::new();
    let mut cross =
        |consumes: &[String], produces: &[String], declared: Option<Arc<CardAction>>| {
            for consumed in consumes.iter().take(MAX_SCHEMAS_PER_LIST) {
                for produced in produces.iter().take(MAX_SCHEMAS_PER_LIST) {
                    if pairs.len() >= MAX_PAIRS_PER_CARD {
                        return;
                    }
                    pairs.push((consumed.clone(), produced.clone(), declared.clone()));
                }
            }
        };
    match card.actions() {
        Some(actions) => {
            for action in actions
                .iter()
                .filter(|action| action.invocable() && keep(Some(action)))
            {
                let shared = Arc::new(action.clone());
                cross(&action.consumes, &action.produces, Some(shared));
            }
        }
        None if keep(None) => cross(card.consumes(), card.produces(), None),
        None => {}
    }
    if pairs.len() >= MAX_PAIRS_PER_CARD {
        tracing::debug!(
            card = card.id(),
            "agentspaces: a card offers more than {MAX_PAIRS_PER_CARD} pairings; the rest are \
             passed over"
        );
    }
    pairs
}

/// Multiset difference (Java `newSince`): the entries of `current` beyond their payload's count
/// in `baseline`.
fn new_since(baseline: &[Value], current: Vec<EntryView>) -> Vec<EntryView> {
    let mut remaining: Vec<&Value> = baseline.iter().collect();
    let mut fresh = Vec::new();
    for candidate in current {
        match remaining
            .iter()
            .position(|held| *held == candidate.payload())
        {
            Some(at) => {
                remaining.swap_remove(at);
            }
            None => fresh.push(candidate),
        }
    }
    fresh
}

/// Whether a candidate issued at `candidate` can answer an input issued at `input`: it was
/// issued after it by HLC order. A stamp that does not parse (or an input not read back) does
/// not rule a candidate out.
fn issued_after(candidate: &str, input: Option<&str>) -> bool {
    match (Stamp::parse(candidate), input.and_then(Stamp::parse)) {
        (Some(candidate), Some(input)) => candidate > input,
        _ => true,
    }
}

/// Whether an action kind is one a caller invokes by writing the consumed entry (Java
/// `CardAction.INVOCABLE`).
pub fn is_invocable_kind(kind: &str) -> bool {
    ads::INVOCABLE_ACTIONS.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::cbor_map;

    #[test]
    fn shared_fields_compare_only_the_fields_both_carry() {
        let input = cbor_map! { "topic" => "rust", "priority" => 1 };
        let answer = cbor_map! { "topic" => "rust", "summary" => "s", "worker" => "w" };
        let decoy = cbor_map! { "topic" => "go", "summary" => "s" };
        let unrelated = cbor_map! { "summary" => "s" };
        assert!(shared_fields(&input, &answer));
        assert!(!shared_fields(&input, &decoy));
        assert!(shared_fields(&input, &unrelated), "no shared field: any");
        assert!(shared_fields(&Value::Int(1), &decoy), "not a record: any");
        let typed = cbor_map! { "topic" => "rust", "priority" => 1.0 };
        assert!(
            shared_fields(&input, &typed),
            "an int and an integral double of the same value correlate"
        );
        let fraction = cbor_map! { "topic" => "rust", "priority" => 1.5 };
        assert!(
            !shared_fields(&input, &fraction),
            "an int and a double of another value differ"
        );
        assert!(Correlation::any().matches(&input, &decoy));
        assert!(!Correlation::default().matches(&input, &decoy));
    }

    /// Nested maps correlate whatever their key order (a JSON input keeps the order it was typed
    /// in; a Java or serde map echoes it in its own), and arrays element by element. An integer
    /// meets an integral double of the same value (an untyped JSON `100` and a Java `double`
    /// field's `100.0`), and nothing else.
    #[test]
    fn values_correlate_by_meaning_not_by_encoding() {
        let typed =
            serde_json::json!({"topic": "t", "meta": {"zeta": 1, "a": [2, {"y": 1, "x": 0}]}});
        let input = crate::json::json_to_value(&typed, None).expect("json");
        let echoed = cbor_map! {
            "topic" => "t",
            "meta" => cbor_map! {
                "a" => agentspaces_wire::cbor_array![2.0, cbor_map! { "x" => 0, "y" => 1 }],
                "zeta" => 1,
            },
            "extra" => true,
        };
        assert!(shared_fields(&input, &echoed), "{input:?} vs {echoed:?}");
        let other = cbor_map! { "topic" => "t", "meta" => cbor_map! { "zeta" => 1, "a" => 3 } };
        assert!(!shared_fields(&input, &other));
        let more = cbor_map! { "topic" => "t", "meta" => cbor_map! {
            "zeta" => 1, "a" => agentspaces_wire::cbor_array![2], "b" => 0
        } };
        assert!(
            !shared_fields(&input, &more),
            "a map with another key differs"
        );
        let reordered = agentspaces_wire::cbor_array![1, 2];
        assert!(!same_value(
            &reordered,
            &agentspaces_wire::cbor_array![2, 1]
        ));

        // Numbers.
        let int = Value::Int(100);
        assert!(same_value(&int, &Value::Float(100.0)));
        assert!(same_value(&Value::Float(100.0), &int));
        assert!(!same_value(&int, &Value::Float(100.5)));
        assert!(!same_value(&Value::Int(0), &Value::Float(f64::NAN)));
        assert!(!same_value(
            &Value::Int(i128::from(i64::MAX)),
            &Value::Float(f64::INFINITY)
        ));
        assert!(!same_value(
            &Value::Int(9_007_199_254_740_993),
            &Value::Float(9_007_199_254_740_992.0)
        ));
        assert!(!same_value(&Value::Int(1), &Value::from("1")));
        assert!(same_value(&Value::Float(0.5), &Value::Float(0.5)));

        // A large map is looked up through a table, with the same answers.
        let mut big_a = Map::new();
        let mut big_b = Map::new();
        for n in 0..100 {
            big_a.insert(format!("k{n}"), n);
        }
        for n in (0..100).rev() {
            big_b.insert(format!("k{n}"), f64::from(n));
        }
        assert!(same_value(
            &Value::Map(big_a.clone()),
            &Value::Map(big_b.clone())
        ));
        big_b.insert("k5", 6);
        assert!(!same_value(&Value::Map(big_a), &Value::Map(big_b)));
    }

    /// A declared take action in `tasks`: its name, consumed and produced schemas.
    type Declared<'a> = (&'a str, Vec<String>, Vec<String>);

    /// A card of `actions` (none: a card from before v0.1.13) and flat lists of `flat` schemas.
    fn card(actions: Option<&[Declared<'_>]>, flat: usize) -> AgentCard {
        let peer = agentspaces_wire::identity::Identity::from_seed(&[5; 32]);
        let actions: Option<Vec<Map>> = actions.map(|actions| {
            actions
                .iter()
                .map(|(name, consumes, produces)| {
                    let consumes: Vec<&str> = consumes.iter().map(String::as_str).collect();
                    let produces: Vec<&str> = produces.iter().map(String::as_str).collect();
                    ads::card_action(
                        name,
                        "",
                        &consumes,
                        &produces,
                        ads::ACTION_TAKE,
                        Some("tasks"),
                    )
                })
                .collect()
        });
        let schemas: Vec<String> = (0..flat).map(|n| format!("s{n}#v1")).collect();
        let flat: Vec<&str> = schemas.iter().map(String::as_str).collect();
        let mut map = ads::agent_card(
            "zGroup",
            &peer,
            "boom",
            &agentspaces_wire::time::instant_iso(1_767_225_600_000),
            "PT10M",
            "a card",
            &[],
            &flat,
            &flat,
            &Map::new(),
            &Map::new(),
            None,
            actions.as_deref().unwrap_or_default(),
            None,
            None,
        )
        .expect("card");
        if actions.is_none() {
            map.remove("actions");
        }
        AgentCard::parse(map).expect("parsed")
    }

    fn schemas(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i}#v1")).collect()
    }

    /// A card's pairings share their declared action (none is copied per pair), read at most 64
    /// schemas of a list, and stop at 4096 a card, so a card of a few kilobytes cannot make a
    /// reader build millions of actions; the catalogue's filter is applied before any pairing is
    /// made.
    #[test]
    fn a_cards_pairings_are_bounded_and_share_their_action() {
        let wide = card(Some(&[("wide", schemas("c", 400), schemas("p", 400))]), 0);
        let started = std::time::Instant::now();
        let paired = pairs(&wide, &|_| true);
        assert_eq!(paired.len(), MAX_SCHEMAS_PER_LIST * MAX_SCHEMAS_PER_LIST);
        assert!(started.elapsed() < Duration::from_secs(5));
        let (first, last) = (&paired[0].2, &paired[paired.len() - 1].2);
        assert!(
            matches!((first, last), (Some(a), Some(b)) if Arc::ptr_eq(a, b)),
            "every pairing shares the one action"
        );
        let several: Vec<Declared<'_>> = (0..3)
            .map(|n| (["a", "b", "c"][n], schemas("c", 40), schemas("p", 40)))
            .collect();
        let many = card(Some(&several), 0);
        assert_eq!(pairs(&many, &|_| true).len(), MAX_PAIRS_PER_CARD);
        assert!(
            pairs(&many, &|_| false).is_empty(),
            "filtered before pairing"
        );
        let flat = card(None, 100);
        assert_eq!(
            pairs(&flat, &|_| true).len(),
            MAX_SCHEMAS_PER_LIST * MAX_SCHEMAS_PER_LIST
        );
        assert!(pairs(&flat, &|declared| declared.is_some()).is_empty());
    }

    #[test]
    fn the_baseline_is_a_multiset_of_payloads() {
        let view = |payload: Value| EntryView {
            entry_id: EntryId::new("x"),
            schema: "R#v1".to_owned(),
            payload: Arc::new(payload),
            tags: Map::new(),
            issuer: "p/a".to_owned(),
            issued: "1:0:p".to_owned(),
            attestation: crate::space::Attestation::PeerAsserted,
            expires_at_millis: 0,
            completed: false,
            holder: None,
        };
        let baseline = vec![Value::Int(1), Value::Int(1), Value::Int(2)];
        let current = vec![
            view(Value::Int(1)),
            view(Value::Int(2)),
            view(Value::Int(1)),
            view(Value::Int(1)),
            view(Value::Int(3)),
        ];
        let fresh: Vec<Value> = new_since(&baseline, current)
            .into_iter()
            .map(EntryView::into_payload)
            .collect();
        assert_eq!(fresh, vec![Value::Int(1), Value::Int(3)]);
    }

    #[test]
    fn stamps_order_candidates_after_their_input() {
        assert!(issued_after("10:0:b", Some("9:5:a")));
        assert!(issued_after("10:1:a", Some("10:0:a")));
        assert!(!issued_after("10:0:a", Some("10:0:a")));
        assert!(!issued_after("9:9:z", Some("10:0:a")));
        assert!(issued_after("garbage", Some("10:0:a")));
        assert!(issued_after("1:0:a", None));
    }

    #[test]
    fn names_and_descriptions_follow_java() {
        assert_eq!(
            simple_name("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1"),
            "ResearchTask"
        );
        assert_eq!(simple_name("shop.Order#v1"), "Order");
        assert_eq!(simple_name("Plain"), "Plain");
        assert_eq!(sanitize("a\nb\tc"), "a b c");
        let long = "x".repeat(MAX_CARD_TEXT + 10);
        let cut = sanitize(&long);
        assert!(cut.ends_with('…'));
        assert_eq!(cut.chars().count(), MAX_CARD_TEXT + 1);
        assert!(is_invocable_kind("take"));
        assert!(!is_invocable_kind("ballot"));
    }
}
