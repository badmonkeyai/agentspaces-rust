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

//! The fleet tool catalogue: the fleet's remote actions folded into *offerings*, the one list MCP,
//! rig, ACP, the bindings, and `aspace call` all read. A Rust port of the hardened Ruby MCP gateway
//! (`agentspaces-mcp/lib/agentspaces/mcp.rb`), so two gateways over the same cards offer the same
//! names, whichever language runs them.
//!
//! ```no_run
//! # async fn run(fleet: agentspaces::space::Fleet) -> Result<(), agentspaces::catalog::CatalogError> {
//! use std::time::Duration;
//! use agentspaces::catalog::{FleetCatalog, Principal};
//! use agentspaces::wire::cbor_map;
//!
//! let catalog = FleetCatalog::new(&fleet).only(["shop.*"]);
//! catalog.refresh().await;
//! for offering in catalog.offerings() {
//!     println!("{}: {} -> {}", offering.name(), offering.consumes(), offering.produces());
//! }
//! let input = cbor_map! { "orderId" => "o-1", "item" => "kite" };
//! let outcome = catalog
//!     .call("shop.Order#v1", input.into(), &Principal::local(), Duration::from_secs(30))
//!     .await?;
//! println!("{:?}", outcome.result_json());
//! # Ok(())
//! # }
//! ```
//!
//! # Offerings
//!
//! The catalogue offers what the Ruby gateway offers (`Capabilities::RemoteActions.actions`): of
//! the [`RemoteActions`], each declared `take` action with exactly one consumed and one produced
//! schema and a space, and each pairing of a card that declares no actions. Then, as `mcp.rb`'s
//! `offerings`:
//!
//! - [`FleetCatalog::only`] keeps the actions a glob pattern matches (by action name, consumed
//!   schema, or produced schema; `*` any run of characters, `?` one), and
//!   [`FleetCatalog::only_if`] those a predicate keeps;
//! - replicas collapse: actions with the same name, consumed schema, produced schema, and space
//!   are one offering, whichever agents declare them, and a call reaches whichever replica
//!   takes the task;
//! - an offering's name is the action's name with every character outside `[a-zA-Z0-9_.-]`
//!   replaced by `_` (at most 128 characters); when different actions share that name, each is
//!   named `<name>_<8 hex>` from the SHA-256 of the JSON array `[name, consumes, produces,
//!   space]` as Ruby's `JSON.generate` writes it, so a name is stable across refreshes and
//!   gateways;
//! - names are unique, which the Ruby rule alone does not make them: an action may be named
//!   literally what another's suffixed name is (`research_854bb186`). Every name still carried
//!   by more than one offering is renamed again, a literal name before a suffixed one (it takes
//!   the suffix the Ruby rule would give it), and suffixed names that still collide take a
//!   longer suffix (16, then 64 hex), so a card cannot take an honest offering's name. A fleet
//!   whose names do not collide keeps the Ruby names; offerings whose names still collide after
//!   [`MAX_NAMING_PASSES`] renamings are withheld;
//! - the list is sorted by name.
//!
//! # Calls
//!
//! [`FleetCatalog::call`] resolves an offering by name, else by its consumed schema when exactly
//! one offering consumes it ([`CatalogError::Ambiguous`] lists the candidates otherwise), from
//! the fleet as it is now: an offering the last [`FleetCatalog::refresh`] listed that the fleet
//! no longer offers is refused ([`CatalogError::NoLongerOffered`]). [`FleetCatalog::authorize`]
//! judges each call with the caller's [`Principal`]. The call is
//! [`RemoteActions::invoke_tracked`]: the input written, the correlated result awaited, and at
//! the timeout the task left leased. A host that has already resolved and judged an offering
//! (an MCP gateway) calls exactly that one with [`FleetCatalog::call_offering`]: it is checked
//! to be still offered under the same name, consumed and produced schemas, and space, never
//! looked up again by name or schema.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agentspaces_wire::ads;
use agentspaces_wire::cbor::Value;
use agentspaces_wire::crypto;
use serde_json::{Value as Json, json};

use crate::agent::CardAction;
use crate::json::value_to_json;
use crate::remote::{RemoteAction, RemoteActions};
use crate::space::{EntryId, EntryView, Fleet, SpaceError};

/// The longest offering name (Ruby `MCP::MAX_NAME`).
pub const MAX_NAME: usize = 128;

/// How many hex digits of the SHA-256 a shared name is suffixed with.
const SUFFIX_HEX: usize = 8;

/// The suffix lengths of the renamings after the Ruby one: 16 hex digits, then the whole digest.
const LONGER_SUFFIX_HEX: [usize; 2] = [16, 64];

/// How many times colliding names are renamed before the offerings still colliding are
/// withheld.
pub const MAX_NAMING_PASSES: usize = 8;

// ---------------------------------------------------------------------------------------------
// Offerings

/// One offering: a name, the representative action, and how many cards offer it (replicas).
#[derive(Debug, Clone, PartialEq)]
pub struct Offering {
    name: String,
    action: RemoteAction,
    replicas: usize,
}

impl Offering {
    /// The offering's name, unique in the catalogue (a tool name).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The representative action: the first card's that offers it.
    pub fn action(&self) -> &RemoteAction {
        &self.action
    }

    /// How many cards offer it.
    pub fn replicas(&self) -> usize {
        self.replicas
    }

    /// The schema of the input entry.
    pub fn consumes(&self) -> &str {
        self.action.consumes()
    }

    /// The schema of the result entry.
    pub fn produces(&self) -> &str {
        self.action.produces()
    }

    /// The space a call writes its input into.
    pub fn space(&self) -> &str {
        self.action.space()
    }

    /// What it does ([`RemoteAction::description`], sanitized card text).
    pub fn description(&self) -> String {
        self.action.description()
    }

    /// The one-line description a tool list shows (Ruby `MCP.description`): the action's
    /// description, the advertising agent, the schemas, and the replicas when more than one.
    pub fn summary(&self) -> String {
        let offered = if self.replicas > 1 {
            format!("; {} replicas", self.replicas)
        } else {
            String::new()
        };
        format!(
            "{} (AgentSpaces agent {}; {} -> {}{offered})",
            self.description(),
            self.action.agent(),
            self.consumes(),
            self.produces()
        )
    }

    /// A JSON Schema description of the input: an object with the consumed entry's wire
    /// fields (cards carry no field list, so any field is allowed).
    pub fn input_schema(&self) -> Json {
        entry_schema(self.consumes())
    }

    /// A JSON Schema description of the result, as [`Offering::input_schema`].
    pub fn output_schema(&self) -> Json {
        entry_schema(self.produces())
    }
}

fn entry_schema(schema: &str) -> Json {
    json!({
        "type": "object",
        "title": schema,
        "description": format!("the {schema} entry's wire fields"),
        "additionalProperties": true,
    })
}

/// Who is calling: what [`FleetCatalog::authorize`] judges. A local caller (standard input, the
/// same process) carries nothing; an HTTP caller carries what its verified token says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Principal {
    /// The token's subject, when there is a token.
    pub subject: Option<String>,
    /// The token's scopes.
    pub scopes: Vec<String>,
}

impl Principal {
    /// A local caller, with no token.
    pub fn local() -> Principal {
        Principal::default()
    }

    /// A caller with a verified token for `subject` carrying `scopes`.
    pub fn token<S: Into<String>>(
        subject: impl Into<String>,
        scopes: impl IntoIterator<Item = S>,
    ) -> Principal {
        Principal {
            subject: Some(subject.into()),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether the caller is local (no token).
    pub fn is_local(&self) -> bool {
        self.subject.is_none()
    }

    /// Whether the token carries `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|held| held == scope)
    }
}

/// What a call did.
#[derive(Debug, Clone, PartialEq)]
pub struct CallOutcome {
    /// The offering called.
    pub offering: String,
    /// The id of the input entry written (left leased when no result came).
    pub input_id: EntryId,
    /// The correlated result; `None` at the timeout.
    pub result: Option<EntryView>,
}

impl CallOutcome {
    /// Whether no result came within the timeout (the task stays leased).
    pub fn timed_out(&self) -> bool {
        self.result.is_none()
    }

    /// The result's payload as JSON ([`value_to_json`]).
    pub fn result_json(&self) -> Option<Json> {
        self.result
            .as_ref()
            .map(|view| value_to_json(view.payload()))
    }
}

/// Why a catalogue lookup or call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// No offering is named so, and none consumes it as a schema.
    #[error("no offering is named {0:?} or consumes it")]
    NotFound(String),
    /// Several offerings consume the schema asked for.
    #[error("{query:?} is consumed by several offerings: {}", candidates.join(", "))]
    Ambiguous {
        /// The schema asked for.
        query: String,
        /// The offerings consuming it, by name.
        candidates: Vec<String>,
    },
    /// The offering was listed, and the fleet no longer offers it.
    #[error("{0} is no longer offered by the fleet")]
    NoLongerOffered(String),
    /// [`FleetCatalog::authorize`] refused the call.
    #[error("not authorized to invoke {0}")]
    Unauthorized(String),
    /// The invocation failed.
    #[error(transparent)]
    Space(#[from] SpaceError),
}

type OnlyIf = Arc<dyn Fn(&RemoteAction) -> bool + Send + Sync>;
type Authorize = Arc<dyn Fn(&Offering, &Principal) -> bool + Send + Sync>;

/// The fleet's actions as offerings; see the [module docs](self). Cheap to clone; clones share
/// the listed offerings.
#[derive(Clone)]
pub struct FleetCatalog {
    remote: RemoteActions,
    patterns: Vec<String>,
    only_if: Option<OnlyIf>,
    authorize: Option<Authorize>,
    listed: Arc<Mutex<Vec<Offering>>>,
}

impl fmt::Debug for FleetCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FleetCatalog")
            .field("patterns", &self.patterns)
            .field("only_if", &self.only_if.is_some())
            .field("authorize", &self.authorize.is_some())
            .field("listed", &self.names())
            .finish()
    }
}

impl FleetCatalog {
    /// The catalogue of the fleet's remote actions ([`RemoteActions::new`]); nothing is listed
    /// until [`FleetCatalog::refresh`].
    pub fn new(fleet: &Fleet) -> FleetCatalog {
        FleetCatalog::with_actions(RemoteActions::new(fleet))
    }

    /// The catalogue over `remote` (its routes, write lease, identity, and correlation).
    pub fn with_actions(remote: RemoteActions) -> FleetCatalog {
        FleetCatalog {
            remote,
            patterns: Vec::new(),
            only_if: None,
            authorize: None,
            listed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The remote actions underneath.
    pub fn remote(&self) -> &RemoteActions {
        &self.remote
    }

    /// Offers only the actions one of `patterns` matches: a glob (`*` any run, `?` one
    /// character) against the action's name, consumed schema, or produced schema. Adds to the
    /// patterns already given; none means every action.
    pub fn only<S: Into<String>>(mut self, patterns: impl IntoIterator<Item = S>) -> FleetCatalog {
        self.patterns.extend(patterns.into_iter().map(Into::into));
        self
    }

    /// Offers only the actions `keep` answers true for (Ruby's `only:` predicate), besides the
    /// patterns.
    pub fn only_if(
        mut self,
        keep: impl Fn(&RemoteAction) -> bool + Send + Sync + 'static,
    ) -> FleetCatalog {
        self.only_if = Some(Arc::new(keep));
        self
    }

    /// Judges each call: `allow(offering, principal)` false refuses it
    /// ([`CatalogError::Unauthorized`]).
    pub fn authorize(
        mut self,
        allow: impl Fn(&Offering, &Principal) -> bool + Send + Sync + 'static,
    ) -> FleetCatalog {
        self.authorize = Some(Arc::new(allow));
        self
    }

    /// The offerings of the fleet as it is now (not listed; [`FleetCatalog::refresh`] lists
    /// them).
    pub async fn current(&self) -> Vec<Offering> {
        // Only what can be offered is paired up at all (Ruby filters before it builds).
        let actions: Vec<RemoteAction> = self
            .remote
            .available_where(offerable)
            .await
            .into_iter()
            .filter(|action| self.keeps(action))
            .collect();
        fold(actions)
    }

    /// Lists the offerings of the fleet as it is now; answers whether the names listed changed
    /// (Ruby `Gateway.refresh`, the cue for `notifications/tools/list_changed`).
    pub async fn refresh(&self) -> bool {
        let current = self.current().await;
        let mut listed = self.listed.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = !listed
            .iter()
            .map(Offering::name)
            .eq(current.iter().map(Offering::name));
        *listed = current;
        changed
    }

    /// The offerings the last [`FleetCatalog::refresh`] listed, sorted by name.
    pub fn offerings(&self) -> Vec<Offering> {
        self.listed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The names the last [`FleetCatalog::refresh`] listed.
    pub fn names(&self) -> Vec<String> {
        self.listed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|offering| offering.name.clone())
            .collect()
    }

    /// The offering of the fleet as it is now named `name_or_schema`, else the one offering
    /// that consumes it as a schema.
    ///
    /// # Errors
    ///
    /// [`CatalogError::Ambiguous`] when several offerings consume the schema,
    /// [`CatalogError::NoLongerOffered`] for a name listed but no longer offered, and
    /// [`CatalogError::NotFound`] otherwise.
    pub async fn find(&self, name_or_schema: &str) -> Result<Offering, CatalogError> {
        let current = self.current().await;
        match resolve(&current, name_or_schema) {
            Err(CatalogError::NotFound(_)) => {
                // Listed once, gone now: refused as no longer offered.
                match resolve(&self.offerings(), name_or_schema) {
                    Ok(listed) => Err(CatalogError::NoLongerOffered(listed.name)),
                    Err(_) => Err(CatalogError::NotFound(name_or_schema.to_owned())),
                }
            }
            found => found,
        }
    }

    /// Calls an offering ([`FleetCatalog::find`]) with `input` (the consumed entry's payload)
    /// for `principal`, awaiting its result for up to `timeout`; see the [module
    /// docs](self#calls).
    ///
    /// # Errors
    ///
    /// Those of [`FleetCatalog::find`]; [`CatalogError::Unauthorized`] when
    /// [`FleetCatalog::authorize`] refuses; [`CatalogError::Space`] when the invocation fails.
    pub async fn call(
        &self,
        name_or_schema: &str,
        input: Value,
        principal: &Principal,
        timeout: Duration,
    ) -> Result<CallOutcome, CatalogError> {
        let offering = self.find(name_or_schema).await?;
        self.invoke(offering, input, principal, timeout).await
    }

    /// Calls exactly `offering` (one [`FleetCatalog::find`] or [`FleetCatalog::offerings`]
    /// answered) with `input` for `principal`, awaiting its result for up to `timeout`: what
    /// [`FleetCatalog::call`] does once it has resolved a name, for a host that resolved and
    /// judged the offering itself. The fleet as it is now must still offer it under the same
    /// name, consumed and produced schemas, and space; it is never looked up again by name or
    /// schema.
    ///
    /// # Errors
    ///
    /// [`CatalogError::NoLongerOffered`] when the fleet no longer offers it so;
    /// [`CatalogError::Unauthorized`] when [`FleetCatalog::authorize`] refuses;
    /// [`CatalogError::Space`] when the invocation fails.
    pub async fn call_offering(
        &self,
        offering: &Offering,
        input: Value,
        principal: &Principal,
        timeout: Duration,
    ) -> Result<CallOutcome, CatalogError> {
        let current = self.current().await;
        let Some(still) = current
            .into_iter()
            .find(|candidate| candidate.name == offering.name && same_key(candidate, offering))
        else {
            return Err(CatalogError::NoLongerOffered(offering.name.clone()));
        };
        self.invoke(still, input, principal, timeout).await
    }

    /// Judges and invokes a resolved offering.
    async fn invoke(
        &self,
        offering: Offering,
        input: Value,
        principal: &Principal,
        timeout: Duration,
    ) -> Result<CallOutcome, CatalogError> {
        if let Some(allow) = &self.authorize
            && !allow(&offering, principal)
        {
            return Err(CatalogError::Unauthorized(offering.name));
        }
        let invocation = self
            .remote
            .invoke_tracked(&offering.action, input, timeout)
            .await?;
        Ok(CallOutcome {
            offering: offering.name,
            input_id: invocation.input_id,
            result: invocation.result,
        })
    }

    fn keeps(&self, action: &RemoteAction) -> bool {
        let matched = self.patterns.is_empty()
            || self.patterns.iter().any(|pattern| {
                glob(pattern, &action.name())
                    || glob(pattern, action.consumes())
                    || glob(pattern, action.produces())
            });
        matched && self.only_if.as_ref().is_none_or(|keep| keep(action))
    }
}

/// Whether the Ruby gateway offers an action (`RemoteActions.actions`): a declared `take` with
/// one consumed and one produced schema and a space, or a pairing of a card that declares none
/// (`None`).
fn offerable(declared: Option<&CardAction>) -> bool {
    declared.is_none_or(|declared| {
        declared.kind == ads::ACTION_TAKE
            && declared.consumes.len() == 1
            && declared.produces.len() == 1
            && declared.space.is_some()
    })
}

/// Ruby `MCP.offerings`: replicas collapse by (name, consumes, produces, space); keys whose
/// sanitized names collide are suffixed; sorted by name. Linear in the actions, as Ruby's
/// `group_by` is: one card flood cannot make every catalogue read quadratic.
fn fold(actions: Vec<RemoteAction>) -> Vec<Offering> {
    // The groups, in the order their first action came (Ruby's insertion-ordered Hash), and
    // where each key's group is.
    let mut groups: Vec<([String; 4], RemoteAction, usize)> = Vec::new();
    let mut index: HashMap<[String; 4], usize> = HashMap::new();
    for action in actions {
        let key = [
            action.name(),
            action.consumes().to_owned(),
            action.produces().to_owned(),
            action.space().to_owned(),
        ];
        match index.get(&key) {
            Some(&at) => {
                if let Some((_, _, replicas)) = groups.get_mut(at) {
                    *replicas += 1;
                }
            }
            None => {
                index.insert(key.clone(), groups.len());
                groups.push((key, action, 1));
            }
        }
    }
    let keys: Vec<&[String; 4]> = groups.iter().map(|(key, _, _)| key).collect();
    let names = unique_names(&keys);
    let mut offerings: Vec<Offering> = groups
        .into_iter()
        .zip(names)
        .filter_map(|((_, action, replicas), name)| {
            let name = name?;
            Some(Offering {
                name,
                action,
                replicas,
            })
        })
        .collect();
    offerings.sort_by(|a, b| a.name.cmp(&b.name));
    offerings
}

/// The name of each (name, consumes, produces, space) key ([module docs](self#offerings)): Ruby's
/// names, then every name carried by more than one key renamed (a literal name first, else a
/// longer suffix for each carrier), until none is shared or [`MAX_NAMING_PASSES`] renamings
/// have run; `None` for a key whose name is still shared then (withheld). Linear in the keys per
/// pass.
fn unique_names(keys: &[&[String; 4]]) -> Vec<Option<String>> {
    let bases: Vec<String> = keys.iter().map(|key| base_name(&key[0])).collect();
    let mut sharing: HashMap<&str, usize> = HashMap::new();
    for base in &bases {
        *sharing.entry(base.as_str()).or_default() += 1;
    }
    // The Ruby rule: a shared base is suffixed (level 1), a unique one is kept (level 0).
    let mut levels: Vec<usize> = bases
        .iter()
        .map(|base| usize::from(sharing.get(base.as_str()).copied().unwrap_or_default() > 1))
        .collect();
    let name_of = |at: usize, level: usize| named(&bases[at], keys[at], level);
    let mut names: Vec<String> = (0..keys.len()).map(|at| name_of(at, levels[at])).collect();
    // Then every name carried twice is renamed: a literal name first (it may be squatting
    // another's suffixed name), else every carrier takes a longer suffix.
    for _ in 0..MAX_NAMING_PASSES {
        let mut carriers: HashMap<&str, Vec<usize>> = HashMap::new();
        for (at, name) in names.iter().enumerate() {
            carriers.entry(name.as_str()).or_default().push(at);
        }
        let mut renamed: Vec<usize> = Vec::new();
        for shared in carriers.values().filter(|carriers| carriers.len() > 1) {
            let literal: Vec<usize> = shared
                .iter()
                .copied()
                .filter(|at| levels[*at] == 0)
                .collect();
            if literal.is_empty() {
                renamed.extend(shared.iter().copied().filter(|at| levels[*at] < MAX_LEVEL));
            } else {
                renamed.extend(literal);
            }
        }
        if renamed.is_empty() {
            break;
        }
        for at in renamed {
            levels[at] += 1;
            names[at] = name_of(at, levels[at]);
        }
    }
    let mut carried: HashMap<String, usize> = HashMap::new();
    for name in &names {
        *carried.entry(name.clone()).or_default() += 1;
    }
    names
        .into_iter()
        .map(|name| {
            if carried.get(&name).copied().unwrap_or_default() == 1 {
                Some(name)
            } else {
                tracing::warn!(
                    name = %name,
                    "an offering whose name still collides after {MAX_NAMING_PASSES} renamings \
                     is withheld"
                );
                None
            }
        })
        .collect()
}

/// The highest naming level: the whole digest as the suffix.
const MAX_LEVEL: usize = 3;

/// A group's name at naming `level`: the base (0), Ruby's `<base>_<8 hex>` (1), then 16 (2) and
/// 64 (3) hex digits of the same digest.
fn named(base: &str, key: &[String; 4], level: usize) -> String {
    match level {
        0 => base.to_owned(),
        1 => suffixed(base, key),
        2 => suffixed_with(base, key, LONGER_SUFFIX_HEX[0]),
        _ => suffixed_with(base, key, LONGER_SUFFIX_HEX[1]),
    }
}

/// Whether two offerings are the same (name, consumes, produces, space) key's.
fn same_key(a: &Offering, b: &Offering) -> bool {
    a.action.name() == b.action.name()
        && a.consumes() == b.consumes()
        && a.produces() == b.produces()
        && a.space() == b.space()
}

/// Ruby `MCP.base_name`: each character outside `[a-zA-Z0-9_.-]` becomes `_`, at most
/// [`MAX_NAME`] characters.
pub fn base_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_NAME)
        .collect()
}

/// Ruby `MCP.suffixed`: `<base>_<8 hex>` from the SHA-256 of `JSON.generate([name, consumes,
/// produces, space])`, the base cut so the whole stays within [`MAX_NAME`].
pub fn suffixed(base: &str, key: &[String; 4]) -> String {
    suffixed_with(base, key, SUFFIX_HEX)
}

/// [`suffixed`] with `hex` digits of the digest (at most 64).
fn suffixed_with(base: &str, key: &[String; 4], hex: usize) -> String {
    let generated = serde_json::to_string(key).unwrap_or_default();
    let digest = crypto::port().sha256(generated.as_bytes());
    let tag: String = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(hex)
        .collect();
    let kept: String = base
        .chars()
        .take(MAX_NAME.saturating_sub(tag.len() + 1))
        .collect();
    format!("{kept}_{tag}")
}

/// The offering named `query`, else the one consuming it. Names are unique ([`fold`]); a name
/// carried twice anyway is refused as ambiguous rather than resolved to either.
fn resolve(offerings: &[Offering], query: &str) -> Result<Offering, CatalogError> {
    let named: Vec<&Offering> = offerings
        .iter()
        .filter(|offering| offering.name == query)
        .collect();
    match named.as_slice() {
        [] => {}
        [one] => return Ok((*one).clone()),
        many => {
            return Err(CatalogError::Ambiguous {
                query: query.to_owned(),
                candidates: many.iter().map(|offering| offering.name.clone()).collect(),
            });
        }
    }
    let consuming: Vec<&Offering> = offerings
        .iter()
        .filter(|offering| offering.consumes() == query)
        .collect();
    match consuming.as_slice() {
        [] => Err(CatalogError::NotFound(query.to_owned())),
        [one] => Ok((*one).clone()),
        many => Err(CatalogError::Ambiguous {
            query: query.to_owned(),
            candidates: many.iter().map(|offering| offering.name.clone()).collect(),
        }),
    }
}

/// Whether `text` matches the glob `pattern`: `*` any run of characters (none included), `?`
/// exactly one, anything else itself.
pub fn glob(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it has absorbed up to.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some('?') => {
                p += 1;
                t += 1;
            }
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((at, absorbed)) => {
                    p = at + 1;
                    t = absorbed + 1;
                    star = Some((at, absorbed + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, consumes: &str, produces: &str, space: &str) -> [String; 4] {
        [
            name.to_owned(),
            consumes.to_owned(),
            produces.to_owned(),
            space.to_owned(),
        ]
    }

    /// The vectors Ruby's `Digest::SHA256.hexdigest(JSON.generate(key))[0, 8]` gives (ruby
    /// 4.0.9, json 2.x), so the Rust and Ruby gateways name shared actions alike.
    #[test]
    fn suffixes_match_the_ruby_gateway() {
        assert_eq!(
            suffixed(
                "research",
                &key(
                    "research",
                    "com.acme.Task#v1",
                    "com.acme.Result#v1",
                    "tasks"
                )
            ),
            "research_854bb186"
        );
        assert_eq!(
            suffixed(
                "research",
                &key(
                    "research",
                    "com.acme.OtherTask#v1",
                    "com.acme.Result#v1",
                    "tasks"
                )
            ),
            "research_9bae3fcd"
        );
        let odd = "résumé \"q\" \\ /\u{1}\u{1f}";
        assert_eq!(
            suffixed(&base_name(odd), &key(odd, "a$B#v1", "c#v1", "sp")),
            format!("{}_83c0cd9c", base_name(odd))
        );
        let long = "n".repeat(200);
        let named = suffixed(&base_name(&long), &key(&long, "a", "b", "c"));
        assert_eq!(named.chars().count(), MAX_NAME);
    }

    /// An action named literally what another's suffixed name is (`research_854bb186`) does not
    /// take that name: the honest suffixed name stays, the literal one takes its own suffix, and
    /// every name is unique. A fleet without collisions keeps the Ruby names.
    #[test]
    fn a_literal_name_never_takes_a_suffixed_one() {
        let task = key(
            "research",
            "com.acme.Task#v1",
            "com.acme.Result#v1",
            "tasks",
        );
        let other = key(
            "research",
            "com.acme.OtherTask#v1",
            "com.acme.Result#v1",
            "tasks",
        );
        let squat = key("research_854bb186", "evil.Loot#v1", "evil.Out#v1", "loot");
        let names = unique_names(&[&task, &other, &squat]);
        assert_eq!(names[0].as_deref(), Some("research_854bb186"));
        assert_eq!(names[1].as_deref(), Some("research_9bae3fcd"));
        assert_eq!(
            names[2].as_deref(),
            Some(suffixed("research_854bb186", &squat).as_str())
        );
        // Order does not matter: the squatter first gets the same names.
        let names = unique_names(&[&squat, &task, &other]);
        assert_eq!(names[1].as_deref(), Some("research_854bb186"));
        assert_eq!(
            names[0].as_deref(),
            Some(suffixed("research_854bb186", &squat).as_str())
        );
        // A chain of squatters (each named what the previous one is renamed to) is renamed in
        // turn; the honest names never move.
        let second_name = suffixed("research_854bb186", &squat);
        let chained = key(&second_name, "evil.More#v1", "evil.Out#v1", "loot");
        let names = unique_names(&[&task, &other, &squat, &chained]);
        assert_eq!(names[0].as_deref(), Some("research_854bb186"));
        assert_eq!(names[1].as_deref(), Some("research_9bae3fcd"));
        let all: Vec<&str> = names.iter().flatten().map(String::as_str).collect();
        let mut unique = all.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(all.len(), 4);
        assert_eq!(unique.len(), 4, "{all:?}");
        // No collision, no change: the Ruby names.
        let plain = key("summarize", "a#v1", "b#v1", "tasks");
        assert_eq!(
            unique_names(&[&task, &other, &plain]),
            [
                Some("research_854bb186".to_owned()),
                Some("research_9bae3fcd".to_owned()),
                Some("summarize".to_owned())
            ]
        );
    }

    /// Two suffixed names that collide (a brute-forced 8-hex match) both take a longer suffix,
    /// and the names stay unique and within [`MAX_NAME`].
    #[test]
    fn colliding_suffixed_names_take_longer_suffixes() {
        let a = key("x", "a#v1", "o#v1", "s");
        let b = key("x", "b#v1", "o#v1", "s");
        assert_eq!(named("x", &a, 2).len(), "x_".len() + 16);
        assert_eq!(named("x", &a, 3).len(), "x_".len() + 64);
        let long = "n".repeat(200);
        let wide = key(&long, "a", "b", "c");
        assert_eq!(named(&base_name(&long), &wide, 3).chars().count(), MAX_NAME);
        let names = unique_names(&[&a, &b]);
        assert_ne!(names[0], names[1]);
    }

    #[test]
    fn base_names_replace_what_tools_refuse() {
        assert_eq!(base_name("x y"), "x_y");
        assert_eq!(base_name("résumé"), "r_sum_");
        assert_eq!(base_name("a.b-c_d9"), "a.b-c_d9");
        assert_eq!(base_name(&"z".repeat(300)).len(), MAX_NAME);
    }

    #[test]
    fn globs_match_runs_and_single_characters() {
        assert!(glob("shop.*", "shop.Order#v1"));
        assert!(!glob("shop.*", "shopOrder"));
        assert!(glob("*", ""));
        assert!(glob("*Task*", "com.acme.Task#v1"));
        assert!(glob("re?earch", "research"));
        assert!(!glob("re?earch", "reearch"));
        assert!(glob("a*b*c", "a-x-b-y-c"));
        assert!(!glob("a*b*c", "a-x-b-y"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("**x", "abx"));
    }

    #[test]
    fn principals_carry_their_token() {
        let local = Principal::local();
        assert!(local.is_local());
        let token = Principal::token("ana", ["orders:write"]);
        assert!(!token.is_local());
        assert!(token.has_scope("orders:write"));
        assert!(!token.has_scope("orders:read"));
    }
}
