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

//! AgentCards (SPEC §6.1): the parsed view a reader works with ([`AgentCard`], [`CardAction`]),
//! and the card a bound agent publishes (Java `AgentBinder.buildCard`, `declared`, and
//! `refreshCards`, `AgentBinder.java` 1130-1245 and 733-756).

use std::collections::BTreeMap;

use agentspaces_wire::ads::{self, AdError};
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::identity::{AgentIdentity, Identity};
use agentspaces_wire::time;

/// The most actions one card declares (Java `AgentCard.MAX_ACTIONS`).
pub const MAX_ACTIONS: usize = 64;

/// The longest action description, in UTF-16 units (Java `CardAction.MAX_DESCRIPTION_LENGTH`).
pub const MAX_ACTION_DESCRIPTION: usize = 512;

// ---------------------------------------------------------------------------------------------
// Card actions

/// One action a card declares (Java `CardAction`, SPEC §6.1 v0.1.13): its name, description,
/// the schemas it consumes and produces, the space it is bound in, and its kind (`take`,
/// `notify`, ...; [`ads::INVOCABLE_ACTIONS`] says which a caller invokes by writing the consumed
/// entry).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardAction {
    /// The action's name, unique within its card.
    pub name: String,
    /// What it does (may be empty: the card's description stands in).
    pub description: String,
    /// The schemas it consumes.
    pub consumes: Vec<String>,
    /// The schemas it produces.
    pub produces: Vec<String>,
    /// The space it is bound in, when the card says.
    pub space: Option<String>,
    /// Its kind (`take`, `notify`, `ordered-take`, `ballot`, ...).
    pub kind: String,
}

impl CardAction {
    /// The action of a card's `actions` element, or `None` when it is not a map with a text
    /// `name` and `kind` (a malformed element is passed over, as Jackson would refuse the card).
    pub fn from_map(map: &Map) -> Option<CardAction> {
        let name = map.get("name")?.as_str()?.to_owned();
        let kind = map.get("kind")?.as_str()?.to_owned();
        Some(CardAction {
            name,
            description: text(map, "description"),
            consumes: texts(map, "consumes"),
            produces: texts(map, "produces"),
            space: map
                .get("space")
                .and_then(Value::as_str)
                .filter(|space| !space.is_empty())
                .map(str::to_owned),
            kind,
        })
    }

    /// The wire form ([`ads::card_action`]).
    pub fn to_map(&self) -> Map {
        let consumes: Vec<&str> = self.consumes.iter().map(String::as_str).collect();
        let produces: Vec<&str> = self.produces.iter().map(String::as_str).collect();
        ads::card_action(
            &self.name,
            &self.description,
            &consumes,
            &produces,
            &self.kind,
            self.space.as_deref(),
        )
    }

    /// Whether a caller invokes it by writing the consumed entry (Java `CardAction.invocable`).
    pub fn invocable(&self) -> bool {
        ads::INVOCABLE_ACTIONS.contains(&self.kind.as_str())
    }
}

// ---------------------------------------------------------------------------------------------
// The parsed card

/// An `AgentCard` as a reader sees it ([`crate::peer::Peer::cards`] answers verified maps; this is
/// their parsed view): who advertises what, where, until when.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentCard {
    map: Map,
    id: String,
    issuer: String,
    agent: String,
    issued: String,
    issued_ms: i64,
    expires_ms: i64,
    description: String,
    goals: Vec<String>,
    consumes: Vec<String>,
    produces: Vec<String>,
    space_bindings: BTreeMap<String, String>,
    actions: Option<Vec<CardAction>>,
    agent_public_key: Option<Vec<u8>>,
}

/// Whether a card's `actions` are ones Java admits (its `AgentCard` and `CardAction`
/// constructors, run as Jackson decodes the card in `AdCache.accept`): absent or null, or an
/// array of at most [`MAX_ACTIONS`] maps, each with a text `kind` and a non-empty text `name`
/// no other element repeats, and a description of at most [`MAX_ACTION_DESCRIPTION`] UTF-16
/// units. `Err` says what Java refuses.
pub fn check_actions(card: &Map) -> Result<(), String> {
    let actions = match card.get("actions") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::Array(actions)) => actions,
        Some(_) => return Err("its actions are not an array".to_owned()),
    };
    if actions.len() > MAX_ACTIONS {
        return Err(format!(
            "a card declares at most {MAX_ACTIONS} actions, not {}",
            actions.len()
        ));
    }
    let mut names = std::collections::HashSet::with_capacity(actions.len());
    for action in actions {
        let action = action
            .as_map()
            .ok_or_else(|| "an action is not a map".to_owned())?;
        let name = action
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "an action has no text name".to_owned())?;
        if action.get("kind").and_then(Value::as_str).is_none() {
            return Err(format!("action {name:?} has no text kind"));
        }
        if name.is_empty() {
            return Err("an action needs a name".to_owned());
        }
        if action
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|text| text.encode_utf16().count() > MAX_ACTION_DESCRIPTION)
        {
            return Err(format!(
                "action description longer than {MAX_ACTION_DESCRIPTION} characters: {name:?}"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "action names must be unique within a card: {name:?}"
            ));
        }
    }
    Ok(())
}

impl AgentCard {
    /// The parsed view of a card map, or `None` when it lacks a text `id`, `issuer`, `agent`,
    /// or a parsable `issued` and `ttl`, or declares actions Java refuses ([`check_actions`]).
    pub fn parse(map: Map) -> Option<AgentCard> {
        check_actions(&map).ok()?;
        let id = map.get("id")?.as_str()?.to_owned();
        let issuer = map.get("issuer")?.as_str()?.to_owned();
        let agent = map.get("agent")?.as_str()?.to_owned();
        let issued = map.get("issued")?.as_str()?.to_owned();
        let issued_ms = time::parse_instant_millis(&issued).ok()?;
        let expires_ms = ads::ad_expires_at_millis(&map)?;
        let space_bindings = map
            .get("spaceBindings")
            .and_then(Value::as_map)
            .map(|bindings| {
                bindings
                    .iter()
                    .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?)))
                    .filter(|(_, space)| !space.is_empty())
                    .map(|(key, space)| (key, space.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let actions = match map.get("actions") {
            None | Some(Value::Null) => None,
            Some(actions) => Some(
                actions
                    .as_array()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(Value::as_map)
                    .filter_map(CardAction::from_map)
                    .collect(),
            ),
        };
        let agent_public_key = map
            .get("agentPublicKey")
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec);
        Some(AgentCard {
            description: text(&map, "description"),
            goals: texts(&map, "goals"),
            consumes: texts(&map, "consumes"),
            produces: texts(&map, "produces"),
            id,
            issuer,
            agent,
            issued,
            issued_ms,
            expires_ms,
            space_bindings,
            actions,
            agent_public_key,
            map,
        })
    }

    /// The card's id, `aspace://<group>/agent/<agentId>`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The issuing peer's PeerID.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The advertised agent's AgentID, `<peerId>/<localName>`.
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// The agent's local name (after the first `/`).
    pub fn local_name(&self) -> &str {
        self.agent
            .split_once('/')
            .map_or(self.agent.as_str(), |(_, local)| local)
    }

    /// The `issued` instant's text.
    pub fn issued(&self) -> &str {
        &self.issued
    }

    /// The `issued` instant, epoch milliseconds.
    pub fn issued_millis(&self) -> i64 {
        self.issued_ms
    }

    /// When the card expires (`issued + ttl`), epoch milliseconds.
    pub fn expires_at_millis(&self) -> i64 {
        self.expires_ms
    }

    /// The agent's description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The agent's goals.
    pub fn goals(&self) -> &[String] {
        &self.goals
    }

    /// The flat list of consumed schemas.
    pub fn consumes(&self) -> &[String] {
        &self.consumes
    }

    /// The flat list of produced schemas.
    pub fn produces(&self) -> &[String] {
        &self.produces
    }

    /// The space the agent takes or watches a consumed schema in (Java `AgentCard.spaceFor`).
    pub fn space_for(&self, consumed: &str) -> Option<&str> {
        self.space_bindings.get(consumed).map(String::as_str)
    }

    /// The declared actions; `None` for a card from before v0.1.13 that declares none.
    pub fn actions(&self) -> Option<&[CardAction]> {
        self.actions.as_deref()
    }

    /// The agent's own public key, when the card carries one (an attested agent).
    pub fn agent_public_key(&self) -> Option<&[u8]> {
        self.agent_public_key.as_deref()
    }

    /// Whether the agent signs with a certified key of its own (Java `AgentCard.attested`).
    pub fn attested(&self) -> bool {
        self.agent_public_key.is_some()
    }

    /// The card's map, as verified.
    pub fn as_map(&self) -> &Map {
        &self.map
    }

    /// The card's map, owned.
    pub fn into_map(self) -> Map {
        self.map
    }
}

fn text(map: &Map, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn texts(map: &Map, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The card a bound agent publishes

/// What a bound agent's card says, fixed at bind; [`CardSpec::build`] makes the card for one
/// issue instant.
#[derive(Debug, Clone)]
pub(crate) struct CardSpec {
    pub group: String,
    pub description: String,
    pub goals: Vec<String>,
    pub consumes: Vec<String>,
    pub produces: Vec<String>,
    pub space_bindings: Map,
    pub actions: Vec<CardAction>,
    pub ttl_iso: String,
}

impl CardSpec {
    /// The card at `issued_ms` (Java `AgentBinder.buildCard` and `refreshCards`): issued by
    /// `peer`, for `agent` with its key and the certificate covering the issue instant.
    pub fn build(
        &self,
        peer: &Identity,
        agent: &AgentIdentity,
        issued_ms: i64,
    ) -> Result<Map, AdError> {
        let goals: Vec<&str> = self.goals.iter().map(String::as_str).collect();
        let consumes: Vec<&str> = self.consumes.iter().map(String::as_str).collect();
        let produces: Vec<&str> = self.produces.iter().map(String::as_str).collect();
        let actions: Vec<Map> = self.actions.iter().map(CardAction::to_map).collect();
        ads::agent_card(
            &self.group,
            peer,
            agent.local_name(),
            &time::instant_iso(issued_ms),
            &self.ttl_iso,
            &self.description,
            &goals,
            &consumes,
            &produces,
            &Map::new(),
            &self.space_bindings,
            Some(agent.public_raw()),
            &actions,
            agent.certificate_covering(issued_ms),
            None,
        )
    }
}

/// The card's action list (Java `AgentBinder.declared`): a name several actions share is
/// disambiguated by their consumed schemas (`name(a,b)`), the list sorted by name so the card's
/// bytes do not depend on declaration order. `Err` names what Java's `AgentCard` refuses: more
/// than [`MAX_ACTIONS`], an empty name, a description over [`MAX_ACTION_DESCRIPTION`], or names
/// still not unique.
pub(crate) fn declared(actions: Vec<CardAction>) -> Result<Vec<CardAction>, String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for action in &actions {
        *counts.entry(action.name.clone()).or_default() += 1;
    }
    let mut named: Vec<CardAction> = actions
        .into_iter()
        .map(|mut action| {
            if counts.get(&action.name).copied().unwrap_or_default() > 1 {
                action.name = format!("{}({})", action.name, action.consumes.join(","));
            }
            action
        })
        .collect();
    named.sort_by(|a, b| java_compare(&a.name, &b.name));
    if named.len() > MAX_ACTIONS {
        return Err(format!(
            "an agent binds at most {MAX_ACTIONS} actions; this one binds {}",
            named.len()
        ));
    }
    for action in &named {
        if action.name.is_empty() {
            return Err("an action needs a name".to_owned());
        }
        if action.description.encode_utf16().count() > MAX_ACTION_DESCRIPTION {
            return Err(format!(
                "action description longer than {MAX_ACTION_DESCRIPTION} characters: {}",
                action.name
            ));
        }
    }
    if named.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err("action names must be unique within a card".to_owned());
    }
    Ok(named)
}

/// Java's `String.compareTo`: by UTF-16 code units.
fn java_compare(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(name: &str, consumes: &str) -> CardAction {
        CardAction {
            name: name.to_owned(),
            description: String::new(),
            consumes: vec![consumes.to_owned()],
            produces: vec!["out#v1".to_owned()],
            space: Some("tasks".to_owned()),
            kind: ads::ACTION_TAKE.to_owned(),
        }
    }

    #[test]
    fn declared_sorts_and_disambiguates_shared_names() {
        let named = declared(vec![
            action("work", "b#v1"),
            action("audit", "c#v1"),
            action("work", "a#v1"),
        ])
        .expect("declared");
        let names: Vec<&str> = named.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["audit", "work(a#v1)", "work(b#v1)"]);
        assert!(declared(vec![action("x", "a#v1"), action("x", "a#v1")]).is_err());
        assert!(declared(vec![action("", "a#v1")]).is_err());
        let mut long = action("y", "a#v1");
        long.description = "d".repeat(MAX_ACTION_DESCRIPTION + 1);
        assert!(declared(vec![long]).is_err());
        let many = (0..=MAX_ACTIONS)
            .map(|n| action(&format!("a{n}"), "a#v1"))
            .collect();
        assert!(declared(many).is_err());
    }

    /// What Java's `AgentCard` refuses does not parse here either.
    #[test]
    fn cards_with_actions_java_refuses_do_not_parse() {
        let peer = Identity::from_seed(&[4; 32]);
        let built = |actions: Vec<CardAction>| {
            let spec = CardSpec {
                group: "zGroup".to_owned(),
                description: String::new(),
                goals: Vec::new(),
                consumes: Vec::new(),
                produces: Vec::new(),
                space_bindings: Map::new(),
                actions,
                ttl_iso: "PT15M".to_owned(),
            };
            let agent = peer
                .renewing_subordinate("w", "PT24H", None, 1_767_225_600_000)
                .expect("agent");
            spec.build(&peer, &agent, 1_767_225_600_000).expect("card")
        };
        let fine = built(vec![action("a", "a#v1"), action("b", "a#v1")]);
        assert!(check_actions(&fine).is_ok());
        assert!(AgentCard::parse(fine).is_some());
        let repeated = built(vec![action("a", "a#v1"), action("a", "b#v1")]);
        assert!(check_actions(&repeated).is_err());
        assert!(AgentCard::parse(repeated).is_none());
        let many = built(
            (0..=MAX_ACTIONS)
                .map(|n| action(&format!("a{n}"), "a#v1"))
                .collect(),
        );
        assert!(AgentCard::parse(many).is_none());
        let mut nameless = built(vec![action("a", "a#v1")]);
        nameless.insert("actions", agentspaces_wire::cbor_array![Map::new()]);
        assert!(AgentCard::parse(nameless).is_none());
    }

    #[test]
    fn actions_round_trip_and_parse_leniently() {
        let original = action("work", "a#v1");
        assert_eq!(CardAction::from_map(&original.to_map()), Some(original));
        assert!(CardAction::from_map(&Map::new()).is_none());
        assert!(action("w", "a#v1").invocable());
        let mut ballot = action("b", "a#v1");
        ballot.kind = ads::ACTION_BALLOT.to_owned();
        assert!(!ballot.invocable());
    }

    #[test]
    fn a_built_card_parses_and_verifies() {
        let peer = Identity::from_seed(&[3; 32]);
        let now = 1_767_225_600_000;
        let agent = peer
            .renewing_subordinate("worker", "PT24H", None, now)
            .expect("agent");
        let mut bindings = Map::new();
        bindings.insert("a#v1", "tasks");
        let spec = CardSpec {
            group: "zGroup".to_owned(),
            description: "works".to_owned(),
            goals: vec!["help".to_owned()],
            consumes: vec!["a#v1".to_owned()],
            produces: vec!["out#v1".to_owned()],
            space_bindings: bindings,
            actions: vec![action("work", "a#v1")],
            ttl_iso: "PT15M".to_owned(),
        };
        let card = spec.build(&peer, &agent, now + 5).expect("card");
        let stored = Value::Map(ads::stored_ad(ads::AD_TYPE_AGENT_CARD, &card, &peer));
        assert!(ads::verify_stored_ad(&stored, now + 10).is_some());
        let parsed = AgentCard::parse(card).expect("parsed");
        assert_eq!(parsed.agent(), agent.agent_id());
        assert_eq!(parsed.local_name(), "worker");
        assert_eq!(parsed.issuer(), peer.peer_id());
        assert_eq!(parsed.space_for("a#v1"), Some("tasks"));
        assert!(parsed.attested());
        assert_eq!(parsed.issued_millis(), now + 5);
        assert_eq!(parsed.expires_at_millis(), now + 5 + 15 * 60 * 1000);
        assert_eq!(parsed.actions().map(<[CardAction]>::len), Some(1));
        assert_eq!(parsed.goals(), ["help"]);
        assert_eq!(parsed.consumes(), ["a#v1"]);
        assert_eq!(parsed.produces(), ["out#v1"]);
        assert_eq!(parsed.description(), "works");
        assert!(parsed.id().ends_with(agent.agent_id()));
    }
}
