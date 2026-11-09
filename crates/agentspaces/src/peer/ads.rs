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

//! The advertisement cache (SPEC §6.2, Java `AdCache`, `Peer.accept_ad` in `peer.py`): stored
//! advertisements admitted by [`verify_stored_ad`], kept per issuer and advertisement id with the
//! newest `issued` winning, until their TTL passes. What the group's revocations refuse
//! (`AdCache.refuseIssuers` and `refuseAgents`: a revoked peer, agent, or agent key advertises
//! nothing) is refused at the door and purged when a revocation lands ([`AdCache::purge`], as Java
//! purges), so a revoked member's advertisements never hold slots of the bounded cache. Expired
//! advertisements are evicted (SPEC §6.2: caches MUST evict them) as new ones arrive, at most once
//! a second, and on the actor's re-lease cadence ([`AdCache::expire`]), so a resident's cache
//! follows the live set rather than every card it ever saw.
//!
//! # One issuer, its own advertisements
//!
//! An advertisement's `id` is text its issuer chooses. Keyed by `id` alone, as Java's `AdCache`
//! keys it (`byId`, last-writer-wins by `issued`), any admitted member could sign an advertisement
//! reusing another member's id with a later `issued` and replace the honest one in every cache.
//! Here the key is the pair (issuer, id), the issuer being the PeerID of the key that signed it: an
//! issuer only ever updates its own advertisements, and an id another issuer reuses is held beside
//! the honest one, never over it. Together with [`verify_stored_ad`]'s binding of an `AgentCard`'s
//! `agent` to its issuer, one issuer's card for its agent is always found. Java does neither: its
//! `AdCache` keys by id alone and admits a peer-signed card naming another peer's agent. Every Java
//! publisher names its own agents (`identity.agent(name)`) and refreshes each card under one id, so
//! an honest Java advertisement is held here exactly as before; only a hostile reuse no longer
//! wins.

use std::collections::BTreeMap;

use agentspaces_wire::ads::{AD_TYPE_AGENT_CARD, ad_expires_at_millis, verify_stored_ad};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::revocation::Registry;
use agentspaces_wire::time::parse_instant_millis;

use crate::agent::card::check_actions;

/// The most advertisements the cache holds; a new (issuer, id) beyond it is refused once the
/// expired and revoked ones are gone.
pub(super) const MAX_CACHED_ADS: usize = 4096;

/// How often, at most, an arriving advertisement makes the cache evict the expired ones.
const EXPIRE_EVERY_MILLIS: i64 = 1000;

/// One admitted advertisement.
#[derive(Debug, Clone)]
pub(super) struct CachedAd {
    /// The type tag (`AgentCard`, `CapabilityAdvertisement`, ...).
    pub ad_type: String,
    /// The advertisement.
    pub ad: Map,
    /// Its issuing peer, the PeerID of the key that signed it.
    pub issuer: String,
    /// Its `issued`, epoch milliseconds.
    pub issued_ms: i64,
    /// When it expires (`issued + ttl`), epoch milliseconds.
    pub expires_ms: i64,
}

/// What [`AdCache::accept`] admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Admitted {
    /// The type tag.
    pub ad_type: String,
    /// The advertisement id.
    pub id: String,
    /// Whether the cache changed (a new (issuer, id), or a newer advertisement under a held one).
    pub changed: bool,
}

/// Where an advertisement is held: its issuer's PeerID and its id. An issuer replaces only its
/// own advertisements.
type AdKey = (String, String);

/// The advertisements a peer has admitted, by (issuer, id).
#[derive(Debug)]
pub(super) struct AdCache {
    entries: BTreeMap<AdKey, CachedAd>,
    /// The most advertisements held, [`MAX_CACHED_ADS`] but in tests.
    max_entries: usize,
    /// When an arrival last evicted the expired advertisements, epoch milliseconds.
    expired_at_ms: i64,
}

impl Default for AdCache {
    fn default() -> AdCache {
        AdCache {
            entries: BTreeMap::new(),
            max_entries: MAX_CACHED_ADS,
            expired_at_ms: i64::MIN,
        }
    }
}

impl AdCache {
    /// A cache holding at most `max_entries` advertisements.
    #[cfg(test)]
    fn bounded(max_entries: usize) -> AdCache {
        AdCache {
            max_entries,
            ..AdCache::default()
        }
    }

    /// [`AdCache::admit`] under no revocations.
    #[cfg(test)]
    fn accept(&mut self, stored: &Value, now_ms: i64) -> Option<Admitted> {
        self.admit(stored, now_ms, &Registry::default())
    }

    /// Evicts every advertisement expired at `now_ms` (SPEC §6.2); answers how many went.
    pub fn expire(&mut self, now_ms: i64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, cached| cached.expires_ms > now_ms);
        self.expired_at_ms = now_ms;
        before - self.entries.len()
    }

    /// Drops every advertisement `registry` now refuses: a revoked issuer's, and an agent card of a
    /// revoked agent or agent key (Java `purgeIssuer`, `purgeAgent`). Called when a revocation
    /// lands, so the slots a revoked member filled are free at once.
    pub fn purge(&mut self, registry: &Registry) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, cached| !refused(cached, registry));
        before - self.entries.len()
    }

    /// Admits one stored advertisement at `now_ms` (`AdCache.accept`): [`verify_stored_ad`]'s
    /// checks (an AgentCard names its issuer's own agent among them), a text `id`, an AgentCard's
    /// actions as Java's `AgentCard` admits them ([`check_actions`]: at most 64, named uniquely,
    /// ...), not refused by `registry` (a revoked issuer, or an agent card of a revoked agent or
    /// agent key: Java's `refuseIssuers` and `refuseAgents`), and last-writer-wins by `issued` per
    /// (issuer, id): an advertisement replaces only one its own issuer issued under the same id
    /// (see the [module docs](self#one-issuer-its-own-advertisements)). Bounded: an update of a
    /// held (issuer, id) always lands; a new one is refused while the cache is full after the
    /// expired and the revoked are dropped. `None` when refused.
    pub fn admit(&mut self, stored: &Value, now_ms: i64, registry: &Registry) -> Option<Admitted> {
        let (ad_type, ad, issuer) = verify_stored_ad(stored, now_ms)?;
        if ad_type == AD_TYPE_AGENT_CARD && check_actions(&ad).is_err() {
            // Jackson's decode in Java's AdCache throws on such a card, which refuses it.
            return None;
        }
        let id = ad.get("id")?.as_str()?.to_owned();
        let issued_ms = parse_instant_millis(ad.get("issued")?.as_str()?).ok()?;
        let expires_ms = ad_expires_at_millis(&ad)?;
        let cached = CachedAd {
            ad_type,
            ad,
            issuer,
            issued_ms,
            expires_ms,
        };
        if refused(&cached, registry) {
            return None;
        }
        // A clock set back counts as time passed too: the eviction never waits for it to return.
        if now_ms.abs_diff(self.expired_at_ms) >= EXPIRE_EVERY_MILLIS.unsigned_abs() {
            self.expire(now_ms);
        }
        let key: AdKey = (cached.issuer.clone(), id);
        if let Some(held) = self.entries.get(&key)
            && held.issued_ms > issued_ms
        {
            return Some(Admitted {
                ad_type: held.ad_type.clone(),
                id: key.1,
                changed: false,
            });
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.entries
                .retain(|_, held| held.expires_ms > now_ms && !refused(held, registry));
            if self.entries.len() >= self.max_entries {
                return None;
            }
        }
        let changed = self
            .entries
            .get(&key)
            .is_none_or(|held| held.ad != cached.ad || held.ad_type != cached.ad_type);
        let admitted = Admitted {
            ad_type: cached.ad_type.clone(),
            id: key.1.clone(),
            changed,
        };
        self.entries.insert(key, cached);
        Some(admitted)
    }

    /// The live advertisements of `ad_type` at `now_ms`, in (issuer, id) order, without those of
    /// a revoked issuer and, for agent cards, of a revoked agent or agent key.
    pub fn live(&self, ad_type: &str, now_ms: i64, registry: &Registry) -> Vec<Map> {
        self.entries
            .values()
            .filter(|cached| {
                cached.ad_type == ad_type
                    && cached.expires_ms > now_ms
                    && !refused(cached, registry)
            })
            .map(|cached| cached.ad.clone())
            .collect()
    }

    /// The live, unrevoked agent cards at `now_ms` (`Peer.cards`).
    pub fn cards(&self, now_ms: i64, registry: &Registry) -> Vec<Map> {
        self.live(AD_TYPE_AGENT_CARD, now_ms, registry)
    }

    /// How many advertisements are held, expired or not.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Whether the revocations refuse a cached advertisement: its issuing peer is revoked, or (an
/// agent card) its agent or its agent key is.
fn refused(cached: &CachedAd, registry: &Registry) -> bool {
    if registry.peer_revoked(&cached.issuer) {
        return true;
    }
    if cached.ad_type != AD_TYPE_AGENT_CARD {
        return false;
    }
    let Some(agent) = cached.ad.get("agent").and_then(Value::as_str) else {
        return false;
    };
    let key = cached.ad.get("agentPublicKey").and_then(Value::as_bytes);
    registry.refuses(agent, key, None)
}

/// The stored advertisements an `ads` stream delta of a pull response carries (`{ads: [...]}`),
/// or `None` when the bytes are not such a map.
pub(super) fn pulled_ads(delta: &[u8]) -> Option<Vec<Value>> {
    let mut delta = cbor::decode(delta).ok()?.into_map()?;
    match delta.remove("ads") {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(ads) => ads.into_array(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::ads::{agent_card, stored_ad};
    use agentspaces_wire::identity::Identity;
    use agentspaces_wire::time::instant_iso;

    const NOW: i64 = 1_767_225_600_000;

    fn card(identity: &Identity, issued_ms: i64, description: &str) -> Map {
        named(identity, "worker", issued_ms, description)
    }

    /// The card of `identity`'s agent `local_name`, issued at `issued_ms`, living 10 minutes.
    fn named(identity: &Identity, local_name: &str, issued_ms: i64, description: &str) -> Map {
        agent_card(
            "zGroup",
            identity,
            local_name,
            &instant_iso(issued_ms),
            "PT10M",
            description,
            &[],
            &[],
            &[],
            &Map::new(),
            &Map::new(),
            None,
            &[],
            None,
            None,
        )
        .expect("card")
    }

    #[test]
    fn newest_issued_wins_and_expired_cards_are_not_live() {
        let identity = Identity::from_seed(&[7; 32]);
        let mut cache = AdCache::default();
        let registry = Registry::default();
        let first = Value::Map(stored_ad(
            AD_TYPE_AGENT_CARD,
            &card(&identity, NOW - 1000, "first"),
            &identity,
        ));
        let second = Value::Map(stored_ad(
            AD_TYPE_AGENT_CARD,
            &card(&identity, NOW, "second"),
            &identity,
        ));
        let admitted = cache.accept(&second, NOW);
        assert!(admitted.as_ref().is_some_and(|a| a.changed));
        let older = cache.accept(&first, NOW);
        assert!(older.is_some_and(|a| !a.changed), "an older card loses");
        let cards = cache.cards(NOW, &registry);
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0].get("description").and_then(Value::as_str),
            Some("second")
        );
        assert!(cache.cards(NOW + 11 * 60 * 1000, &registry).is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.accept(&Value::Null, NOW).is_none());
    }

    /// `card` signed by `identity`, stored.
    fn stored(card: &Map, identity: &Identity) -> Value {
        Value::Map(stored_ad(AD_TYPE_AGENT_CARD, card, identity))
    }

    fn id_of(card: &Map) -> String {
        card.get("id")
            .and_then(Value::as_str)
            .expect("an id")
            .to_owned()
    }

    fn description_of(card: &Map) -> Option<&str> {
        card.get("description").and_then(Value::as_str)
    }

    /// The live cards naming `agent`.
    fn cards_of(cache: &AdCache, agent: &str, now_ms: i64) -> Vec<Map> {
        cache
            .cards(now_ms, &Registry::default())
            .into_iter()
            .filter(|card| card.get("agent").and_then(Value::as_str) == Some(agent))
            .collect()
    }

    /// A hostile member's card reusing an honest card's id with a later `issued` (its own
    /// agent, signed by its own key, so admissible) is held beside the honest card, never over
    /// it: the honest card for the honest agent is still found, unchanged. Each issuer still
    /// updates its own advertisement under the id, newest `issued` winning.
    #[test]
    fn another_issuer_reusing_an_id_never_replaces_the_honest_ad() {
        let honest = Identity::from_seed(&[1; 32]);
        let hostile = Identity::from_seed(&[2; 32]);
        let mut cache = AdCache::default();
        let honest_card = card(&honest, NOW - 1000, "honest");
        let id = id_of(&honest_card);
        let admitted = cache.accept(&stored(&honest_card, &honest), NOW);
        assert!(admitted.as_ref().is_some_and(|a| a.changed && a.id == id));

        let mut reuse = card(&hostile, NOW, "hostile");
        reuse.insert("id", id.clone());
        let admitted = cache
            .accept(&stored(&reuse, &hostile), NOW)
            .expect("its own card");
        assert!(admitted.changed);
        assert_eq!(admitted.id, id);
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cards_of(&cache, &honest.agent("worker"), NOW),
            [honest_card]
        );
        assert_eq!(
            cards_of(&cache, &hostile.agent("worker"), NOW),
            [reuse.clone()]
        );

        // The honest issuer's newer card replaces its own, and only its own.
        let refreshed = card(&honest, NOW + 1000, "honest, refreshed");
        assert_eq!(id_of(&refreshed), id);
        let admitted = cache.accept(&stored(&refreshed, &honest), NOW);
        assert!(admitted.is_some_and(|a| a.changed));
        assert_eq!(cards_of(&cache, &honest.agent("worker"), NOW), [refreshed]);
        assert_eq!(cards_of(&cache, &hostile.agent("worker"), NOW), [reuse]);

        // A still later reuse replaces the hostile's own card, not the honest one; an older one
        // loses to the hostile's own.
        let mut later = card(&hostile, NOW + 2000, "hostile, later");
        later.insert("id", id.clone());
        assert!(
            cache
                .accept(&stored(&later, &hostile), NOW)
                .is_some_and(|a| a.changed)
        );
        let mut older = card(&hostile, NOW - 2000, "hostile, older");
        older.insert("id", id.clone());
        assert!(
            cache
                .accept(&stored(&older, &hostile), NOW)
                .is_some_and(|a| !a.changed)
        );
        let honest_cards = cards_of(&cache, &honest.agent("worker"), NOW);
        assert_eq!(honest_cards.len(), 1);
        assert_eq!(description_of(&honest_cards[0]), Some("honest, refreshed"));
        assert_eq!(cards_of(&cache, &hostile.agent("worker"), NOW), [later]);
        assert_eq!(cache.len(), 2);
    }

    /// A hostile member's peer-signed card naming the honest peer's agent is refused, under its
    /// own id or the honest card's; the honest card is all the cache holds.
    #[test]
    fn a_card_naming_another_peers_agent_is_refused() {
        let honest = Identity::from_seed(&[3; 32]);
        let hostile = Identity::from_seed(&[4; 32]);
        let mut cache = AdCache::default();
        let honest_card = card(&honest, NOW - 1000, "honest");
        assert!(cache.accept(&stored(&honest_card, &honest), NOW).is_some());

        let mut impostor = card(&hostile, NOW, "impostor");
        assert!(
            cache
                .accept(&stored(&impostor, &hostile), NOW + 1)
                .is_some(),
            "the hostile's own card is admissible"
        );
        impostor.insert("agent", honest.agent("worker"));
        impostor.insert("issued", instant_iso(NOW + 1000));
        assert!(cache.accept(&stored(&impostor, &hostile), NOW).is_none());
        impostor.insert("id", id_of(&honest_card));
        assert!(cache.accept(&stored(&impostor, &hostile), NOW).is_none());
        assert_eq!(
            cards_of(&cache, &honest.agent("worker"), NOW),
            [honest_card]
        );
        assert_eq!(cache.len(), 2);
    }

    /// The bound over (issuer, id): when the cache is full, an update of a held (issuer, id)
    /// lands; a new one is refused, another issuer's reuse of a held id among them, until the
    /// expired advertisements are dropped to make room.
    #[test]
    fn the_bound_holds_per_issuer_and_id() {
        let honest = Identity::from_seed(&[5; 32]);
        let hostile = Identity::from_seed(&[6; 32]);
        let mut cache = AdCache::bounded(3);
        // Expires a minute after NOW.
        let early = named(&honest, "early", NOW - 9 * 60 * 1000, "early");
        let a = named(&honest, "a", NOW, "a");
        let b = named(&honest, "b", NOW, "b");
        for card in [&early, &a, &b] {
            assert!(cache.accept(&stored(card, &honest), NOW).is_some());
        }
        assert_eq!(cache.len(), 3);

        let mut reuse = named(&hostile, "a", NOW + 1000, "reuse");
        reuse.insert("id", id_of(&a));
        assert!(
            cache.accept(&stored(&reuse, &hostile), NOW).is_none(),
            "a new (issuer, id) while full"
        );
        let own = named(&hostile, "own", NOW, "own");
        assert!(cache.accept(&stored(&own, &hostile), NOW).is_none());
        let a_refreshed = named(&honest, "a", NOW + 1000, "a, refreshed");
        assert!(
            cache
                .accept(&stored(&a_refreshed, &honest), NOW)
                .is_some_and(|admitted| admitted.changed),
            "an update of a held (issuer, id) lands while full"
        );
        assert_eq!(cache.len(), 3);

        // Once `early` expires, room is made for one new (issuer, id).
        let later = NOW + 61 * 1000;
        assert!(cache.accept(&stored(&reuse, &hostile), later).is_some());
        assert!(cache.accept(&stored(&own, &hostile), later).is_none());
        assert_eq!(cache.len(), 3);
        assert_eq!(cards_of(&cache, &honest.agent("a"), later), [a_refreshed]);
        assert_eq!(cards_of(&cache, &honest.agent("b"), later), [b]);
        assert_eq!(cards_of(&cache, &hostile.agent("a"), later), [reuse]);
        assert!(cards_of(&cache, &honest.agent("early"), later).is_empty());
    }

    /// The founder's signed revocation of peer `revoked` in `zGroup`, issued just before NOW.
    fn peer_revocation(founder: &Identity, revoked: &str) -> Value {
        let mut ad = Map::new();
        ad.insert("issuer", founder.peer_id());
        ad.insert("group", "zGroup");
        ad.insert("issued", instant_iso(NOW - 1000));
        ad.insert("revoked", revoked);
        ad.insert("reason", agentspaces_wire::revocation::KEY_COMPROMISE);
        Value::Map(agentspaces_wire::revocation::sign_revocation(&ad, founder))
    }

    /// One hostile issuer fills the bounded cache with long-lived cards; an honest newcomer is
    /// refused while it is full. Once the founder revokes the hostile peer, the purge frees its
    /// slots at once, so the honest card is admitted without waiting for the hostile cards' TTL;
    /// the revoked issuer's cards are refused at the door from then on, also when the cache has
    /// room.
    #[test]
    fn a_revoked_issuers_cards_leave_the_cache_and_stay_out() {
        let founder = Identity::from_seed(&[10; 32]);
        let hostile = Identity::from_seed(&[11; 32]);
        let honest = Identity::from_seed(&[12; 32]);
        let mut registry = Registry::new(
            Some(founder.peer_id().to_owned()),
            Some("zGroup".to_owned()),
        );
        let mut cache = AdCache::bounded(4);
        for name in ["h1", "h2", "h3", "h4"] {
            let card = named(&hostile, name, NOW, name);
            assert!(
                cache
                    .admit(&stored(&card, &hostile), NOW, &registry)
                    .is_some()
            );
        }
        let newcomer = named(&honest, "worker", NOW, "honest");
        assert!(
            cache
                .admit(&stored(&newcomer, &honest), NOW, &registry)
                .is_none(),
            "the cache is full of the hostile issuer's cards"
        );
        assert!(registry.accept_signed(
            agentspaces_wire::revocation::PEER_STREAM,
            &peer_revocation(&founder, hostile.peer_id()),
            NOW,
        ));
        assert_eq!(cache.purge(&registry), 4, "every hostile card leaves");
        assert_eq!(cache.len(), 0);
        assert!(
            cache
                .admit(&stored(&newcomer, &honest), NOW, &registry)
                .is_some_and(|admitted| admitted.changed),
            "the honest card is admitted at once"
        );
        let again = named(&hostile, "h5", NOW + 1000, "again");
        assert!(
            cache
                .admit(&stored(&again, &hostile), NOW + 1000, &registry)
                .is_none(),
            "a revoked issuer's card is refused at the door"
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cards_of(&cache, &honest.agent("worker"), NOW), [newcomer]);
    }

    /// The full-cache path drops revoked advertisements too (a revocation the purge has not
    /// seen yet, as when the cache is filled again before the next one lands).
    #[test]
    fn a_full_cache_makes_room_by_dropping_revoked_ads() {
        let founder = Identity::from_seed(&[13; 32]);
        let hostile = Identity::from_seed(&[14; 32]);
        let honest = Identity::from_seed(&[15; 32]);
        let mut registry = Registry::new(
            Some(founder.peer_id().to_owned()),
            Some("zGroup".to_owned()),
        );
        let mut cache = AdCache::bounded(2);
        for name in ["h1", "h2"] {
            let card = named(&hostile, name, NOW, name);
            assert!(
                cache
                    .admit(&stored(&card, &hostile), NOW, &registry)
                    .is_some()
            );
        }
        assert!(registry.accept_signed(
            agentspaces_wire::revocation::PEER_STREAM,
            &peer_revocation(&founder, hostile.peer_id()),
            NOW,
        ));
        let newcomer = named(&honest, "worker", NOW, "honest");
        assert!(
            cache
                .admit(&stored(&newcomer, &honest), NOW, &registry)
                .is_some()
        );
        assert_eq!(cache.len(), 1);
    }

    /// SPEC §6.2: expired advertisements leave the cache without new arrivals once the actor's
    /// cadence runs [`AdCache::expire`], and an arrival evicts them too (at most once a second), so
    /// the cache follows the live set instead of every card it has seen.
    #[test]
    fn expired_ads_are_evicted_without_waiting_for_the_bound() {
        let identity = Identity::from_seed(&[16; 32]);
        let mut cache = AdCache::default();
        for name in ["a", "b", "c"] {
            let card = named(&identity, name, NOW, name);
            assert!(cache.accept(&stored(&card, &identity), NOW).is_some());
        }
        assert_eq!(cache.len(), 3);
        // The cards live 10 minutes; nothing arrives, the cadence runs past their TTL.
        assert_eq!(cache.expire(NOW + 9 * 60 * 1000), 0, "still live");
        assert_eq!(cache.expire(NOW + 11 * 60 * 1000), 3);
        assert_eq!(
            cache.len(),
            0,
            "a cache whose ads all expired holds nothing"
        );

        // An arrival past the others' TTL evicts them as it lands.
        for name in ["d", "e"] {
            let card = named(&identity, name, NOW, name);
            assert!(cache.accept(&stored(&card, &identity), NOW).is_some());
        }
        let later = NOW + 11 * 60 * 1000;
        let fresh = named(&identity, "f", later, "f");
        assert!(cache.accept(&stored(&fresh, &identity), later).is_some());
        assert_eq!(cache.len(), 1, "only the live card is held");
    }

    /// A card declaring `actions` (maps), issued by `identity` at NOW, stored.
    fn card_with(identity: &Identity, id_suffix: &str, actions: &[Map]) -> Value {
        Value::Map(stored_ad(
            AD_TYPE_AGENT_CARD,
            &card_map(identity, id_suffix, actions),
            identity,
        ))
    }

    /// The card [`card_with`] stores.
    fn card_map(identity: &Identity, id_suffix: &str, actions: &[Map]) -> Map {
        agent_card(
            "zGroup",
            identity,
            id_suffix,
            &instant_iso(NOW),
            "PT10M",
            "a card",
            &[],
            &[],
            &[],
            &Map::new(),
            &Map::new(),
            None,
            actions,
            None,
            None,
        )
        .expect("card")
    }

    fn action(name: &str) -> Map {
        agentspaces_wire::ads::card_action(
            name,
            "",
            &["in#v1"],
            &["out#v1"],
            agentspaces_wire::ads::ACTION_TAKE,
            Some("tasks"),
        )
    }

    /// The AgentCards Java's `AgentCard` and `CardAction` constructors refuse (as Jackson decodes
    /// them in `AdCache.accept`) are refused here too: more than 64 actions, a repeated name, an
    /// empty name, an over-long description, an element that is not an action, actions that are not
    /// an array. 64 uniquely named actions are admitted.
    #[test]
    fn cards_java_refuses_are_refused() {
        let identity = Identity::from_seed(&[9; 32]);
        let mut cache = AdCache::default();
        let most: Vec<Map> = (0..64).map(|n| action(&format!("a{n}"))).collect();
        assert!(
            cache
                .accept(&card_with(&identity, "most", &most), NOW)
                .is_some()
        );
        let too_many: Vec<Map> = (0..65).map(|n| action(&format!("a{n}"))).collect();
        assert!(
            cache
                .accept(&card_with(&identity, "many", &too_many), NOW)
                .is_none()
        );
        let repeated = [action("same"), action("other"), action("same")];
        assert!(
            cache
                .accept(&card_with(&identity, "dup", &repeated), NOW)
                .is_none()
        );
        assert!(
            cache
                .accept(&card_with(&identity, "empty", &[action("")]), NOW)
                .is_none()
        );
        let mut long = action("long");
        long.insert("description", "d".repeat(513));
        assert!(
            cache
                .accept(&card_with(&identity, "long", &[long]), NOW)
                .is_none()
        );
        let mut fits = action("fits");
        fits.insert("description", "é".repeat(512));
        assert!(
            cache
                .accept(&card_with(&identity, "fits", &[fits]), NOW)
                .is_some()
        );
        let mut kindless = action("kindless");
        kindless.remove("kind");
        assert!(
            cache
                .accept(&card_with(&identity, "kindless", &[kindless]), NOW)
                .is_none()
        );
        // The element and the list themselves, signed over the edited card.
        let card = card_map(&identity, "shape", &[action("x")]);
        for actions in [Value::from("not a list"), agentspaces_wire::cbor_array![1]] {
            let mut edited = card.clone();
            edited.insert("actions", actions);
            let stored = Value::Map(stored_ad(AD_TYPE_AGENT_CARD, &edited, &identity));
            assert!(cache.accept(&stored, NOW).is_none(), "{edited:?}");
        }
        // Only the two admissible cards are held.
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn a_pulled_ads_delta_is_a_list_of_stored_ads() {
        let bytes = cbor::encode(&agentspaces_wire::cbor_map! {
            "ads" => agentspaces_wire::cbor_array![1, 2],
        });
        assert_eq!(pulled_ads(&bytes).map(|ads| ads.len()), Some(2));
        assert_eq!(pulled_ads(&[0xff]), None);
    }
}
