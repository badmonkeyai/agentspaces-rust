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
//! # The cache budget (SPEC §6.3, v0.1.32)
//!
//! The cache is bounded by entry count and by bytes, the sum of the lengths of its
//! advertisements' canonical encodings (`adBytes`): [`MAX_CACHED_ADS`] advertisements and
//! [`MAX_CACHED_AD_BYTES`] bytes, the defaults every implementation shares (this peer never
//! serves the RENDEZVOUS role, whose cache holds four times as much; a listening peer advertises
//! RELAY alone). After the expired
//! and revoked advertisements leave, a new (issuer, id) that would pass either bound is refused,
//! and a newer version of a held one that would pass the byte budget is refused while the held
//! version stays. Each refusal counts ([`AdCache::refused_cache_full`], `adsRefusedCacheFull`),
//! drops the advertisement from this cache alone, and strikes nobody; anti-entropy offers it again
//! once room returns. No card kind has a size cap of its own: a card past 65,536 bytes travels as
//! a stub ([`agentspaces_wire::ads::spill_card`]), and a stub is held as it is.
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
use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::limits::{AD_CACHE_MAX_BYTES, AD_CACHE_MAX_ENTRIES};
use agentspaces_wire::revocation::Registry;
use agentspaces_wire::time::parse_instant_millis;

use crate::agent::card::check_actions;

/// The most advertisements the cache holds (SPEC §6.3's default); a new (issuer, id) beyond it is
/// refused once the expired and revoked ones are gone.
pub(super) const MAX_CACHED_ADS: usize = AD_CACHE_MAX_ENTRIES;

/// The most bytes of advertisement encodings the cache holds (SPEC §6.3's default, 32 MiB).
pub(super) const MAX_CACHED_AD_BYTES: usize = AD_CACHE_MAX_BYTES;

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
    /// The length of its canonical encoding (`adBytes`), what it costs the byte budget.
    pub bytes: usize,
    /// The stored advertisement it arrived as (`AdCache.StoredAd`), what a listening peer hands
    /// a partner whose digest lacks it.
    pub stored: Value,
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
    /// The most bytes held, [`MAX_CACHED_AD_BYTES`] but in tests.
    max_bytes: usize,
    /// The sum of the held advertisements' [`CachedAd::bytes`].
    bytes: usize,
    /// Advertisements refused under either bound (`adsRefusedCacheFull`).
    refused_cache_full: u64,
    /// When an arrival last evicted the expired advertisements, epoch milliseconds.
    expired_at_ms: i64,
}

impl Default for AdCache {
    fn default() -> AdCache {
        AdCache {
            entries: BTreeMap::new(),
            max_entries: MAX_CACHED_ADS,
            max_bytes: MAX_CACHED_AD_BYTES,
            bytes: 0,
            refused_cache_full: 0,
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

    /// A cache holding at most `max_bytes` bytes of advertisement encodings.
    #[cfg(test)]
    fn budgeted(max_bytes: usize) -> AdCache {
        AdCache {
            max_bytes,
            ..AdCache::default()
        }
    }

    /// How many advertisements the cache refused under its entry bound or its byte budget
    /// (`adsRefusedCacheFull`, SPEC §6.3).
    pub fn refused_cache_full(&self) -> u64 {
        self.refused_cache_full
    }

    /// The bytes of advertisement encodings held now.
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Recounts [`AdCache::bytes`] after entries left.
    fn recount(&mut self) {
        self.bytes = self.entries.values().map(|cached| cached.bytes).sum();
    }

    /// Whether `cached`, under `key`, fits both bounds given what the cache holds (Java
    /// `AdCache.fits`): a new key needs room for one more advertisement and its bytes; a newer
    /// version of a held key needs room for the difference.
    fn fits(&self, key: &AdKey, cached: &CachedAd) -> bool {
        match self.entries.get(key) {
            None => {
                self.entries.len() < self.max_entries
                    && self.bytes.saturating_add(cached.bytes) <= self.max_bytes
            }
            Some(held) => {
                self.bytes
                    .saturating_sub(held.bytes)
                    .saturating_add(cached.bytes)
                    <= self.max_bytes
            }
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
        self.recount();
        before - self.entries.len()
    }

    /// Drops every advertisement `registry` now refuses: a revoked issuer's, and an agent card of a
    /// revoked agent or agent key (Java `purgeIssuer`, `purgeAgent`). Called when a revocation
    /// lands, so the slots a revoked member filled are free at once.
    pub fn purge(&mut self, registry: &Registry) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, cached| !refused(cached, registry));
        self.recount();
        before - self.entries.len()
    }

    /// Admits one stored advertisement at `now_ms` (`AdCache.accept`): [`verify_stored_ad`]'s
    /// checks (an AgentCard names its issuer's own agent among them), a text `id`, an AgentCard's
    /// actions as Java's `AgentCard` admits them ([`check_actions`]: at most 64, named uniquely,
    /// ...), not refused by `registry` (a revoked issuer, or an agent card of a revoked agent or
    /// agent key: Java's `refuseIssuers` and `refuseAgents`), and last-writer-wins by `issued` per
    /// (issuer, id): an advertisement replaces only one its own issuer issued under the same id
    /// (see the [module docs](self#one-issuer-its-own-advertisements)). Bounded by entries and
    /// by bytes ([module docs](self#the-cache-budget-spec-63-v0132)): a new one, or a newer
    /// version of a held one, that does not fit after the expired and the revoked are dropped is
    /// refused and counted. `None` when refused.
    pub fn admit(&mut self, stored: &Value, now_ms: i64, registry: &Registry) -> Option<Admitted> {
        let (ad_type, ad, issuer) = verify_stored_ad(stored, now_ms)?;
        let bytes = stored
            .get("adBytes")
            .and_then(Value::as_bytes)
            .map_or(0, <[u8]>::len);
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
            bytes,
            stored: stored.clone(),
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
        if !self.fits(&key, &cached) {
            self.entries
                .retain(|_, held| held.expires_ms > now_ms && !refused(held, registry));
            self.recount();
            if !self.fits(&key, &cached) {
                self.refused_cache_full = self.refused_cache_full.saturating_add(1);
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
        let added = cached.bytes;
        if let Some(previous) = self.entries.insert(key, cached) {
            self.bytes = self.bytes.saturating_sub(previous.bytes);
        }
        self.bytes = self.bytes.saturating_add(added);
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

    /// The live advertisements at `now_ms` with their stored form, unless revoked: what the ads
    /// stream's digest names and its delta carries (SPEC §6.2: an expired advertisement is never
    /// forwarded).
    pub fn live_entries<'a>(
        &'a self,
        now_ms: i64,
        registry: &'a Registry,
    ) -> impl Iterator<Item = &'a CachedAd> + 'a {
        self.entries
            .values()
            .filter(move |cached| cached.expires_ms > now_ms && !refused(cached, registry))
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

/// The stored advertisements an `ads` stream delta of a pull response carries (`AdCache.Delta`
/// `{ads: [...]}` under the wire encoding, SPEC §9.1), or `None` when the bytes are no such
/// record.
pub(super) fn pulled_ads(delta: &[u8]) -> Option<Vec<Value>> {
    let mut delta = agentspaces_wire::schema::decode_map(delta, "AdCache.Delta")?;
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

    /// SPEC §6.3 (v0.1.32): the cache's byte budget. A new card that would pass it is refused
    /// and counted, a newer version of a held card that would pass it is refused while the held
    /// version stays, and a refusal strikes nobody: the card lands once room returns.
    #[test]
    fn the_byte_budget_refuses_and_counts_and_keeps_the_held_version() {
        let issuer = Identity::from_seed(&[8; 32]);
        let small = named(&issuer, "a", NOW, "a");
        let length = |card: &Map| {
            stored(card, &issuer)
                .get("adBytes")
                .and_then(Value::as_bytes)
                .map_or(0, <[u8]>::len)
        };
        let mut cache = AdCache::budgeted(2 * length(&small) + 10);
        assert!(cache.accept(&stored(&small, &issuer), NOW).is_some());
        let other = named(&issuer, "b", NOW, "b");
        assert!(cache.accept(&stored(&other, &issuer), NOW).is_some());
        assert_eq!(cache.bytes(), length(&small) + length(&other));
        // A third card would pass the budget.
        let third = named(&issuer, "c", NOW, "c");
        assert!(cache.accept(&stored(&third, &issuer), NOW).is_none());
        assert_eq!(cache.refused_cache_full(), 1);
        // A newer version of a held card that grows past the budget is refused; the held stays.
        let grown = named(&issuer, "a", NOW + 1000, &"x".repeat(64));
        assert!(cache.accept(&stored(&grown, &issuer), NOW).is_none());
        assert_eq!(cache.refused_cache_full(), 2);
        assert_eq!(
            cards_of(&cache, &issuer.agent("a"), NOW)
                .first()
                .and_then(description_of),
            Some("a")
        );
        // A newer version of the same size fits, and the bytes follow it.
        let refreshed = named(&issuer, "a", NOW + 1000, "A");
        assert!(cache.accept(&stored(&refreshed, &issuer), NOW).is_some());
        assert_eq!(cache.bytes(), length(&refreshed) + length(&other));
        // Once the cards expire, room returns.
        let later = NOW + 11 * 60 * 1000;
        let fresh = named(&issuer, "c", later, "c");
        assert!(cache.accept(&stored(&fresh, &issuer), later).is_some());
        assert_eq!(cache.bytes(), length(&fresh));
        assert_eq!(MAX_CACHED_ADS, 8_192);
        assert_eq!(MAX_CACHED_AD_BYTES, 33_554_432);
    }

    /// The founder's signed revocation of peer `revoked` in `zGroup`, issued just before NOW.
    fn peer_revocation(founder: &Identity, revoked: &str) -> Value {
        let ad = agentspaces_wire::revocation::peer_revocation(
            founder.peer_id(),
            "zGroup",
            &instant_iso(NOW - 1000),
            "PT1H",
            revoked,
            agentspaces_wire::revocation::KEY_COMPROMISE,
            None,
        );
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
        let encode = agentspaces_wire::cbor::encode;
        let identity = Identity::from_seed(&[9; 32]);
        let one = stored(&card(&identity, NOW, "one"), &identity);
        let two = stored(&card(&identity, NOW + 1, "two"), &identity);
        let bytes = encode(&agentspaces_wire::cbor_map! {
            "ads" => Value::Array(vec![one, two]),
        });
        assert_eq!(pulled_ads(&bytes).map(|ads| ads.len()), Some(2));
        let null = encode(&agentspaces_wire::cbor_map! { "ads" => Value::Null });
        assert_eq!(pulled_ads(&null), Some(Vec::new()));
        // An item that is no StoredAd breaks the record rules (SPEC §9.1): the delta is refused.
        let numbers = encode(&agentspaces_wire::cbor_map! {
            "ads" => agentspaces_wire::cbor_array![1, 2],
        });
        assert_eq!(pulled_ads(&numbers), None);
        assert_eq!(pulled_ads(&[0xff]), None);
    }
}
