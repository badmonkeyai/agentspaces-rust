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

//! The replicated space state store (SPEC §7.3, §7.4, §11a.4, §5.6): one replica's view of the
//! entry states and take claims it has folded, a port of the fold half of the Python peer
//! (`peer.py`'s `_fold`, `_verify_state`, `_refused_for_revocation`, `_signing_ms`, `_fold_claim`,
//! `_claim_of`, `_available`, `_join`, and `_union_dots`), with Java `ReplicatedSpace`
//! (`mergeState`, `verifyState`, `refusedForRevocation`, `mergeClaim`) as the authority on
//! behavior.
//!
//! A [`SpaceStore`] keeps, per entry id, the *joined* state (the CRDT join of every state that
//! folded: dot sets union, the lease register is last-writer-wins by HLC stamp, completion is
//! monotone) and the most advanced *signed* state seen (verbatim, so anti-entropy can forward a
//! DTO whose `stateSig` still verifies), and the winning signed claim by the lattice of SPEC §7.4.
//! Nothing enters unauthenticated: [`SpaceStore::fold_state`] and [`SpaceStore::fold_claim`]
//! apply every judgment of the Python peer and answer a [`FoldOutcome`] naming the [`Refusal`]
//! when one applies.
//!
//! # Claims before states
//!
//! A completion authenticates against the holder's claim, which must already be folded: the
//! caller folds the claim of a delta (`claimEntry`, `claim`) before its `state`, and the `claims`
//! of a pull response before its `states`, as `peer.py`'s `_handle` does. A completion that
//! arrives first is refused ([`Refusal::NoClaim`]) and lands when anti-entropy re-offers it.
//!
//! # Order and bounds
//!
//! Iteration is in *insertion order*: the order in which each entry id first folded, as the
//! Python peer's `dict` keeps it (the vote tally's "first ballot observed" reads this order).
//! The store holds at most [`SpaceStore::max_entries`] states and as many claims; a fold that
//! would add an entry beyond that is refused ([`Refusal::Full`]) and counted
//! ([`SpaceStore::refused_inserts`]), and an entry already held keeps folding.
//!
//! # Where this fold is stricter than `peer.py`
//!
//! Each addition is a Java rule, so a Rust replica refuses what a Java replica refuses:
//!
//! - a state with more than [`MAX_DOTS_PER_STATE`] dots in a set, or a dot naming a replica other
//!   than the issuer's peer (Java `dotsBoundToIssuer`);
//! - a record whose `issued`, or a state whose `leaseStamp`, is not an HLC stamp (Java cannot
//!   decode one; the join needs a total order on lease stamps);
//! - with [`FoldContext::space_id`] set, a record or a claim of another space (Java
//!   `verifyClaim`'s space binding); without it the store spans spaces, as the Python peer's does;
//! - a claim whose stamp predates its held entry's issue stamp by more than
//!   [`crate::records::MAX_CLAIM_PREDATES_ISSUE_MILLIS`], and a far-past claim contesting another
//!   holder's claim (SPEC §7.4/§11; the Ruby peer applies both too).
//!
//! [`SpaceStore::available`] reads the joined lease register (`leaseValue`, which a renewal
//! advances), lets only a `WRITE` lease lapse, and requires an unremoved add dot, as Java's
//! `liveRecords` does, where `peer.py` reads the record's original lease of any kind and ignores
//! withdrawal.
//!
//! # Stamps (SPEC §7.3, §7.4, §9; v0.1.30 and v0.1.31)
//!
//! After a state's or claim's signatures verify and its actor passes the revocation check, the
//! fold judges its stamps against the receiver's wall time ([`FoldContext::now_ms`]), as Java's
//! `ReplicatedSpace` does:
//!
//! - a counter above [`crate::limits::LOGICAL_LIMIT`] in the record's `issued`, the state's
//!   `leaseStamp`, an agent-signed state's `signedAt`, or a claim's `stamp` refuses the carrier
//!   ([`Refusal::StampLogical`], counted in [`SpaceStore::stamps_logical_refused`]);
//! - a stamp more than [`FAR_FUTURE_HOSTILE_MILLIS`] past `wall + MAX_DRIFT + SKEW_MARGIN` is
//!   hostile and refuses it ([`Refusal::StampFarFuture`], counted in
//!   [`SpaceStore::stamps_far_future_refused`]), judged after the logical limit;
//! - a stamp past `wall + MAX_DRIFT + SKEW_MARGIN` by less defers it ([`FoldOutcome::Deferred`],
//!   counted in [`SpaceStore::stamps_far_future_deferred`]): nothing merges and nobody is struck,
//!   and the carrier merges once the wall catches up and a partner offers it again.
//!
//! Each count is once per distinct signed content, keyed on the entry, the issue stamp, and the
//! digest of the state's signed view, or on the entry and the digest of the signed claim, under
//! a cache of the [`REFUSED_OFFERS_CAPACITY`] most recently offered keys, so a re-offer by gossip
//! or anti-entropy counts once. The cache decides nothing: every offer is judged afresh. A claim
//! the ordered log commits meets the logical limit alone ([`SpaceStore::judge_committed_claim`]).
//! A certificate bounds a record's, claim's, or `signedAt`'s stamp by its validity window alone
//! (SPEC §4.2); the far-future rule bounds how far the stamp leads.
//!
//! Left to the layers above: admission (SPEC §7.5), tag shards, tombstone collection, the
//! ordered log's decided epochs, misbehavior reports, and feeding the caller's HLC with the
//! stamps of what folded (Java calls `hlc.update` on the record's `issued`, the `leaseStamp`, and
//! the claim's `stamp`; [`crate::hlc::Hlc::observe`] clamps each).
//!
//! The module is sans-IO and has no clock: [`FoldContext::now_ms`] is the receiver's time. Every
//! judgment of untrusted input returns a [`FoldOutcome`] and never panics.
#![warn(missing_docs)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::cbor::{self, Map, Value};
use crate::crypto::KEY_LENGTH;
use crate::limits::{
    FAR_FUTURE_HOSTILE_MILLIS, MAX_DRIFT_MILLIS, REFUSED_OFFERS_CAPACITY, SKEW_MARGIN_MILLIS,
};
// `Stamp` is the crate's one HLC stamp parser, shared with the record and claim verifiers so the
// fold admits exactly the stamps they accept.
use crate::hlc::Stamp;
use crate::records::{
    WRITE_LEASE_KIND, claim_is_well_formed, claim_not_before_issue, claim_within_bounds,
    merge_claims, state_sign_view_of, verify_claim_proof, verify_claim_signature, verify_record,
    verify_state_signature,
};
use crate::revocation::Registry;
use crate::util::{field, java_order, present, text};

/// The default bound on the entries a [`SpaceStore`] holds (states and claims each).
pub const DEFAULT_MAX_ENTRIES: usize = 1 << 16;

/// The most dots a received state may carry per set (Java `ReplicatedSpace.MAX_DOTS_PER_STATE`):
/// honest entries hold a handful, and a validly signed state inflated with fabricated dots would
/// otherwise be stored and re-sorted forever.
pub const MAX_DOTS_PER_STATE: usize = 1_024;

/// The default settle window of a take, in milliseconds: the race allowance of the far-past
/// contest rule ([`Refusal::LateContest`]). SPEC §9.2 R6 has every implementation judge the rule
/// as Java's `mergeClaim` does, with a Java space's default window of 200 ms (`peer.py` moved
/// from 600 ms to 200 ms with it).
pub const DEFAULT_SETTLE_MILLIS: i64 = 200;

// ---------------------------------------------------------------------------------------------
// Outcomes

/// Why a fold left the store as it was. Each names one rule of the fold; the order of the checks
/// is `peer.py`'s, with Java's additional checks where Java runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Refusal {
    /// A field the fold reads is missing or has the wrong type: a state without a record map, an
    /// entry id, an issuer, a 32-byte `issuerPublicKey`, or a `stateSig`; a signed claim without a
    /// claim map or a `holderKey`, or whose claim is not well formed
    /// ([`crate::records::claim_is_well_formed`]: epoch from 1, finite bid, parseable stamp).
    Malformed,
    /// The record's `issued` or the state's `leaseStamp` is not an HLC stamp
    /// `physical:logical:node`.
    MalformedStamp,
    /// More than [`MAX_DOTS_PER_STATE`] dots in `adds` or `removes`.
    TooManyDots,
    /// A dot names a replica other than the issuer's peer.
    ForeignDots,
    /// The record or the claim belongs to another space than [`FoldContext::space_id`].
    ForeignSpace,
    /// The record signature does not verify ([`crate::records::verify_record`], TECH-SPEC §7.2's
    /// two-key rule judged at the record's issue stamp).
    UnverifiedRecord,
    /// A completion arrived without a folded claim to attribute it to.
    NoClaim,
    /// The claim is bound to another entry than the one it travels under (a transplanted
    /// claim), or, for a completion, to another entry or space than the record's.
    ClaimMismatch,
    /// The claim's proof fails ([`crate::records::verify_claim_proof`]: holder key, signature,
    /// certificate at the claim's stamp, and the hold bound).
    UnverifiedClaim,
    /// The state signature does not authenticate the transition for its party (SPEC §11a.4): a
    /// forged signature, a peer-signed state on an agent-attested entry, a signer other than
    /// the party, or a certificate that does not cover `signedAt` or leads the receiver by more
    /// than the drift ceiling.
    UnverifiedState,
    /// The actor of the transition, or the claim's holder, is revoked (SPEC §5.6's freeze rule).
    Revoked,
    /// The claim's epoch leaps more than [`crate::limits::MAX_CLAIM_EPOCH_JUMP`] beyond the
    /// held claim's.
    OutOfBounds,
    /// The claim's stamp predates its entry's issue stamp by more than
    /// [`crate::records::MAX_CLAIM_PREDATES_ISSUE_MILLIS`] (SPEC §7.4/§11).
    PredatesIssue,
    /// The claim contests another holder's claim with a stamp older than the drift ceiling plus
    /// one settle window (SPEC §7.4/§11: a queue-jump, since an honest race settles within the
    /// window).
    LateContest,
    /// The fold would add an entry to a store already holding [`SpaceStore::max_entries`].
    Full,
    /// A recordless state (SPEC §7.3, v0.1.29) names an entry whose record this
    /// store does not hold; Java keeps such a state pending, bounded, until the record arrives.
    RecordPending,
    /// A verified state or claim carries a stamp whose logical counter is above
    /// [`crate::limits::LOGICAL_LIMIT`] (SPEC §7.3, §7.4, v0.1.30): `logical counter above 65536`.
    StampLogical,
    /// A verified state or claim carries a stamp more than [`FAR_FUTURE_HOSTILE_MILLIS`] past
    /// `wall + MAX_DRIFT + SKEW_MARGIN` (SPEC §7.3, v0.1.30): `far-future stamp`.
    StampFarFuture,
}

impl Refusal {
    /// A stable kebab-case name for logs and counters.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::MalformedStamp => "malformed-stamp",
            Refusal::TooManyDots => "too-many-dots",
            Refusal::ForeignDots => "foreign-dots",
            Refusal::ForeignSpace => "foreign-space",
            Refusal::UnverifiedRecord => "unverified-record",
            Refusal::NoClaim => "no-claim",
            Refusal::ClaimMismatch => "claim-mismatch",
            Refusal::UnverifiedClaim => "unverified-claim",
            Refusal::UnverifiedState => "unverified-state",
            Refusal::Revoked => "revoked",
            Refusal::OutOfBounds => "out-of-bounds",
            Refusal::PredatesIssue => "predates-issue",
            Refusal::LateContest => "late-contest",
            Refusal::Full => "full",
            Refusal::RecordPending => "record-pending",
            Refusal::StampLogical => "stamp-logical",
            Refusal::StampFarFuture => "stamp-far-future",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one fold did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FoldOutcome {
    /// The store changed: a new entry or claim, a join that moved the state, a more advanced
    /// signed state, or a claim that won the lattice.
    Applied,
    /// Authentic and admitted, but the store already held all of it (a replay, or a claim the
    /// held one beats).
    Unchanged,
    /// Refused for the given reason; the store is as it was.
    Refused(Refusal),
    /// Authentic, but stamped past `wall + MAX_DRIFT + SKEW_MARGIN` by at most
    /// [`FAR_FUTURE_HOSTILE_MILLIS`] (SPEC §7.3, v0.1.30): nothing merged, nobody struck, and the
    /// store merges it when a partner offers it again after the receiver's wall caught up.
    Deferred,
}

impl FoldOutcome {
    /// Whether the store changed.
    pub fn is_applied(self) -> bool {
        self == FoldOutcome::Applied
    }

    /// Whether the fold was refused.
    pub fn is_refused(self) -> bool {
        matches!(self, FoldOutcome::Refused(_))
    }

    /// The refusal, when the fold was refused.
    pub fn refusal(self) -> Option<Refusal> {
        match self {
            FoldOutcome::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Context

/// What a fold judges against besides the store: the receiver's clock, the group's revocations,
/// and optionally the one space this store replicates.
#[derive(Debug, Clone, Copy)]
pub struct FoldContext<'a> {
    /// The receiver's time, epoch milliseconds: the far-future rule judges every stamp against it
    /// (SPEC §7.3), and claim holds and epochs are bounded from it.
    pub now_ms: i64,
    /// The group's accepted revocations (SPEC §5.6), applied at merge.
    pub revocations: &'a Registry,
    /// The space this store replicates (`ids::space_id_local("<group>/<name>")`): records and
    /// claims of any other space are refused. `None` spans spaces, as `peer.py` does.
    pub space_id: Option<&'a str>,
    /// The settle window of a take, milliseconds: the race allowance of the far-past contest
    /// rule ([`Refusal::LateContest`]).
    pub settle_millis: i64,
}

impl<'a> FoldContext<'a> {
    /// A context at `now_ms` over `revocations`, spanning spaces, with the
    /// [`DEFAULT_SETTLE_MILLIS`] window.
    pub fn new(now_ms: i64, revocations: &'a Registry) -> Self {
        FoldContext {
            now_ms,
            revocations,
            space_id: None,
            settle_millis: DEFAULT_SETTLE_MILLIS,
        }
    }

    /// This context bound to one space.
    pub fn with_space(self, space_id: &'a str) -> Self {
        FoldContext {
            space_id: Some(space_id),
            ..self
        }
    }

    /// This context with another settle window.
    pub fn with_settle_millis(self, settle_millis: i64) -> Self {
        FoldContext {
            settle_millis,
            ..self
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Stamps, dots, small helpers

/// `peer.py`'s `_signing_ms`: the physical time of a `signedAt` stamp, else `fallback` (also when
/// `signedAt` is no stamp).
fn signing_ms(dto: &Map, fallback: Option<i64>) -> Option<i64> {
    Stamp::of(dto.get("signedAt"))
        .map(|stamp| stamp.physical)
        .or(fallback)
}

/// How a stamp stands against the receiver's far-future margin (Java `ReplicatedSpace.Lead`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lead {
    /// At or inside `wall + MAX_DRIFT + SKEW_MARGIN`: merges, clamped by the clock.
    Within,
    /// Past it by at most [`FAR_FUTURE_HOSTILE_MILLIS`]: deferred.
    Deferred,
    /// Further past it: hostile.
    Hostile,
}

/// Java `ReplicatedSpace.lead`: a stamp's physical part against `now_ms + MAX_DRIFT +
/// SKEW_MARGIN`, exactly.
fn lead(physical: i64, now_ms: i64) -> Lead {
    let margin = i128::from(now_ms) + i128::from(MAX_DRIFT_MILLIS) + i128::from(SKEW_MARGIN_MILLIS);
    let ahead = i128::from(physical) - margin;
    if ahead <= 0 {
        Lead::Within
    } else if ahead <= i128::from(FAR_FUTURE_HOSTILE_MILLIS) {
        Lead::Deferred
    } else {
        Lead::Hostile
    }
}

/// The verdict on a verified carrier's stamps (SPEC §7.3): a logical refusal first, then the
/// furthest lead. Absent stamps pass; a present one that does not parse cannot reach here (the
/// verifiers refuse it).
fn stamp_verdict<'a>(
    stamps: impl IntoIterator<Item = Option<&'a Value>>,
    now_ms: i64,
) -> StampVerdict {
    let stamps: Vec<Stamp<'_>> = stamps.into_iter().flat_map(Stamp::of).collect();
    if stamps.iter().any(|stamp| !stamp.is_acceptable()) {
        return StampVerdict::Refuse(Refusal::StampLogical);
    }
    match stamps
        .iter()
        .map(|stamp| lead(stamp.physical, now_ms))
        .max()
        .unwrap_or(Lead::Within)
    {
        Lead::Within => StampVerdict::Merge,
        Lead::Deferred => StampVerdict::Defer,
        Lead::Hostile => StampVerdict::Refuse(Refusal::StampFarFuture),
    }
}

/// What the fold does with a verified carrier for its stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StampVerdict {
    Merge,
    Defer,
    Refuse(Refusal),
}

/// A bounded memory of keys that evicts the least recently offered first (SPEC §7.3, v0.1.30:
/// the cache of refused offers holds 4096 keys in every implementation).
#[derive(Debug, Clone, Default)]
struct RecentKeys {
    ticks: BTreeMap<Vec<u8>, u64>,
    order: BTreeMap<u64, Vec<u8>>,
    next: u64,
}

impl RecentKeys {
    /// Marks `key` most recently offered and answers whether it was new.
    fn offer(&mut self, key: Vec<u8>) -> bool {
        let tick = self.next;
        self.next = self.next.wrapping_add(1);
        let new = match self.ticks.insert(key.clone(), tick) {
            Some(old) => {
                self.order.remove(&old);
                false
            }
            None => true,
        };
        self.order.insert(tick, key);
        while self.order.len() > REFUSED_OFFERS_CAPACITY {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.ticks.remove(&oldest);
            }
        }
        new
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

/// The key a state offer is counted under, its signed content alone (Java `stateOfferKey`): the
/// entry, the issue stamp, and the SHA-256 of the state's signed view.
fn state_offer_key(entry_id: &str, dto: &Map) -> Vec<u8> {
    let issued = dto
        .get("record")
        .and_then(|record| record.get("issued"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let view = state_sign_view_of(dto)
        .map(|view| cbor::encode(&Value::Map(view)))
        .unwrap_or_default();
    let mut key = format!("state:{entry_id}={issued}/").into_bytes();
    key.extend_from_slice(&crate::crypto::port().sha256(&view));
    key
}

/// The key a claim offer is counted under (Java `claimOfferKey`): the SHA-256 of the signed claim
/// map and the entry it travels under.
fn claim_offer_key(entry_id: &str, claim: &Map) -> Vec<u8> {
    let digest = crate::crypto::port().sha256(&cbor::encode(&Value::Map(claim.clone())));
    let mut key = b"claim:".to_vec();
    key.extend_from_slice(&digest);
    key.extend_from_slice(b"@");
    key.extend_from_slice(entry_id.as_bytes());
    key
}

/// The agent key of a certificate field, when it carries one as bytes.
fn certificate_key(certificate: Option<&Value>) -> Option<&[u8]> {
    certificate?.get("agentPublicKey")?.as_bytes()
}

/// Whether a state is completed (`completed` is `true`).
fn is_completed(state: &Map) -> bool {
    state.get("completed").and_then(Value::as_bool) == Some(true)
}

/// The items of a dot list (absent, null, or not an array is empty).
fn dot_list<'a>(state: &'a Map, name: &str) -> &'a [Value] {
    state
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_default()
}

/// A dot's `(replica, counter)`, ordered as Java `ReplicatedSpace.sortedDots` orders dots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DotKey<'a>(&'a str, i64);

impl Ord for DotKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        java_order(self.0, other.0).then(self.1.cmp(&other.1))
    }
}

impl PartialOrd for DotKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The well-formed dots of a dot list with their identities: `{replica: text, counter:
/// integer}` maps; anything else is skipped.
fn dots(list: Option<&Value>) -> impl Iterator<Item = (DotKey<'_>, &Value)> {
    list.and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|dot| {
            let replica = dot.get("replica")?.as_str()?;
            let counter = dot.get("counter")?.as_i64()?;
            Some((DotKey(replica, counter), dot))
        })
}

/// Java `ReplicatedSpace.dotsBoundToIssuer`: every dot names the issuer's peer.
fn dots_bound_to(dto: &Map, issuer_peer: &str) -> bool {
    ["adds", "removes"].into_iter().all(|name| {
        dot_list(dto, name)
            .iter()
            .all(|dot| dot.get("replica").and_then(Value::as_str) == Some(issuer_peer))
    })
}

/// The expiry of a state's lease: the joined register `leaseValue`, else the record's own
/// `lease`.
fn lease_expires_at(state: &Map) -> Option<i64> {
    let expiry = |lease: Option<&Value>| lease?.get("expiresAtMillis")?.as_i64();
    expiry(state.get("leaseValue")).or_else(|| expiry(state.get("record")?.get("lease")))
}

/// Java `ReplicatedSpace.liveRecords`' lease rule: whether the state's lease (the joined
/// `leaseValue`, else the record's `lease`) still holds at `now_ms`. Only a `WRITE` lease lapses
/// (at `expiresAtMillis`, Java `LeaseInfo.expired`); a lease of another kind (`TAKE`) never
/// hides an entry. A state with no readable lease is not live.
fn lease_holds(state: &Map, now_ms: i64) -> bool {
    fn kind(lease: Option<&Value>) -> Option<&str> {
        lease?.get("kind")?.as_str()
    }
    let kind = kind(state.get("leaseValue")).or_else(|| kind(state.get("record")?.get("lease")));
    match lease_expires_at(state) {
        None => false,
        Some(_) if kind.is_some_and(|kind| kind != WRITE_LEASE_KIND) => true,
        Some(expires) => expires > now_ms,
    }
}

/// Java `EntryState.present`: not completed, and some add dot is not removed.
///
/// Dots are `{replica, counter}` maps; malformed dots are ignored. The vote module reads this as
/// `vote.py`'s withdrawn check.
pub fn is_present(state: &Map) -> bool {
    if is_completed(state) {
        return false;
    }
    let removes: BTreeSet<DotKey<'_>> = dots(state.get("removes")).map(|(key, _)| key).collect();
    dots(state.get("adds")).any(|(key, _)| !removes.contains(&key))
}

/// `peer.py`'s `_union_dots`: the union of two dot lists, deduplicated by `(replica, counter)`
/// (a later dot replaces an earlier one with the same identity) and sorted as Java sorts dots
/// (replica in Java string order, then counter). Absent, null, or non-array lists are empty, and
/// dots that are not `{replica: text, counter: integer}` maps are dropped.
pub fn union_dots(a: Option<&Value>, b: Option<&Value>) -> Vec<Value> {
    let mut seen: BTreeMap<DotKey<'_>, &Value> = BTreeMap::new();
    for (key, dot) in dots(a).chain(dots(b)) {
        seen.insert(key, dot);
    }
    seen.into_values().cloned().collect()
}

/// `peer.py`'s `_join`, mirroring Java `EntryState.merge`: the state `previous` becomes once
/// `incoming` folds into it. Every other field of `previous` is kept (its record, keys,
/// certificates, and signature fields); the dot sets are the [`union_dots`] of both; the lease
/// register (`leaseStamp`, `leaseValue`) is `incoming`'s when its stamp is strictly later
/// (`physical`, `logical`, then node in Java string order; a stamp that does not parse is
/// earlier than any that does); and `completed` is true once either is.
///
/// A replayed early state, validly signed by its author, can therefore never shrink the sets,
/// roll back the lease, or undo a completion. The join is idempotent
/// (`join(&join(a, b), b) == join(a, b)`), and its CRDT fields are commutative and associative.
pub fn join(previous: &Map, incoming: &Map) -> Map {
    let mut merged = previous.clone();
    merged.insert(
        "adds",
        union_dots(previous.get("adds"), incoming.get("adds")),
    );
    merged.insert(
        "removes",
        union_dots(previous.get("removes"), incoming.get("removes")),
    );
    if Stamp::of(incoming.get("leaseStamp")) > Stamp::of(previous.get("leaseStamp")) {
        merged.insert("leaseStamp", field(incoming, "leaseStamp"));
        merged.insert("leaseValue", field(incoming, "leaseValue"));
    }
    merged.insert(
        "completed",
        is_completed(previous) || is_completed(incoming),
    );
    merged
}

/// Java `ReplicatedSpace.advances`: whether signed state `a` is at least as advanced as `b`
/// (completion dominates, then more removes, then the later lease stamp, then at least as many
/// adds), so anti-entropy forwards the most advanced one verbatim.
fn advances(a: &Map, b: &Map) -> bool {
    let (completed_a, completed_b) = (is_completed(a), is_completed(b));
    if completed_a != completed_b {
        return completed_a;
    }
    let (removes_a, removes_b) = (dot_list(a, "removes").len(), dot_list(b, "removes").len());
    if removes_a != removes_b {
        return removes_a > removes_b;
    }
    match Stamp::of(a.get("leaseStamp")).cmp(&Stamp::of(b.get("leaseStamp"))) {
        Ordering::Equal => dot_list(a, "adds").len() >= dot_list(b, "adds").len(),
        order => order == Ordering::Greater,
    }
}

// ---------------------------------------------------------------------------------------------
// An insertion-ordered map

/// String-keyed values in first-insertion order with logarithmic lookup: the shape of Python's
/// `dict`, without a hash table's per-process randomness.
#[derive(Debug, Clone)]
struct Ordered<V> {
    index: BTreeMap<String, u64>,
    slots: BTreeMap<u64, (String, V)>,
    next: u64,
}

impl<V> Default for Ordered<V> {
    fn default() -> Self {
        Ordered {
            index: BTreeMap::new(),
            slots: BTreeMap::new(),
            next: 0,
        }
    }
}

impl<V> Ordered<V> {
    fn len(&self) -> usize {
        self.slots.len()
    }

    fn get(&self, key: &str) -> Option<&V> {
        let slot = self.index.get(key)?;
        self.slots.get(slot).map(|(_, value)| value)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        let slot = self.index.get(key)?;
        self.slots.get_mut(slot).map(|(_, value)| value)
    }

    /// Adds a key that is not held yet, after every other.
    fn push(&mut self, key: &str, value: V) {
        let slot = self.next;
        // A u64 counter of insertions does not wrap in practice; wrapping keeps it total.
        self.next = self.next.wrapping_add(1);
        self.index.insert(key.to_owned(), slot);
        self.slots.insert(slot, (key.to_owned(), value));
    }

    fn remove(&mut self, key: &str) -> Option<V> {
        let slot = self.index.remove(key)?;
        self.slots.remove(&slot).map(|(_, value)| value)
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = (&str, &V)> + ExactSizeIterator + Clone {
        self.slots
            .values()
            .map(|(key, value)| (key.as_str(), value))
    }
}

// ---------------------------------------------------------------------------------------------
// The store

/// One entry's state as the store holds it.
#[derive(Debug, Clone)]
struct Held {
    /// The join of every state that folded.
    joined: Map,
    /// The most advanced signed state that folded, verbatim.
    signed: Map,
}

/// One replica's folded view of a replicated space: entry states and the winning take claims,
/// each keyed by entry id and iterated in insertion order. See the [module docs](self) for the
/// rules, the claim-before-state order the caller keeps, and the bounds.
///
/// The store is not internally synchronized; wrap it in a lock to share it between threads.
#[derive(Clone)]
pub struct SpaceStore {
    states: Ordered<Held>,
    claims: Ordered<Map>,
    max_entries: usize,
    refused_inserts: u64,
    refused_offers: RecentKeys,
    deferred_offers: RecentKeys,
    stamps_logical_refused: u64,
    stamps_far_future_refused: u64,
    stamps_far_future_deferred: u64,
}

impl fmt::Debug for SpaceStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpaceStore")
            .field("states", &self.states.len())
            .field("claims", &self.claims.len())
            .field("max_entries", &self.max_entries)
            .field("refused_inserts", &self.refused_inserts)
            .field("refused_offers", &self.refused_offers.len())
            .field("deferred_offers", &self.deferred_offers.len())
            .finish()
    }
}

impl Default for SpaceStore {
    fn default() -> Self {
        SpaceStore::new()
    }
}

impl SpaceStore {
    /// An empty store bounded by [`DEFAULT_MAX_ENTRIES`].
    pub fn new() -> Self {
        SpaceStore::with_max_entries(DEFAULT_MAX_ENTRIES)
    }

    /// An empty store holding at most `max_entries` states and as many claims.
    pub fn with_max_entries(max_entries: usize) -> Self {
        SpaceStore {
            states: Ordered::default(),
            claims: Ordered::default(),
            max_entries,
            refused_inserts: 0,
            refused_offers: RecentKeys::default(),
            deferred_offers: RecentKeys::default(),
            stamps_logical_refused: 0,
            stamps_far_future_refused: 0,
            stamps_far_future_deferred: 0,
        }
    }

    /// Distinct verified states and claims refused for a stamp whose logical counter is above
    /// [`crate::limits::LOGICAL_LIMIT`] (`stampsLogicalRefused`, SPEC §9).
    pub fn stamps_logical_refused(&self) -> u64 {
        self.stamps_logical_refused
    }

    /// Distinct verified states and claims refused for a stamp more than
    /// [`FAR_FUTURE_HOSTILE_MILLIS`] past the far-future margin (`stampsFarFutureRefused`).
    pub fn stamps_far_future_refused(&self) -> u64 {
        self.stamps_far_future_refused
    }

    /// Distinct verified states and claims deferred for a stamp past the far-future margin
    /// (`stampsFarFutureDeferred`), a count of no misbehavior.
    pub fn stamps_far_future_deferred(&self) -> u64 {
        self.stamps_far_future_deferred
    }

    /// Counts a refusal of `refusal` once per distinct `key` (the stamp refusals alone count).
    fn count_refusal(&mut self, key: Vec<u8>, refusal: Refusal) {
        let counter = match refusal {
            Refusal::StampLogical => &mut self.stamps_logical_refused,
            Refusal::StampFarFuture => &mut self.stamps_far_future_refused,
            _ => return,
        };
        if self.refused_offers.offer(key) {
            *counter = counter.saturating_add(1);
        }
    }

    /// Counts a deferral once per distinct `key`.
    fn count_deferral(&mut self, key: Vec<u8>) {
        if self.deferred_offers.offer(key) {
            self.stamps_far_future_deferred = self.stamps_far_future_deferred.saturating_add(1);
        }
    }

    /// The logical limit a claim the ordered log committed meets before it is installed (SPEC
    /// §7.4, v0.1.30): the log's arbitration must stay identical on every member, so a committed
    /// claim meets no far-future rule. `Err` ([`Refusal::StampLogical`], counted once per
    /// distinct claim) when its stamp is not acceptable, or [`Refusal::Malformed`] when it holds
    /// no stamp.
    pub fn judge_committed_claim(&mut self, entry_id: &str, claim: &Map) -> Result<(), Refusal> {
        let stamp = Stamp::of(claim.get("stamp")).ok_or(Refusal::Malformed)?;
        if stamp.is_acceptable() {
            return Ok(());
        }
        self.count_refusal(claim_offer_key(entry_id, claim), Refusal::StampLogical);
        Err(Refusal::StampLogical)
    }

    /// The bound on held states (and, separately, on held claims).
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// How many authentic states and claims were refused because the store was full.
    pub fn refused_inserts(&self) -> u64 {
        self.refused_inserts
    }

    /// The number of entries with a state.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether no state is held.
    pub fn is_empty(&self) -> bool {
        self.states.len() == 0
    }

    /// The number of entries with a claim.
    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    /// The joined state of an entry (`peer.py`'s `states[entry_id]`).
    pub fn state(&self, entry_id: &str) -> Option<&Map> {
        self.states.get(entry_id).map(|held| &held.joined)
    }

    /// The most advanced signed state of an entry, verbatim as it folded (Java
    /// `ReplicatedSpace.signedState`): what anti-entropy forwards, since the joined state's
    /// `stateSig` covers only the state it came with.
    pub fn signed_state(&self, entry_id: &str) -> Option<&Map> {
        self.states.get(entry_id).map(|held| &held.signed)
    }

    /// Every joined state with its entry id, in insertion order.
    pub fn states(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&str, &Map)> + ExactSizeIterator + Clone {
        self.states
            .iter()
            .map(|(entry_id, held)| (entry_id, &held.joined))
    }

    /// Every joined state, in insertion order: the input of the [`crate::vote`] functions.
    pub fn state_values(
        &self,
    ) -> impl DoubleEndedIterator<Item = &Map> + ExactSizeIterator + Clone {
        self.states.iter().map(|(_, held)| &held.joined)
    }

    /// Every signed state with its entry id, in insertion order: what a pull response carries.
    pub fn signed_states(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&str, &Map)> + ExactSizeIterator + Clone {
        self.states
            .iter()
            .map(|(entry_id, held)| (entry_id, &held.signed))
    }

    /// Every winning signed claim (`{claim, holderKey, signature, holderCertificate?}`) with its
    /// entry id, in insertion order.
    pub fn claims(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&str, &Map)> + ExactSizeIterator + Clone {
        self.claims.iter()
    }

    /// The winning signed claim of an entry: the proof a completion travels with.
    pub fn claim_proof(&self, entry_id: &str) -> Option<&Map> {
        self.claims.get(entry_id)
    }

    /// The winning claim of an entry, without its proof (`peer.py`'s `_claim_of`).
    pub fn claim_of(&self, entry_id: &str) -> Option<&Map> {
        self.claims
            .get(entry_id)
            .and_then(|signed| signed.get("claim"))
            .and_then(Value::as_map)
    }

    /// Removes an entry's state and claim (a collected tombstone, a lapsed entry), returning its
    /// joined state. A removed entry folds again as new.
    pub fn remove(&mut self, entry_id: &str) -> Option<Map> {
        self.claims.remove(entry_id);
        self.states.remove(entry_id).map(|held| held.joined)
    }

    /// Folds one received state DTO (`peer.py`'s `_fold`): authenticated (record and transition),
    /// refused when its actor is revoked, then joined into the entry's state ([`join`]); a new
    /// entry is stored as `join(dto, dto)`, its own normal form. The DTO is also kept verbatim as
    /// the entry's signed state when it is the most advanced one seen.
    ///
    /// The checks, in order (the first that fails is the [`Refusal`]):
    ///
    /// 1. at most [`MAX_DOTS_PER_STATE`] dots per set;
    /// 2. a record map with a non-empty text `entryId` and a text `issuer`, and a 32-byte
    ///    `issuerPublicKey`;
    /// 3. the record's space is [`FoldContext::space_id`], when set;
    /// 4. the record's `issued` and the state's `leaseStamp` are HLC stamps;
    /// 5. every dot names the issuer's peer;
    /// 6. the record verifies ([`crate::records::verify_record`], with the `agentCertificate`
    ///    when one rides, judged at the record's issue stamp);
    /// 7. a `stateSig` is present;
    /// 8. the party: for a completion, the holder of the entry's *folded* claim, which must be
    ///    bound to this entry and space and whose proof must still verify; otherwise the record's
    ///    issuer;
    /// 9. the state signature authenticates the transition for that party
    ///    ([`crate::records::verify_state_signature`]: an agent-attested party's transitions must
    ///    be agent-signed, its certificate covering `signedAt`);
    /// 10. the freeze rule (SPEC §5.6): the holder of a completion is judged at `signedAt` (an
    ///     unknown time when absent, refused under any revocation of it); the issuer of any
    ///     other transition at `signedAt`, else at the `leaseStamp` of the last write or renewal,
    ///     with the record's agent key and, for an agent-signed state, the state's agent key too;
    /// 11. the stamps (SPEC §7.3): `issued`, `leaseStamp`, and `signedAt` acceptable
    ///     ([`Refusal::StampLogical`]), none more than an hour past the far-future margin
    ///     ([`Refusal::StampFarFuture`]), each refusal counted once per distinct signed state;
    ///     one past the margin by less defers the state ([`FoldOutcome::Deferred`]);
    /// 12. room for a new entry.
    ///
    /// A recordless state (SPEC §7.3, [`crate::records::without_record`])
    /// is first put over the record this store holds for the entry it names
    /// ([`crate::records::with_record`]) and then judged exactly as above; when the store holds
    /// no record for that entry it is refused as [`Refusal::RecordPending`], and a caller that
    /// wants Java's behaviour keeps it until the record arrives.
    pub fn fold_state(&mut self, dto: &Map, ctx: &FoldContext<'_>) -> FoldOutcome {
        if crate::records::is_recordless(dto) {
            let Some(entry_id) = crate::records::state_entry_id(dto) else {
                return FoldOutcome::Refused(Refusal::Malformed);
            };
            let held = self
                .states
                .get(entry_id)
                .and_then(|held| held.signed.get("record"))
                .and_then(Value::as_map);
            return match held.and_then(|record| crate::records::with_record(dto, record)) {
                Some(full) => self.fold_state(&full, ctx),
                None => FoldOutcome::Refused(Refusal::RecordPending),
            };
        }
        let entry_id = match self.judge_state(dto, ctx) {
            Ok(entry_id) => entry_id,
            Err(refusal) => return FoldOutcome::Refused(refusal),
        };
        let issued = dto.get("record").and_then(|record| record.get("issued"));
        let stamps = [issued, dto.get("leaseStamp"), dto.get("signedAt")];
        match stamp_verdict(stamps, ctx.now_ms) {
            StampVerdict::Merge => {}
            StampVerdict::Defer => {
                self.count_deferral(state_offer_key(entry_id, dto));
                return FoldOutcome::Deferred;
            }
            StampVerdict::Refuse(refusal) => {
                self.count_refusal(state_offer_key(entry_id, dto), refusal);
                return FoldOutcome::Refused(refusal);
            }
        }
        if let Some(held) = self.states.get_mut(entry_id) {
            let joined = join(&held.joined, dto);
            let joined_changed = joined != held.joined;
            let advanced = advances(dto, &held.signed) && *dto != held.signed;
            if joined_changed {
                held.joined = joined;
            }
            if advanced {
                held.signed = dto.clone();
            }
            return if joined_changed || advanced {
                FoldOutcome::Applied
            } else {
                FoldOutcome::Unchanged
            };
        }
        if self.states.len() >= self.max_entries {
            return self.refuse_insert();
        }
        let held = Held {
            joined: join(dto, dto),
            signed: dto.clone(),
        };
        self.states.push(entry_id, held);
        FoldOutcome::Applied
    }

    /// Folds one received signed claim under the entry id it travels under (`peer.py`'s
    /// `_fold_claim`, Java `verifyClaim` then `mergeClaim`), merging it by the lattice of
    /// SPEC §7.4 ([`crate::records::merge_claims`]) when it passes.
    ///
    /// The checks, in order (the first that fails is the [`Refusal`]):
    ///
    /// 1. a claim map and a byte-string `holderKey`;
    /// 2. the claim's signed `entryId` is `entry_id` (a claim transplanted under a foreign key is
    ///    dropped);
    /// 3. its `spaceId` is [`FoldContext::space_id`], when set;
    /// 4. it is well formed ([`crate::records::claim_is_well_formed`]: a NaN bid cannot make the
    ///    total order lie, and epoch 0 is no take);
    /// 5. its signature verifies ([`crate::records::verify_claim_signature`], a certificate
    ///    covering the claim's stamp);
    /// 6. its holder is not revoked, judged at an unknown time (a revoked holder takes nothing,
    ///    whatever the claim's stamp);
    /// 7. its stamp is acceptable ([`Refusal::StampLogical`]) and not more than an hour past the
    ///    far-future margin ([`Refusal::StampFarFuture`]), each refusal counted once per distinct
    ///    signed claim (SPEC §7.4);
    /// 8. its epoch is within [`crate::limits::MAX_CLAIM_EPOCH_JUMP`] of the held claim's (0
    ///    when none), and its hold ends within [`crate::limits::MAX_CLAIM_HOLD_MILLIS`];
    /// 9. when the entry's state is held, the claim does not predate its issue stamp by more
    ///    than [`crate::records::MAX_CLAIM_PREDATES_ISSUE_MILLIS`];
    /// 10. when another holder's claim is held, the claim's stamp is not older than
    ///     `now_ms - MAX_DRIFT_MILLIS - settle_millis`;
    /// 11. a stamp past the far-future margin by less than an hour defers the claim
    ///     ([`FoldOutcome::Deferred`], counted once per distinct claim);
    /// 12. room for a new claim.
    pub fn fold_claim(
        &mut self,
        entry_id: &str,
        signed: &Map,
        ctx: &FoldContext<'_>,
    ) -> FoldOutcome {
        match self.judge_claim(entry_id, signed, ctx) {
            Ok(StampVerdict::Merge) => self.merge_own_claim(entry_id, signed),
            Ok(StampVerdict::Defer) => {
                if let Some(claim) = signed.get("claim").and_then(Value::as_map) {
                    self.count_deferral(claim_offer_key(entry_id, claim));
                }
                FoldOutcome::Deferred
            }
            Ok(StampVerdict::Refuse(refusal)) | Err(refusal) => {
                if let Some(claim) = signed.get("claim").and_then(Value::as_map) {
                    self.count_refusal(claim_offer_key(entry_id, claim), refusal);
                }
                FoldOutcome::Refused(refusal)
            }
        }
    }

    /// Merges a claim this replica signed itself (a take's own claim, as Java `tryTakeOnce`
    /// merges it) by the lattice alone, without the receiver's checks: [`FoldOutcome::Applied`]
    /// when it is new or wins, [`FoldOutcome::Unchanged`] when the held claim beats or equals it,
    /// and [`Refusal::Full`] when it would add a claim beyond the bound. Never pass a received
    /// claim here; [`SpaceStore::fold_claim`] is for those.
    pub fn merge_own_claim(&mut self, entry_id: &str, signed: &Map) -> FoldOutcome {
        if let Some(current) = self.claims.get_mut(entry_id) {
            let winner = merge_claims(Some(current), signed);
            if winner == *current {
                return FoldOutcome::Unchanged;
            }
            *current = winner;
            return FoldOutcome::Applied;
        }
        if self.claims.len() >= self.max_entries {
            return self.refuse_insert();
        }
        self.claims.push(entry_id, signed.clone());
        FoldOutcome::Applied
    }

    /// The entries a take of `type_name` may claim, and a read may see, at `now_ms` (`peer.py`'s
    /// `_available`, Java `ReplicatedSpace.availableRecords`), in insertion order: the record is
    /// of that type, the entry is present (not completed, an add dot not removed), its lease (the
    /// joined `leaseValue`, else the record's `lease`) is a `WRITE` lease that expires after
    /// `now_ms` or a lease of another kind (Java lets only a `WRITE` lease lapse), and no claim on
    /// it expires after `now_ms`. The caller narrows by space and template. The vote reads its
    /// ballots and proposals through this ([`crate::vote::live_vote_states`]).
    pub fn available(&self, type_name: &str, now_ms: i64) -> Vec<(&str, &Map)> {
        self.states()
            .filter(|&(entry_id, state)| {
                let record_type = state
                    .get("record")
                    .and_then(|record| record.get("type"))
                    .and_then(Value::as_str);
                let claimed = self.claim_of(entry_id).is_some_and(|claim| {
                    claim
                        .get("expiresAtMillis")
                        .and_then(Value::as_i64)
                        .is_some_and(|expires| expires > now_ms)
                });
                record_type == Some(type_name)
                    && is_present(state)
                    && lease_holds(state, now_ms)
                    && !claimed
            })
            .collect()
    }

    /// Counts and answers a refusal for want of room.
    fn refuse_insert(&mut self) -> FoldOutcome {
        self.refused_inserts = self.refused_inserts.saturating_add(1);
        FoldOutcome::Refused(Refusal::Full)
    }

    /// `peer.py`'s `_verify_state` and `_refused_for_revocation`, with Java's shape checks; the
    /// entry id of an admitted state.
    fn judge_state<'d>(&self, dto: &'d Map, ctx: &FoldContext<'_>) -> Result<&'d str, Refusal> {
        if dot_list(dto, "adds").len() > MAX_DOTS_PER_STATE
            || dot_list(dto, "removes").len() > MAX_DOTS_PER_STATE
        {
            return Err(Refusal::TooManyDots);
        }
        let record = dto
            .get("record")
            .and_then(Value::as_map)
            .ok_or(Refusal::Malformed)?;
        let entry_id = text(record, "entryId")
            .filter(|entry_id| !entry_id.is_empty())
            .ok_or(Refusal::Malformed)?;
        let issuer = text(record, "issuer").ok_or(Refusal::Malformed)?;
        let issuer_key = dto
            .get("issuerPublicKey")
            .and_then(Value::as_bytes)
            .filter(|key| key.len() == KEY_LENGTH)
            .ok_or(Refusal::Malformed)?;
        if let Some(space_id) = ctx.space_id
            && text(record, "spaceId") != Some(space_id)
        {
            return Err(Refusal::ForeignSpace);
        }
        if Stamp::of(record.get("issued")).is_none() || Stamp::of(dto.get("leaseStamp")).is_none() {
            return Err(Refusal::MalformedStamp);
        }
        let issuer_peer = issuer.split('/').next().unwrap_or(issuer);
        if !dots_bound_to(dto, issuer_peer) {
            return Err(Refusal::ForeignDots);
        }
        if !verify_record(record, issuer_key, dto.get("agentCertificate"), ctx.now_ms) {
            return Err(Refusal::UnverifiedRecord);
        }
        if dto.get("stateSig").and_then(Value::as_bytes).is_none() {
            return Err(Refusal::Malformed);
        }
        let completed = is_completed(dto);
        let (party, party_key, party_attested) = if completed {
            let signed = self.claims.get(entry_id).ok_or(Refusal::NoClaim)?;
            let claim = signed
                .get("claim")
                .and_then(Value::as_map)
                .ok_or(Refusal::NoClaim)?;
            // The claim authenticating this completion must be bound to exactly this entry and
            // space by its own signed fields.
            if claim.get("entryId") != record.get("entryId")
                || claim.get("spaceId") != record.get("spaceId")
            {
                return Err(Refusal::ClaimMismatch);
            }
            if !verify_claim_proof(&Value::Map(signed.clone()), ctx.now_ms) {
                return Err(Refusal::UnverifiedClaim);
            }
            let holder = text(claim, "holder").ok_or(Refusal::UnverifiedClaim)?;
            let holder_key = signed
                .get("holderKey")
                .and_then(Value::as_bytes)
                .ok_or(Refusal::UnverifiedClaim)?;
            (
                holder,
                holder_key,
                present(signed, "holderCertificate").is_some(),
            )
        } else {
            (
                issuer,
                issuer_key,
                present(dto, "agentCertificate").is_some(),
            )
        };
        if party_key.len() != KEY_LENGTH {
            return Err(Refusal::Malformed);
        }
        if !verify_state_signature(dto, party, party_key, party_attested, ctx.now_ms) {
            return Err(Refusal::UnverifiedState);
        }
        if self.refused_for_revocation(dto, entry_id, issuer, completed, ctx.revocations) {
            return Err(Refusal::Revoked);
        }
        Ok(entry_id)
    }

    /// `peer.py`'s `_refused_for_revocation` (Java `refusedForRevocation`), SPEC §5.6's freeze
    /// rule at merge for an authenticated state: the actor of the transition (the claim holder
    /// for a completion, the issuer otherwise) must not be revoked, peers and agents alike. An
    /// agent is judged at the state's `signedAt` with the keys it signed with; a peer-signed
    /// state (no `signedAt`) at its `leaseStamp`, the stamp of the last write or renewal, so a
    /// renewal after the effective instant is refused while the original history still folds.
    fn refused_for_revocation(
        &self,
        dto: &Map,
        entry_id: &str,
        issuer: &str,
        completed: bool,
        registry: &Registry,
    ) -> bool {
        if completed {
            let Some(signed) = self.claims.get(entry_id) else {
                return false;
            };
            let Some(holder) = signed
                .get("claim")
                .and_then(|claim| claim.get("holder"))
                .and_then(Value::as_str)
            else {
                return false;
            };
            return registry.refuses(
                holder,
                certificate_key(signed.get("holderCertificate")),
                signing_ms(dto, None),
            );
        }
        let lease_ms = Stamp::of(dto.get("leaseStamp")).map(|stamp| stamp.physical);
        registry.refuses(
            issuer,
            certificate_key(dto.get("agentCertificate")),
            signing_ms(dto, lease_ms),
        ) || (present(dto, "signer").is_some()
            && registry.refuses(
                issuer,
                certificate_key(dto.get("stateCertificate")),
                signing_ms(dto, None),
            ))
    }

    /// `peer.py`'s `_fold_claim` checks, with Java's and Ruby's bounds against the held entry.
    fn judge_claim(
        &self,
        entry_id: &str,
        signed: &Map,
        ctx: &FoldContext<'_>,
    ) -> Result<StampVerdict, Refusal> {
        let claim = signed
            .get("claim")
            .and_then(Value::as_map)
            .ok_or(Refusal::Malformed)?;
        if signed.get("holderKey").and_then(Value::as_bytes).is_none() {
            return Err(Refusal::Malformed);
        }
        if text(claim, "entryId") != Some(entry_id) {
            return Err(Refusal::ClaimMismatch);
        }
        if let Some(space_id) = ctx.space_id
            && text(claim, "spaceId") != Some(space_id)
        {
            return Err(Refusal::ForeignSpace);
        }
        if !claim_is_well_formed(claim) {
            return Err(Refusal::Malformed);
        }
        if !verify_claim_signature(&Value::Map(signed.clone())) {
            return Err(Refusal::UnverifiedClaim);
        }
        // Well formed, so the holder is text and the stamp parses.
        let holder = text(claim, "holder").ok_or(Refusal::Malformed)?;
        let stamp = Stamp::of(claim.get("stamp")).ok_or(Refusal::Malformed)?;
        if ctx.revocations.refuses(
            holder,
            certificate_key(signed.get("holderCertificate")),
            None,
        ) {
            return Err(Refusal::Revoked);
        }
        // SPEC §7.4's third rule and the far-future rule of §7.3, judged after verification and
        // revocation and before the epoch, hold, and contest bounds, as Java's mergeClaim does.
        let verdict = stamp_verdict([claim.get("stamp")], ctx.now_ms);
        if let StampVerdict::Refuse(refusal) = verdict {
            return Err(refusal);
        }
        let current = self.claim_of(entry_id);
        let observed = current
            .and_then(|current| current.get("epoch"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if !claim_within_bounds(claim, observed, ctx.now_ms) {
            return Err(Refusal::OutOfBounds);
        }
        let issued = self
            .state(entry_id)
            .and_then(|state| state.get("record"))
            .and_then(|record| record.get("issued"))
            .and_then(Value::as_str);
        if let Some(issued) = issued
            && !claim_not_before_issue(claim, issued)
        {
            return Err(Refusal::PredatesIssue);
        }
        if let Some(current) = current
            && text(current, "holder") != Some(holder)
        {
            let horizon = i128::from(ctx.now_ms)
                - i128::from(MAX_DRIFT_MILLIS)
                - i128::from(ctx.settle_millis);
            if i128::from(stamp.physical) < horizon {
                return Err(Refusal::LateContest);
            }
        }
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_map;

    fn dot(replica: &str, counter: i64) -> Value {
        cbor_map! { "replica" => replica, "counter" => counter }
    }

    fn map(value: Value) -> Map {
        value.into_map().unwrap()
    }

    fn state(adds: Vec<Value>, removes: Vec<Value>, stamp: &str, completed: bool) -> Map {
        map(cbor_map! {
            "adds" => adds,
            "removes" => removes,
            "leaseStamp" => stamp,
            "leaseValue" => cbor_map! { "expiresAtMillis" => 10 },
            "completed" => completed,
        })
    }

    #[test]
    fn stamps_parse_and_order_as_java_does() {
        let a = Stamp::parse("5:0:a").unwrap();
        assert!(Stamp::parse("5:1:a").unwrap() > a);
        assert!(Stamp::parse("6:0:a").unwrap() > Stamp::parse("5:9:z").unwrap());
        assert!(Stamp::parse("5:0:b").unwrap() > a);
        for bad in [
            "", "5", "5:0", "5:0:", "-1:0:a", "5:-1:a", "x:0:a", "5:0:a:b",
        ] {
            assert!(Stamp::parse(bad).is_none(), "{bad}");
        }
        assert!(Some(a) > None);
        // Java order: a supplementary character sorts before U+FFFD, unlike code point order.
        assert_eq!(java_order("\u{1F600}", "\u{FFFD}"), Ordering::Less);
        assert_eq!(crate::hlc::physical_lenient("+12:0:n"), Some(12));
        assert_eq!(crate::hlc::physical_lenient("x"), None);
        // Since v0.1.30 a stamp has one text, and the fold reads no other.
        assert!(Stamp::parse("+12:0:n").is_none());
    }

    #[test]
    fn a_stamp_leads_within_defers_or_is_hostile() {
        let now = 1_000_000;
        let margin = now + MAX_DRIFT_MILLIS + SKEW_MARGIN_MILLIS;
        assert_eq!(lead(margin, now), Lead::Within);
        assert_eq!(lead(margin + 1, now), Lead::Deferred);
        assert_eq!(
            lead(margin + FAR_FUTURE_HOSTILE_MILLIS, now),
            Lead::Deferred
        );
        assert_eq!(
            lead(margin + FAR_FUTURE_HOSTILE_MILLIS + 1, now),
            Lead::Hostile
        );
        assert_eq!(lead(i64::MAX, i64::MAX), Lead::Within);
        assert_eq!(lead(i64::MAX, i64::MIN), Lead::Hostile);
        let at = |physical: i64, logical: i32| Value::from(format!("{physical}:{logical}:n"));
        let (merge, defer, hostile) = (at(now, 0), at(margin + 1, 0), at(i64::MAX, 0));
        let logical = at(now, crate::limits::LOGICAL_LIMIT + 1);
        assert_eq!(
            stamp_verdict([Some(&merge), None], now),
            StampVerdict::Merge
        );
        assert_eq!(
            stamp_verdict([Some(&merge), Some(&defer)], now),
            StampVerdict::Defer
        );
        assert_eq!(
            stamp_verdict([Some(&defer), Some(&hostile)], now),
            StampVerdict::Refuse(Refusal::StampFarFuture)
        );
        // The logical limit is judged first, so a stamp that fails both is a logical refusal.
        let both = at(i64::MAX, crate::limits::LOGICAL_LIMIT + 1);
        assert_eq!(
            stamp_verdict([Some(&both)], now),
            StampVerdict::Refuse(Refusal::StampLogical)
        );
        assert_eq!(
            stamp_verdict([Some(&merge), Some(&logical)], now),
            StampVerdict::Refuse(Refusal::StampLogical)
        );
    }

    #[test]
    fn the_refused_offer_cache_forgets_the_least_recently_offered_key() {
        let mut keys = RecentKeys::default();
        assert!(keys.offer(b"first".to_vec()));
        assert!(!keys.offer(b"first".to_vec()));
        for index in 0..REFUSED_OFFERS_CAPACITY - 1 {
            assert!(keys.offer(index.to_be_bytes().to_vec()));
        }
        assert_eq!(keys.len(), REFUSED_OFFERS_CAPACITY);
        // "first" is offered again, so it is the most recent, and key 0 is now the oldest.
        assert!(!keys.offer(b"first".to_vec()));
        assert!(keys.offer(b"newcomer".to_vec()));
        assert_eq!(keys.len(), REFUSED_OFFERS_CAPACITY);
        assert!(
            !keys.offer(b"first".to_vec()),
            "kept: it was offered recently"
        );
        assert!(
            keys.offer(0usize.to_be_bytes().to_vec()),
            "forgotten: the oldest offer"
        );
    }

    #[test]
    fn union_dots_dedupes_and_sorts() {
        let a = Value::from(vec![dot("b", 2), dot("a", 1), dot("b", 2)]);
        let b = Value::from(vec![dot("a", 3), cbor_map! { "replica" => 1 }, Value::Null]);
        assert_eq!(
            union_dots(Some(&a), Some(&b)),
            vec![dot("a", 1), dot("a", 3), dot("b", 2)]
        );
        assert!(union_dots(None, Some(&Value::from("x"))).is_empty());
    }

    #[test]
    fn join_is_monotone_and_idempotent() {
        let early = state(vec![dot("p", 1)], vec![], "1:0:p", false);
        let late = state(vec![dot("p", 1)], vec![dot("p", 1)], "2:0:p", true);
        let joined = join(&early, &late);
        assert!(is_completed(&joined));
        assert_eq!(joined.get("leaseStamp"), Some(&Value::from("2:0:p")));
        assert_eq!(join(&joined, &early), joined);
        assert_eq!(join(&joined, &late), joined);
        assert!(!is_present(&joined));
        assert!(is_present(&early));
        let withdrawn = state(vec![dot("p", 1)], vec![dot("p", 1)], "1:0:p", false);
        assert!(!is_present(&withdrawn));
        let readded = join(
            &withdrawn,
            &state(vec![dot("p", 2)], vec![], "1:0:p", false),
        );
        assert!(is_present(&readded));
    }

    #[test]
    fn advances_follows_java() {
        let base = state(vec![dot("p", 1)], vec![], "1:0:p", false);
        let renewed = state(vec![dot("p", 1)], vec![], "2:0:p", false);
        let cancelled = state(vec![dot("p", 1)], vec![dot("p", 1)], "1:0:p", false);
        let completed = state(vec![dot("p", 1)], vec![], "1:0:p", true);
        assert!(advances(&renewed, &base) && !advances(&base, &renewed));
        assert!(advances(&cancelled, &renewed) && !advances(&renewed, &cancelled));
        assert!(advances(&completed, &cancelled) && !advances(&cancelled, &completed));
        assert!(advances(&base, &base));
    }

    #[test]
    fn signing_time_reads_signed_at_then_the_fallback() {
        let mut dto = Map::new();
        assert_eq!(signing_ms(&dto, Some(7)), Some(7));
        dto.insert("signedAt", "");
        assert_eq!(signing_ms(&dto, Some(7)), Some(7));
        dto.insert("signedAt", "garbage");
        assert_eq!(signing_ms(&dto, None), None);
        dto.insert("signedAt", "12:0:n");
        assert_eq!(signing_ms(&dto, Some(7)), Some(12));
    }

    #[test]
    fn ordered_keeps_first_insertion_order_across_removal() {
        let mut ordered = Ordered::default();
        ordered.push("b", 1);
        ordered.push("a", 2);
        ordered.push("c", 3);
        assert_eq!(ordered.remove("a"), Some(2));
        ordered.push("a", 4);
        let keys: Vec<_> = ordered.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["b", "c", "a"]);
        assert_eq!(ordered.get("a"), Some(&4));
        assert_eq!(ordered.remove("z"), None);
    }

    #[test]
    fn hostile_shapes_are_refused_without_panicking() {
        let registry = Registry::default();
        let ctx = FoldContext::new(0, &registry);
        let mut store = SpaceStore::new();
        let shapes = [
            Map::new(),
            map(cbor_map! { "record" => 1 }),
            map(cbor_map! { "record" => cbor_map! { "entryId" => "" } }),
            map(cbor_map! { "adds" => vec![Value::Null; MAX_DOTS_PER_STATE + 1] }),
        ];
        for dto in &shapes {
            assert!(store.fold_state(dto, &ctx).is_refused());
        }
        for signed in [
            Map::new(),
            map(cbor_map! { "claim" => cbor_map! {}, "holderKey" => 1 }),
            map(cbor_map! { "claim" => cbor_map! { "entryId" => "e" }, "holderKey" => [0u8; 32] }),
        ] {
            assert!(store.fold_claim("e", &signed, &ctx).is_refused());
        }
        assert!(store.is_empty());
        assert_eq!(store.claim_count(), 0);
    }
}
