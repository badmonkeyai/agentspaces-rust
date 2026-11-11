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

//! The listening role (SPEC §5.1 to §5.4): what a [`Peer`](super::Peer) that accepts links is
//! configured with ([`ListenConfig`], [`ListenerSpec`]), what it counts ([`ListenCounters`]),
//! and the accept tasks that hand each accepted channel to the actor.
//!
//! A listening peer is a hub: dial-only members (and Java, TypeScript, Python, or Ruby members
//! that dial it) link to it, it admits them under the group's membership policy, forwards the
//! rumors one link brings to the others, answers their anti-entropy pulls, relays the frames they
//! address to one another, and holds the payload blocks of the entries it replicates. It does not
//! dial the members it learns of: a full mesh is not its job. It may itself dial seeds (another
//! listening peer, a Java node) and then forwards between that link and its accepted ones too.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use agentspaces_wire::ads as wire_ads;
use agentspaces_wire::cbor::Map;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::{Seed, seed_address};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::PeerError;
use super::actor::Inbound;
use crate::transport::tcp::TcpListener;
use crate::transport::tls::TlsListener;
use crate::transport::{Listener, TransportError};

/// One listener a peer binds: a `tcp` or `tls` address, or a listener the caller bound itself
/// (an in-memory one in tests), with the address the peer's advertisement names for it.
#[derive(Clone)]
pub struct ListenerSpec {
    source: Source,
    advertise: Option<String>,
    priority: i32,
}

#[derive(Clone)]
enum Source {
    Tcp(String),
    Tls(String),
    Bound(Arc<dyn Listener>),
}

impl fmt::Debug for ListenerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            Source::Tcp(bind) => format!("tcp://{bind}"),
            Source::Tls(bind) => format!("tls://{bind}"),
            Source::Bound(listener) => {
                format!("{}://{}", listener.scheme(), listener.local_address())
            }
        };
        f.debug_struct("ListenerSpec")
            .field("source", &source)
            .field("advertise", &self.advertise)
            .field("priority", &self.priority)
            .finish()
    }
}

impl ListenerSpec {
    /// A `tcp` listener on `bind` (`host:port`, `[v6]:port`, or `:port` for every IPv4
    /// interface; port `0` lets the OS choose, [`Peer::listen_addrs`](super::Peer::listen_addrs)
    /// reports it). Every frame on it stays signed.
    pub fn tcp(bind: impl Into<String>) -> Self {
        Self::of(Source::Tcp(bind.into()))
    }

    /// A `tls` listener on `bind`, presenting the peer's channel certificate (SPEC §5.6): a
    /// member that presents its own is attested on the link.
    pub fn tls(bind: impl Into<String>) -> Self {
        Self::of(Source::Tls(bind.into()))
    }

    /// A listener the caller bound (an in-memory listener in tests, or one with options of its
    /// own); its scheme and address are its own.
    pub fn bound(listener: Arc<dyn Listener>) -> Self {
        Self::of(Source::Bound(listener))
    }

    fn of(source: Source) -> Self {
        Self {
            source,
            advertise: None,
            priority: 0,
        }
    }

    /// The address the advertisement names for this listener (`host:port`), when the bound one
    /// is not what members dial (a wildcard bind, a NAT, a container). Without it a listener
    /// bound to a wildcard address advertises nothing.
    #[must_use]
    pub fn advertise(mut self, address: impl Into<String>) -> Self {
        self.advertise = Some(address.into());
        self
    }

    /// The endpoint's priority in the advertisement (lower is dialed first; default 0).
    #[must_use]
    pub fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// The scheme this listener serves.
    pub fn scheme(&self) -> &str {
        match &self.source {
            Source::Tcp(_) => crate::transport::tcp::SCHEME,
            Source::Tls(_) => crate::transport::tls::SCHEME,
            Source::Bound(listener) => listener.scheme(),
        }
    }
}

/// How a listening peer runs: its listeners, whether it requires attestation, which spaces it
/// replicates, and its bounds and timers. [`ListenConfig::default`] listens nowhere (a dial-only
/// peer); add listeners to [`ListenConfig::listeners`] or with
/// [`PeerConfig::listen_on`](super::PeerConfig::listen_on).
///
/// # Which spaces a listening peer replicates
///
/// The spaces in [`ListenConfig::replicate`], opened at start, and, while
/// [`ListenConfig::replicate_heard`] holds (the default), every space a rumor or a pull brings it
/// an entry of, up to [`ListenConfig::max_replicated_spaces`] spaces opened that way (a further
/// one is refused and counted, [`ListenCounters::spaces_refused`], and its rumors are still
/// forwarded). Each space holds at most
/// [`PeerConfig::space_max_entries`](super::PeerConfig::space_max_entries) entries and
/// [`PeerConfig::space_max_bytes`](super::PeerConfig::space_max_bytes) bytes of states, and
/// collects its tombstones as every space does (SPEC §7.3). A replicated entry whose payload
/// travels as a block has the block fetched from its writer (or another member) and held within
/// [`PeerConfig::fetched_block_bytes`](super::PeerConfig::fetched_block_bytes), so the writer may
/// leave once the block is held here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListenConfig {
    /// The listeners to bind; none makes a dial-only peer.
    pub listeners: Vec<ListenerSpec>,
    /// SPEC §5.6's required attestation: every frame, on an accepted link or the dialed one,
    /// must come from the PeerID the link's transport attested, introductions included; relayed
    /// inner frames are dropped, a member whose fresh link attests nobody is evicted, and a third
    /// party's copy of an advertisement admits nobody (it never does here). Only attesting
    /// listeners and seeds (`tls`) are allowed with it.
    pub require_attestation: bool,
    /// The spaces replicated from the start.
    pub replicate: Vec<String>,
    /// Whether every space heard of is replicated too (default `true`).
    pub replicate_heard: bool,
    /// The most spaces opened because they were heard of (default 64).
    pub max_replicated_spaces: usize,
    /// The most accepted links held at once (default 1024). A further one takes the place of
    /// the oldest link nobody introduced itself on, and is closed at once when every link held
    /// carries a member.
    pub max_links: usize,
    /// The most admitted members held at once (default 4096); a further admission is refused
    /// once the members whose advertisement lapsed with no link are gone.
    pub max_members: usize,
    /// Admissions (a newcomer's verified introduction that the membership policy admits)
    /// allowed in a burst, and per second after it (defaults 64 and 32). Only an admission
    /// spends the bucket: a stranger's other frames cost the allowance of its own link, so a
    /// flood of them starves no newcomer.
    pub admission_burst: u32,
    /// See [`ListenConfig::admission_burst`].
    pub admissions_per_second: u32,
    /// The base period of this peer's own anti-entropy rounds (default: the founding's gossip
    /// period, one second for a group founded from text). While nothing moves it doubles per
    /// round up to 32 times (SPEC §5.3).
    pub anti_entropy_period: Option<Duration>,
    /// How long an accepted link may stay without a verified introduction before it is closed
    /// (default 30 s).
    pub introduction_timeout: Duration,
    /// How long an accepted link may stay silent before it is closed (default 120 s; keep it
    /// above the members' advertisement interval, which every member refreshes on its link).
    pub link_idle_timeout: Duration,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            listeners: Vec::new(),
            require_attestation: false,
            replicate: Vec::new(),
            replicate_heard: true,
            max_replicated_spaces: 64,
            max_links: 1024,
            max_members: 4096,
            admission_burst: 64,
            admissions_per_second: 32,
            anti_entropy_period: None,
            introduction_timeout: Duration::from_secs(30),
            link_idle_timeout: Duration::from_secs(120),
        }
    }
}

/// Admissions refused, by reason (each also drops the introduction that asked).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionRefusals {
    /// The admission bucket was empty ([`ListenConfig::admission_burst`]).
    pub rate: u64,
    /// The membership policy refused it: no credential, one that does not verify (or is not in
    /// the wire encoding of its record), a revoked credential or delegation, an expired
    /// delegation never admitted before, a `POLICY` group (no validator runs here), or a join by
    /// GroupID whose founding has not verified yet.
    pub policy: u64,
    /// The newcomer's PeerID is revoked.
    pub revoked: u64,
    /// The advertisement does not verify, or names another issuer than the frame's sender (a
    /// third party's copy admits nobody).
    pub forged: u64,
    /// The advertisement names another group.
    pub foreign: u64,
    /// The advertisement had lapsed, or was issued too far ahead.
    pub expired: u64,
    /// [`ListenConfig::max_members`] members are held.
    pub full: u64,
    /// Required attestation: the link does not attest the newcomer.
    pub unattested: u64,
    /// The link already carries another member's admission.
    pub link_taken: u64,
}

impl AdmissionRefusals {
    /// Every refusal, whatever the reason.
    pub fn total(&self) -> u64 {
        [
            self.rate,
            self.policy,
            self.revoked,
            self.forged,
            self.foreign,
            self.expired,
            self.full,
            self.unattested,
            self.link_taken,
        ]
        .into_iter()
        .fold(0u64, u64::saturating_add)
    }
}

/// What a listening peer counted ([`PeerCounters::listen`](super::PeerCounters::listen)).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenCounters {
    /// Links accepted.
    pub links_accepted: u64,
    /// Links closed at once: [`ListenConfig::max_links`] links carrying members were held, or
    /// the peer was closing.
    pub links_refused: u64,
    /// Accepted links that ended (either end closed, or this peer closed them).
    pub links_closed: u64,
    /// Accepted links this peer closed because they did not introduce a member in time, stayed
    /// silent too long, sent too many frames before introducing one, or (introducing nobody
    /// yet) were the oldest such link when a new one arrived at [`ListenConfig::max_links`].
    pub links_silent: u64,
    /// Members admitted from their own introduction.
    pub admitted: u64,
    /// Admissions refused, by reason.
    pub refused: AdmissionRefusals,
    /// Frames from peers outside the membership dropped: all but an introduction, a PING, a
    /// GROUP_AD_WANT, and a CHANNEL_HELLO, and those too past the 64 stranger frames a link may
    /// carry (a link nobody introduced itself on is then closed).
    pub stranger_frames: u64,
    /// Members' frames dropped over their rate.
    pub rate_limited: u64,
    /// Frames dropped under required attestation: their link does not attest their sender, or
    /// they arrived inside a relay.
    pub unattested_frames: u64,
    /// Members dropped because their advertisement lapsed while no link carried them.
    pub members_expired: u64,
    /// Rumors forwarded to the other links (one per rumor, however many links).
    pub rumors_forwarded: u64,
    /// Rumors received again and neither processed nor forwarded.
    pub rumors_duplicate: u64,
    /// Rumors not forwarded because they did not decode or verify.
    pub rumors_unforwarded: u64,
    /// Frames a link's backlog dropped because it held its bound of bytes or frames.
    pub backlog_dropped: u64,
    /// DIGESTs answered with at least one PULL_RESP.
    pub pulls_answered: u64,
    /// PULL_RESP frames sent (an answer larger than one frame is sent in several).
    pub pull_frames: u64,
    /// DIGESTs not answered because their sender asked too often.
    pub pulls_paced: u64,
    /// Streams of a DIGEST ignored past the bound of streams one DIGEST may name, and answers
    /// cut short at the bound of PULL_RESP frames one answer may take.
    pub digests_truncated: u64,
    /// PULL_RESPs dropped because this peer had not asked their sender.
    pub pull_resps_unsolicited: u64,
    /// This peer's own anti-entropy rounds (periodic and targeted).
    pub rounds: u64,
    /// RELAY_FRAMEs delivered to a member on a link this peer holds, or passed to the next relay
    /// of their path.
    pub relays_forwarded: u64,
    /// RELAY_FRAMEs refused because their target is not a member.
    pub relays_not_member: u64,
    /// RELAY_FRAMEs dropped because no link reaches their target or next relay.
    pub relays_unreachable: u64,
    /// RELAY_FRAMEs refused for a malformed path.
    pub relays_bad_path: u64,
    /// Blocks this peer fetched for the entries it replicates.
    pub blocks_fetched: u64,
    /// BLOCK_WANTs sent for them (first asks and retries).
    pub block_asks: u64,
    /// Block fetches given up: the deadline passed, the entry left, or too many were pending.
    pub block_fetches_abandoned: u64,
    /// Spaces opened because a rumor or a pull brought an entry of them.
    pub spaces_replicated: u64,
    /// Entries of spaces not opened because [`ListenConfig::max_replicated_spaces`] were.
    pub spaces_refused: u64,
    /// GROUP_ADs served (SPEC §5.1).
    pub group_ads_served: u64,
}

/// A listener bound at start, with what the advertisement names for it.
pub(super) struct BoundListener {
    pub listener: Arc<dyn Listener>,
    /// The address bound (`host:port`).
    pub address: String,
    /// The endpoint the advertisement names, when there is one.
    pub endpoint: Option<Map>,
}

/// Binds every listener of `specs` as `identity`; the first failure stops and is returned (the
/// listeners bound so far close as they drop).
pub(super) async fn bind(
    specs: &[ListenerSpec],
    identity: &Identity,
) -> Result<Vec<BoundListener>, PeerError> {
    let mut bound = Vec::with_capacity(specs.len());
    for spec in specs {
        let listener: Arc<dyn Listener> = match &spec.source {
            Source::Tcp(address) => Arc::new(TcpListener::bind(address).await?),
            Source::Tls(address) => Arc::new(TlsListener::bind(address, identity).await?),
            Source::Bound(listener) => Arc::clone(listener),
        };
        let address = listener.local_address();
        let advertised = spec
            .advertise
            .clone()
            .or_else(|| dialable(&address).then(|| address.clone()));
        if advertised.is_none() {
            tracing::warn!(
                %address,
                "agentspaces: a listener bound to a wildcard address advertises no endpoint; \
                 give it the address members dial"
            );
        }
        let endpoint = advertised
            .map(|address| wire_ads::endpoint(listener.scheme(), &address, spec.priority));
        bound.push(BoundListener {
            listener,
            address,
            endpoint,
        });
    }
    Ok(bound)
}

/// Whether a bound address names a host a member can dial (not a wildcard).
fn dialable(address: &str) -> bool {
    match seed_address(address) {
        Ok((host, _)) => !matches!(host.as_str(), "0.0.0.0" | "::" | ""),
        Err(_) => true,
    }
}

/// The dialable form of a bound listener's address, as a seed of its scheme.
pub(super) fn listen_seed(listener: &BoundListener) -> Option<Seed> {
    let (host, port) = seed_address(&listener.address).ok()?;
    Some(Seed::new(host, port, listener.listener.scheme()))
}

/// Accepts channels from `listener` and hands each to the actor until it closes or the actor is
/// gone. A failed accept (a refused handshake, descriptor exhaustion) pauses briefly and goes on.
pub(super) fn spawn_accept(
    listener: Arc<dyn Listener>,
    inbound: mpsc::Sender<Inbound>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if inbound.is_closed() {
                return;
            }
            match listener.accept().await {
                None => return,
                Some(Ok(channel)) => {
                    let message = Inbound::Accepted {
                        channel: Box::new(channel),
                    };
                    if let Err(mpsc::error::SendError(Inbound::Accepted { channel })) =
                        inbound.send(message).await
                    {
                        channel.closer.close();
                        return;
                    }
                }
                Some(Err(error)) => {
                    tracing::debug!(%error, "agentspaces: an accept failed");
                    if matches!(error, TransportError::Io(_)) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    })
}

/// A token bucket: `capacity` tokens, refilled at `rate` per second, spent one at a time.
#[derive(Debug, Clone)]
pub(super) struct TokenBucket {
    capacity: f64,
    rate: f64,
    tokens: f64,
    at: tokio::time::Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(capacity: u32, rate: u32) -> Self {
        let capacity = f64::from(capacity.max(1));
        Self {
            capacity,
            rate: f64::from(rate),
            tokens: capacity,
            at: tokio::time::Instant::now(),
        }
    }

    /// Spends one token; whether there was one.
    pub fn take(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_spends_its_burst_then_refuses() {
        let mut bucket = TokenBucket::new(3, 0);
        assert!(bucket.take() && bucket.take() && bucket.take());
        assert!(!bucket.take());
    }

    #[test]
    fn wildcard_binds_are_not_dialable() {
        assert!(!dialable("0.0.0.0:7711"));
        assert!(!dialable("[::]:7711"));
        assert!(dialable("127.0.0.1:7711"));
        assert!(dialable("seed.example:7711"));
    }

    #[test]
    fn refusals_total_every_reason() {
        let refusals = AdmissionRefusals {
            rate: 1,
            policy: 2,
            full: 3,
            ..AdmissionRefusals::default()
        };
        assert_eq!(refusals.total(), 6);
    }
}
