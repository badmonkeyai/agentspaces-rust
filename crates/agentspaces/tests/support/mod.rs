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

//! Test support for the peer: a scripted in-memory seed over a [`MemoryNetwork`], the golden
//! vectors of the wire crate, and small waiting helpers.
//!
//! The [`FakeSeed`] accepts links, verifies and records every frame a peer sends (with the link
//! it came on and how it was authenticated), and sends what a test scripts: signed frames under
//! its own identity with fresh or chosen stamps, bare frames, raw bytes (golden frames, garbage),
//! PINGs, and PULL_RESPs. It can close a link, stop listening, or accept links without ever
//! reading them (a stalled far end).
//!
//! A [`RawPeer`] is the other way round: a scripted member (or stranger) that dials a listening
//! peer, signs whatever a test sends (its own introduction, rumors, digests, relay frames, a third
//! party's advertisement), and records the verified frames it receives.
//!
//! A *relaying* seed ([`FakeSeed::start_relay`]) also does what a seed does for the members of a
//! group, so two or three peers can race through it: it re-signs every RUMOR one link carries
//! and sends it to every other link (in order, per link), folds the space rumors into replicas
//! of its own (one [`SpaceStore`] per space, judged as a Java seed judges them), and answers a
//! DIGEST that names `space:<name>` with a PULL_RESP of that space's signed states and claims. It
//! also carries what members address to one another: a RELAY_FRAME addressed to it goes on to
//! its target (as Java's relay sends it), and a frame addressed to another member goes on as is.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use agentspaces::clock::SharedClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::PeerConfig;
use agentspaces::transport::memory::{MemoryListener, MemoryNetwork};
use agentspaces::transport::{Channel, Closer, Dialer, FrameReceiver, FrameSender, Listener};
use agentspaces::wire::ads as wire_ads;
use agentspaces::wire::bodies::{self, Rumor};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::envelope::{self, Auth};
use agentspaces::wire::fold::{FoldContext, SpaceStore};
use agentspaces::wire::hlc::Hlc;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::revocation::Registry;
use agentspaces::wire::seed::Seed;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long a test waits for something that should happen at once.
pub const PATIENCE: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------------------- golden

/// The wire crate's golden vectors, read once.
pub fn golden() -> &'static serde_json::Value {
    static GOLDEN: OnceLock<serde_json::Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        serde_json::from_str(include_str!("../../../agentspaces-wire/tests/golden.json"))
            .expect("golden.json parses")
    })
}

/// A golden entry's text.
pub fn s(name: &str) -> &'static str {
    golden()[name]
        .as_str()
        .unwrap_or_else(|| panic!("golden {name} is not text"))
}

/// A golden entry's hex as bytes.
pub fn hex(name: &str) -> Vec<u8> {
    hex::decode(s(name)).unwrap_or_else(|error| panic!("golden {name} is not hex: {error}"))
}

/// The golden identity (the founder of the golden group, and the sender of the golden frames).
pub fn golden_identity() -> Identity {
    Identity::from_pkcs8(&hex("private_key_pkcs8")).expect("golden key")
}

/// The physical milliseconds of the golden stamp `hlc_encoded`.
pub fn golden_ms() -> i64 {
    s("hlc_encoded")
        .split(':')
        .next()
        .and_then(|physical| physical.parse().ok())
        .expect("golden stamp")
}

// ------------------------------------------------------------------------------- peers

/// A peer configuration on `network` with test timings: redial every 50 ms for 10 s, dial
/// within 1 s, join within 2 s.
pub fn config(
    network: &MemoryNetwork,
    identity: Identity,
    group: GroupSpec,
    seeds: &[&str],
    clock: SharedClock,
) -> PeerConfig {
    let mut config = PeerConfig::new(identity, group);
    config.seeds = seeds
        .iter()
        .map(|seed| seed.parse().expect("seed"))
        .collect();
    config.dialers = vec![Arc::new(network.dialer())];
    config.clock = clock;
    config.reconnect_interval = Duration::from_millis(50);
    config.reconnect_window = Duration::from_secs(10);
    config.dial_timeout = Duration::from_secs(1);
    config.join_timeout = Duration::from_secs(2);
    config
}

/// Waits until `check` holds, polling every 10 ms; panics naming `what` after [`PATIENCE`].
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + PATIENCE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ------------------------------------------------------------------------------- the seed

/// One verified frame a seed received.
#[derive(Debug, Clone)]
pub struct Received {
    /// The index of the link it came on (0 for the first link accepted).
    pub link: usize,
    /// Its envelope.
    pub env: Map,
    /// How it was authenticated.
    pub auth: Auth,
}

impl Received {
    /// The frame kind.
    pub fn kind(&self) -> &str {
        self.text("kind").unwrap_or_default()
    }

    /// A text field of the envelope.
    pub fn text(&self, field: &str) -> Option<&str> {
        self.env.get(field).and_then(Value::as_str)
    }

    /// The envelope's `to`.
    pub fn to(&self) -> Option<&str> {
        self.text("to")
    }

    /// The body bytes.
    pub fn body(&self) -> &[u8] {
        self.env
            .get("body")
            .and_then(Value::as_bytes)
            .unwrap_or_default()
    }

    /// The rumor a RUMOR carries.
    pub fn rumor(&self) -> Option<Rumor> {
        (self.kind() == bodies::KIND_RUMOR)
            .then(|| bodies::parse_rumor(self.body()))
            .flatten()
    }

    /// The stream of a RUMOR, if this is one.
    pub fn stream(&self) -> Option<String> {
        self.rumor().map(|rumor| rumor.stream_id)
    }
}

struct SeedLink {
    sender: FrameSender,
    closer: Closer,
    /// A relaying seed's ordered outbound queue for this link (its pump writes to `sender`).
    out: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

#[derive(Default)]
struct State {
    links: Vec<SeedLink>,
    received: Vec<Received>,
    malformed: usize,
    parked: Vec<FrameReceiver>,
}

/// What a relaying seed needs to sign, forward, and answer.
struct Relay {
    identity: Identity,
    group: String,
    clock: SharedClock,
    /// The seed's clock, shared with [`FakeSeed::stamp`] so no two frames repeat a stamp.
    hlc: Arc<Mutex<Hlc>>,
    registry: Registry,
    stores: Mutex<HashMap<String, SpaceStore>>,
    relayed: Mutex<usize>,
    /// The link each member's frames arrive on, by PeerID.
    members: Mutex<HashMap<String, usize>>,
}

impl Relay {
    /// A frame signed by the seed with a fresh stamp.
    fn frame(&self, kind: &str, body: &[u8], to: Option<&str>) -> Vec<u8> {
        let stamp = lock(&self.hlc).now(self.clock.now_ms());
        let env = envelope::envelope(&self.group, kind, self.identity.peer_id(), &stamp, body, to);
        envelope::encode_frame(&env, &self.identity)
    }

    /// Folds a space rumor's delta into the seed's replica of the space (claim before state).
    fn fold(&self, space: &str, payload: &[u8]) {
        let Some(delta) = cbor::decode(payload).ok().and_then(Value::into_map) else {
            return;
        };
        let now = self.clock.now_ms();
        let space_id = ids::space_id_local(&format!("{}/{space}", self.group));
        let ctx = FoldContext::new(now, &self.registry).with_space(&space_id);
        let mut stores = lock(&self.stores);
        let store = stores.entry(space.to_owned()).or_default();
        if let (Some(entry), Some(claim)) = (
            delta.get("claimEntry").and_then(Value::as_str),
            delta.get("claim").and_then(Value::as_map),
        ) {
            store.fold_claim(entry, claim, &ctx);
        }
        if let Some(state) = delta.get("state").and_then(Value::as_map) {
            store.fold_state(state, &ctx);
        }
    }

    /// The PULL_RESP delta of one space: `{states, claims}` of the seed's replica.
    fn sync(&self, space: &str) -> Vec<u8> {
        let stores = lock(&self.stores);
        let (states, claims) = match stores.get(space) {
            Some(store) => (
                store
                    .signed_states()
                    .map(|(_, state)| Value::Map(state.clone()))
                    .collect::<Vec<_>>(),
                store
                    .claims()
                    .map(|(entry, claim)| (entry, Value::Map(claim.clone())))
                    .collect::<Map>(),
            ),
            None => (Vec::new(), Map::new()),
        };
        let mut sync = Map::new();
        sync.insert("states", Value::Array(states));
        // Java writes a map's keys in the RFC 8949 order, and a receiver refuses another
        // (SPEC §9.1 P2).
        sync.insert("claims", cbor::canonical_map(&claims));
        cbor::encode(&Value::Map(sync))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A scripted seed listening on a [`MemoryNetwork`]. See the [module docs](self).
pub struct FakeSeed {
    /// The seed's identity: it signs every frame the seed sends.
    pub identity: Identity,
    /// The GroupID the seed's frames name.
    pub group: String,
    /// The address it listens at.
    pub address: String,
    clock: SharedClock,
    network: MemoryNetwork,
    state: Arc<Mutex<State>>,
    hlc: Arc<Mutex<Hlc>>,
    accept: JoinHandle<()>,
    relay: Option<Arc<Relay>>,
}

impl FakeSeed {
    /// A seed with a fresh identity that reads every link.
    pub fn start(network: &MemoryNetwork, address: &str, group: &str, clock: SharedClock) -> Self {
        let identity = Identity::generate().expect("identity");
        Self::start_as(network, address, group, clock, identity, true)
    }

    /// A seed with `identity`; with `reading` false it accepts links and never reads them.
    pub fn start_as(
        network: &MemoryNetwork,
        address: &str,
        group: &str,
        clock: SharedClock,
        identity: Identity,
        reading: bool,
    ) -> Self {
        Self::launch(network, address, group, clock, identity, reading, false)
    }

    /// A relaying seed with a fresh identity (see the [module docs](self)): it forwards every
    /// RUMOR to the other links, keeps replicas of the spaces rumored, and answers their pulls.
    pub fn start_relay(
        network: &MemoryNetwork,
        address: &str,
        group: &str,
        clock: SharedClock,
    ) -> Self {
        let identity = Identity::generate().expect("identity");
        Self::launch(network, address, group, clock, identity, true, true)
    }

    fn launch(
        network: &MemoryNetwork,
        address: &str,
        group: &str,
        clock: SharedClock,
        identity: Identity,
        reading: bool,
        relaying: bool,
    ) -> Self {
        let listener = network.listen(address);
        let state = Arc::new(Mutex::new(State::default()));
        let hlc = Arc::new(Mutex::new(
            Hlc::new(identity.peer_id()).expect("a PeerID is a stamp node"),
        ));
        let relay = relaying.then(|| {
            Arc::new(Relay {
                identity: identity.clone(),
                group: group.to_owned(),
                clock: Arc::clone(&clock),
                hlc: Arc::clone(&hlc),
                registry: Registry::new(None, Some(group.to_owned())),
                stores: Mutex::new(HashMap::new()),
                relayed: Mutex::new(0),
                members: Mutex::new(HashMap::new()),
            })
        });
        let accept = tokio::spawn(accept_loop(
            listener,
            Arc::clone(&state),
            reading,
            relay.clone(),
        ));
        Self {
            hlc,
            identity,
            group: group.to_owned(),
            address: address.to_owned(),
            clock,
            network: network.clone(),
            state,
            accept,
            relay,
        }
    }

    /// How many RUMOR frames a relaying seed has forwarded (one per receiving link).
    pub fn relayed(&self) -> usize {
        self.relay.as_ref().map_or(0, |relay| *lock(&relay.relayed))
    }

    /// The seed's replica of a space (a relaying seed): its joined states by entry id.
    pub fn space_states(&self, space: &str) -> Vec<(String, Map)> {
        let Some(relay) = &self.relay else {
            return Vec::new();
        };
        lock(&relay.stores)
            .get(space)
            .map(|store| {
                store
                    .states()
                    .map(|(entry, state)| (entry.to_owned(), state.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sends a seed-signed frame with a fresh stamp to every link, in order with what the seed
    /// relays.
    pub async fn broadcast(&self, kind: &str, body: &[u8]) {
        let count = self.links();
        for link in 0..count {
            self.send(link, kind, body, None).await;
        }
    }

    /// The seed's PeerID.
    pub fn peer_id(&self) -> &str {
        self.identity.peer_id()
    }

    /// How many links it has accepted.
    pub fn links(&self) -> usize {
        lock(&self.state).links.len()
    }

    /// Every verified frame received so far.
    pub fn received(&self) -> Vec<Received> {
        lock(&self.state).received.clone()
    }

    /// How many frames failed to verify.
    pub fn malformed(&self) -> usize {
        lock(&self.state).malformed
    }

    /// The kinds received on `link`, in order.
    pub fn kinds(&self, link: usize) -> Vec<String> {
        lock(&self.state)
            .received
            .iter()
            .filter(|received| received.link == link)
            .map(|received| received.kind().to_owned())
            .collect()
    }

    /// The frames received on `link` of `kind`.
    pub fn of_kind(&self, link: usize, kind: &str) -> Vec<Received> {
        lock(&self.state)
            .received
            .iter()
            .filter(|received| received.link == link && received.kind() == kind)
            .cloned()
            .collect()
    }

    /// Waits until `ready` holds over the frames received; returns them. Panics after
    /// [`PATIENCE`], naming `what` and the kinds received.
    pub async fn wait_for(&self, what: &str, ready: impl Fn(&[Received]) -> bool) -> Vec<Received> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            {
                let state = lock(&self.state);
                if ready(&state.received) {
                    return state.received.clone();
                }
            }
            if Instant::now() >= deadline {
                let kinds: Vec<(usize, String)> = self
                    .received()
                    .iter()
                    .map(|received| (received.link, received.kind().to_owned()))
                    .collect();
                panic!("timed out waiting for {what}; received {kinds:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until `link` has carried at least `count` frames; returns their kinds.
    pub async fn wait_kinds(&self, link: usize, count: usize) -> Vec<String> {
        self.wait_for(&format!("{count} frames on link {link}"), |received| {
            received.iter().filter(|r| r.link == link).count() >= count
        })
        .await;
        self.kinds(link)
    }

    /// Waits until a link has been accepted.
    pub async fn wait_links(&self, count: usize) {
        let deadline = Instant::now() + PATIENCE;
        while self.links() < count {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for link {count}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A fresh stamp from the seed's clock.
    pub fn stamp(&self) -> String {
        lock(&self.hlc).now(self.clock.now_ms())
    }

    /// The stamp `ms:logical:<seed>`.
    pub fn stamp_at(&self, ms: i64, logical: i32) -> String {
        format!("{ms}:{logical}:{}", self.peer_id())
    }

    /// The envelope of a frame from the seed.
    pub fn envelope(&self, kind: &str, body: &[u8], to: Option<&str>, stamp: &str) -> Map {
        envelope::envelope(&self.group, kind, self.peer_id(), stamp, body, to)
    }

    /// A frame signed by the seed with a fresh stamp.
    pub fn frame(&self, kind: &str, body: &[u8], to: Option<&str>) -> Vec<u8> {
        let stamp = self.stamp();
        self.frame_stamped(kind, body, to, &stamp)
    }

    /// A frame signed by the seed with `stamp`.
    pub fn frame_stamped(&self, kind: &str, body: &[u8], to: Option<&str>, stamp: &str) -> Vec<u8> {
        envelope::encode_frame(&self.envelope(kind, body, to, stamp), &self.identity)
    }

    /// Sends raw bytes on `link` (through a relaying seed's ordered queue, when it has one).
    pub async fn send_raw(&self, link: usize, frame: Vec<u8>) {
        let (sender, out) = {
            let state = lock(&self.state);
            let l = state
                .links
                .get(link)
                .unwrap_or_else(|| panic!("no link {link}"));
            (l.sender.clone(), l.out.clone())
        };
        match out {
            Some(out) => out.send(frame).expect("the seed's pump"),
            None => sender.send(frame).await.expect("the seed's send"),
        }
    }

    /// Sends a signed frame with a fresh stamp on `link`.
    pub async fn send(&self, link: usize, kind: &str, body: &[u8], to: Option<&str>) {
        let frame = self.frame(kind, body, to);
        self.send_raw(link, frame).await;
    }

    /// Sends a PING with `nonce` on `link`.
    pub async fn ping(&self, link: usize, nonce: i64, to: Option<&str>) {
        self.send(link, bodies::KIND_PING, &bodies::ping_body(nonce), to)
            .await;
    }

    /// Closes `link` (both ends).
    pub fn close_link(&self, link: usize) {
        if let Some(l) = lock(&self.state).links.get(link) {
            l.closer.close();
        }
    }

    /// Whether `link` has closed.
    pub fn link_closed(&self, link: usize) -> bool {
        lock(&self.state)
            .links
            .get(link)
            .is_some_and(|l| l.closer.is_closed() || l.sender.is_closed())
    }

    /// Stops listening and closes every link.
    pub fn stop(&self) {
        self.network.unlisten(&self.address);
        self.accept.abort();
        for link in &lock(&self.state).links {
            link.closer.close();
        }
    }
}

impl Drop for FakeSeed {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn accept_loop(
    listener: MemoryListener,
    state: Arc<Mutex<State>>,
    reading: bool,
    relay: Option<Arc<Relay>>,
) {
    while let Some(Ok(channel)) = listener.accept().await {
        let Channel {
            attested,
            sender,
            receiver,
            closer,
            ..
        } = channel;
        let out = relay.as_ref().map(|_| {
            let (out, mut queue) = mpsc::unbounded_channel::<Vec<u8>>();
            let pump = sender.clone();
            tokio::spawn(async move {
                while let Some(frame) = queue.recv().await {
                    if pump.send(frame).await.is_err() {
                        return;
                    }
                }
            });
            out
        });
        let index = {
            let mut state = lock(&state);
            state.links.push(SeedLink {
                sender,
                closer,
                out,
            });
            state.links.len() - 1
        };
        if !reading {
            lock(&state).parked.push(receiver);
            continue;
        }
        tokio::spawn(read_loop(
            receiver,
            attested,
            index,
            Arc::clone(&state),
            relay.clone(),
        ));
    }
}

async fn read_loop(
    mut receiver: FrameReceiver,
    attested: Option<String>,
    link: usize,
    state: Arc<Mutex<State>>,
    relay: Option<Arc<Relay>>,
) {
    while let Some(frame) = receiver.recv().await {
        let decoded = envelope::decode_frame_detailed(&frame, attested.as_deref(), None);
        let mut state = lock(&state);
        match decoded {
            Some((env, auth)) => {
                if let Some(relay) = &relay {
                    act_as_relay(relay, &state, link, &env, &frame);
                }
                state.received.push(Received { link, env, auth });
            }
            None => state.malformed += 1,
        }
    }
}

/// A relaying seed's part: a RUMOR is folded (a space's) and forwarded to every other link; a
/// DIGEST naming spaces is answered with their PULL_RESP; a RELAY_FRAME goes on to its target and
/// a frame addressed to another member goes on as is.
fn act_as_relay(relay: &Relay, state: &State, link: usize, env: &Map, frame: &[u8]) {
    let kind = env.get("kind").and_then(Value::as_str).unwrap_or_default();
    let body = env
        .get("body")
        .and_then(Value::as_bytes)
        .unwrap_or_default();
    if let Some(from) = env.get("from").and_then(Value::as_str) {
        lock(&relay.members).insert(from.to_owned(), link);
    }
    let link_of = |peer: &str| lock(&relay.members).get(peer).copied();
    let to = env.get("to").and_then(Value::as_str);
    if let Some(to) = to.filter(|to| *to != relay.identity.peer_id()) {
        if let Some(out) = link_of(to)
            .and_then(|target| state.links.get(target))
            .and_then(|target| target.out.as_ref())
        {
            let _ = out.send(frame.to_vec());
        }
        return;
    }
    match kind {
        bodies::KIND_RELAY_FRAME => {
            let Some(carried) = bodies::parse_relay_frame(body) else {
                return;
            };
            if let Some(out) = link_of(&carried.target)
                .and_then(|target| state.links.get(target))
                .and_then(|target| target.out.as_ref())
            {
                let _ =
                    out.send(relay.frame(bodies::KIND_RELAY_FRAME, body, Some(&carried.target)));
            }
        }
        bodies::KIND_RUMOR => {
            let Some(rumor) = bodies::parse_rumor(body) else {
                return;
            };
            if let Some(space) = rumor.stream_id.strip_prefix(bodies::STREAM_SPACE_PREFIX) {
                relay.fold(space, &rumor.payload);
            }
            for (index, other) in state.links.iter().enumerate() {
                if index == link || other.closer.is_closed() {
                    continue;
                }
                if let Some(out) = &other.out
                    && out
                        .send(relay.frame(bodies::KIND_RUMOR, body, None))
                        .is_ok()
                {
                    *lock(&relay.relayed) += 1;
                }
            }
        }
        bodies::KIND_DIGEST => {
            let Some(digests) = bodies::parse_digest(body) else {
                return;
            };
            let mut deltas = Map::new();
            for stream in digests.keys().filter_map(Value::as_str) {
                if let Some(space) = stream.strip_prefix(bodies::STREAM_SPACE_PREFIX) {
                    deltas.insert(stream, relay.sync(space));
                }
            }
            if deltas.is_empty() {
                return;
            }
            let from = env.get("from").and_then(Value::as_str);
            let frame = relay.frame(
                bodies::KIND_PULL_RESP,
                &bodies::pull_resp_body(&deltas),
                from,
            );
            if let Some(out) = state.links.get(link).and_then(|l| l.out.as_ref()) {
                let _ = out.send(frame);
            }
        }
        _ => {}
    }
}

// ------------------------------------------------------------------------------- raw peers

/// A scripted peer on a link to a listening peer (see the [module docs](self)).
pub struct RawPeer {
    /// Its identity: it signs every frame it sends.
    pub identity: Identity,
    /// The GroupID its frames name.
    pub group: String,
    clock: SharedClock,
    sender: FrameSender,
    closer: Closer,
    hlc: Mutex<Hlc>,
    received: Arc<Mutex<Vec<Map>>>,
    reader: JoinHandle<()>,
}

impl RawPeer {
    /// Dials `address` on `network` as `identity`, for `group`.
    pub async fn dial(
        network: &MemoryNetwork,
        address: &str,
        identity: Identity,
        group: &str,
        clock: SharedClock,
    ) -> RawPeer {
        Self::dial_with(network.dialer(), address, identity, group, clock).await
    }

    /// [`RawPeer::dial`] over a link both ends attest, as `tls` does: the listener sees this
    /// peer attested as `attested_as` (its own PeerID, or another to impersonate), and this peer
    /// sees the listener as `listener`.
    pub async fn dial_attested(
        network: &MemoryNetwork,
        address: &str,
        identity: Identity,
        group: &str,
        clock: SharedClock,
        listener: &str,
        attested_as: &str,
    ) -> RawPeer {
        let mut dialer = network.dialer();
        dialer.attest_as = Some((listener.to_owned(), attested_as.to_owned()));
        Self::dial_with(dialer, address, identity, group, clock).await
    }

    async fn dial_with(
        dialer: agentspaces::transport::memory::MemoryDialer,
        address: &str,
        identity: Identity,
        group: &str,
        clock: SharedClock,
    ) -> RawPeer {
        let seed: Seed = address.parse().expect("an address");
        let channel = dialer
            .dial(&seed, &identity, Duration::from_secs(1))
            .await
            .expect("the raw peer dials");
        let Channel {
            attested,
            sender,
            mut receiver,
            closer,
            ..
        } = channel;
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let reader = tokio::spawn(async move {
            while let Some(frame) = receiver.recv().await {
                if let Some((env, _)) =
                    envelope::decode_frame_detailed(&frame, attested.as_deref(), None)
                {
                    lock(&sink).push(env);
                }
            }
        });
        RawPeer {
            hlc: Mutex::new(Hlc::new(identity.peer_id()).expect("a PeerID is a stamp node")),
            identity,
            group: group.to_owned(),
            clock,
            sender,
            closer,
            received,
            reader,
        }
    }

    /// Its PeerID.
    pub fn peer_id(&self) -> &str {
        self.identity.peer_id()
    }

    /// A frame it signs with a fresh stamp.
    pub fn frame(&self, kind: &str, body: &[u8], to: Option<&str>) -> Vec<u8> {
        let stamp = lock(&self.hlc).now(self.clock.now_ms());
        let env = envelope::envelope(&self.group, kind, self.peer_id(), &stamp, body, to);
        envelope::encode_frame(&env, &self.identity)
    }

    /// Sends raw bytes; whether the link took them.
    pub async fn send_raw(&self, frame: Vec<u8>) -> bool {
        self.sender.send(frame).await.is_ok()
    }

    /// Sends a frame it signs; whether the link took it.
    pub async fn send(&self, kind: &str, body: &[u8], to: Option<&str>) -> bool {
        let frame = self.frame(kind, body, to);
        self.send_raw(frame).await
    }

    /// The `peers` payload of an advertisement `identity` signs for `group` with `hints`, issued
    /// now.
    pub fn signed_ad(&self, identity: &Identity, group: &str, hints: &Map) -> Vec<u8> {
        let now = self.clock.now_ms();
        let issued = agentspaces::wire::time::instant_iso(now.div_euclid(1000) * 1000);
        let ad = wire_ads::peer_advertisement(group, identity, &issued, Some(hints));
        wire_ads::signed_peer_ad(&ad, identity)
    }

    /// Sends a RUMOR on `stream` with `payload`.
    pub async fn rumor(&self, stream: &str, item: &str, payload: &[u8]) -> bool {
        let body = bodies::rumor_body(stream, item, bodies::RUMOR_HOPS, payload);
        self.send(bodies::KIND_RUMOR, &body, None).await
    }

    /// Introduces itself: its own signed advertisement (with `hints`) on the `peers` stream.
    pub async fn introduce(&self, hints: &Map) -> bool {
        let payload = self.signed_ad(&self.identity, &self.group, hints);
        let item = format!("peer:{}:{}", self.peer_id(), self.clock.now_ms());
        self.rumor(bodies::STREAM_PEERS, &item, &payload).await
    }

    /// Every verified frame received so far.
    pub fn received(&self) -> Vec<Map> {
        lock(&self.received).clone()
    }

    /// The verified frames of `kind` received so far.
    pub fn of_kind(&self, kind: &str) -> Vec<Map> {
        self.received()
            .into_iter()
            .filter(|env| env.get("kind").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    /// Waits until `ready` holds over the frames received; panics naming `what` after
    /// [`PATIENCE`].
    pub async fn wait_for(&self, what: &str, ready: impl Fn(&[Map]) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        while !ready(&lock(&self.received)) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Whether its link has closed (either end).
    pub fn is_closed(&self) -> bool {
        self.closer.is_closed() || self.sender.is_closed()
    }

    /// Closes its link.
    pub fn close(&self) {
        self.closer.close();
    }
}

impl Drop for RawPeer {
    fn drop(&mut self) {
        self.closer.close();
        self.reader.abort();
    }
}
