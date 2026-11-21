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

//! The task that owns the content service's state: serving, fetching, holdings, and the
//! advertisement. Everything here runs on one task, so no state is shared.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc, oneshot};

use super::{
    CAPABILITY, Command, ContentConfig, ContentCounters, ContentError, FetchOptions, FetchReport, HOLDING_TYPE,
    TREES_PARAMETER, TREES_VERSION,
};
use crate::peer::{Peer, PeerEvent};
use crate::space::{EntryId, Lease, Space, Template};
use crate::wire::cbor::{self, Map, Value};
use crate::wire::content::{self as forms, Holding, Message};
use crate::wire::pdt::store::Nodes;
use crate::wire::pdt::{cid, node};

/// The bytes a `NODES` carries at most, less room for its framing.
const NODES_BUDGET: usize = forms::MAX_NODES_BYTES - 64 * 1024;
/// Framing counted per node in a `NODES`.
const NODE_FRAMING: usize = 5;
/// `NODE_WANT`s outstanding at once in one fetch.
const MAX_IN_FLIGHT: usize = 4;
/// The first bench of a source that answered a node missing.
const BENCH_BASE: Duration = Duration::from_secs(1);
/// The longest such bench.
const BENCH_MAX: Duration = Duration::from_secs(16);
/// How long a source that timed out three times in a row sits out.
const SIT_OUT: Duration = Duration::from_secs(60);
/// How long a source that refused a request sits out.
const REJECT_BENCH: Duration = Duration::from_secs(5);
/// The budget a `TREE_WANT` asks for.
const TREE_BUDGET: i64 = forms::MAX_TREE_BUDGET;
/// The capability advertisement's lifetime.
const AD_TTL: &str = "PT15M";
/// The most nodes a completeness walk visits.
const WALK_LIMIT: usize = 1_000_000;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The nodes of the tree under `root` that the store lacks (at most `limit`), and how many it
/// holds; refusal of a stored node's bytes counts as missing.
fn walk_missing(nodes: &dyn Nodes, root: &str, limit: usize) -> (Vec<String>, u64) {
    let mut missing = Vec::new();
    let mut held = 0u64;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root.to_string()]);
    while let Some(c) = queue.pop_front() {
        if !seen.insert(c.clone()) || seen.len() > WALK_LIMIT {
            continue;
        }
        match nodes.get(&c) {
            None => {
                missing.push(c);
                if missing.len() >= limit {
                    break;
                }
            }
            Some(bytes) => {
                held += 1;
                if let Ok(links) = node::links(&bytes, Some(&c)) {
                    queue.extend(links);
                }
            }
        }
    }
    (missing, held)
}

/// Every node held under `root` (stopping at missing nodes), at most `cap`.
fn reachable(nodes: &dyn Nodes, root: &str, cap: usize) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root.to_string()]);
    while let Some(c) = queue.pop_front() {
        if seen.len() >= cap || seen.contains(&c) {
            continue;
        }
        let Some(bytes) = nodes.get(&c) else { continue };
        seen.insert(c.clone());
        if let Ok(links) = node::links(&bytes, Some(&c)) {
            queue.extend(links);
        }
    }
    seen
}

/// The CID of node bytes among the CIDs expected, under either codec.
fn match_expected(bytes: &[u8], expected: &HashSet<String>) -> Option<String> {
    let structured = cid::of(bytes, cid::DAG_CBOR);
    if expected.contains(&structured) {
        return Some(structured);
    }
    let raw = cid::of(bytes, cid::RAW);
    expected.contains(&raw).then_some(raw)
}

struct Held {
    entry: Option<EntryId>,
    renewed: Instant,
    count: u64,
}

#[derive(Default)]
struct Source {
    srtt_ms: Option<f64>,
    timeouts: u32,
    sit_out_until: Option<Instant>,
    benched: HashMap<String, (Instant, Duration)>,
    struck: bool,
}

impl Source {
    fn usable(&self, now: Instant) -> bool {
        !self.struck && self.sit_out_until.is_none_or(|t| t <= now)
    }

    fn lacks(&self, c: &str, now: Instant) -> bool {
        self.benched.get(c).is_some_and(|(until, _)| *until > now)
    }

    fn lack(&mut self, c: &str, now: Instant) {
        let next = match self.benched.get(c) {
            Some((_, last)) => (*last * 2).min(BENCH_MAX),
            None => BENCH_BASE,
        };
        // up to half of spread, from the clock's sub-second part
        let spread_ms = (now_ms().unsigned_abs() % 1000) * next.as_millis() as u64 / 2000;
        self.benched.insert(c.to_string(), (now + next + Duration::from_millis(spread_ms), next));
    }
}

enum Kind {
    Tree,
    Nodes(Vec<String>),
}

struct Request {
    to: String,
    kind: Kind,
    sent: Instant,
    deadline: Instant,
    matched: HashSet<String>,
}

struct TreeFetch {
    root: String,
    haves: Vec<String>,
    prefer: Vec<String>,
    deadline: Option<Instant>,
    reply: Option<oneshot::Sender<Result<FetchReport, ContentError>>>,
    expected: HashSet<String>,
    asked: HashSet<String>,
    sources: HashMap<String, Source>,
    outstanding: HashMap<i64, Request>,
    tree_asked: bool,
    report: FetchReport,
    last_missing: usize,
    note: String,
}

pub(super) struct Actor {
    peer: Peer,
    space: Space,
    nodes: Arc<dyn Nodes>,
    config: ContentConfig,
    counters: ContentCounters,
    tree_members: HashSet<String>,
    members_at: Option<Instant>,
    pulled_ads_at: Option<Instant>,
    held: HashMap<String, Held>,
    fetches: Vec<TreeFetch>,
    next_req: i64,
    upload_window: Instant,
    upload_used: u64,
    advertised_at: Instant,
}

impl Actor {
    pub(super) fn new(peer: Peer, nodes: Arc<dyn Nodes>, config: ContentConfig) -> Actor {
        let space = peer.space(&config.space);
        Actor {
            peer,
            space,
            nodes,
            config,
            counters: ContentCounters::default(),
            tree_members: HashSet::new(),
            members_at: None,
            pulled_ads_at: None,
            held: HashMap::new(),
            fetches: Vec::new(),
            next_req: 1,
            upload_window: Instant::now(),
            upload_used: 0,
            advertised_at: Instant::now(),
        }
    }

    /// This peer's content-swarm advertisement, in Java field order.
    fn advertisement(&self) -> Map {
        let group = self.peer.group_id().to_string();
        let me = self.peer.peer_id().to_string();
        let now = now_ms();
        let mut parameters = Map::new();
        parameters.insert("pieceSizes", format!("{}-{}", forms::MIN_PIECE_SIZE, forms::MAX_PIECE_SIZE));
        parameters.insert("sealing", forms::SEALING_NONE);
        parameters.insert("seedMode", "auto");
        parameters.insert(TREES_PARAMETER, TREES_VERSION);
        let mut ad = Map::new();
        ad.insert("id", format!("aspace://{group}/cap/content-swarm/{me}"));
        ad.insert("issuer", me.as_str());
        ad.insert("group", group.as_str());
        ad.insert("issued", crate::wire::time::instant_iso(now - now % 1000));
        ad.insert("ttl", AD_TTL);
        ad.insert("capabilityType", CAPABILITY);
        ad.insert("version", "0.1");
        ad.insert("binding", "pipe");
        ad.insert("parameters", Value::Map(cbor::canonical_map(&parameters)));
        ad.insert("costHints", Value::Map(Map::new()));
        ad
    }

    pub(super) async fn advertise(&self) -> Result<(), ContentError> {
        self.peer.publish_ad(crate::wire::ads::AD_TYPE_CAPABILITY, self.advertisement()).await?;
        Ok(())
    }

    pub(super) async fn run(mut self, mut commands: mpsc::Receiver<Command>, mut events: broadcast::Receiver<PeerEvent>) {
        let mut tick = tokio::time::interval(self.config.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.advertised_at = Instant::now();
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    None => break,
                    Some(Command::Close { reply }) => {
                        self.shutdown().await;
                        let _ = reply.send(());
                        return;
                    }
                    Some(command) => self.command(command).await,
                },
                event = events.recv() => match event {
                    Ok(PeerEvent::Pipe { from, capability, payload }) if capability == CAPABILITY => {
                        self.on_frame(from, payload).await;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = tick.tick() => self.on_tick().await,
            }
        }
        self.shutdown().await;
    }

    async fn shutdown(&mut self) {
        for fetch in self.fetches.drain(..) {
            if let Some(reply) = fetch.reply {
                let _ = reply.send(Err(ContentError::Closed));
            }
        }
        let held: Vec<String> = self.held.keys().cloned().collect();
        for root in held {
            self.release(&root).await;
        }
    }

    async fn command(&mut self, command: Command) {
        match command {
            Command::HoldTree { root, reply } => {
                let _ = reply.send(self.hold(&root).await);
            }
            Command::ReleaseTree { root, reply } => {
                self.release(&root).await;
                let _ = reply.send(());
            }
            Command::FetchTree { root, options, reply } => self.start_fetch(root, options, reply).await,
            Command::Holders { root, reply } => {
                let _ = reply.send(self.holders(&root).await);
            }
            Command::TreeMembers { reply } => {
                self.refresh_members(true).await;
                let mut members: Vec<String> = self.tree_members.iter().cloned().collect();
                members.sort();
                let _ = reply.send(members);
            }
            Command::Counters { reply } => {
                let _ = reply.send(self.counters.clone());
            }
            Command::Close { .. } => {}
        }
    }

    // ------------------------------------------------------------------ members and holdings

    async fn refresh_members(&mut self, force: bool) {
        if !force && self.members_at.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return;
        }
        self.members_at = Some(Instant::now());
        // a member that joined after an advertisement went out learns it by asking
        if self.pulled_ads_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(2)) {
            self.pulled_ads_at = Some(Instant::now());
            let _ = self.peer.pull_ads().await;
        }
        let ads = self.peer.ads(crate::wire::ads::AD_TYPE_CAPABILITY).await;
        self.tree_members = ads
            .iter()
            .filter(|ad| ad.get("capabilityType").and_then(Value::as_str) == Some(CAPABILITY))
            .filter(|ad| {
                ad.get("parameters").and_then(|p| p.get(TREES_PARAMETER)).and_then(Value::as_str) == Some(TREES_VERSION)
            })
            .filter_map(|ad| ad.get("issuer").and_then(Value::as_str).map(str::to_string))
            .filter(|issuer| issuer != self.peer.peer_id())
            .collect();
    }

    async fn is_tree_member(&mut self, peer: &str) -> bool {
        if self.tree_members.contains(peer) {
            return true;
        }
        self.refresh_members(true).await;
        self.tree_members.contains(peer)
    }

    async fn holders(&mut self, root: &str) -> Vec<String> {
        let template = Template::new(HOLDING_TYPE).tag_eq("root", root);
        let Ok(entries) = self.space.read_all(&template, 256).await else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries {
            let Some(map) = entry.payload().as_map() else { continue };
            let Some(holding) = Holding::from_map(map) else { continue };
            // a holding names its own writer, so no member can name another as a holder
            let writer = entry.issuer().split('/').next().unwrap_or_default();
            if holding.root == root && holding.holder == writer && holding.complete && !out.contains(&holding.holder) {
                out.push(holding.holder);
            }
        }
        out
    }

    async fn write_holding(&mut self, root: &str, count: u64) -> Result<EntryId, ContentError> {
        let holding = Holding::complete_tree(root, self.peer.peer_id(), count as i64, None);
        let lease = Lease::from_millis(self.config.holding_lease.as_millis() as i64)
            .map_err(|e| ContentError::Invalid(e.to_string()))?;
        let id = self
            .space
            .write_value(HOLDING_TYPE, holding.to_value(), lease, holding.tags())
            .await
            .map_err(|e| ContentError::Peer(e.to_string()))?;
        self.counters.holdings_written += 1;
        Ok(id)
    }

    async fn hold(&mut self, root: &str) -> Result<(), ContentError> {
        cid::parse(root).map_err(|e| ContentError::Invalid(e.to_string()))?;
        let (missing, count) = walk_missing(&*self.nodes, root, 1);
        if !missing.is_empty() {
            return Err(ContentError::Incomplete(root.to_string()));
        }
        if self.held.contains_key(root) {
            return Ok(());
        }
        let entry = self.write_holding(root, count).await?;
        self.held.insert(root.to_string(), Held { entry: Some(entry), renewed: Instant::now(), count });
        Ok(())
    }

    async fn release(&mut self, root: &str) {
        if let Some(held) = self.held.remove(root)
            && let Some(entry) = held.entry
        {
            let _ = self.space.cancel(&entry).await;
        }
    }

    async fn renew_holdings(&mut self) {
        let half = self.config.holding_lease / 2;
        let due: Vec<String> =
            self.held.iter().filter(|(_, h)| h.renewed.elapsed() >= half).map(|(r, _)| r.clone()).collect();
        for root in due {
            let Some(held) = self.held.get(&root) else { continue };
            let (entry, count) = (held.entry.clone(), held.count);
            let renewed = match &entry {
                Some(id) => {
                    let lease = Lease::from_millis(self.config.holding_lease.as_millis() as i64).ok();
                    match lease {
                        Some(lease) => self.space.renew_write(id, lease).await.is_ok(),
                        None => false,
                    }
                }
                None => false,
            };
            let entry = if renewed {
                self.counters.holdings_written += 1;
                entry
            } else {
                self.write_holding(&root, count).await.ok()
            };
            if let Some(held) = self.held.get_mut(&root) {
                held.entry = entry;
                held.renewed = Instant::now();
            }
        }
    }

    async fn on_tick(&mut self) {
        if self.advertised_at.elapsed() >= self.config.advertise_every {
            self.advertised_at = Instant::now();
            let _ = self.advertise().await;
        }
        self.renew_holdings().await;
        if !self.fetches.is_empty() {
            self.refresh_members(false).await;
            for i in (0..self.fetches.len()).rev() {
                self.drive(i).await;
            }
        }
    }

    // ------------------------------------------------------------------ frames

    async fn send(&mut self, to: &str, message: &Message) {
        let _ = self.peer.send_pipe(to, CAPABILITY, &message.encode()).await;
    }

    async fn reject(&mut self, to: &str, root: &str, index: i64, reason: i64) {
        self.counters.rejects_sent += 1;
        let message = Message::Reject { root: root.to_string(), index, reason };
        self.send(to, &message).await;
    }

    async fn on_frame(&mut self, from: String, payload: Vec<u8>) {
        let message = match forms::decode(&payload) {
            Ok(message) => message,
            Err(dropped) => {
                if dropped.is_piece_message() {
                    self.counters.piece_messages_dropped += 1;
                } else {
                    self.counters.tree_messages_dropped += 1;
                }
                return;
            }
        };
        match message {
            Message::PieceWant { root, index, .. } => {
                self.counters.piece_messages_dropped += 1;
                self.reject(&from, &root, index, forms::REASON_UNKNOWN_ROOT).await;
            }
            Message::ManifestWant { root } => {
                self.counters.piece_messages_dropped += 1;
                self.reject(&from, &root, -1, forms::REASON_UNKNOWN_ROOT).await;
            }
            Message::Piece { .. } | Message::Have { .. } | Message::Cancel { .. } | Message::Manifest { .. } => {
                self.counters.piece_messages_dropped += 1;
            }
            Message::NodeWant { req, cids } => {
                if !self.is_tree_member(&from).await {
                    self.counters.tree_messages_dropped += 1;
                    return;
                }
                self.serve_nodes(&from, req, &cids).await;
            }
            Message::TreeWant { req, root, haves, budget } => {
                if !self.is_tree_member(&from).await {
                    self.counters.tree_messages_dropped += 1;
                    return;
                }
                self.serve_tree(&from, req, &root, haves.unwrap_or_default(), budget).await;
            }
            Message::Nodes { req, nodes, sealed, missing, .. } => {
                if sealed.is_some() {
                    // a group-key answer this keyless peer cannot open: released without a strike
                    self.counters.tree_messages_dropped += 1;
                    self.release_request(&from, req, true);
                    return;
                }
                self.on_nodes(&from, req, nodes.unwrap_or_default(), missing).await;
            }
            Message::TreeEnd { req, frontier, .. } => self.on_tree_end(&from, req, frontier).await,
            Message::Reject { root, index, .. } => {
                if index == -1 {
                    self.on_reject(&from, &root).await;
                } else {
                    self.counters.piece_messages_dropped += 1;
                }
            }
        }
    }

    // ------------------------------------------------------------------ serving

    fn spend(&mut self, bytes: usize) -> bool {
        if self.upload_window.elapsed() >= Duration::from_secs(1) {
            self.upload_window = Instant::now();
            self.upload_used = 0;
        }
        if self.upload_used > 0 && self.upload_used + bytes as u64 > self.config.upload_bytes_per_second {
            return false;
        }
        self.upload_used += bytes as u64;
        true
    }

    /// Sends `found` packed under the `NODES` bound, `missing` on the last message.
    async fn packed(&mut self, to: &str, req: i64, found: Vec<Arc<[u8]>>, missing: Option<Vec<String>>) {
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut size = 0usize;
        for data in found {
            if !batch.is_empty() && size + data.len() + NODE_FRAMING > NODES_BUDGET {
                let message = Message::Nodes { req, nodes: Some(std::mem::take(&mut batch)), sealed: None, epoch: None, missing: None };
                self.send(to, &message).await;
                size = 0;
            }
            size += data.len() + NODE_FRAMING;
            self.counters.nodes_served += 1;
            self.counters.bytes_served += data.len() as u64;
            batch.push(data.to_vec());
        }
        let message = Message::Nodes { req, nodes: Some(batch), sealed: None, epoch: None, missing };
        self.send(to, &message).await;
    }

    async fn serve_nodes(&mut self, from: &str, req: i64, cids: &[String]) {
        self.counters.tree_wants_served += 1;
        let mut found = Vec::new();
        let mut missing = Vec::new();
        let mut bytes = 0usize;
        for c in cids {
            match self.nodes.get(c) {
                Some(data) => {
                    bytes += data.len();
                    found.push(data);
                }
                None => missing.push(c.clone()),
            }
        }
        if !self.spend(bytes) {
            let first = cids.first().cloned().unwrap_or_default();
            self.reject(from, &first, -1, forms::REASON_OVER_BUDGET).await;
            return;
        }
        let missing = (!missing.is_empty()).then_some(missing);
        self.packed(from, req, found, missing).await;
    }

    async fn serve_tree(&mut self, from: &str, req: i64, root: &str, haves: Vec<String>, budget: i64) {
        self.counters.tree_wants_served += 1;
        if !self.nodes.has(root) {
            self.reject(from, root, -1, forms::REASON_NOT_HELD).await;
            return;
        }
        let haves: Vec<String> = haves.into_iter().filter(|h| h != root).collect();
        let mut prune = HashSet::new();
        let mut walked = 0usize;
        let mut held_haves = 0;
        for h in &haves {
            if !self.nodes.has(h) {
                continue;
            }
            held_haves += 1;
            let reach = reachable(&*self.nodes, h, forms::MAX_TREE_WALK - walked);
            walked += reach.len();
            prune.extend(reach);
            if walked >= forms::MAX_TREE_WALK {
                break;
            }
        }
        let two_levels = !haves.is_empty() && held_haves == 0;
        let budget = budget.max(0) as usize;
        let mut sent = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::from([(root.to_string(), 0)]);
        let mut frontier = Vec::new();
        let mut found = Vec::new();
        let mut spent = 0usize;
        let mut reason = forms::END_DONE;
        while let Some((c, level)) = queue.pop_front() {
            if prune.contains(&c) || sent.contains(&c) {
                continue;
            }
            if two_levels && level > 1 {
                frontier.push(c);
                continue;
            }
            let Some(data) = self.nodes.get(&c) else { continue };
            if !sent.is_empty() && spent + data.len() > budget {
                reason = forms::END_BUDGET;
                queue.push_front((c, level));
                break;
            }
            if walked >= forms::MAX_TREE_WALK {
                reason = forms::END_WALK_CAP;
                queue.push_front((c, level));
                break;
            }
            if let Ok(links) = node::links(&data, Some(&c)) {
                for link in links {
                    if !prune.contains(&link) && !sent.contains(&link) {
                        queue.push_back((link, level + 1));
                    }
                }
            }
            sent.insert(c);
            spent += data.len();
            walked += 1;
            found.push(data);
        }
        if two_levels && reason == forms::END_DONE {
            reason = forms::END_HAVES_NOT_HELD;
        }
        if !self.spend(spent) {
            self.reject(from, root, -1, forms::REASON_OVER_BUDGET).await;
            return;
        }
        self.packed(from, req, found, None).await;
        let mut rest: Vec<String> = Vec::new();
        let mut listed = HashSet::new();
        for c in frontier.into_iter().chain(queue.into_iter().map(|(c, _)| c)) {
            if !sent.contains(&c) && !prune.contains(&c) && listed.insert(c.clone()) {
                rest.push(c);
            }
            if rest.len() >= forms::MAX_FRONTIER {
                break;
            }
        }
        let end = Message::TreeEnd { req, frontier: rest, reason };
        self.send(from, &end).await;
    }

    // ------------------------------------------------------------------ fetching

    async fn start_fetch(&mut self, root: String, options: FetchOptions, reply: oneshot::Sender<Result<FetchReport, ContentError>>) {
        let mut haves = options.haves;
        haves.truncate(forms::MAX_HAVES);
        let fetch = TreeFetch {
            expected: HashSet::from([root.clone()]),
            report: FetchReport { root: root.clone(), ..Default::default() },
            root,
            haves,
            prefer: options.prefer,
            deadline: options.timeout.map(|t| Instant::now() + t),
            reply: Some(reply),
            asked: HashSet::new(),
            sources: HashMap::new(),
            outstanding: HashMap::new(),
            tree_asked: false,
            last_missing: 0,
            note: "starting".to_string(),
        };
        self.fetches.push(fetch);
        self.refresh_members(true).await;
        let i = self.fetches.len() - 1;
        self.drive(i).await;
    }

    fn finish(&mut self, i: usize, result: Result<FetchReport, ContentError>) {
        let mut fetch = self.fetches.swap_remove(i);
        if let Some(reply) = fetch.reply.take() {
            let _ = reply.send(result);
        }
    }


    /// Advances fetch `i`: completion, timeouts, sources, and new requests.
    async fn drive(&mut self, i: usize) {
        let now = Instant::now();
        // timeouts
        let expired: Vec<i64> = self.fetches[i]
            .outstanding
            .iter()
            .filter(|(_, r)| r.deadline <= now)
            .map(|(req, _)| *req)
            .collect();
        for req in expired {
            let fetch = &mut self.fetches[i];
            if let Some(r) = fetch.outstanding.remove(&req) {
                self.counters.request_timeouts += 1;
                fetch.report.timeouts += 1;
                if let Kind::Nodes(cids) = &r.kind {
                    for c in cids {
                        if !r.matched.contains(c) {
                            fetch.asked.remove(c);
                        }
                    }
                }
                let source = fetch.sources.entry(r.to.clone()).or_default();
                source.timeouts += 1;
                if source.timeouts >= 3 {
                    source.timeouts = 0;
                    source.sit_out_until = Some(now + SIT_OUT);
                }
                fetch.note = format!("a request to {} timed out", short(&r.to));
            }
        }
        // completion
        let (missing, _) = walk_missing(&*self.nodes, &self.fetches[i].root, 4096);
        self.fetches[i].last_missing = missing.len();
        if missing.is_empty() {
            let report = self.fetches[i].report.clone();
            self.finish(i, Ok(report));
            return;
        }
        if self.fetches[i].deadline.is_some_and(|d| d <= now) {
            let fetch = &self.fetches[i];
            let error = ContentError::TimedOut {
                root: fetch.root.clone(),
                missing: missing.len(),
                detail: fetch.note.clone(),
            };
            self.finish(i, Err(error));
            return;
        }
        // sources: the preferred members, then the holders the content space names
        let mut candidates = self.fetches[i].prefer.clone();
        let root = self.fetches[i].root.clone();
        for holder in self.holders(&root).await {
            if !candidates.contains(&holder) {
                candidates.push(holder);
            }
        }
        let me = self.peer.peer_id().to_string();
        let ranked: Vec<String> = candidates
            .into_iter()
            .filter(|c| *c != me && self.tree_members.contains(c))
            .filter(|c| self.fetches[i].sources.get(c).is_none_or(|s| s.usable(now)))
            .collect();
        if ranked.is_empty() {
            self.fetches[i].note = "no member that holds the tree and serves trees is reachable".to_string();
            return;
        }
        // the first request: the whole tree from the best source
        if !self.fetches[i].tree_asked && !self.nodes.has(&root) && self.fetches[i].outstanding.is_empty() {
            let to = ranked[0].clone();
            let req = self.next_req();
            let fetch = &mut self.fetches[i];
            fetch.tree_asked = true;
            let haves = (!fetch.haves.is_empty()).then(|| fetch.haves.clone());
            let message = Message::TreeWant { req, root: root.clone(), haves, budget: TREE_BUDGET };
            let deadline = now + timeout_for(self.config.request_timeout, fetch.sources.get(&to));
            let fetch = &mut self.fetches[i];
            fetch.outstanding.insert(req, Request { to: to.clone(), kind: Kind::Tree, sent: now, deadline, matched: HashSet::new() });
            fetch.report.requests += 1;
            fetch.note = format!("asked {} for the tree", short(&to));
            self.send(&to, &message).await;
            return;
        }
        // then what is still missing, by NODE_WANT, spread over the sources
        if self.fetches[i].outstanding.values().any(|r| matches!(r.kind, Kind::Tree)) {
            return;
        }
        let mut queue: VecDeque<String> = missing.into_iter().filter(|c| !self.fetches[i].asked.contains(c)).collect();
        let mut next_source = 0usize;
        let mut attempts = 0usize;
        while !queue.is_empty() && self.fetches[i].outstanding.len() < MAX_IN_FLIGHT && attempts < ranked.len() * 2 {
            attempts += 1;
            let to = ranked[next_source % ranked.len()].clone();
            next_source += 1;
            let mut batch = Vec::new();
            let mut skipped = VecDeque::new();
            while let Some(c) = queue.pop_front() {
                if self.fetches[i].sources.get(&to).is_some_and(|s| s.lacks(&c, now)) {
                    skipped.push_back(c);
                    continue;
                }
                batch.push(c);
                if batch.len() >= forms::MAX_WANT_CIDS {
                    break;
                }
            }
            queue.extend(skipped);
            if batch.is_empty() {
                continue;
            }
            let req = self.next_req();
            let deadline = now + timeout_for(self.config.request_timeout, self.fetches[i].sources.get(&to));
            let fetch = &mut self.fetches[i];
            for c in &batch {
                fetch.asked.insert(c.clone());
                fetch.expected.insert(c.clone());
            }
            fetch.report.requests += 1;
            fetch.note = format!("asked {} for {} node(s)", short(&to), batch.len());
            let message = Message::NodeWant { req, cids: batch.clone() };
            fetch.outstanding.insert(req, Request { to: to.clone(), kind: Kind::Nodes(batch), sent: now, deadline, matched: HashSet::new() });
            self.send(&to, &message).await;
        }
    }

    fn next_req(&mut self) -> i64 {
        let req = self.next_req;
        self.next_req = if self.next_req >= i64::from(i32::MAX) { 1 } else { self.next_req + 1 };
        req
    }

    fn find_request(&self, from: &str, req: i64) -> Option<usize> {
        self.fetches.iter().position(|f| f.outstanding.get(&req).is_some_and(|r| r.to == from))
    }

    fn release_request(&mut self, from: &str, req: i64, back_off: bool) {
        if let Some(i) = self.find_request(from, req) {
            let fetch = &mut self.fetches[i];
            if let Some(r) = fetch.outstanding.remove(&req) {
                if let Kind::Nodes(cids) = &r.kind {
                    for c in cids {
                        fetch.asked.remove(c);
                    }
                }
                if back_off {
                    fetch.sources.entry(from.to_string()).or_default().sit_out_until = Some(Instant::now() + SIT_OUT);
                }
            }
        }
    }

    async fn on_nodes(&mut self, from: &str, req: i64, nodes: Vec<Vec<u8>>, missing: Option<Vec<String>>) {
        let Some(i) = self.find_request(from, req) else {
            self.counters.tree_messages_dropped += 1;
            self.counters.nodes_refused += nodes.len() as u64;
            return;
        };
        let now = Instant::now();
        let mut struck = false;
        {
            let fetch = &mut self.fetches[i];
            let sent = fetch.outstanding.get(&req).map(|r| r.sent).unwrap_or(now);
            let rtt = now.duration_since(sent).as_secs_f64() * 1000.0;
            let source = fetch.sources.entry(from.to_string()).or_default();
            source.srtt_ms = Some(source.srtt_ms.map_or(rtt, |s| (s * 7.0 + rtt) / 8.0));
            source.timeouts = 0;
            for data in nodes {
                let Some(c) = match_expected(&data, &fetch.expected) else {
                    struck = true;
                    break;
                };
                if self.nodes.put(&c, &data) {
                    fetch.report.nodes += 1;
                    fetch.report.bytes += data.len() as u64;
                    self.counters.nodes_fetched += 1;
                }
                if let Ok(links) = node::links(&data, Some(&c)) {
                    fetch.expected.extend(links);
                }
                if let Some(r) = fetch.outstanding.get_mut(&req) {
                    r.matched.insert(c);
                }
            }
        }
        if struck {
            self.counters.strikes += 1;
            self.counters.nodes_refused += 1;
            let fetch = &mut self.fetches[i];
            fetch.sources.entry(from.to_string()).or_default().struck = true;
            fetch.note = format!("struck {} for a node that matched nothing asked", short(from));
            self.release_request(from, req, false);
            self.drive(i).await;
            return;
        }
        let fetch = &mut self.fetches[i];
        let done = match fetch.outstanding.get(&req) {
            Some(Request { kind: Kind::Nodes(cids), matched, .. }) => missing.is_some() || matched.len() >= cids.len(),
            _ => false,
        };
        if done && let Some(r) = fetch.outstanding.remove(&req)
            && let Kind::Nodes(cids) = &r.kind
        {
            let source = fetch.sources.entry(from.to_string()).or_default();
            for c in missing.iter().flatten() {
                if cids.contains(c) && !r.matched.contains(c) {
                    source.lack(c, now);
                }
            }
            for c in cids {
                if !r.matched.contains(c) {
                    fetch.asked.remove(c);
                }
            }
        }
        if done {
            self.drive(i).await;
        }
    }

    async fn on_tree_end(&mut self, from: &str, req: i64, frontier: Vec<String>) {
        let Some(i) = self.find_request(from, req) else {
            self.counters.tree_messages_dropped += 1;
            return;
        };
        let fetch = &mut self.fetches[i];
        fetch.outstanding.remove(&req);
        fetch.expected.extend(frontier);
        self.drive(i).await;
    }

    async fn on_reject(&mut self, from: &str, root: &str) {
        let positions: Vec<i64> = self
            .fetches
            .iter()
            .flat_map(|f| {
                f.outstanding.iter().filter(|(_, r)| {
                    r.to == from
                        && match &r.kind {
                            Kind::Tree => f.root == root,
                            Kind::Nodes(cids) => cids.first().is_some_and(|c| c == root),
                        }
                })
            })
            .map(|(req, _)| *req)
            .collect();
        if positions.is_empty() {
            self.counters.tree_messages_dropped += 1;
            return;
        }
        for req in positions {
            if let Some(i) = self.find_request(from, req) {
                self.release_request(from, req, false);
                // a refusal benches the source a while: it may not hold the root yet
                self.fetches[i].sources.entry(from.to_string()).or_default().sit_out_until =
                    Some(Instant::now() + REJECT_BENCH);
                self.fetches[i].note = format!("{} refused the request", short(from));
                self.drive(i).await;
            }
        }
    }
}

/// How long a request to `source` waits: the configured timeout or eight round trips.
fn timeout_for(base: Duration, source: Option<&Source>) -> Duration {
    let rtt = source.and_then(|s| s.srtt_ms).map(|ms| Duration::from_millis((ms * 8.0) as u64)).unwrap_or_default();
    base.max(rtt)
}

fn short(peer: &str) -> &str {
    &peer[..peer.len().min(10)]
}
