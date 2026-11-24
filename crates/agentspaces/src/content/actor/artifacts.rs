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
//! The piece exchange of the service task: artifacts held (their manifest and holding entries),
//! `PIECE_WANT` and `MANIFEST_WANT` served, and artifact fetches.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::time::Instant;

use tokio::sync::oneshot;

use super::{Actor, short, timeout_for};
use crate::content::pieces::piece_length;
use crate::content::{ContentError, FetchOptions, FetchReport, MANIFEST_TYPE};
use crate::space::{EntryId, Lease, Template};
use crate::wire::cbor;
use crate::wire::content::{self as forms, Holding, Manifest, Message};

/// The first window of requests to one holder.
const FIRST_WINDOW: usize = 2;
/// The largest window.
const MAX_WINDOW: usize = 16;
/// How often a partial holding is written again while pieces arrive.
const HOLDING_EVERY: Duration = Duration::from_secs(2);
/// How often a missing manifest or table is asked for again.
const ASK_AGAIN: Duration = Duration::from_secs(2);
/// How long a holder that answered over its budget sits out.
const BUSY_BENCH: Duration = Duration::from_secs(5);

pub(super) struct HeldArtifact {
    manifest_entry: Option<EntryId>,
    holding_entry: Option<EntryId>,
    lease: Duration,
    holding_renewed: Instant,
    manifest_renewed: Instant,
}

#[derive(Default)]
struct PieceSource {
    have: Option<Vec<bool>>,
    window: usize,
    in_flight: usize,
    srtt_ms: Option<f64>,
    timeouts: u32,
    sit_out_until: Option<Instant>,
    struck: bool,
}

impl PieceSource {
    fn usable(&self, now: Instant) -> bool {
        !self.struck && self.sit_out_until.is_none_or(|t| t <= now)
    }

    fn has(&self, index: usize) -> bool {
        self.have.as_ref().is_none_or(|h| h.get(index).copied().unwrap_or(false))
    }
}

struct PieceRequest {
    to: String,
    index: i64,
    sent: Instant,
    deadline: Instant,
}

pub(super) struct ArtifactFetch {
    root: String,
    manifest: Option<Manifest>,
    table: Option<Vec<u8>>,
    opened: bool,
    prefer: Vec<String>,
    deadline: Option<Instant>,
    reply: Option<oneshot::Sender<Result<FetchReport, ContentError>>>,
    sources: HashMap<String, PieceSource>,
    in_flight: HashMap<i64, PieceRequest>,
    asked_at: Option<Instant>,
    holding: Option<EntryId>,
    holding_at: Option<Instant>,
    report: FetchReport,
    note: String,
}

impl ArtifactFetch {
    pub(super) fn root_is(&self, root: &str) -> bool {
        self.root == root
    }
}

impl Actor {
    pub(super) fn holding_lease(&self) -> Option<Lease> {
        Lease::from_millis(self.config.holding_lease.as_millis() as i64).ok()
    }

    async fn write_artifact_holding(&mut self, holding: &Holding) -> Option<EntryId> {
        let lease = self.holding_lease()?;
        let id = self.space.write_value(forms::HOLDING_TYPE, holding.to_value(), lease, holding.tags()).await.ok()?;
        self.counters.holdings_written += 1;
        Some(id)
    }

    /// Holds a complete artifact: its manifest entry (unless this member wrote one) and a
    /// complete holding, renewed while held.
    pub(super) async fn hold_artifact(&mut self, manifest: Manifest, table: Vec<u8>, lease: Duration) -> Result<(), ContentError> {
        if forms::content_root(&table) != manifest.root {
            return Err(ContentError::Invalid("the table does not hash to the root".into()));
        }
        if self.held_artifacts.contains_key(&manifest.root) {
            return Ok(());
        }
        let mut tags = cbor::Map::new();
        for (k, v) in manifest.attrs.iter().flatten() {
            tags.insert(k.as_str(), v.as_str());
        }
        tags.insert("root", manifest.root.as_str());
        if let Some(name) = &manifest.name {
            tags.insert("name", name.as_str());
        }
        let manifest_lease = Lease::from_millis(lease.as_millis() as i64).map_err(|e| ContentError::Invalid(e.to_string()))?;
        let manifest_entry = self
            .space
            .write_value(MANIFEST_TYPE, manifest.to_value(), manifest_lease, cbor::canonical_map(&tags))
            .await
            .map_err(|e| ContentError::Peer(e.to_string()))
            .ok();
        let holding = Holding {
            v: forms::VERSION,
            root: manifest.root.clone(),
            holder: self.peer.peer_id().to_string(),
            complete: true,
            have: None,
            count: manifest.pieces,
            via: None,
            cost: None,
        };
        let holding_entry = self.write_artifact_holding(&holding).await;
        let now = Instant::now();
        self.held_artifacts.insert(
            manifest.root.clone(),
            HeldArtifact { manifest_entry, holding_entry, lease, holding_renewed: now, manifest_renewed: now },
        );
        Ok(())
    }

    /// When each held artifact's holding (at `holding_half`) and manifest (at half its own lease)
    /// fall due for renewal.
    pub(super) fn artifact_renewals(&self, holding_half: Duration) -> impl Iterator<Item = Instant> + '_ {
        self.held_artifacts.values().flat_map(move |held| {
            [held.holding_renewed + holding_half, held.manifest_renewed + held.lease / 2]
        })
    }

    /// Renews the holdings and manifests of held artifacts at half their leases.
    pub(super) async fn renew_artifacts(&mut self) {
        let half = self.config.holding_lease / 2;
        let roots: Vec<String> = self.held_artifacts.keys().cloned().collect();
        for root in roots {
            let (holding, due_h, manifest, due_m, lease) = {
                let Some(h) = self.held_artifacts.get(&root) else { continue };
                (h.holding_entry.clone(), h.holding_renewed.elapsed() >= half, h.manifest_entry.clone(), h.manifest_renewed.elapsed() >= h.lease / 2, h.lease)
            };
            if due_h && let (Some(id), Some(l)) = (holding, self.holding_lease()) {
                let _ = self.space.renew_write(&id, l).await;
            }
            if due_m && let (Some(id), Ok(l)) = (manifest, Lease::from_millis(lease.as_millis() as i64)) {
                let _ = self.space.renew_write(&id, l).await;
            }
            if let Some(h) = self.held_artifacts.get_mut(&root) {
                if due_h {
                    h.holding_renewed = Instant::now();
                }
                if due_m {
                    h.manifest_renewed = Instant::now();
                }
            }
        }
    }

    /// Withdraws every artifact holding (on close).
    pub(super) async fn release_artifacts(&mut self) {
        let held: Vec<HeldArtifact> = self.held_artifacts.drain().map(|(_, h)| h).collect();
        for h in held {
            if let Some(id) = h.holding_entry {
                let _ = self.space.cancel(&id).await;
            }
        }
    }

    // ------------------------------------------------------------------ serving

    pub(super) async fn serve_piece(&mut self, from: &str, root: &str, index: i64, offset: i64, length: i64, req: i64) {
        let Some(m) = self.shared.manifest(root) else {
            self.reject(from, root, index, forms::REASON_UNKNOWN_ROOT).await;
            return;
        };
        if index < 0 || index >= m.pieces || offset + length > piece_length(&m, index) {
            self.counters.piece_messages_dropped += 1;
            return;
        }
        let in_place = self.shared.in_place.lock().unwrap_or_else(|e| e.into_inner()).get(root).cloned();
        if let Some(place) = &in_place
            && std::fs::metadata(&place.path).map(|meta| meta.len()).ok() != Some(m.size as u64)
        {
            // the file changed under its manifest: no longer served
            self.shared.in_place.lock().unwrap_or_else(|e| e.into_inner()).remove(root);
            self.reject(from, root, index, forms::REASON_NOT_HELD).await;
            return;
        }
        if !self.spend(length as usize) {
            self.reject(from, root, index, forms::REASON_OVER_BUDGET).await;
            return;
        }
        match self.shared.read(root, index, offset, length) {
            Some(bytes) => {
                self.counters.pieces_served += 1;
                self.counters.piece_bytes_served += bytes.len() as u64;
                let message = Message::Piece { root: root.to_string(), index, offset, bytes, req };
                self.send(from, &message).await;
            }
            None => self.reject(from, root, index, forms::REASON_NOT_HELD).await,
        }
    }

    pub(super) async fn serve_manifest(&mut self, from: &str, root: &str) {
        match self.shared.manifest(root) {
            Some(m) => {
                let message = Message::Manifest { root: root.to_string(), record: m.encode() };
                self.send(from, &message).await;
            }
            None => self.reject(from, root, -1, forms::REASON_UNKNOWN_ROOT).await,
        }
    }

    // ------------------------------------------------------------------ fetching

    pub(super) async fn start_artifact(&mut self, root: String, options: FetchOptions, reply: oneshot::Sender<Result<FetchReport, ContentError>>) {
        let fetch = ArtifactFetch {
            report: FetchReport { root: root.clone(), ..Default::default() },
            root,
            manifest: None,
            table: None,
            opened: false,
            prefer: options.prefer,
            deadline: options.timeout.map(|t| Instant::now() + t),
            reply: Some(reply),
            sources: HashMap::new(),
            in_flight: HashMap::new(),
            asked_at: None,
            holding: None,
            holding_at: None,
            note: "starting".into(),
        };
        self.artifact_fetches.push(fetch);
        // the manifests and holdings are entries of the content space: pulled before the first look
        let _ = self.space.pull().await;
        let i = self.artifact_fetches.len() - 1;
        self.drive_artifact(i).await;
    }

    fn finish_artifact(&mut self, i: usize, result: Result<FetchReport, ContentError>) {
        let mut fetch = self.artifact_fetches.swap_remove(i);
        if let Some(reply) = fetch.reply.take() {
            let _ = reply.send(result);
        }
    }

    /// The manifest of `root` the content space holds, checked.
    async fn manifest_from_space(&mut self, root: &str) -> Option<Manifest> {
        let template = Template::new(MANIFEST_TYPE).tag_eq("root", root);
        let entries = self.space.read_all(&template, 16).await.ok()?;
        entries.iter().find_map(|e| {
            let m = Manifest::from_map(e.payload().as_map()?)?;
            (m.root == root && m.violation().is_none()).then_some(m)
        })
    }

    /// The holders the content space names for `root`, with what each holds.
    async fn piece_holders(&mut self, root: &str, pieces: usize) -> Vec<(String, Option<Vec<bool>>)> {
        let template = Template::new(forms::HOLDING_TYPE).tag_eq("root", root);
        let Ok(entries) = self.space.read_all(&template, 256).await else { return Vec::new() };
        let me = self.peer.peer_id().to_string();
        entries
            .iter()
            .filter_map(|e| {
                let h = Holding::from_map(e.payload().as_map()?)?;
                let writer = e.issuer().split('/').next().unwrap_or_default();
                (h.root == root && h.holder == writer && h.holder != me).then(|| {
                    let have = (!h.complete).then(|| forms::decode_have(h.have.as_deref(), pieces));
                    (h.holder, have)
                })
            })
            .collect()
    }

    pub(super) async fn drive_artifact(&mut self, i: usize) {
        let now = Instant::now();
        let root = self.artifact_fetches[i].root.clone();
        // the manifest: the content space, the store (a resumed fetch), else MANIFEST_WANT
        if self.artifact_fetches[i].manifest.is_none() {
            let found = match self.shared.pieces.manifest(&root) {
                Some(m) => Some(m),
                None => self.manifest_from_space(&root).await,
            };
            match found {
                Some(m) => self.artifact_fetches[i].manifest = Some(m),
                None => {
                    if self.artifact_fetches[i].asked_at.is_none_or(|t| t.elapsed() >= ASK_AGAIN) {
                        self.artifact_fetches[i].asked_at = Some(now);
                        let mut targets = self.artifact_fetches[i].prefer.clone();
                        targets.extend(self.piece_holders(&root, 0).await.into_iter().map(|(h, _)| h));
                        targets.sort();
                        targets.dedup();
                        for t in targets {
                            self.send(&t, &Message::ManifestWant { root: root.clone() }).await;
                        }
                        self.artifact_fetches[i].note = "asking for the manifest".into();
                    }
                    return self.artifact_deadline(i, now);
                }
            }
        }
        let Some(m) = self.artifact_fetches[i].manifest.clone() else { return };
        // the table: inline, else its block
        if self.artifact_fetches[i].table.is_none() {
            let table = match (&m.table, &m.table_ref) {
                (Some(t), _) => Some(t.clone()),
                (None, Some(r)) => match self.peer.block(r).await {
                    Some(t) => Some(t),
                    None => {
                        if self.artifact_fetches[i].asked_at.is_none_or(|t| t.elapsed() >= ASK_AGAIN) {
                            self.artifact_fetches[i].asked_at = Some(now);
                            let _ = self.peer.fetch_block(r, Some(&m.origin)).await;
                            self.artifact_fetches[i].note = "asking for the piece table".into();
                        }
                        return self.artifact_deadline(i, now);
                    }
                },
                (None, None) => None,
            };
            match table {
                Some(t) if forms::content_root(&t) == root && t.len() as i64 == m.pieces * forms::HASH_BYTES as i64 => {
                    self.artifact_fetches[i].table = Some(t);
                }
                _ => {
                    self.finish_artifact(i, Err(ContentError::Invalid(format!("the piece table of {root} does not hash to it"))));
                    return;
                }
            }
        }
        if !self.artifact_fetches[i].opened {
            if let Err(e) = self.shared.pieces.open(&m) {
                self.finish_artifact(i, Err(ContentError::Invalid(format!("the piece store: {e}"))));
                return;
            }
            self.artifact_fetches[i].opened = true;
        }
        let have = self.shared.pieces.have(&root);
        if !have.is_empty() && have.iter().all(|h| *h) {
            self.shared.pieces.flush();
            let table = self.artifact_fetches[i].table.clone().unwrap_or_default();
            if let Some(id) = self.artifact_fetches[i].holding.take() {
                let _ = self.space.cancel(&id).await;
            }
            let _ = self.hold_artifact(m, table, crate::content::PublishOptions::default().lease).await;
            let report = self.artifact_fetches[i].report.clone();
            self.finish_artifact(i, Ok(report));
            return;
        }
        // timeouts: the piece goes back, the window halves
        let expired: Vec<i64> = self.artifact_fetches[i].in_flight.iter().filter(|(_, r)| r.deadline <= now).map(|(k, _)| *k).collect();
        for req in expired {
            let fetch = &mut self.artifact_fetches[i];
            if let Some(r) = fetch.in_flight.remove(&req) {
                self.counters.request_timeouts += 1;
                fetch.report.timeouts += 1;
                let s = fetch.sources.entry(r.to.clone()).or_default();
                s.in_flight = s.in_flight.saturating_sub(1);
                s.window = (s.window / 2).max(1);
                s.timeouts += 1;
                if s.timeouts >= 3 {
                    s.timeouts = 0;
                    s.sit_out_until = Some(now + Duration::from_secs(60));
                }
                fetch.note = format!("a piece request to {} timed out", short(&r.to));
            }
        }
        // sources: the preferred members, then the holders the content space names
        let pieces = m.pieces as usize;
        let holders = self.piece_holders(&root, pieces).await;
        {
            let fetch = &mut self.artifact_fetches[i];
            for p in fetch.prefer.clone() {
                fetch.sources.entry(p).or_insert_with(|| PieceSource { window: FIRST_WINDOW, ..Default::default() });
            }
            for (h, have) in holders {
                let s = fetch.sources.entry(h).or_insert_with(|| PieceSource { window: FIRST_WINDOW, ..Default::default() });
                s.have = have;
            }
        }
        self.schedule_pieces(i, &m, &have, now).await;
        self.artifact_deadline(i, now);
    }

    fn artifact_deadline(&mut self, i: usize, now: Instant) {
        if i < self.artifact_fetches.len() && self.artifact_fetches[i].deadline.is_some_and(|d| d <= now) {
            let f = &self.artifact_fetches[i];
            let missing = f.manifest.as_ref().map_or(1, |m| self.shared.pieces.have(&m.root).iter().filter(|h| !**h).count().max(1));
            let error = ContentError::TimedOut { root: f.root.clone(), missing, detail: f.note.clone() };
            self.finish_artifact(i, Err(error));
        }
    }

    /// Sends piece requests: the rarest missing piece first, per holder up to its window; once
    /// every missing piece is asked, the last ones go to a second holder too.
    async fn schedule_pieces(&mut self, i: usize, m: &Manifest, have: &[bool], now: Instant) {
        let root = m.root.clone();
        let missing: Vec<usize> = (0..have.len()).filter(|k| !have[*k]).collect();
        let mut sends: Vec<(String, Message)> = Vec::new();
        {
            let me = self.peer.peer_id().to_string();
            let fetch = &mut self.artifact_fetches[i];
            let asked: HashMap<usize, Vec<String>> = fetch.in_flight.values().fold(HashMap::new(), |mut acc, r| {
                acc.entry(r.index as usize).or_default().push(r.to.clone());
                acc
            });
            let availability: Vec<usize> =
                (0..have.len()).map(|k| fetch.sources.iter().filter(|(_, s)| s.usable(now) && s.has(k)).count()).collect();
            let mut names: Vec<String> =
                fetch.sources.iter().filter(|(n, s)| s.usable(now) && **n != me).map(|(n, _)| n.clone()).collect();
            names.sort_by_key(|n| fetch.sources.get(n).map_or(0, |s| s.in_flight));
            let endgame = missing.iter().all(|k| asked.contains_key(k));
            let mut planned: HashSet<usize> = HashSet::new();
            for name in names {
                while let Some(s) = fetch.sources.get(&name) {
                    if s.in_flight >= s.window.max(1) {
                        break;
                    }
                    let pick = missing
                        .iter()
                        .copied()
                        .filter(|k| s.has(*k) && !planned.contains(k))
                        .filter(|k| match asked.get(k) {
                            None => true,
                            Some(by) => endgame && by.len() < 2 && !by.contains(&name),
                        })
                        .min_by_key(|k| (availability[*k], *k));
                    let Some(k) = pick else { break };
                    planned.insert(k);
                    self.next_req = if self.next_req >= i64::from(i32::MAX) { 1 } else { self.next_req + 1 };
                    let req = self.next_req;
                    let deadline = now + timeout_for(self.config.request_timeout, None).max(Duration::from_millis(
                        s.srtt_ms.map_or(0, |ms| (ms * 8.0) as u64),
                    ));
                    let length = piece_length(m, k as i64);
                    fetch.in_flight.insert(req, PieceRequest { to: name.clone(), index: k as i64, sent: now, deadline });
                    if let Some(s) = fetch.sources.get_mut(&name) {
                        s.in_flight += 1;
                    }
                    fetch.report.requests += 1;
                    sends.push((name.clone(), Message::PieceWant { root: root.clone(), index: k as i64, offset: 0, length, req }));
                }
            }
            if sends.is_empty() && fetch.in_flight.is_empty() {
                fetch.note = "no reachable member holds the missing pieces".into();
            } else if !sends.is_empty() {
                fetch.note = format!("asking {} piece(s)", sends.len());
            }
        }
        for (to, message) in sends {
            self.send(&to, &message).await;
        }
    }

    fn artifact_request(&self, from: &str, req: i64) -> Option<usize> {
        self.artifact_fetches.iter().position(|f| f.in_flight.get(&req).is_some_and(|r| r.to == from))
    }

    pub(super) async fn on_piece(&mut self, from: &str, root: &str, index: i64, offset: i64, bytes: Vec<u8>, req: i64) {
        let Some(i) = self.artifact_request(from, req) else {
            self.counters.piece_messages_dropped += 1;
            return;
        };
        let now = Instant::now();
        let fetch = &mut self.artifact_fetches[i];
        let Some(r) = fetch.in_flight.remove(&req) else { return };
        let s = fetch.sources.entry(from.to_string()).or_default();
        s.in_flight = s.in_flight.saturating_sub(1);
        let (Some(m), Some(table)) = (fetch.manifest.clone(), fetch.table.clone()) else { return };
        let k = index as usize;
        let verified = r.index == index
            && fetch.root == root
            && offset == 0
            && bytes.len() as i64 == piece_length(&m, index)
            && table.get(k * 32..k * 32 + 32).is_some_and(|h| crate::wire::pdt::sha256(&bytes)[..] == *h);
        if !verified {
            s.struck = true;
            self.counters.pieces_refused += 1;
            self.counters.strikes += 1;
            fetch.note = format!("struck {} for a piece that failed its hash", short(from));
            self.drive_artifact(i).await;
            return;
        }
        let rtt = now.duration_since(r.sent).as_secs_f64() * 1000.0;
        s.srtt_ms = Some(s.srtt_ms.map_or(rtt, |v| (v * 7.0 + rtt) / 8.0));
        s.window = (s.window + 1).min(MAX_WINDOW);
        s.timeouts = 0;
        let already = self.shared.pieces.have(root).get(k).copied().unwrap_or(false);
        if !already && self.shared.pieces.write(root, index, &bytes).is_ok() {
            fetch.report.nodes += 1;
            fetch.report.bytes += bytes.len() as u64;
            self.counters.pieces_fetched += 1;
        }
        // the same piece asked of another holder is cancelled
        let duplicates: Vec<(i64, String)> =
            fetch.in_flight.iter().filter(|(_, d)| d.index == index).map(|(q, d)| (*q, d.to.clone())).collect();
        let mut cancels = Vec::new();
        for (q, to) in duplicates {
            fetch.in_flight.remove(&q);
            if let Some(s) = fetch.sources.get_mut(&to) {
                s.in_flight = s.in_flight.saturating_sub(1);
            }
            cancels.push((to, Message::Cancel { root: root.to_string(), index, req: q }));
        }
        for (to, message) in cancels {
            self.send(&to, &message).await;
        }
        self.publish_partial(i).await;
        self.drive_artifact(i).await;
    }

    /// Writes a fresh partial holding at most every few seconds, so the pieces held serve others.
    async fn publish_partial(&mut self, i: usize) {
        let fetch = &self.artifact_fetches[i];
        if fetch.holding_at.is_some_and(|t| t.elapsed() < HOLDING_EVERY) {
            return;
        }
        let have = self.shared.pieces.have(&fetch.root);
        if have.iter().all(|h| *h) {
            return;
        }
        let bits = forms::encode_have(&have);
        if bits.len() > forms::MAX_HAVE_BYTES {
            return;
        }
        let holding = Holding {
            v: forms::VERSION,
            root: fetch.root.clone(),
            holder: self.peer.peer_id().to_string(),
            complete: false,
            have: Some(bits),
            count: have.iter().filter(|h| **h).count() as i64,
            via: None,
            cost: None,
        };
        let old = self.artifact_fetches[i].holding.take();
        let id = self.write_artifact_holding(&holding).await;
        if let Some(old) = old {
            let _ = self.space.cancel(&old).await;
        }
        let fetch = &mut self.artifact_fetches[i];
        fetch.holding = id;
        fetch.holding_at = Some(Instant::now());
    }

    pub(super) fn on_have(&mut self, from: &str, root: &str, have: Option<Vec<u8>>, complete: bool) {
        for fetch in self.artifact_fetches.iter_mut().filter(|f| f.root == root) {
            let pieces = fetch.manifest.as_ref().map_or(0, |m| m.pieces as usize);
            let s = fetch.sources.entry(from.to_string()).or_insert_with(|| PieceSource { window: FIRST_WINDOW, ..Default::default() });
            s.have = if complete { None } else { Some(forms::decode_have(have.as_deref(), pieces)) };
        }
    }

    pub(super) async fn on_manifest(&mut self, root: &str, record: &[u8]) {
        let Some(m) = Manifest::decode(record).filter(|m| m.root == root && m.violation().is_none()) else {
            self.counters.piece_messages_dropped += 1;
            return;
        };
        let waiting: Vec<usize> =
            (0..self.artifact_fetches.len()).filter(|i| self.artifact_fetches[*i].root == root && self.artifact_fetches[*i].manifest.is_none()).collect();
        for i in &waiting {
            self.artifact_fetches[*i].manifest = Some(m.clone());
        }
        if let Some(i) = waiting.first() {
            self.drive_artifact(*i).await;
        }
    }

    pub(super) async fn on_artifact_reject(&mut self, from: &str, root: &str, index: i64, reason: i64) {
        let now = Instant::now();
        let Some(i) = self.artifact_fetches.iter().position(|f| f.root == root) else {
            self.counters.piece_messages_dropped += 1;
            return;
        };
        let fetch = &mut self.artifact_fetches[i];
        let reqs: Vec<i64> = fetch.in_flight.iter().filter(|(_, r)| r.to == from && (index < 0 || r.index == index)).map(|(q, _)| *q).collect();
        for q in reqs {
            fetch.in_flight.remove(&q);
        }
        let s = fetch.sources.entry(from.to_string()).or_default();
        s.in_flight = fetch.in_flight.values().filter(|r| r.to == from).count();
        match reason {
            forms::REASON_NOT_HELD if index >= 0 => {
                let pieces = fetch.manifest.as_ref().map_or(0, |m| m.pieces as usize);
                let have = s.have.get_or_insert_with(|| vec![true; pieces]);
                if let Some(h) = have.get_mut(index as usize) {
                    *h = false;
                }
            }
            forms::REASON_OVER_BUDGET => s.sit_out_until = Some(now + BUSY_BENCH),
            _ => s.sit_out_until = Some(now + Duration::from_secs(60)),
        }
        fetch.note = format!("{} refused (reason {reason})", short(from));
        self.drive_artifact(i).await;
    }

    pub(super) async fn tick_artifacts(&mut self) {
        self.renew_artifacts().await;
        for i in (0..self.artifact_fetches.len()).rev() {
            self.drive_artifact(i).await;
        }
    }

    pub(super) fn close_artifact_fetches(&mut self) {
        for mut f in self.artifact_fetches.drain(..) {
            if let Some(reply) = f.reply.take() {
                let _ = reply.send(Err(ContentError::Closed));
            }
        }
    }
}
