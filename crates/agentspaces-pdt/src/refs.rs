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

//! The ref engine: heads, loading, the common base, the merge, swaps, and the upkeep of the
//! heads this member wrote.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentspaces::content::{Content, ContentError, FetchOptions};
use agentspaces::space::{EntryId, Lease, Space, Template};
use agentspaces::wire::cbor::{self, Value};
use agentspaces::wire::hlc::Stamp;
use agentspaces::wire::limits::{MAX_DRIFT_MILLIS, SKEW_MARGIN_MILLIS};
use agentspaces::wire::pdt::champ::PMap;
use agentspaces::wire::pdt::node;
use agentspaces::wire::pdt::pref::{self, PRef};
use agentspaces::wire::pdt::store::Nodes;
use agentspaces::wire::pdt::value::Slot;
use agentspaces::wire::pdt::vg::VgNode;
use agentspaces::wire::ref_heads::{self, RefVersion};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// The most steps a base walk takes.
const MAX_BASE_STEPS: usize = 64;
/// The live heads of one name read at most.
const MAX_LIVE: usize = 4096;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// How the engine runs.
#[derive(Debug, Clone)]
pub struct PdtConfig {
    /// The space the heads live in (Java `agentspaces.pdt.space`).
    pub space: String,
    /// The most bytes a head carries inline (at most 32 KiB).
    pub inline_delta: usize,
    /// The lease of a head this member writes, renewed at half its length.
    pub head_lease: Duration,
    /// How long a read waits for a head's tree.
    pub load_timeout: Duration,
    /// How long a superseded own head stays before it is withdrawn (two gossip rounds).
    pub cancel_grace: Duration,
}

impl Default for PdtConfig {
    fn default() -> Self {
        PdtConfig {
            space: "pdt".to_string(),
            inline_delta: pref::INLINE_DELTA_BYTES,
            head_lease: Duration::from_secs(10 * 60),
            load_timeout: Duration::from_secs(20),
            cancel_grace: Duration::from_secs(2),
        }
    }
}

/// Why a ref operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PdtError {
    /// The content swarm failed.
    #[error("content swarm: {0}")]
    Content(#[from] ContentError),
    /// A node or value broke a rule, or a node is missing.
    #[error("{0}")]
    Value(#[from] agentspaces::wire::pdt::PdtError),
    /// The ref space refused an operation.
    #[error("ref space: {0}")]
    Space(String),
    /// The ref's heads say `linear`; this engine reads such a ref and writes none.
    #[error("ref {0} is linear; this member reads it and does not swap it")]
    Linear(String),
    /// The ref's heads are of another kind.
    #[error("ref {name} is a {found}, not a {wanted}")]
    Kind {
        /// The ref.
        name: String,
        /// The kind asked for.
        wanted: String,
        /// The kind its heads name.
        found: String,
    },
    /// The swap function or the new head broke a rule.
    #[error("{0}")]
    Invalid(String),
}

/// One version of a ref as a reader keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The root.
    pub root: String,
    /// The roots it was computed from.
    pub base: Vec<String>,
    /// Its seq.
    pub seq: i64,
    /// Entries or bytes.
    pub size: i64,
    /// `multi` or `linear`.
    pub mode: String,
    /// The writer's PeerID, as the merge order reads it.
    pub issuer: String,
    /// The issued stamp's physical part.
    pub physical: i64,
    /// The issued stamp's logical part.
    pub logical: u32,
    /// The entry.
    pub entry_id: String,
    /// The inline delta.
    pub inline: Option<Vec<Vec<u8>>>,
    /// Its `vg` node, from `pdt.ancestry`.
    pub ancestry: Option<String>,
}

impl Head {
    fn version(&self) -> RefVersion {
        RefVersion {
            root: self.root.clone(),
            base: self.base.clone(),
            seq: self.seq,
            issued_physical: self.physical,
            issued_logical: self.logical,
            issuer: self.issuer.clone(),
            entry_id: self.entry_id.clone(),
        }
    }
}

/// What a swap did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swapped {
    /// The new root.
    pub root: String,
    /// The head written, or `None` when the value did not change.
    pub entry: Option<EntryId>,
    /// Its seq.
    pub seq: i64,
    /// Bytes of nodes carried inline.
    pub inline_bytes: usize,
}

/// What a ref counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefStats {
    /// Head entries ignored (undecodable, out of bounds, another ref or kind), each once.
    pub heads_ignored: u64,
    /// Keys a merge settled for the later head, and heads taken whole.
    pub conflicts: u64,
    /// Common bases fetched for a merge.
    pub bases_fetched: u64,
    /// Heads this member wrote.
    pub swaps: u64,
}

struct Own {
    entry: EntryId,
    root: String,
    renewed_at: Instant,
    superseded_at: Option<Instant>,
    displaced: bool,
}

#[derive(Default)]
struct RefState {
    known: HashMap<String, Head>,
    ancestry: HashMap<String, String>,
    chain: HashMap<String, VgNode>,
    ignored: HashSet<String>,
    stats: RefStats,
    own: Vec<Own>,
}

/// The refs of an engine by name: each with its kind and its state.
type RefTable = HashMap<String, (String, Arc<tokio::sync::Mutex<RefState>>)>;

struct Inner {
    content: Content,
    space: Space,
    nodes: Arc<dyn Nodes>,
    config: PdtConfig,
    refs: Mutex<RefTable>,
    /// Wakes the ticker when an own head was written, displaced, or superseded.
    wake: tokio::sync::Notify,
}

/// Persistent data trees over one group's content swarm. Cheap to clone.
#[derive(Clone)]
pub struct Pdt {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Pdt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pdt").field("space", &self.inner.config.space).finish()
    }
}

impl Pdt {
    /// The engine over `content`, its heads in `config.space`.
    pub fn new(content: Content, config: PdtConfig) -> Pdt {
        // SPEC v0.1.36 §9.5: a head lease under the 60 s floor warns. This constructor cannot
        // refuse, so under a strict policy it warns as the lax one does.
        let policy = agentspaces::ttl::TtlPolicy::from_env();
        if agentspaces::ttl::check("pdt.head-lease", config.head_lease, &policy).is_err() {
            let lax = agentspaces::ttl::TtlPolicy { strict: false, ..policy };
            let _ = agentspaces::ttl::check("pdt.head-lease", config.head_lease, &lax);
        }
        let space = content.peer().space(&config.space);
        let nodes = content.nodes().clone();
        Pdt {
            inner: Arc::new(Inner {
                content,
                space,
                nodes,
                config,
                refs: Mutex::new(HashMap::new()),
                wake: tokio::sync::Notify::new(),
            }),
        }
    }

    /// The node store.
    pub fn nodes(&self) -> &Arc<dyn Nodes> {
        &self.inner.nodes
    }

    /// The content swarm.
    pub fn content(&self) -> &Content {
        &self.inner.content
    }

    fn handle(&self, name: &str, kind: &'static str) -> Result<Ref, PdtError> {
        if name.is_empty() || name.len() > pref::MAX_NAME_BYTES {
            return Err(PdtError::Invalid(format!("a ref name is 1 to {} bytes", pref::MAX_NAME_BYTES)));
        }
        let mut refs = self.inner.refs.lock().unwrap_or_else(|e| e.into_inner());
        let (existing, state) = refs
            .entry(name.to_string())
            .or_insert_with(|| (kind.to_string(), Arc::new(tokio::sync::Mutex::new(RefState::default()))));
        if existing != kind {
            return Err(PdtError::Kind { name: name.to_string(), wanted: kind.to_string(), found: existing.clone() });
        }
        Ok(Ref { pdt: self.clone(), name: name.to_string(), kind, state: state.clone() })
    }

    /// A map ref.
    pub fn map_ref(&self, name: &str) -> Result<Ref, PdtError> {
        self.handle(name, pref::KIND_MAP)
    }

    /// A set ref (a map whose every value is null).
    pub fn set_ref(&self, name: &str) -> Result<Ref, PdtError> {
        self.handle(name, pref::KIND_SET)
    }

    /// A tree ref: a map from relative path to `FileEntry` (the Groovy console's `file-share`).
    pub fn tree_ref(&self, name: &str) -> Result<Ref, PdtError> {
        self.handle(name, pref::KIND_TREE)
    }

    /// Renews the heads this member wrote at half their lease and withdraws its superseded heads
    /// after the grace. Call it when [`Pdt::tick_due`] says ([`Pdt::spawn_ticker`] does).
    pub async fn tick(&self) {
        self.tick_due().await;
    }

    /// [`Pdt::tick`], answering when it next has something to do: the earliest renewal (half a
    /// head's lease after its last) or withdrawal (a superseded head's grace); `None` when this
    /// member holds no head.
    pub async fn tick_due(&self) -> Option<Instant> {
        let refs: Vec<Arc<tokio::sync::Mutex<RefState>>> = {
            let refs = self.inner.refs.lock().unwrap_or_else(|e| e.into_inner());
            refs.values().map(|(_, s)| s.clone()).collect()
        };
        let mut due: Option<Instant> = None;
        for state in refs {
            let mut state = state.lock().await;
            if let Some(next) = self.tend_own(&mut state).await {
                due = Some(due.map_or(next, |due| due.min(next)));
            }
        }
        due
    }

    /// A task that runs [`Pdt::tick`] when it next falls due ([`Pdt::tick_due`]), when a head of
    /// this member is written, displaced, or superseded, and at least every `period` (a
    /// backstop), until the engine is dropped everywhere. Due work, not a fixed tick (SPEC v0.1.36
    /// §9.5): an idle member with no heads sleeps the whole `period`.
    pub fn spawn_ticker(&self, period: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let mut wait = Duration::ZERO;
            loop {
                {
                    let Some(inner) = weak.upgrade() else { return };
                    let woken = inner.wake.notified();
                    tokio::pin!(woken);
                    woken.as_mut().enable();
                    tokio::select! {
                        () = tokio::time::sleep(wait) => {}
                        () = &mut woken => {}
                    }
                }
                let Some(inner) = weak.upgrade() else { return };
                let due = Pdt { inner }.tick_due().await;
                wait = due.map_or(period, |due| due.saturating_duration_since(Instant::now()).min(period));
            }
        })
    }

    /// Withdraws this member's displaced and superseded heads and renews the rest at half their
    /// lease; answers when it next has something to do.
    async fn tend_own(&self, state: &mut RefState) -> Option<Instant> {
        let lease = self.inner.config.head_lease;
        let grace = self.inner.config.cancel_grace;
        let mut kept = Vec::new();
        let mut released = Vec::new();
        let mut due: Option<Instant> = None;
        for mut own in std::mem::take(&mut state.own) {
            let withdraw = own.displaced || own.superseded_at.is_some_and(|t| t.elapsed() >= grace);
            if withdraw {
                let _ = self.inner.space.cancel(&own.entry).await;
                released.push(own.root.clone());
                continue;
            }
            if own.renewed_at.elapsed() >= lease / 2 {
                if let Ok(l) = Lease::from_millis(lease.as_millis() as i64) {
                    let _ = self.inner.space.renew_write(&own.entry, l).await;
                }
                own.renewed_at = Instant::now();
            }
            let next = [Some(own.renewed_at + lease / 2), own.superseded_at.map(|t| t + grace)]
                .into_iter()
                .flatten()
                .min();
            if let Some(next) = next {
                due = Some(due.map_or(next, |due| due.min(next)));
            }
            kept.push(own);
        }
        for root in released {
            if !kept.iter().any(|o| o.root == root) {
                let _ = self.inner.content.release_tree(&root).await;
            }
        }
        state.own = kept;
        due
    }
}

/// Whether every node of the tree under `root` is in the store.
fn complete(nodes: &dyn Nodes, root: &str) -> bool {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root.to_string()]);
    while let Some(c) = queue.pop_front() {
        if !seen.insert(c.clone()) {
            continue;
        }
        let Some(bytes) = nodes.get(&c) else { return false };
        match node::links(&bytes, Some(&c)) {
            Ok(links) => queue.extend(links),
            Err(_) => return false,
        }
    }
    true
}

/// Stores the inline nodes a walk from `root` reaches, each verified by its CID.
fn apply_inline(nodes: &dyn Nodes, root: &str, inline: &[Vec<u8>]) {
    let by_digest: HashMap<[u8; 32], &Vec<u8>> =
        inline.iter().map(|d| (agentspaces::wire::pdt::sha256(d), d)).collect();
    let mut seen = HashSet::new();
    let mut frontier = vec![root.to_string()];
    while let Some(c) = frontier.pop() {
        if !seen.insert(c.clone()) {
            continue;
        }
        let bytes = match nodes.get(&c) {
            Some(b) => b.to_vec(),
            None => {
                let Ok(parsed) = agentspaces::wire::pdt::cid::parse(&c) else { continue };
                let Some(data) = by_digest.get(&parsed.digest) else { continue };
                if nodes.put_verified(&c, data).is_err() {
                    continue;
                }
                (*data).clone()
            }
        };
        if let Ok(links) = node::links(&bytes, Some(&c)) {
            frontier.extend(links);
        }
    }
}

/// The (issued, issuer) a head orders by: `pdt.issued`/`pdt.issuer` when acceptable, else the
/// entry's own stamp and issuer (annex H, the advisory head stamp).
fn head_order(issued: &str, issuer: &str, record: &PRef, now: i64) -> (i64, u32, String) {
    let peer_of = |agent: &str| agent.split('/').next().unwrap_or_default().to_string();
    let own = Stamp::parse(issued)
        .map(|s| (s.physical, s.logical.max(0) as u32, peer_of(issuer)))
        .unwrap_or((0, 0, peer_of(issuer)));
    let Some(stamped) = record.attr(pref::ISSUED_ATTR) else { return own };
    let Some(stamp) = Stamp::acceptable(stamped) else { return own };
    if stamp.physical > now + MAX_DRIFT_MILLIS + SKEW_MARGIN_MILLIS {
        return own;
    }
    let attrs = record.attrs.as_deref().unwrap_or(&[]);
    let original_issuer = match attrs.iter().find(|(k, _)| k == pref::ISSUER_ATTR) {
        None => issuer.to_string(),
        Some((_, Value::Text(t))) if agentspaces::wire::ids::parse_agent_id(t).is_some() => t.clone(),
        Some(_) => return own,
    };
    (stamp.physical, stamp.logical.max(0) as u32, peer_of(&original_issuer))
}

/// A handle on one named ref.
#[derive(Clone)]
pub struct Ref {
    pdt: Pdt,
    name: String,
    kind: &'static str,
    state: Arc<tokio::sync::Mutex<RefState>>,
}

impl std::fmt::Debug for Ref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ref").field("name", &self.name).field("kind", &self.kind).finish()
    }
}

enum Base {
    Empty,
    Root(String),
}

impl Ref {
    /// The ref's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the ref counted.
    pub async fn stats(&self) -> RefStats {
        self.state.lock().await.stats.clone()
    }

    fn nodes(&self) -> &dyn Nodes {
        &*self.pdt.inner.nodes
    }

    /// The live heads of the name, each recorded among the known versions.
    async fn live(&self, state: &mut RefState) -> Result<Vec<Head>, PdtError> {
        let template = Template::new(pref::PREF_TYPE).tag_eq(pref::NAME_TAG, &self.name);
        let entries = self
            .pdt
            .inner
            .space
            .read_all(&template, MAX_LIVE)
            .await
            .map_err(|e| PdtError::Space(e.to_string()))?;
        let now = now_ms();
        let mut live = Vec::new();
        let mut ids = HashSet::new();
        for entry in entries {
            if entry.expires_at_millis() <= now {
                continue;
            }
            let id = entry.entry_id().as_str().to_string();
            ids.insert(id.clone());
            let record = PRef::decode(&cbor::encode(entry.payload()));
            let usable = record.as_ref().is_some_and(|r| {
                r.violation().is_none() && r.name == self.name && (r.kind == self.kind || self.compatible(&r.kind))
            });
            let Some(record) = record.filter(|_| usable) else {
                if state.ignored.insert(id) {
                    state.stats.heads_ignored += 1;
                }
                continue;
            };
            if record.v != pref::VERSION {
                // a level-2 head: read by level-2 members alone
                if state.ignored.insert(id) {
                    state.stats.heads_ignored += 1;
                }
                continue;
            }
            let (physical, logical, issuer) = head_order(entry.issued(), entry.issuer(), &record, now);
            let ancestry = record.attr(pref::ANCESTRY_ATTR).map(str::to_string);
            let head = Head {
                root: record.root.clone(),
                base: record.base.clone(),
                seq: record.seq,
                size: record.size,
                mode: record.mode.clone(),
                issuer,
                physical,
                logical,
                entry_id: id,
                inline: record.nodes.clone(),
                ancestry: ancestry.clone(),
            };
            if let Some(vg) = ancestry {
                state.ancestry.entry(head.root.clone()).or_insert(vg);
            }
            know(state, &head);
            live.push(head);
        }
        state.ignored.retain(|id| ids.contains(id));
        Ok(live)
    }

    /// A tree ref and a map ref read the same nodes; a reader of one accepts the other's heads.
    fn compatible(&self, kind: &str) -> bool {
        matches!((self.kind, kind), (pref::KIND_TREE, pref::KIND_MAP) | (pref::KIND_MAP, pref::KIND_TREE))
    }

    /// The heads in merge order, each loaded; a head whose tree cannot load within the load
    /// timeout is left out, and the versions a loaded head supersedes through it with it.
    async fn load_heads(&self, state: &mut RefState) -> Result<Vec<Head>, PdtError> {
        let live = self.live(state).await?;
        let mut fetches = JoinSet::new();
        for head in &live {
            if complete(self.nodes(), &head.root) {
                continue;
            }
            if let Some(inline) = &head.inline {
                apply_inline(self.nodes(), &head.root, inline);
                if complete(self.nodes(), &head.root) {
                    continue;
                }
            }
            let haves: Vec<String> = state
                .known
                .keys()
                .filter(|r| **r != head.root && complete(self.nodes(), r))
                .take(pref::MAX_BASE)
                .cloned()
                .collect();
            let options = FetchOptions {
                haves,
                prefer: vec![head.issuer.clone()],
                timeout: Some(self.pdt.inner.config.load_timeout),
            };
            let (content, root) = (self.pdt.inner.content.clone(), head.root.clone());
            fetches.spawn(async move { content.fetch_tree(&root, options).await });
        }
        while fetches.join_next().await.is_some() {}
        let versions: Vec<RefVersion> = live.iter().map(Head::version).collect();
        let nodes = self.nodes();
        let heads = ref_heads::loaded_heads(&versions, |v| complete(nodes, &v.root));
        Ok(heads
            .into_iter()
            .filter_map(|v| live.iter().find(|h| h.root == v.root && h.entry_id == v.entry_id).cloned())
            .collect())
    }

    /// The heads of the ref, loaded, in merge order (the last is the latest).
    pub async fn heads(&self) -> Result<Vec<Head>, PdtError> {
        let mut state = self.state.lock().await;
        self.load_heads(&mut state).await
    }

    /// The ref's value: the single head's, the merge of several, or the empty map.
    pub async fn deref_map(&self) -> Result<PMap, PdtError> {
        let mut state = self.state.lock().await;
        let heads = self.load_heads(&mut state).await?;
        self.materialize(&mut state, &heads).await
    }

    async fn materialize(&self, state: &mut RefState, heads: &[Head]) -> Result<PMap, PdtError> {
        let nodes = self.nodes();
        match heads {
            [] => Ok(PMap::empty()),
            [one] => Ok(PMap::load(nodes, &one.root)?),
            _ => {
                let latest = &heads[heads.len() - 1];
                let base = match self.common_base(state, heads).await {
                    Some(Base::Empty) => PMap::empty(),
                    Some(Base::Root(root)) => PMap::load(nodes, &root)?,
                    None => {
                        state.stats.conflicts += heads.len() as u64 - 1;
                        return Ok(PMap::load(nodes, &latest.root)?);
                    }
                };
                let mut acc = PMap::load(nodes, &heads[0].root)?;
                for later in &heads[1..] {
                    let theirs = PMap::load(nodes, &later.root)?;
                    acc = merge3(nodes, &acc, &base, &theirs, &mut state.stats.conflicts)?;
                }
                Ok(acc)
            }
        }
    }

    /// The peers a walk asks for `vg` nodes: the heads' writers, then every known version's.
    fn chain_sources(state: &RefState, heads: &[Head]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for issuer in heads.iter().map(|h| &h.issuer).chain(state.known.values().map(|h| &h.issuer)) {
            if !out.contains(issuer) {
                out.push(issuer.clone());
            }
        }
        out
    }

    async fn chain_node(&self, state: &mut RefState, root: &str, sources: &[String]) -> Option<VgNode> {
        if let Some(node) = state.chain.get(root) {
            return Some(node.clone());
        }
        let cid = state.ancestry.get(root)?.clone();
        if self.nodes().get(&cid).is_none() {
            let options = FetchOptions { prefer: sources.to_vec(), timeout: Some(self.pdt.inner.config.load_timeout), ..Default::default() };
            let _ = self.pdt.inner.content.fetch_tree(&cid, options).await;
        }
        let bytes = self.nodes().get(&cid)?;
        match VgNode::decode(&cid, &bytes) {
            Ok(node) if node.root == root => {
                state.chain.insert(root.to_string(), node.clone());
                Some(node)
            }
            _ => {
                // bytes that fail the check: forgotten, so the next walk asks again
                state.ancestry.remove(root);
                None
            }
        }
    }

    async fn bases(&self, state: &mut RefState, root: &str, sources: &[String]) -> Option<Vec<String>> {
        if let Some(version) = state.known.get(root) {
            return Some(version.base.clone());
        }
        self.chain_node(state, root, sources).await.map(|n| n.bases)
    }

    /// Learns which `vg` node describes each base no seen entry describes, from the version's own
    /// `vg` node, which links one per base.
    async fn learn_parents(&self, state: &mut RefState, root: &str, bases: &[String], sources: &[String]) {
        if bases.iter().all(|b| state.known.contains_key(b) || state.ancestry.contains_key(b)) {
            return;
        }
        let Some(child) = self.chain_node(state, root, sources).await else { return };
        for link in &child.parents {
            let Some(bytes) = self.nodes().get(link) else { continue };
            if let Ok(parent) = VgNode::decode(link, &bytes)
                && bases.contains(&parent.root)
            {
                state.ancestry.entry(parent.root.clone()).or_insert_with(|| link.clone());
                state.chain.entry(parent.root.clone()).or_insert(parent);
            }
        }
    }

    /// The roots reachable from `root` over base links, breadth first, and whether the walk
    /// ended at first versions within the step bound.
    async fn walk(&self, state: &mut RefState, root: &str, sources: &[String]) -> (Vec<String>, bool) {
        let mut seen: Vec<String> = Vec::new();
        let mut complete_walk = true;
        let mut frontier = VecDeque::from([(root.to_string(), 0usize)]);
        while let Some((c, depth)) = frontier.pop_front() {
            if seen.contains(&c) {
                continue;
            }
            seen.push(c.clone());
            let Some(bases) = self.bases(state, &c, sources).await else {
                complete_walk = false;
                continue;
            };
            if depth >= MAX_BASE_STEPS {
                complete_walk = complete_walk && bases.is_empty();
                continue;
            }
            self.learn_parents(state, &c, &bases, sources).await;
            for b in bases {
                if !seen.contains(&b) {
                    frontier.push_back((b, depth + 1));
                }
            }
        }
        (seen, complete_walk)
    }

    /// The common base of the heads: the first root on the latest head's walk that every other
    /// walk reaches (fetched when the store lacks it), the empty value when the walks share none
    /// and every walk ends at first versions, else none.
    async fn common_base(&self, state: &mut RefState, heads: &[Head]) -> Option<Base> {
        if heads.iter().all(|h| h.base.is_empty()) {
            return Some(Base::Empty);
        }
        let sources = Self::chain_sources(state, heads);
        let mut walks = Vec::new();
        for h in heads {
            walks.push(self.walk(state, &h.root, &sources).await);
        }
        let (last, others) = walks.split_last()?;
        for candidate in &last.0 {
            if !others.iter().all(|(w, _)| w.contains(candidate)) {
                continue;
            }
            if complete(self.nodes(), candidate) {
                return Some(Base::Root(candidate.clone()));
            }
            let mut issuers: Vec<String> = Vec::new();
            for h in heads {
                if !issuers.contains(&h.issuer) {
                    issuers.push(h.issuer.clone());
                }
            }
            let haves: Vec<String> = heads.iter().map(|h| h.root.clone()).take(pref::MAX_BASE).collect();
            let options = FetchOptions { haves, prefer: issuers, timeout: Some(self.pdt.inner.config.load_timeout) };
            let _ = self.pdt.inner.content.fetch_tree(candidate, options).await;
            if complete(self.nodes(), candidate) {
                state.stats.bases_fetched += 1;
                return Some(Base::Root(candidate.clone()));
            }
            return None;
        }
        walks.iter().all(|(_, c)| *c).then_some(Base::Empty)
    }

    /// Applies `f` to the current value and publishes the result as a new head whose `base`
    /// lists the heads it read. `f` gets the node store and the current map.
    pub async fn swap_map<F>(&self, f: F) -> Result<Swapped, PdtError>
    where
        F: FnOnce(&dyn Nodes, PMap) -> Result<PMap, agentspaces::wire::pdt::PdtError>,
    {
        let mut state = self.state.lock().await;
        let heads = self.load_heads(&mut state).await?;
        if heads.iter().any(|h| h.mode == pref::MODE_LINEAR) {
            return Err(PdtError::Linear(self.name.clone()));
        }
        let current = self.materialize(&mut state, &heads).await?;
        let nodes = self.nodes();
        let next = f(nodes, current)?;
        let (root, written) = next.commit(nodes)?;
        let seq_now = heads.iter().map(|h| h.seq).max().unwrap_or(0);
        if heads.len() == 1 && heads[0].root == root {
            return Ok(Swapped { root, entry: None, seq: seq_now, inline_bytes: 0 });
        }
        let total: usize = written.iter().map(|(_, d)| d.len()).sum();
        let inline: Option<Vec<Vec<u8>>> = if total > 0 && total <= self.pdt.inner.config.inline_delta {
            Some(written.iter().map(|(_, d)| d.to_vec()).collect())
        } else if total == 0 {
            nodes.get(&root).map(|d| vec![d.to_vec()])
        } else {
            None
        };
        let seq = seq_now.min(pref::MAX_SEQ - 1) + 1;
        let base: Vec<String> = heads.iter().map(|h| h.root.clone()).take(pref::MAX_BASE).collect();
        let peer = self.pdt.inner.content.peer().peer_id().to_string();
        let vg = VgNode {
            root: root.clone(),
            bases: base.clone(),
            issuer: format!("{peer}/{}", agentspaces::peer::DEFAULT_AGENT_NAME),
            stamp: format!("{}:0:{peer}", now_ms()),
            parents: base.iter().filter_map(|b| state.ancestry.get(b).cloned()).collect(),
        };
        let vg_bytes = vg.encode()?;
        let vg_cid = agentspaces::wire::pdt::cid::of(&vg_bytes, agentspaces::wire::pdt::cid::DAG_CBOR);
        nodes.put(&vg_cid, &vg_bytes);
        let mut record = PRef::new(&self.name, self.kind, &root, base.clone(), seq, next.count() as i64);
        record.nodes = inline.clone();
        record.set_attr(pref::ANCESTRY_ATTR, &vg_cid);
        if let Some(why) = record.violation() {
            return Err(PdtError::Invalid(format!("every reader would refuse the head: {why}")));
        }
        let lease = Lease::from_millis(self.pdt.inner.config.head_lease.as_millis() as i64)
            .map_err(|e| PdtError::Invalid(e.to_string()))?;
        let entry = self
            .pdt
            .inner
            .space
            .write_value(pref::PREF_TYPE, record.to_value(), lease, record.tags())
            .await
            .map_err(|e| PdtError::Space(e.to_string()))?;
        state.ancestry.insert(root.clone(), vg_cid);
        state.chain.insert(root.clone(), vg);
        let superseded: HashSet<&String> = heads.iter().map(|h| &h.root).collect();
        for own in &mut state.own {
            if own.root == root {
                own.displaced = true;
            } else if superseded.contains(&own.root) && own.superseded_at.is_none() {
                own.superseded_at = Some(Instant::now());
            }
        }
        state.own.push(Own { entry: entry.clone(), root: root.clone(), renewed_at: Instant::now(), superseded_at: None, displaced: false });
        // The ticker withdraws the superseded heads after their grace and renews this one.
        self.pdt.inner.wake.notify_one();
        state.stats.swaps += 1;
        self.pdt.inner.content.hold_tree(&root).await?;
        Ok(Swapped { root, entry: Some(entry), seq, inline_bytes: inline.map_or(0, |n| n.iter().map(Vec::len).sum()) })
    }
}

/// Records a head among the known versions: a later record of a known root keeps the union of
/// the bases, the newer record's first, so every reader's walk meets shared versions in one order.
fn know(state: &mut RefState, head: &Head) {
    match state.known.get(&head.root) {
        None => {
            state.known.insert(head.root.clone(), head.clone());
        }
        Some(known) => {
            let newer = head.seq > known.seq;
            let (first, then) = if newer { (&head.base, &known.base) } else { (&known.base, &head.base) };
            let mut bases: Vec<String> = Vec::new();
            for b in first.iter().chain(then) {
                if !bases.contains(b) {
                    bases.push(b.clone());
                }
            }
            let mut kept = if newer { head.clone() } else { Head { entry_id: head.entry_id.clone(), ..known.clone() } };
            kept.base = bases;
            state.known.insert(head.root.clone(), kept);
        }
    }
}

fn same_outcome(nodes: &dyn Nodes, a: &Option<Slot>, b: &Option<Slot>) -> Result<bool, PdtError> {
    Ok(match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same(y) || x.resolve(nodes)? == y.resolve(nodes)?,
        _ => false,
    })
}

/// The key-wise three-way merge: their changes from `base` applied to `mine`, and a key both
/// sides changed to different outcomes taking theirs (the later head), counted.
fn merge3(nodes: &dyn Nodes, mine: &PMap, base: &PMap, theirs: &PMap, conflicts: &mut u64) -> Result<PMap, PdtError> {
    let my_diff = mine.diff(base, nodes)?;
    let their_diff = theirs.diff(base, nodes)?;
    let mut out = mine.clone();
    for (key, (_, after)) in their_diff {
        if let Some((_, my_after)) = my_diff.get(&key) {
            if same_outcome(nodes, my_after, &after)? {
                continue;
            }
            *conflicts += 1;
        }
        out = match after {
            None => out.dissoc(nodes, &key)?,
            Some(slot) => out.assoc(nodes, &key, &slot.resolve(nodes)?)?,
        };
    }
    Ok(out)
}
