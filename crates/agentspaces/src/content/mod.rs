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

//! The content swarm, `aspace:cap/content-swarm` (SPEC §7.1, §8, annexes G and H), as a
//! service over a running [`Peer`].
//!
//! [`Content::start`] spawns one task that owns the service's state. It advertises the
//! capability with `trees` = `"1"`, answers the tree messages (`NODE_WANT`, `TREE_WANT`) from
//! its node store, keeps one leased `Holding` entry per tree root it holds in the group's content
//! space, and runs tree fetches: a `TREE_WANT` to a holder first, then `NODE_WANT`s for what is
//! still missing, every node verified against the CID asked for or a link of a node already
//! verified. A fetch waits on other members the way SPEC §9.4 states: a request times out after
//! the larger of the request timeout and eight round trips, only the undelivered part is asked
//! again, a `missing` answer benches that source for that node (1 s doubling to 16 s, with up to
//! half of spread), and a source that times out three times sits out a minute. A fetch with a
//! living holder never gives up on its own; the caller may bound it.
//!
//! Tree messages go only to members whose current content-swarm advertisement carries `trees`,
//! and a message from any member is dropped and counted when it breaks its schema or a bound,
//! with no strike.
//!
//! Artifacts move by the piece exchange (annex G): [`Content::publish_file`] hashes a file into
//! fixed-size pieces, writes its `Manifest` entry (the table inline up to 64 pieces, else as a
//! block) and a complete `Holding`, and serves `PIECE_WANT` and `MANIFEST_WANT` from a
//! [`PieceStore`] or, published in place, from the file itself. [`Content::fetch_artifact`]
//! reads the manifest (from the content space, else by `MANIFEST_WANT`), asks the rarest
//! missing piece first among the holders, keeps a window of requests per holder that grows by
//! one on success and halves on a timeout, asks the last pieces of several holders and cancels
//! the duplicates, verifies every piece against the table, strikes a holder whose piece fails,
//! and publishes a partial holding as it goes, so it serves what it has.

mod actor;
pub mod pieces;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::peer::{Peer, PeerError};
use crate::wire::content::Manifest;
use crate::wire::pdt::store::Nodes;
pub use pieces::{FilePieces, InPlace, MemoryPieces, PieceStore};

pub use crate::wire::content::{CAPABILITY, HOLDING_TYPE, MANIFEST_TYPE};

/// The parameter that says a member holds and serves persistent trees.
pub const TREES_PARAMETER: &str = "trees";
/// Its value.
pub const TREES_VERSION: &str = "1";
/// The default content space.
pub const DEFAULT_SPACE: &str = "content";

/// How the service runs.
#[derive(Debug, Clone)]
pub struct ContentConfig {
    /// The group's content space, where manifests and holdings live.
    pub space: String,
    /// The lease of a holding entry, renewed at half its length.
    pub holding_lease: Duration,
    /// How long a request waits before it is asked again elsewhere (at least).
    pub request_timeout: Duration,
    /// How often the advertisement is published again (its TTL is 15 minutes).
    pub advertise_every: Duration,
    /// How often the service looks at its fetches, holdings, and sources.
    pub tick: Duration,
    /// Bytes this peer serves at most per second, over every member.
    pub upload_bytes_per_second: u64,
}

impl Default for ContentConfig {
    fn default() -> Self {
        ContentConfig {
            space: DEFAULT_SPACE.to_string(),
            holding_lease: Duration::from_secs(5 * 60),
            request_timeout: Duration::from_secs(10),
            advertise_every: Duration::from_secs(5 * 60),
            tick: Duration::from_millis(250),
            upload_bytes_per_second: 64 * 1024 * 1024,
        }
    }
}

/// Why a content operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    /// The service or its peer is closed.
    #[error("the content service is closed")]
    Closed,
    /// A tree the operation needs is not complete in the node store.
    #[error("tree {0} is not complete in the node store")]
    Incomplete(String),
    /// The caller's bound passed before the fetch completed.
    #[error("fetch of {root} timed out with {missing} node(s) or piece(s) still missing ({detail})")]
    TimedOut {
        /// The root.
        root: String,
        /// Nodes still missing at the last count.
        missing: usize,
        /// What the fetch last saw.
        detail: String,
    },
    /// A CID or an argument is malformed.
    #[error("{0}")]
    Invalid(String),
    /// The peer refused an operation.
    #[error("peer: {0}")]
    Peer(String),
}

impl From<PeerError> for ContentError {
    fn from(e: PeerError) -> Self {
        match e {
            PeerError::Closed => ContentError::Closed,
            other => ContentError::Peer(other.to_string()),
        }
    }
}

/// How an artifact is published.
#[derive(Debug, Clone)]
pub struct PublishOptions {
    /// The piece size: a power of two from 64 KiB to 4 MiB (default 1 MiB).
    pub piece_size: i64,
    /// A display name (at most 256 bytes).
    pub name: Option<String>,
    /// The media type.
    pub media_type: Option<String>,
    /// Attributes, text to text (at most 32 and 4 KiB).
    pub attrs: Vec<(String, String)>,
    /// Serve the file where it is instead of copying its pieces into the store.
    pub in_place: bool,
    /// The manifest entry's lease (default 7 days, renewed at half life while held).
    pub lease: Duration,
}

impl Default for PublishOptions {
    fn default() -> Self {
        PublishOptions {
            piece_size: crate::wire::content::DEFAULT_PIECE_SIZE,
            name: None,
            media_type: None,
            attrs: Vec::new(),
            in_place: false,
            lease: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

/// An artifact as this member holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInfo {
    /// The manifest.
    pub manifest: Manifest,
    /// Pieces held.
    pub held: i64,
    /// Whether it is served from a file in place.
    pub in_place: bool,
}

/// How one tree fetch runs.
#[derive(Debug, Clone, Default)]
pub struct FetchOptions {
    /// Roots this peer holds that the tree may share nodes with (at most 64 are sent).
    pub haves: Vec<String>,
    /// Members to ask first (a head's issuer, say), before the holders the content space names.
    pub prefer: Vec<String>,
    /// Give up after this long; `None` waits while any holder may still answer.
    pub timeout: Option<Duration>,
}

/// What a completed fetch did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchReport {
    /// The root.
    pub root: String,
    /// Nodes stored by this fetch.
    pub nodes: u64,
    /// Bytes stored by this fetch.
    pub bytes: u64,
    /// Requests sent.
    pub requests: u64,
    /// Requests that timed out and went back to the queue.
    pub timeouts: u64,
}

/// What the service counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentCounters {
    /// Tree requests answered (`NODE_WANT` and `TREE_WANT`).
    pub tree_wants_served: u64,
    /// Nodes sent.
    pub nodes_served: u64,
    /// Bytes of nodes sent.
    pub bytes_served: u64,
    /// Nodes stored from fetches.
    pub nodes_fetched: u64,
    /// Nodes refused (no outstanding request, or bytes that matched no expected CID).
    pub nodes_refused: u64,
    /// Members struck for sending a node that failed.
    pub strikes: u64,
    /// Tree messages dropped (undecodable, out of bounds, unknown tag, from a member without
    /// `trees`, or answering no request).
    pub tree_messages_dropped: u64,
    /// Piece messages dropped or refused (tags 1 to 7).
    pub piece_messages_dropped: u64,
    /// `REJECT`s sent.
    pub rejects_sent: u64,
    /// Holding entries written or renewed.
    pub holdings_written: u64,
    /// Requests that timed out.
    pub request_timeouts: u64,
    /// Pieces served.
    pub pieces_served: u64,
    /// Bytes of pieces served.
    pub piece_bytes_served: u64,
    /// Pieces stored from fetches.
    pub pieces_fetched: u64,
    /// Pieces that failed their hash (their sender struck).
    pub pieces_refused: u64,
}

enum Command {
    HoldTree {
        root: String,
        reply: oneshot::Sender<Result<(), ContentError>>,
    },
    ReleaseTree {
        root: String,
        reply: oneshot::Sender<()>,
    },
    FetchTree {
        root: String,
        options: FetchOptions,
        reply: oneshot::Sender<Result<FetchReport, ContentError>>,
    },
    Holders {
        root: String,
        reply: oneshot::Sender<Vec<String>>,
    },
    TreeMembers {
        reply: oneshot::Sender<Vec<String>>,
    },
    Counters {
        reply: oneshot::Sender<ContentCounters>,
    },
    HoldArtifact {
        manifest: Box<Manifest>,
        table: Vec<u8>,
        lease: Duration,
        reply: oneshot::Sender<Result<(), ContentError>>,
    },
    FetchArtifact {
        root: String,
        options: FetchOptions,
        reply: oneshot::Sender<Result<FetchReport, ContentError>>,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
}

/// What the handle and the service task share: the piece store and the files served in place.
pub(crate) struct Shared {
    pub(crate) pieces: Arc<dyn PieceStore>,
    pub(crate) in_place: std::sync::Mutex<std::collections::HashMap<String, InPlace>>,
}

impl Shared {
    /// A range of a piece of `root`, from a file in place or the store.
    pub(crate) fn read(&self, root: &str, index: i64, offset: i64, length: i64) -> Option<Vec<u8>> {
        let place = self.in_place.lock().unwrap_or_else(|e| e.into_inner()).get(root).cloned();
        match place {
            Some(p) => p.read(index, offset, length),
            None => self.pieces.read(root, index, offset, length),
        }
    }

    /// The manifest of a root held here.
    pub(crate) fn manifest(&self, root: &str) -> Option<Manifest> {
        let place = self.in_place.lock().unwrap_or_else(|e| e.into_inner()).get(root).map(|p| p.manifest.clone());
        place.or_else(|| self.pieces.manifest(root))
    }
}

/// A handle on the content swarm service of one peer. Cheap to clone.
#[derive(Clone)]
pub struct Content {
    commands: mpsc::Sender<Command>,
    nodes: Arc<dyn Nodes>,
    peer: Peer,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content").field("peer", &self.peer.peer_id()).finish()
    }
}

impl Content {
    /// Starts the service over `peer` with `nodes` as its node store and artifact pieces in
    /// memory, and advertises it.
    pub async fn start(peer: Peer, nodes: Arc<dyn Nodes>, config: ContentConfig) -> Result<Content, ContentError> {
        Self::start_with(peer, nodes, Arc::new(MemoryPieces::new()), config).await
    }

    /// Starts the service with a piece store of the caller's choosing ([`FilePieces`] keeps
    /// artifacts across restarts and holds them again).
    pub async fn start_with(
        peer: Peer,
        nodes: Arc<dyn Nodes>,
        pieces: Arc<dyn PieceStore>,
        config: ContentConfig,
    ) -> Result<Content, ContentError> {
        let (commands, receiver) = mpsc::channel(64);
        let events = peer.subscribe();
        let shared = Arc::new(Shared { pieces, in_place: std::sync::Mutex::new(std::collections::HashMap::new()) });
        let task = actor::Actor::new(peer.clone(), nodes.clone(), shared.clone(), config);
        task.advertise().await?;
        tokio::spawn(task.run(receiver, events));
        let content = Content { commands, nodes, peer, shared };
        // the complete artifacts a durable store already holds are held again
        for root in content.shared.pieces.roots() {
            let Some(m) = content.shared.pieces.manifest(&root) else { continue };
            if content.shared.pieces.have(&root).iter().all(|h| *h)
                && let Ok(table) = content.table_of(&m).await
            {
                let lease = PublishOptions::default().lease;
                let _ = content.ask(|reply| Command::HoldArtifact { manifest: Box::new(m), table, lease, reply }).await;
            }
        }
        Ok(content)
    }

    /// The piece table of a manifest: inline, else its block (asked of the seed when missing).
    pub async fn table_of(&self, m: &Manifest) -> Result<Vec<u8>, ContentError> {
        if let Some(t) = &m.table {
            return Ok(t.clone());
        }
        let r = m.table_ref.as_deref().ok_or_else(|| ContentError::Invalid("a manifest with neither table nor tableRef".into()))?;
        for _ in 0..50 {
            if let Some(t) = self.peer.block(r).await {
                return Ok(t);
            }
            let _ = self.peer.fetch_block(r, Some(&m.origin)).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(ContentError::Invalid(format!("the piece table {r} did not arrive")))
    }

    /// Publishes a file as an artifact: hashes it into pieces, stores them (or serves the file in
    /// place), writes the manifest entry, and holds it. Returns the manifest.
    pub async fn publish_file(&self, path: &std::path::Path, options: PublishOptions) -> Result<Manifest, ContentError> {
        let ps = options.piece_size;
        if !(crate::wire::content::MIN_PIECE_SIZE..=crate::wire::content::MAX_PIECE_SIZE).contains(&ps) || ps & (ps - 1) != 0 {
            return Err(ContentError::Invalid(format!("piece size {ps} is not a power of two from 64 KiB to 4 MiB")));
        }
        let file = path.to_path_buf();
        let (table, size) = tokio::task::spawn_blocking(move || pieces::hash_file(&file, ps))
            .await
            .map_err(|e| ContentError::Invalid(e.to_string()))?
            .map_err(|e| ContentError::Invalid(format!("{}: {e}", path.display())))?;
        let manifest = self.manifest_for(&table, size, &options).await?;
        if options.in_place {
            let place = InPlace { path: path.to_path_buf(), manifest: manifest.clone(), table: table.clone() };
            self.shared.in_place.lock().unwrap_or_else(|e| e.into_inner()).insert(manifest.root.clone(), place);
        } else {
            let (store, m, file) = (self.shared.pieces.clone(), manifest.clone(), path.to_path_buf());
            tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                use std::io::Read;
                store.open(&m)?;
                let mut f = std::fs::File::open(&file)?;
                for i in 0..m.pieces {
                    let mut piece = vec![0u8; pieces::piece_length(&m, i) as usize];
                    f.read_exact(&mut piece)?;
                    store.write(&m.root, i, &piece)?;
                }
                store.flush();
                Ok(())
            })
            .await
            .map_err(|e| ContentError::Invalid(e.to_string()))?
            .map_err(|e| ContentError::Invalid(format!("{}: {e}", path.display())))?;
        }
        let m = manifest.clone();
        let lease = options.lease;
        self.ask(|reply| Command::HoldArtifact { manifest: Box::new(m), table, lease, reply }).await??;
        Ok(manifest)
    }

    async fn manifest_for(&self, table: &[u8], size: i64, o: &PublishOptions) -> Result<Manifest, ContentError> {
        use crate::wire::content as forms;
        let pieces = forms::pieces_of(size, o.piece_size);
        let (inline, table_ref) = if pieces <= forms::INLINE_TABLE_PIECES {
            (Some(table.to_vec()), None)
        } else {
            (None, Some(self.peer.put_block(table.to_vec()).await?))
        };
        let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let manifest = Manifest {
            v: forms::VERSION,
            root: forms::content_root(table),
            size,
            piece_size: o.piece_size,
            pieces,
            table: inline,
            table_ref,
            table_refs: None,
            name: o.name.clone(),
            media_type: o.media_type.clone(),
            sealing: forms::SEALING_NONE.to_string(),
            key_epoch: None,
            hashing: forms::HASHING_PLAIN.to_string(),
            origin: self.peer.peer_id().to_string(),
            created,
            attrs: (!o.attrs.is_empty()).then(|| o.attrs.clone()),
            layout: None,
        };
        if let Some(why) = manifest.violation() {
            return Err(ContentError::Invalid(format!("the manifest would be refused: {why}")));
        }
        Ok(manifest)
    }

    /// Fetches an artifact by its root from the members that hold it, into the piece store.
    pub async fn fetch_artifact(&self, root: &str, options: FetchOptions) -> Result<FetchReport, ContentError> {
        crate::wire::pdt::cid::parse(root).map_err(|e| ContentError::Invalid(e.to_string()))?;
        let root = root.to_string();
        self.ask(|reply| Command::FetchArtifact { root, options, reply }).await?
    }

    /// The artifacts this member holds, whole or in part.
    pub fn artifacts(&self) -> Vec<ArtifactInfo> {
        let mut out: Vec<ArtifactInfo> = self
            .shared
            .in_place
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|p| ArtifactInfo { manifest: p.manifest.clone(), held: p.manifest.pieces, in_place: true })
            .collect();
        for root in self.shared.pieces.roots() {
            if let Some(m) = self.shared.pieces.manifest(&root) {
                let held = self.shared.pieces.have(&root).iter().filter(|h| **h).count() as i64;
                out.push(ArtifactInfo { manifest: m, held, in_place: false });
            }
        }
        out.sort_by(|a, b| a.manifest.root.cmp(&b.manifest.root));
        out
    }

    /// Writes a complete artifact to `out`.
    pub fn read_artifact(&self, root: &str, out: &mut dyn std::io::Write) -> Result<u64, ContentError> {
        let m = self.shared.manifest(root).ok_or_else(|| ContentError::Incomplete(root.to_string()))?;
        let mut written = 0u64;
        for i in 0..m.pieces {
            let len = pieces::piece_length(&m, i);
            let piece = self.shared.read(root, i, 0, len).ok_or_else(|| ContentError::Incomplete(root.to_string()))?;
            out.write_all(&piece).map_err(|e| ContentError::Invalid(e.to_string()))?;
            written += piece.len() as u64;
        }
        Ok(written)
    }

    /// The node store.
    pub fn nodes(&self) -> &Arc<dyn Nodes> {
        &self.nodes
    }

    /// The peer.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    async fn ask<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T, ContentError> {
        let (reply, answer) = oneshot::channel();
        self.commands.send(make(reply)).await.map_err(|_| ContentError::Closed)?;
        answer.await.map_err(|_| ContentError::Closed)
    }

    /// Holds a tree that is complete in the node store: serves it and keeps a leased holding
    /// entry for it in the content space until [`Content::release_tree`].
    pub async fn hold_tree(&self, root: &str) -> Result<(), ContentError> {
        let root = root.to_string();
        self.ask(|reply| Command::HoldTree { root, reply }).await?
    }

    /// Stops holding a tree: its holding entry is withdrawn (the nodes stay in the store).
    pub async fn release_tree(&self, root: &str) -> Result<(), ContentError> {
        let root = root.to_string();
        self.ask(|reply| Command::ReleaseTree { root, reply }).await
    }

    /// Fetches the tree rooted at `root` into the node store, from the members that hold it.
    pub async fn fetch_tree(&self, root: &str, options: FetchOptions) -> Result<FetchReport, ContentError> {
        crate::wire::pdt::cid::parse(root).map_err(|e| ContentError::Invalid(e.to_string()))?;
        let root = root.to_string();
        self.ask(|reply| Command::FetchTree { root, options, reply }).await?
    }

    /// The members whose live holding entries say they hold `root`.
    pub async fn holders(&self, root: &str) -> Result<Vec<String>, ContentError> {
        let root = root.to_string();
        self.ask(|reply| Command::Holders { root, reply }).await
    }

    /// The members that advertise persistent trees.
    pub async fn tree_members(&self) -> Result<Vec<String>, ContentError> {
        self.ask(|reply| Command::TreeMembers { reply }).await
    }

    /// What the service counted.
    pub async fn counters(&self) -> Result<ContentCounters, ContentError> {
        self.ask(|reply| Command::Counters { reply }).await
    }

    /// Stops the service, withdrawing its holdings (the peer keeps running).
    pub async fn close(&self) -> Result<(), ContentError> {
        self.ask(|reply| Command::Close { reply }).await
    }
}
