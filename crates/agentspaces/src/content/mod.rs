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
//! with no strike. The piece messages (tags 1 to 7) are answered with `REJECT` (unknown root)
//! until the piece exchange is served here.

mod actor;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::peer::{Peer, PeerError};
use crate::wire::pdt::store::Nodes;

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
    #[error("fetch of {root} timed out with {missing} node(s) still missing ({detail})")]
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
    Close {
        reply: oneshot::Sender<()>,
    },
}

/// A handle on the content swarm service of one peer. Cheap to clone.
#[derive(Clone)]
pub struct Content {
    commands: mpsc::Sender<Command>,
    nodes: Arc<dyn Nodes>,
    peer: Peer,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content").field("peer", &self.peer.peer_id()).finish()
    }
}

impl Content {
    /// Starts the service over `peer` with `nodes` as its node store, and advertises it.
    pub async fn start(peer: Peer, nodes: Arc<dyn Nodes>, config: ContentConfig) -> Result<Content, ContentError> {
        let (commands, receiver) = mpsc::channel(64);
        let events = peer.subscribe();
        let task = actor::Actor::new(peer.clone(), nodes.clone(), config);
        task.advertise().await?;
        tokio::spawn(task.run(receiver, events));
        Ok(Content { commands, nodes, peer })
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
