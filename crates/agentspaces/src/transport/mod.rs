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

//! Transports: a [`Dialer`] opens a [`Channel`] that carries whole frames (SPEC §5.5, §9).
//!
//! Every binding is reduced to the same shape: a [`FrameSender`] and a [`FrameReceiver`] over
//! bounded queues, plus what the handshake proved (the attested PeerID, if any). The peer never
//! sees sockets. Stream bindings (`tcp`, `tls`) frame with a 4-byte big-endian length through
//! [`stream::spawn_stream_channel`]; tests use [`memory`].

pub mod memory;
pub mod stream;
pub mod tcp;
pub mod tls;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::Seed;
use tokio::sync::{mpsc, watch};

/// A boxed, sendable future (dialers are used as trait objects).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How many frames may wait in either direction of a channel before a sender waits.
///
/// Deliberately small. Outbound, the peer counts the bytes it has queued for a link only until
/// its pump hands a frame to the channel, so every frame waiting here is memory beyond the
/// peer's send-queue bound (at most this many frames, plus the one being written). Inbound, a
/// frame waiting here is memory beyond the peer's inbound byte budget. Two frames keep the
/// reader and the writer busy while the other side works.
pub const CHANNEL_QUEUE: usize = 2;

/// Why a dial or a send failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The scheme has no dialer in this peer.
    #[error("no dialer for scheme {0}")]
    UnsupportedScheme(String),
    /// The dial did not complete in time.
    #[error("dial to {0} timed out")]
    Timeout(String),
    /// An I/O failure.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The TLS handshake or the channel-certificate attestation failed.
    #[error("tls: {0}")]
    Tls(String),
    /// The remote end presented no endorsed channel certificate where one is required.
    #[error("{0} presented no endorsed channel certificate")]
    NotAttested(String),
    /// The channel is closed.
    #[error("channel closed")]
    Closed,
    /// A frame is empty or larger than the frame cap.
    #[error("frame of {0} bytes is outside 1..=MAX_FRAME_BYTES")]
    FrameSize(usize),
}

/// The sending half of a channel: whole frames, in order.
#[derive(Debug, Clone)]
pub struct FrameSender {
    tx: mpsc::Sender<Vec<u8>>,
    closed: watch::Receiver<bool>,
}

impl FrameSender {
    /// Wraps a queue whose consumer writes frames to the link, watching the link's close signal.
    pub fn new(tx: mpsc::Sender<Vec<u8>>, closed: watch::Receiver<bool>) -> Self {
        Self { tx, closed }
    }

    /// Queues one frame; fails when the frame is empty or over the cap, or the channel closed.
    pub async fn send(&self, frame: Vec<u8>) -> Result<(), TransportError> {
        if frame.is_empty() || frame.len() > agentspaces_wire::limits::MAX_FRAME_BYTES {
            return Err(TransportError::FrameSize(frame.len()));
        }
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        self.tx
            .send(frame)
            .await
            .map_err(|_| TransportError::Closed)
    }

    /// Whether the link behind this sender has closed.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed() || *self.closed.borrow() || self.closed.has_changed().is_err()
    }
}

/// The receiving half of a channel.
#[derive(Debug)]
pub struct FrameReceiver {
    rx: mpsc::Receiver<Vec<u8>>,
    closed: watch::Receiver<bool>,
}

impl FrameReceiver {
    /// Wraps a queue the link's reader fills, watching the link's close signal.
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, closed: watch::Receiver<bool>) -> Self {
        Self { rx, closed }
    }

    /// The next frame, or `None` once the link has closed. Frames already queued when the link
    /// closes are still delivered first.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Ok(frame) = self.rx.try_recv() {
                return Some(frame);
            }
            if *self.closed.borrow() {
                return None;
            }
            tokio::select! {
                frame = self.rx.recv() => return frame,
                changed = self.closed.changed() => {
                    if changed.is_err() {
                        return self.rx.try_recv().ok();
                    }
                }
            }
        }
    }
}

/// One open link: a sender, a receiver, and what the handshake proved.
#[derive(Debug)]
pub struct Channel {
    /// The scheme the channel was opened with (`tcp`, `tls`, `mem`, ...).
    pub scheme: String,
    /// The remote address as dialed or accepted.
    pub remote: String,
    /// The PeerID the transport attested (TLS channel certificate), or `None`.
    pub attested: Option<String>,
    /// Sends whole frames.
    pub sender: FrameSender,
    /// Receives whole frames; `None` when the link closed.
    pub receiver: FrameReceiver,
    /// Closes the link when dropped or signalled (the stream tasks watch it).
    pub closer: Closer,
}

/// Closes a channel's link: calling [`Closer::close`] (or dropping every clone) ends the link's
/// tasks, fails later sends, and ends the receiver after any queued frames.
#[derive(Debug, Clone)]
pub struct Closer {
    tx: watch::Sender<bool>,
}

impl Closer {
    /// A closer and the watch its link's tasks and halves observe.
    pub fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self { tx }, rx)
    }

    /// Another watch on this link's close signal.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Whether the link has been asked to close.
    pub fn is_closed(&self) -> bool {
        *self.tx.borrow()
    }

    /// Asks the link to close; idempotent.
    pub fn close(&self) {
        let _ = self.tx.send(true);
    }
}

/// Opens channels for one or more schemes.
pub trait Dialer: Send + Sync + std::fmt::Debug {
    /// The schemes this dialer serves (lower case).
    fn schemes(&self) -> &[&'static str];

    /// Dials `seed`, presenting `identity` where the binding attests (TLS), within `timeout`.
    fn dial<'a>(
        &'a self,
        seed: &'a Seed,
        identity: &'a Identity,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Channel, TransportError>>;
}

/// Accepts channels for one scheme (the seed and tests).
pub trait Listener: Send + Sync + std::fmt::Debug {
    /// The scheme this listener serves.
    fn scheme(&self) -> &'static str;
    /// The bound address (`host:port`), with the port the OS chose for `:0`.
    fn local_address(&self) -> String;
    /// The next accepted channel, or `None` when the listener closed.
    fn accept(&self) -> BoxFuture<'_, Option<Result<Channel, TransportError>>>;
}
