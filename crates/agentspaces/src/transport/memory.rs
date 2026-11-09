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

//! An in-memory network for tests: listeners by address, dials that connect to them, and
//! optional attestation, with no sockets.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::Seed;
use tokio::sync::mpsc;

use super::{
    BoxFuture, CHANNEL_QUEUE, Channel, Closer, Dialer, FrameReceiver, FrameSender, Listener,
    TransportError,
};

/// Two connected channels, `a` and `b`; each side's `attested` is what it believes of the other.
/// Closing either side's [`Closer`] closes both: sends fail and receivers end.
pub fn pair(
    scheme: &str,
    a_remote: &str,
    b_remote: &str,
    a_attested: Option<String>,
    b_attested: Option<String>,
) -> (Channel, Channel) {
    let (a_tx, b_rx) = mpsc::channel(CHANNEL_QUEUE);
    let (b_tx, a_rx) = mpsc::channel(CHANNEL_QUEUE);
    let (closer, _closed) = Closer::new();
    let a = Channel {
        scheme: scheme.to_owned(),
        remote: a_remote.to_owned(),
        attested: a_attested,
        sender: FrameSender::new(a_tx, closer.watch()),
        receiver: FrameReceiver::new(a_rx, closer.watch()),
        closer: closer.clone(),
    };
    let b = Channel {
        scheme: scheme.to_owned(),
        remote: b_remote.to_owned(),
        attested: b_attested,
        sender: FrameSender::new(b_tx, closer.watch()),
        receiver: FrameReceiver::new(b_rx, closer.watch()),
        closer,
    };
    (a, b)
}

/// A network of in-memory listeners keyed by `host:port`.
#[derive(Debug, Clone, Default)]
pub struct MemoryNetwork {
    listeners: Arc<Mutex<HashMap<String, mpsc::Sender<Channel>>>>,
}

impl MemoryNetwork {
    /// An empty network.
    pub fn new() -> Self {
        Self::default()
    }

    /// Listens at `address`; replaces an earlier listener there.
    pub fn listen(&self, address: &str) -> MemoryListener {
        let (tx, rx) = mpsc::channel(16);
        if let Ok(mut map) = self.listeners.lock() {
            map.insert(address.to_owned(), tx);
        }
        MemoryListener {
            address: address.to_owned(),
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Removes the listener at `address`; later dials there fail as refused.
    pub fn unlisten(&self, address: &str) {
        if let Ok(mut map) = self.listeners.lock() {
            map.remove(address);
        }
    }

    /// A dialer for scheme `mem` (and `tcp`, so seeds written as `host:port` reach it).
    pub fn dialer(&self) -> MemoryDialer {
        MemoryDialer {
            network: self.clone(),
            attest_as: None,
        }
    }
}

/// Dials listeners of a [`MemoryNetwork`].
#[derive(Debug, Clone)]
pub struct MemoryDialer {
    network: MemoryNetwork,
    /// When set, each side's channel claims the other is attested as these PeerIDs
    /// (`(dialer's view of the listener, listener's view of the dialer)`): simulates `tls`.
    pub attest_as: Option<(String, String)>,
}

impl Dialer for MemoryDialer {
    fn schemes(&self) -> &[&'static str] {
        &["mem", "tcp", "tls"]
    }

    fn dial<'a>(
        &'a self,
        seed: &'a Seed,
        _identity: &'a Identity,
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<Channel, TransportError>> {
        Box::pin(async move {
            let address = seed.address();
            let target = self
                .network
                .listeners
                .lock()
                .ok()
                .and_then(|map| map.get(&address).cloned());
            let Some(target) = target else {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("no listener at {address}"),
                )));
            };
            let (dialer_view, listener_view) = match &self.attest_as {
                Some((listener_peer, dialer_peer)) => {
                    (Some(listener_peer.clone()), Some(dialer_peer.clone()))
                }
                None => (None, None),
            };
            let (mine, theirs) = pair(
                &seed.scheme,
                &address,
                "memory-client",
                dialer_view,
                listener_view,
            );
            target
                .send(theirs)
                .await
                .map_err(|_| TransportError::Closed)?;
            Ok(mine)
        })
    }
}

/// A listener on a [`MemoryNetwork`].
#[derive(Debug)]
pub struct MemoryListener {
    address: String,
    rx: tokio::sync::Mutex<mpsc::Receiver<Channel>>,
}

impl Listener for MemoryListener {
    fn scheme(&self) -> &'static str {
        "mem"
    }

    fn local_address(&self) -> String {
        self.address.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Option<Result<Channel, TransportError>>> {
        Box::pin(async move { self.rx.lock().await.recv().await.map(Ok) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_cross_and_close_ends_both_sides() {
        let (a, mut b) = pair("mem", "b", "a", None, None);
        a.sender.send(vec![1, 2, 3]).await.expect("send");
        assert_eq!(b.receiver.recv().await, Some(vec![1, 2, 3]));
        a.sender.send(vec![4]).await.expect("send");
        b.closer.close();
        assert_eq!(
            b.receiver.recv().await,
            Some(vec![4]),
            "a queued frame is still delivered"
        );
        assert_eq!(b.receiver.recv().await, None);
        assert!(
            a.sender.send(vec![5]).await.is_err(),
            "a closed link refuses sends"
        );
        assert!(a.sender.send(Vec::new()).await.is_err());
    }

    #[tokio::test]
    async fn a_dial_reaches_a_listener_and_a_missing_one_is_refused() {
        let net = MemoryNetwork::new();
        let listener = net.listen("127.0.0.1:7500");
        let id = Identity::generate().expect("identity");
        let seed: Seed = "127.0.0.1:7500".parse().expect("seed");
        let dialed = net
            .dialer()
            .dial(&seed, &id, Duration::from_secs(1))
            .await
            .expect("dial");
        let mut accepted = listener.accept().await.expect("accept").expect("channel");
        dialed.sender.send(vec![9]).await.expect("send");
        assert_eq!(accepted.receiver.recv().await, Some(vec![9]));
        let missing: Seed = "127.0.0.1:7501".parse().expect("seed");
        assert!(
            net.dialer()
                .dial(&missing, &id, Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
