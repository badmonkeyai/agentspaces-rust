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

//! The `tcp` binding (SPEC §5.5, §9): length-prefixed frames over a plain TCP socket, a port of
//! Java `TcpTransport`. Nothing is attested: every frame on a `tcp` channel stays signed (or
//! rides a session, SPEC §5.6). The `tls` binding reuses the dial and bind helpers here.

use std::io;
use std::time::Duration;

use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::{Seed, seed_address};
use tokio::net::TcpStream;

use super::stream::spawn_stream_channel;
use super::{BoxFuture, Channel, Dialer, Listener, TransportError};

/// The scheme of this binding.
pub const SCHEME: &str = "tcp";

/// Dials `tcp` seeds: resolves the host, connects to the first address that answers within the
/// timeout, and frames over the socket with `TCP_NODELAY` on. Presents nothing, so its channels
/// are unattested.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

impl TcpDialer {
    /// A `tcp` dialer.
    pub fn new() -> Self {
        Self
    }
}

impl Dialer for TcpDialer {
    fn schemes(&self) -> &[&'static str] {
        &[SCHEME]
    }

    fn dial<'a>(
        &'a self,
        seed: &'a Seed,
        _identity: &'a Identity,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Channel, TransportError>> {
        Box::pin(async move {
            let stream = tokio::time::timeout(timeout, connect(seed))
                .await
                .map_err(|_| TransportError::Timeout(seed.to_string()))??;
            Ok(spawn_stream_channel(stream, SCHEME, &seed.address(), None))
        })
    }
}

/// Accepts `tcp` channels on a bound address.
#[derive(Debug)]
pub struct TcpListener {
    listener: tokio::net::TcpListener,
    address: String,
}

impl TcpListener {
    /// Binds `address`: `host:port`, `[v6]:port`, or `:port` for every IPv4 interface; port `0`
    /// lets the OS choose, and [`Listener::local_address`] then reports the port it chose.
    pub async fn bind(address: &str) -> Result<Self, TransportError> {
        let listener = bind_socket(address).await?;
        let address = listener.local_addr()?.to_string();
        Ok(Self { listener, address })
    }
}

impl Listener for TcpListener {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn local_address(&self) -> String {
        self.address.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Option<Result<Channel, TransportError>>> {
        Box::pin(async move {
            let accepted = self.listener.accept().await.and_then(|(stream, remote)| {
                stream.set_nodelay(true)?;
                Ok(spawn_stream_channel(
                    stream,
                    SCHEME,
                    &remote.to_string(),
                    None,
                ))
            });
            Some(accepted.map_err(TransportError::Io))
        })
    }
}

/// A TCP connection to `seed` with `TCP_NODELAY` on: the host is resolved and each of its
/// addresses tried in turn, as the resolver orders them. The caller bounds the time.
pub(crate) async fn connect(seed: &Seed) -> Result<TcpStream, TransportError> {
    let stream = TcpStream::connect((seed.host.as_str(), seed.port)).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// A TCP listening socket on `address` (`host:port`, `[v6]:port`, or `:port` for every IPv4
/// interface).
pub(crate) async fn bind_socket(address: &str) -> Result<tokio::net::TcpListener, TransportError> {
    let trimmed = address.trim();
    let full = if trimmed.starts_with(':') {
        format!("0.0.0.0{trimmed}")
    } else {
        trimmed.to_owned()
    };
    let (host, port) = seed_address(&full)
        .map_err(|error| TransportError::Io(io::Error::new(io::ErrorKind::InvalidInput, error)))?;
    Ok(tokio::net::TcpListener::bind((host.as_str(), port)).await?)
}
