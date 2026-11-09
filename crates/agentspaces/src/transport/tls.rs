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

//! The `tls` binding (SPEC §5.5, §5.6): the `tcp` binding's length-prefixed frames inside TLS 1.3
//! (RFC 8446), each end presenting a channel certificate ([`crate::channel_cert`]). A port of
//! Java `TlsTcpTransport` on rustls.
//!
//! No CA participates. The certificate verifiers accept any chain at the handshake but still
//! verify the handshake's own signature (CertificateVerify) with the key of the certificate the
//! remote end presented, so the handshake proves possession of that key; once it completes, the
//! presented end-entity certificate is attested ([`crate::channel_cert::attest`]) and the
//! channel carries the PeerID it binds. Skipping the handshake signature would let anyone replay
//! a victim's certificate without its key, so it is never skipped.
//!
//! - [`TlsDialer`] presents the dialing identity's channel certificate and refuses a seed whose
//!   certificate attests nobody ([`TransportError::NotAttested`]): a peer only ever dials a seed
//!   to reach a fleet member, and the `tls` scheme promises an attested one.
//! - [`TlsListener`] presents its own channel certificate and requests the client's without
//!   requiring it (Java `setWantClientAuth`): a client presenting none, or one that attests
//!   nobody, connects with `attested` `None`, and its frames stay signed.
//!
//! Only TLS 1.3 is negotiated. Neither side resumes a session or accepts early data: the client
//! keeps no session cache, the server keeps none and issues no tickets, so every attestation rests
//! on a full handshake that proved possession of the presented key. No ALPN is offered (Java offers
//! none). SNI is sent only when the seed's host is a DNS name.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agentspaces_wire::identity::Identity;
use agentspaces_wire::seed::Seed;
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{Acceptor, NoServerSessionStorage};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use super::stream::spawn_stream_channel;
use super::tcp;
use super::{BoxFuture, Channel, Dialer, Listener, TransportError};
use crate::channel_cert::{ChannelCertificate, attest};

/// The scheme of this binding.
pub const SCHEME: &str = "tls";

/// How long a listener waits for one client's whole handshake, its ClientHello included, before
/// dropping the connection.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a listener waits for a connection's first flight (its ClientHello) before dropping
/// it. A connection holds no handshake slot until its ClientHello has arrived, so sockets that
/// send nothing cannot starve honest handshakes.
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);

/// How many connections from one address may be handshaking at once (waiting for their
/// ClientHello, or past it); a further one is closed at once. One address can therefore hold at
/// most half of the [`MAX_PENDING_HANDSHAKES`] slots, however it stalls its handshakes.
pub const MAX_HANDSHAKES_PER_ADDRESS: usize = 32;

/// How many connections in all may wait for their ClientHello at once; beyond it the acceptor
/// pauses and further connections wait in the backlog.
const MAX_FIRST_FLIGHTS: usize = 1024;

/// How many handshakes (after the ClientHello) a listener runs at once. A slot is held until the
/// handshaken channel is in the [`ACCEPT_QUEUE`], so when [`Listener::accept`] is not called the
/// listener stops completing handshakes once this many channels wait behind a full queue.
pub const MAX_PENDING_HANDSHAKES: usize = 64;

/// How many handshaken channels wait in the queue [`Listener::accept`] reads. At most
/// `ACCEPT_QUEUE + MAX_PENDING_HANDSHAKES` handshaken channels ever wait for it; further
/// handshakes wait for a slot (within [`HANDSHAKE_TIMEOUT`]) and then drop their connection.
pub const ACCEPT_QUEUE: usize = 16;

/// How long the acceptor pauses after the socket fails to accept (descriptor exhaustion, ...).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The crypto provider every TLS configuration of this binding is built from (aws-lc-rs, the
/// rustls default). The one place a provider is chosen, so rustls 0.24's move to explicit
/// provider crates changes this function alone.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A TLS 1.3 client configuration presenting `presenting` (or no certificate), verifying server
/// handshake signatures only, with resumption and early data off.
fn client_config(
    presenting: Option<&ChannelCertificate>,
) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = provider();
    let verifier = Arc::new(AttestAfterHandshake::new(&provider));
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match presenting {
        Some(certificate) => builder
            .with_client_auth_cert(certificate.rustls_chain(), certificate.rustls_key())
            .map_err(tls_error)?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// A TLS 1.3 server configuration presenting `certificate`, requesting but not requiring a
/// client certificate, with no session storage, no tickets, and no early data.
fn server_config(certificate: &ChannelCertificate) -> Result<Arc<ServerConfig>, TransportError> {
    let provider = provider();
    let verifier = Arc::new(AttestAfterHandshake::new(&provider));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate.rustls_chain(), certificate.rustls_key())
        .map_err(tls_error)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

fn tls_error(error: rustls::Error) -> TransportError {
    TransportError::Tls(error.to_string())
}

/// The PeerID the end-entity certificate of a presented chain attests, or `None` when the chain
/// is absent or attests nobody (Java `ChannelAttestation.attest` in the self-signed mode).
fn attested_by(chain: Option<&[CertificateDer<'_>]>) -> Option<String> {
    chain
        .and_then(|chain| chain.first())
        .and_then(|leaf| attest(leaf.as_ref()))
}

// ---------------------------------------------------------------------------------------------
// The verifier

/// Accepts any certificate chain at the handshake and defers the trust decision to
/// [`attest`] after it (Java `AttestLaterTrustManager`), while verifying every TLS 1.3 handshake
/// signature with the presented certificate's key. Serves both ends.
#[derive(Debug)]
struct AttestAfterHandshake {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AttestAfterHandshake {
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            algorithms: provider.signature_verification_algorithms,
        }
    }

    fn tls13(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signed, &self.algorithms)
    }

    fn tls12() -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable: both configurations offer TLS 1.3 alone. Refused should that change.
        Err(rustls::Error::General(
            "the tls binding negotiates TLS 1.3 only".into(),
        ))
    }
}

impl ServerCertVerifier for AttestAfterHandshake {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(message, certificate, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for AttestAfterHandshake {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(message, certificate, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------------------------
// The dialer

/// Dials `tls` seeds (SPEC §5.6): TLS 1.3, presenting a channel certificate, and refusing a seed
/// whose certificate attests nobody.
///
/// [`TlsDialer::new`] presents the channel certificate of the identity each dial is given,
/// generated on the first dial and kept while the identity stays the same.
/// [`TlsDialer::presenting`] presents a fixed credential and [`TlsDialer::anonymous`] none; the
/// listener then sees what that credential attests, or nothing.
#[derive(Debug)]
pub struct TlsDialer {
    presenting: Presenting,
}

#[derive(Debug)]
enum Presenting {
    /// The dialing identity's channel certificate: the configuration built for the last
    /// identity, by PeerID.
    Identity(Mutex<Option<(String, Arc<ClientConfig>)>>),
    /// A fixed configuration (a given credential, or none).
    Fixed(Arc<ClientConfig>),
}

impl TlsDialer {
    /// A dialer presenting each dial's identity's channel certificate.
    pub fn new() -> Self {
        Self {
            presenting: Presenting::Identity(Mutex::new(None)),
        }
    }

    /// A dialer presenting `certificate` whatever identity a dial is given.
    pub fn presenting(certificate: &ChannelCertificate) -> Result<Self, TransportError> {
        Ok(Self {
            presenting: Presenting::Fixed(client_config(Some(certificate))?),
        })
    }

    /// A dialer presenting no client certificate: the listener's channel stays unattested (and
    /// every frame on it signed). The seed is still attested.
    pub fn anonymous() -> Result<Self, TransportError> {
        Ok(Self {
            presenting: Presenting::Fixed(client_config(None)?),
        })
    }

    /// The client configuration for a dial as `identity`.
    fn config(&self, identity: &Identity) -> Result<Arc<ClientConfig>, TransportError> {
        let cache = match &self.presenting {
            Presenting::Fixed(config) => return Ok(Arc::clone(config)),
            Presenting::Identity(cache) => cache,
        };
        let mut cached = cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((peer, config)) = cached.as_ref()
            && peer == identity.peer_id()
        {
            return Ok(Arc::clone(config));
        }
        let certificate = ChannelCertificate::generate(identity)
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        let config = client_config(Some(&certificate))?;
        *cached = Some((identity.peer_id().to_owned(), Arc::clone(&config)));
        Ok(config)
    }
}

impl Default for TlsDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl Dialer for TlsDialer {
    fn schemes(&self) -> &[&'static str] {
        &[SCHEME]
    }

    fn dial<'a>(
        &'a self,
        seed: &'a Seed,
        identity: &'a Identity,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Channel, TransportError>> {
        Box::pin(async move {
            let config = self.config(identity)?;
            tokio::time::timeout(timeout, dial_attested(seed, config))
                .await
                .map_err(|_| TransportError::Timeout(seed.to_string()))?
        })
    }
}

/// Connects, handshakes, and attests the seed; the caller bounds the time.
async fn dial_attested(seed: &Seed, config: Arc<ClientConfig>) -> Result<Channel, TransportError> {
    let stream = tcp::connect(seed).await?;
    let name = server_name(&seed.host, &stream);
    let tls = TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|error| TransportError::Tls(format!("handshake with {seed}: {error}")))?;
    let Some(peer) = attested_by(tls.get_ref().1.peer_certificates()) else {
        // Dropping the stream closes the socket; the seed sees the link end.
        return Err(TransportError::NotAttested(seed.to_string()));
    };
    Ok(spawn_stream_channel(
        tls,
        SCHEME,
        &seed.address(),
        Some(peer),
    ))
}

/// The name the handshake is for: a DNS host as itself (sent as SNI), an address as the address
/// (no SNI). A host rustls cannot read as either (an IPv6 zone, say) goes as the connected
/// address.
fn server_name(host: &str, stream: &TcpStream) -> ServerName<'static> {
    ServerName::try_from(host.to_owned()).unwrap_or_else(|_| {
        let address = stream
            .peer_addr()
            .map(|address| address.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        ServerName::IpAddress(address.into())
    })
}

// ---------------------------------------------------------------------------------------------
// The listener

/// Accepts `tls` channels on a bound address, presenting a channel certificate and requesting
/// the client's without requiring it. Each accepted channel carries the PeerID the client's
/// certificate attests, or `None`.
///
/// Each connection is handshaken off the accept loop in two stages, all within
/// [`HANDSHAKE_TIMEOUT`]. First its ClientHello is read within [`CLIENT_HELLO_TIMEOUT`], holding
/// no handshake slot, so idle sockets cannot starve honest handshakes. Then the handshake takes
/// one of [`MAX_PENDING_HANDSHAKES`] slots and holds it until its channel is in the
/// [`ACCEPT_QUEUE`]. At most [`MAX_HANDSHAKES_PER_ADDRESS`] connections from one address are in
/// either stage at once (a further one is closed at once). A handshake that fails or stalls
/// drops its connection alone, as Java's does. Dropping the listener closes the socket.
#[derive(Debug)]
pub struct TlsListener {
    address: String,
    accepted: tokio::sync::Mutex<mpsc::Receiver<Result<Channel, TransportError>>>,
    acceptor: JoinHandle<()>,
}

impl TlsListener {
    /// Binds `address` (as [`super::tcp::TcpListener::bind`] reads it), presenting `identity`'s
    /// freshly generated channel certificate.
    pub async fn bind(address: &str, identity: &Identity) -> Result<Self, TransportError> {
        let certificate = ChannelCertificate::generate(identity)
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        Self::bind_presenting(address, &certificate).await
    }

    /// Binds `address`, presenting `certificate` as given (an ordinary certificate attests
    /// nobody to a dialer, which then refuses the link).
    pub async fn bind_presenting(
        address: &str,
        certificate: &ChannelCertificate,
    ) -> Result<Self, TransportError> {
        let config = server_config(certificate)?;
        let listener = tcp::bind_socket(address).await?;
        let address = listener.local_addr()?.to_string();
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        let acceptor = tokio::spawn(accept_loop(listener, config, tx));
        Ok(Self {
            address,
            accepted: tokio::sync::Mutex::new(rx),
            acceptor,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

impl Listener for TlsListener {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn local_address(&self) -> String {
        self.address.clone()
    }

    fn accept(&self) -> BoxFuture<'_, Option<Result<Channel, TransportError>>> {
        Box::pin(async move { self.accepted.lock().await.recv().await })
    }
}

/// One connection's claim on its address's handshake allowance
/// ([`MAX_HANDSHAKES_PER_ADDRESS`]), given back when dropped.
struct AddressSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    address: IpAddr,
}

impl AddressSlot {
    /// A slot for `address`, or `None` when its allowance is used up.
    fn take(counts: &Arc<Mutex<HashMap<IpAddr, usize>>>, address: IpAddr) -> Option<Self> {
        let mut held = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(address).or_insert(0);
        if *count >= MAX_HANDSHAKES_PER_ADDRESS {
            return None;
        }
        *count = count.saturating_add(1);
        Some(Self {
            counts: Arc::clone(counts),
            address,
        })
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut held = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.address);
            }
        }
    }
}

/// Accepts sockets and hands each to its own handshake task; ends when the listener is dropped.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    config: Arc<ServerConfig>,
    accepted: mpsc::Sender<Result<Channel, TransportError>>,
) {
    let first_flights = Arc::new(Semaphore::new(MAX_FIRST_FLIGHTS));
    let handshakes = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let per_address = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let Ok(total) = Arc::clone(&first_flights).acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok((stream, remote)) => {
                let Some(address) = AddressSlot::take(&per_address, remote.ip()) else {
                    tracing::debug!(%remote, "tls: too many handshakes from one address; closed");
                    continue;
                };
                let config = Arc::clone(&config);
                let handshakes = Arc::clone(&handshakes);
                let accepted = accepted.clone();
                tokio::spawn(async move {
                    let held = Held {
                        first_flight: total,
                        address,
                    };
                    if let Some((channel, slot)) =
                        handshake(config, stream, remote, held, handshakes).await
                    {
                        // The handshake slot is held until the channel is queued, so the
                        // listener stops handshaking while nobody accepts. A closed queue means
                        // the listener is gone; the channel then drops.
                        let _ = accepted.send(Ok(channel)).await;
                        drop(slot);
                    }
                });
            }
            Err(error) => {
                drop(total);
                if accepted.send(Err(TransportError::Io(error))).await.is_err() {
                    return;
                }
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

/// What a connection's handshake task holds from the accept loop: its first-flight slot (given
/// back once the ClientHello is in) and its address's allowance (given back once the handshake
/// ends).
struct Held {
    first_flight: OwnedSemaphorePermit,
    address: AddressSlot,
}

/// One server handshake: the ClientHello within [`CLIENT_HELLO_TIMEOUT`], then a handshake slot
/// and the rest of the handshake, all within [`HANDSHAKE_TIMEOUT`]; then the channel over it,
/// attested by the client's certificate when it presented one, with the slot it holds. `None`
/// when the handshake failed or ran out of time.
async fn handshake(
    config: Arc<ServerConfig>,
    stream: TcpStream,
    remote: SocketAddr,
    held: Held,
    handshakes: Arc<Semaphore>,
) -> Option<(Channel, OwnedSemaphorePermit)> {
    let Held {
        first_flight,
        address,
    } = held;
    let started = Instant::now();
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(%remote, %error, "tls: TCP_NODELAY not set");
    }
    let hello = LazyConfigAcceptor::new(Acceptor::default(), stream);
    let start = match tokio::time::timeout(CLIENT_HELLO_TIMEOUT, hello).await {
        Ok(Ok(start)) => start,
        Ok(Err(error)) => {
            tracing::debug!(%remote, %error, "tls: no readable ClientHello");
            return None;
        }
        Err(_) => {
            tracing::debug!(%remote, "tls: no ClientHello in time");
            return None;
        }
    };
    drop(first_flight);
    let remaining = HANDSHAKE_TIMEOUT.saturating_sub(started.elapsed());
    let finished = tokio::time::timeout(remaining, async move {
        let slot = handshakes.acquire_owned().await.ok()?;
        match start.into_stream(config).await {
            Ok(tls) => Some((tls, slot)),
            Err(error) => {
                tracing::debug!(%remote, %error, "tls: handshake failed");
                None
            }
        }
    })
    .await;
    let (tls, slot) = match finished {
        Ok(Some(done)) => done,
        Ok(None) => return None,
        Err(_) => {
            tracing::debug!(%remote, "tls: handshake timed out");
            return None;
        }
    };
    drop(address);
    let attested = attested_by(tls.get_ref().1.peer_certificates());
    Some((
        spawn_stream_channel(tls, SCHEME, &remote.to_string(), attested),
        slot,
    ))
}
