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

//! The `tcp` and `tls` bindings over real sockets, and the channel certificate (SPEC §5.5, §5.6):
//! mutual attestation, refusal of a seed that attests nobody, unattested clients, and `attest`
//! on hostile bytes. Two ignored tests cross-check against the Java reference
//! (`cargo test -p agentspaces --test transport_tls -- --ignored`).

use std::sync::Arc;
use std::time::Duration;

use agentspaces::channel_cert::{ChannelCertificate, MAX_CN_CHARS, attest};
use agentspaces::transport::tcp::{TcpDialer, TcpListener};
use agentspaces::transport::tls::{
    ACCEPT_QUEUE, CLIENT_HELLO_TIMEOUT, MAX_HANDSHAKES_PER_ADDRESS, MAX_PENDING_HANDSHAKES,
    TlsDialer, TlsListener,
};
use agentspaces::transport::{Channel, Dialer, Listener, TransportError};
use agentspaces::wire::base58;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::seed::{Seed, parse_seed};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, PKCS_ED25519, PublicKeyData,
    SignatureAlgorithm, SigningKey,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, DigitallySignedStruct, HandshakeKind, ServerConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::FromDer;

const WAIT: Duration = Duration::from_secs(10);

fn identity() -> Identity {
    Identity::generate().expect("identity")
}

fn seed_of(listener: &dyn Listener, scheme: &str) -> Seed {
    parse_seed(&format!("{scheme}://{}", listener.local_address()), scheme).expect("seed")
}

async fn accept(listener: &dyn Listener) -> Channel {
    tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("accept in time")
        .expect("listener open")
        .expect("accepted")
}

async fn recv(channel: &mut Channel) -> Option<Vec<u8>> {
    tokio::time::timeout(WAIT, channel.receiver.recv())
        .await
        .expect("a frame or the close in time")
}

/// Sends a few frames each way, one larger than a TLS record, and checks they arrive in order.
async fn frames_cross(a: &mut Channel, b: &mut Channel) {
    for n in 0..20u8 {
        a.sender
            .send(vec![n; 1 + usize::from(n)])
            .await
            .expect("send");
    }
    let large: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    a.sender.send(large.clone()).await.expect("send large");
    for n in 0..20u8 {
        assert_eq!(recv(b).await, Some(vec![n; 1 + usize::from(n)]));
    }
    assert_eq!(recv(b).await, Some(large));
    b.sender.send(b"back".to_vec()).await.expect("send back");
    assert_eq!(recv(a).await.as_deref(), Some(&b"back"[..]));
}

/// rcgen's view of an identity as an Ed25519 issuer key, to craft certificates `attest` must
/// refuse.
struct Endorser<'a>(&'a Identity);

impl PublicKeyData for Endorser<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.public_raw()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl SigningKey for Endorser<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.sign(message).to_vec())
    }
}

/// A P-256 certificate with the subject `name`, Ed25519-signed by `signer`.
fn endorsed_with_subject(name: DistinguishedName, signer: &Identity) -> Vec<u8> {
    let key = KeyPair::generate().expect("p-256");
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    let issuer = Issuer::from_params(&params, Endorser(signer));
    params
        .signed_by(&key, &issuer)
        .expect("certificate")
        .der()
        .to_vec()
}

fn cn(value: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, value);
    name
}

// ---------------------------------------------------------------------------------------------
// tls

#[tokio::test]
async fn a_tls_dialer_and_listener_attest_each_other_and_frames_cross() {
    let server = identity();
    let client = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    assert_eq!(listener.scheme(), "tls");
    let seed = seed_of(&listener, "tls");
    assert_ne!(seed.port, 0, "the OS chose a port");
    let dialer = TlsDialer::new();
    assert_eq!(dialer.schemes(), &["tls"]);

    let mut dialed = dialer.dial(&seed, &client, WAIT).await.expect("dial");
    let mut accepted = accept(&listener).await;
    assert_eq!(dialed.scheme, "tls");
    assert_eq!(dialed.remote, seed.address());
    assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
    assert_eq!(accepted.attested.as_deref(), Some(client.peer_id()));
    assert!(accepted.remote.starts_with("127.0.0.1:"));
    frames_cross(&mut dialed, &mut accepted).await;
    frames_cross(&mut accepted, &mut dialed).await;

    dialed.closer.close();
    assert_eq!(
        recv(&mut accepted).await,
        None,
        "closing one end ends the other"
    );

    // A second dial by name sends SNI and reuses the dialer's certificate; a different identity
    // on the same dialer is presented as itself.
    let named = Seed::new("localhost", seed.port, "tls");
    let other = identity();
    for (who, target) in [(&client, &named), (&other, &seed)] {
        let dialed = dialer.dial(target, who, WAIT).await.expect("dial again");
        let accepted = accept(&listener).await;
        assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
        assert_eq!(accepted.attested.as_deref(), Some(who.peer_id()));
    }
}

#[tokio::test]
async fn a_server_presenting_an_ordinary_certificate_is_refused_as_not_attested() {
    let ordinary = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
    let credential = ChannelCertificate::from_der(
        ordinary.signing_key.serialize_der(),
        ordinary.cert.der().to_vec(),
    );
    assert_eq!(credential.attested(), None);
    let listener = TlsListener::bind_presenting("127.0.0.1:0", &credential)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let refused = TlsDialer::new().dial(&seed, &identity(), WAIT).await;
    assert!(
        matches!(&refused, Err(TransportError::NotAttested(seed)) if seed.starts_with("tls://")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_certificate_naming_one_identity_but_signed_by_another_attests_nobody() {
    let victim = identity();
    let attacker = identity();
    let forged = ChannelCertificate::build(victim.public_raw(), &attacker, 1_700_000_000_000)
        .expect("build");
    assert_eq!(attest(forged.certificate_der()), None);
    let honest = ChannelCertificate::generate(&victim).expect("generate");
    assert_eq!(honest.attested().as_deref(), Some(victim.peer_id()));

    // Presented by a server: the dialer refuses it.
    let listener = TlsListener::bind_presenting("127.0.0.1:0", &forged)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let refused = TlsDialer::new().dial(&seed, &identity(), WAIT).await;
    assert!(
        matches!(refused, Err(TransportError::NotAttested(_))),
        "{refused:?}"
    );

    // Presented by a client: the link stands, unattested.
    let server = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let mut dialed = TlsDialer::presenting(&forged)
        .expect("dialer")
        .dial(&seed, &attacker, WAIT)
        .await
        .expect("dial");
    let mut accepted = accept(&listener).await;
    assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
    assert_eq!(accepted.attested, None);
    frames_cross(&mut dialed, &mut accepted).await;
}

#[tokio::test]
async fn a_client_without_a_certificate_connects_unattested() {
    let server = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let mut dialed = TlsDialer::anonymous()
        .expect("dialer")
        .dial(&seed, &identity(), WAIT)
        .await
        .expect("dial");
    let mut accepted = accept(&listener).await;
    assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
    assert_eq!(accepted.attested, None);
    frames_cross(&mut dialed, &mut accepted).await;
}

/// The victim's certificate under the attacker's P-256 key: what an impostor replaying a
/// certificate it observed can present. rustls refuses to build such a pair through
/// `with_single_cert`, so the test assembles it by hand.
fn impostor(stolen: &ChannelCertificate) -> Arc<SingleCertAndKey> {
    let attacker = KeyPair::generate().expect("p-256");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(attacker.serialize_der()));
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).expect("key");
    Arc::new(SingleCertAndKey::from(CertifiedKey::new(
        stolen.rustls_chain(),
        signer,
    )))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A client verifier that checks nothing, so the impostor client gets as far as it can.
#[derive(Debug)]
struct Gullible;

impl ServerCertVerifier for Gullible {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test]
async fn a_server_replaying_a_certificate_without_its_key_fails_the_handshake() {
    let victim = identity();
    let stolen = ChannelCertificate::generate(&victim).expect("generate");
    assert_eq!(stolen.attested().as_deref(), Some(victim.peer_id()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3")
        .with_no_client_auth()
        .with_cert_resolver(impostor(&stolen));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = socket.local_addr().expect("address").port();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let server = tokio::spawn(async move {
        let (stream, _) = socket.accept().await.expect("accept");
        acceptor.accept(stream).await.is_ok()
    });
    let refused = TlsDialer::new()
        .dial(&Seed::new("127.0.0.1", port, "tls"), &identity(), WAIT)
        .await;
    assert!(
        matches!(&refused, Err(TransportError::Tls(why)) if why.contains("ignature")),
        "the handshake signature is checked against the presented key: {refused:?}"
    );
    assert!(!server.await.expect("server task"));
}

#[tokio::test]
async fn a_client_replaying_a_certificate_without_its_key_is_never_accepted() {
    let server = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let stolen = ChannelCertificate::generate(&identity()).expect("generate");
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Gullible))
        .with_client_cert_resolver(impostor(&stolen));
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", seed.port))
        .await
        .expect("connect");
    let name = ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into());
    // TLS 1.3 completes the client's side first; the listener then checks the client's
    // CertificateVerify, fails it, and aborts.
    if let Ok(mut tls) = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
    {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(WAIT, tls.read(&mut byte))
            .await
            .expect("the listener answers in time");
        assert!(matches!(read, Err(_) | Ok(0)), "{read:?}");
    }
    // No channel came of it: the next one accepted is an honest client's.
    let honest = identity();
    let _dialed = TlsDialer::new()
        .dial(&seed, &honest, WAIT)
        .await
        .expect("dial");
    let accepted = accept(&listener).await;
    assert_eq!(accepted.attested.as_deref(), Some(honest.peer_id()));
}

fn loopback() -> ServerName<'static> {
    ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into())
}

#[tokio::test]
async fn tls_1_2_is_refused_both_ways() {
    // A TLS 1.2 server presenting a genuine channel certificate: the dial fails.
    let server = identity();
    let genuine = ChannelCertificate::generate(&server).expect("generate");
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls 1.2")
        .with_no_client_auth()
        .with_single_cert(genuine.rustls_chain(), genuine.rustls_key())
        .expect("credential");
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = socket.local_addr().expect("address").port();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        if let Ok((stream, _)) = socket.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    let refused = TlsDialer::new()
        .dial(&Seed::new("127.0.0.1", port, "tls"), &identity(), WAIT)
        .await;
    assert!(
        matches!(refused, Err(TransportError::Tls(_))),
        "{refused:?}"
    );

    // A TLS 1.2 client: the listener produces no channel for it.
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls 1.2")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Gullible))
        .with_no_client_auth();
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", seed.port))
        .await
        .expect("connect");
    let refused = TlsConnector::from(Arc::new(config))
        .connect(loopback(), stream)
        .await;
    assert!(refused.is_err());
    let honest = identity();
    let _dialed = TlsDialer::new()
        .dial(&seed, &honest, WAIT)
        .await
        .expect("dial");
    assert_eq!(
        accept(&listener).await.attested.as_deref(),
        Some(honest.peer_id())
    );
}

#[tokio::test]
async fn neither_end_resumes_a_session() {
    // A client that would resume, against the listener: no ticket arrives, so every handshake
    // is full.
    let server = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let resuming = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Gullible))
            .with_no_client_auth(),
    );
    for _ in 0..2 {
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", seed.port))
            .await
            .expect("connect");
        let mut tls = TlsConnector::from(Arc::clone(&resuming))
            .connect(loopback(), stream)
            .await
            .expect("handshake");
        let accepted = accept(&listener).await;
        accepted.sender.send(vec![1]).await.expect("send");
        // Reading the frame also reads any ticket sent before it.
        let mut frame = [0u8; 5];
        tls.read_exact(&mut frame).await.expect("frame");
        assert_eq!(
            tls.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full),
            "the listener issued a ticket that resumed"
        );
    }

    // A server that would resume, against the dialer: the dialer never offers a session.
    let genuine = ChannelCertificate::generate(&server).expect("generate");
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3")
        .with_no_client_auth()
        .with_single_cert(genuine.rustls_chain(), genuine.rustls_key())
        .expect("credential");
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let seed = Seed::new(
        "127.0.0.1",
        socket.local_addr().expect("address").port(),
        "tls",
    );
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let kinds = tokio::spawn(async move {
        let mut kinds = Vec::new();
        for _ in 0..2 {
            let (stream, _) = socket.accept().await.expect("accept");
            let mut tls = acceptor.accept(stream).await.expect("handshake");
            kinds.push(tls.get_ref().1.handshake_kind());
            // A frame after the tickets, so the dialer has read them before it dials again.
            tls.write_all(&[0, 0, 0, 1, 7]).await.expect("write");
            tls.flush().await.expect("flush");
            let mut rest = Vec::new();
            let _ = tls.read_to_end(&mut rest).await;
        }
        kinds
    });
    let dialer = TlsDialer::new();
    let me = identity();
    for _ in 0..2 {
        let mut dialed = dialer.dial(&seed, &me, WAIT).await.expect("dial");
        assert_eq!(recv(&mut dialed).await, Some(vec![7]));
        dialed.closer.close();
    }
    assert_eq!(
        kinds.await.expect("server task"),
        vec![Some(HandshakeKind::Full); 2],
        "the dialer resumed a session"
    );
}

#[tokio::test]
async fn a_plain_tcp_listener_dialed_as_tls_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let seed = seed_of(&listener, "tls");
    let server = tokio::spawn(async move {
        // The ClientHello reads as a length prefix far over the frame cap: the link closes.
        let mut channel = accept(&listener).await;
        recv(&mut channel).await
    });
    let failed = TlsDialer::new().dial(&seed, &identity(), WAIT).await;
    assert!(matches!(failed, Err(TransportError::Tls(_))), "{failed:?}");
    assert_eq!(server.await.expect("server task"), None);
}

#[tokio::test]
async fn a_tls_dial_that_never_completes_its_handshake_times_out() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = silent.local_addr().expect("address").port();
    let seed = Seed::new("127.0.0.1", port, "tls");
    let failed = TlsDialer::new()
        .dial(&seed, &identity(), Duration::from_millis(300))
        .await;
    let expected = format!("tls://127.0.0.1:{port}");
    assert!(
        matches!(&failed, Err(TransportError::Timeout(what)) if *what == expected),
        "{failed:?}"
    );
}

#[tokio::test]
async fn a_tls_listener_survives_a_client_that_fails_its_handshake() {
    let server = identity();
    let listener = TlsListener::bind(":0", &server).await.expect("bind");
    let port = seed_of(&listener, "tls").port;
    let seed = Seed::new("127.0.0.1", port, "tls");
    // A plain TCP client writes garbage and leaves.
    let garbage = TcpDialer::new()
        .dial(&Seed::new("127.0.0.1", port, "tcp"), &server, WAIT)
        .await
        .expect("tcp dial");
    garbage.sender.send(vec![0xEE; 64]).await.expect("send");
    garbage.closer.close();
    let client = identity();
    let dialed = TlsDialer::new()
        .dial(&seed, &client, WAIT)
        .await
        .expect("dial");
    let accepted = accept(&listener).await;
    assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
    assert_eq!(accepted.attested.as_deref(), Some(client.peer_id()));
}

/// Whether `socket` reads the end of the stream (or a reset) within `wait`.
async fn closed_within(socket: &mut tokio::net::TcpStream, wait: Duration) -> bool {
    let mut buffer = [0u8; 64];
    matches!(
        tokio::time::timeout(wait, socket.read(&mut buffer)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// Sockets that connect and send nothing must not hold every handshake slot for the whole handshake
/// timeout (64 of them would lock every honest client out): an idle socket holds no handshake slot,
/// one address holds a bounded share, and the rest are closed at once. The idle sockets come from
/// `::1` and the honest client from `127.0.0.1` (a dual-stack listener), so the per-address bound
/// does not touch the honest dial.
#[tokio::test]
async fn idle_sockets_do_not_starve_honest_handshakes() {
    let server = identity();
    let Ok(listener) = TlsListener::bind("[::]:0", &server).await else {
        eprintln!("skipped: this host cannot bind a dual-stack listener on [::]");
        return;
    };
    let port = seed_of(&listener, "tls").port;
    let mut idle = Vec::new();
    for _ in 0..MAX_PENDING_HANDSHAKES {
        match tokio::net::TcpStream::connect(("::1", port)).await {
            Ok(socket) => idle.push(socket),
            Err(error) => {
                eprintln!("skipped: no IPv6 loopback here ({error})");
                return;
            }
        }
    }
    // Over the per-address allowance, idle sockets are closed at once: well inside the ClientHello
    // deadline, exactly those read the end of the stream.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut buffer = [0u8; 64];
    let closed_at_once = idle
        .iter()
        .filter(|socket| match socket.try_read(&mut buffer) {
            Ok(_) => true,
            Err(error) => error.kind() != std::io::ErrorKind::WouldBlock,
        })
        .count();
    assert_eq!(
        closed_at_once,
        MAX_PENDING_HANDSHAKES - MAX_HANDSHAKES_PER_ADDRESS
    );
    // An honest client is not held up by the idle ones.
    let client = identity();
    let started = tokio::time::Instant::now();
    let dialed = TlsDialer::new()
        .dial(
            &Seed::new("127.0.0.1", port, "tls"),
            &client,
            Duration::from_secs(3),
        )
        .await
        .expect("an honest dial while idle sockets wait");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the honest handshake waited {:?}",
        started.elapsed()
    );
    let accepted = accept(&listener).await;
    assert_eq!(dialed.attested.as_deref(), Some(server.peer_id()));
    assert_eq!(accepted.attested.as_deref(), Some(client.peer_id()));
    // The rest are dropped once their ClientHello is overdue.
    for socket in &mut idle {
        assert!(
            closed_within(socket, CLIENT_HELLO_TIMEOUT + Duration::from_secs(2)).await,
            "an idle socket outlived the ClientHello deadline"
        );
    }
}

/// With nobody calling `accept`, the listener stops completing handshakes once its documented limit
/// of channels waits (the accept queue plus the handshake slots held behind it), instead of piling
/// up live channels without bound; accepting one lets one more through.
#[tokio::test]
async fn a_listener_nobody_accepts_from_stops_handshaking_at_its_limit() {
    let server = identity();
    let listener = TlsListener::bind("127.0.0.1:0", &server)
        .await
        .expect("bind");
    let seed = seed_of(&listener, "tls");
    let client = identity();
    let dialer = TlsDialer::new();
    let mut held = Vec::new();
    for n in 0..ACCEPT_QUEUE + MAX_PENDING_HANDSHAKES {
        let channel = dialer
            .dial(&seed, &client, Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("dial {n} within the limit: {error}"));
        held.push(channel);
    }
    let refused = dialer
        .dial(&seed, &client, Duration::from_millis(500))
        .await;
    assert!(
        matches!(refused, Err(TransportError::Timeout(_))),
        "{refused:?}"
    );
    let first = accept(&listener).await;
    assert_eq!(first.attested.as_deref(), Some(client.peer_id()));
    let more = dialer.dial(&seed, &client, Duration::from_secs(3)).await;
    assert!(more.is_ok(), "one accepted frees one handshake: {more:?}");
}

// ---------------------------------------------------------------------------------------------
// tcp

#[tokio::test]
async fn tcp_dialer_and_listener_round_trip_unattested() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    assert_eq!(listener.scheme(), "tcp");
    let seed = seed_of(&listener, "tcp");
    assert_ne!(seed.port, 0);
    let dialer = TcpDialer::new();
    assert_eq!(dialer.schemes(), &["tcp"]);
    let mut dialed = dialer.dial(&seed, &identity(), WAIT).await.expect("dial");
    let mut accepted = accept(&listener).await;
    assert_eq!(
        (dialed.attested.as_ref(), accepted.attested.as_ref()),
        (None, None)
    );
    assert_eq!(dialed.scheme, "tcp");
    assert_eq!(dialed.remote, seed.address());
    frames_cross(&mut dialed, &mut accepted).await;
    frames_cross(&mut accepted, &mut dialed).await;
    accepted.closer.close();
    assert_eq!(recv(&mut dialed).await, None);
    assert!(dialed.sender.send(vec![1]).await.is_err());

    assert!(TcpListener::bind("no-port").await.is_err());
    assert!(TcpListener::bind(":0").await.is_ok());
    let refused_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        probe.local_addr().expect("address").port()
    };
    let refused = dialer
        .dial(
            &Seed::new("127.0.0.1", refused_port, "tcp"),
            &identity(),
            WAIT,
        )
        .await;
    assert!(matches!(refused, Err(TransportError::Io(_))), "{refused:?}");
}

// ---------------------------------------------------------------------------------------------
// channel certificates

#[test]
fn a_channel_certificate_has_the_java_shape() {
    let id = identity();
    let now_ms = 1_762_000_000_123;
    let certificate = ChannelCertificate::generate_at(&id, now_ms).expect("generate");
    let der = certificate.certificate_der();
    let (rest, parsed) = x509_parser::certificate::X509Certificate::from_der(der).expect("parses");
    assert!(rest.is_empty());
    let tbs = &parsed.tbs_certificate;
    assert_eq!(tbs.version().0, 2, "X.509 v3");
    assert!(
        tbs.extensions().is_empty(),
        "no extensions, as Java's builder"
    );
    let name = format!("CN={}", base58::multibase(id.public_raw()));
    assert_eq!(tbs.subject().to_string(), name);
    assert_eq!(tbs.issuer().to_string(), name);
    assert_eq!(
        tbs.subject()
            .iter_common_name()
            .next()
            .map(|a| a.attr_value().header.tag()),
        Some(x509_parser::der_parser::asn1_rs::Tag::Utf8String),
        "the CN is a UTF8String, as BouncyCastle's X500Name writes it"
    );
    let serial = tbs.raw_serial();
    assert!(
        serial.len() <= 10 && serial.first().is_some_and(|b| *b < 0x80),
        "{serial:?}"
    );
    assert_eq!(
        parsed.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert!(
        parsed.signature_algorithm.parameters.is_none(),
        "RFC 8410: no parameters"
    );
    assert_eq!(tbs.signature, parsed.signature_algorithm);
    let spki = &tbs.subject_pki;
    assert_eq!(spki.algorithm.algorithm.to_id_string(), "1.2.840.10045.2.1");
    assert_eq!(
        spki.algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| oid.to_id_string())
            .as_deref(),
        Some("1.2.840.10045.3.1.7"),
        "a P-256 key"
    );
    let not_before = (now_ms - 3_600_000) / 1000;
    assert_eq!(tbs.validity().not_before.timestamp(), not_before);
    assert_eq!(
        tbs.validity().not_after.timestamp(),
        not_before + 365 * 86_400
    );
    assert_eq!(certificate.attested().as_deref(), Some(id.peer_id()));
    assert!(certificate.key_der().len() > 32, "a PKCS#8 key");
    let again = ChannelCertificate::generate_at(&id, now_ms).expect("generate");
    assert_ne!(
        again.certificate_der(),
        der,
        "a fresh key and serial each time"
    );
}

#[test]
fn attest_refuses_every_subject_but_one_endorsed_cn() {
    let id = identity();
    let key = base58::multibase(id.public_raw());
    assert_eq!(
        attest(&endorsed_with_subject(cn(&key), &id)).as_deref(),
        Some(id.peer_id())
    );
    // The key without the multibase prefix, too long, or not 32 bytes.
    assert_eq!(attest(&endorsed_with_subject(cn(&key[1..]), &id)), None);
    let long = format!("{key}{}", "1".repeat(MAX_CN_CHARS + 1 - key.len()));
    assert_eq!(attest(&endorsed_with_subject(cn(&long), &id)), None);
    let short = base58::multibase(&id.public_raw()[..31]);
    assert_eq!(attest(&endorsed_with_subject(cn(&short), &id)), None);
    assert_eq!(attest(&endorsed_with_subject(cn("z0OIl"), &id)), None);
    // A further attribute, or the key under another attribute.
    let mut extra = cn(&key);
    extra.push(DnType::OrganizationName, "fleet");
    assert_eq!(attest(&endorsed_with_subject(extra, &id)), None);
    let mut organization = DistinguishedName::new();
    organization.push(DnType::OrganizationName, key.clone());
    assert_eq!(attest(&endorsed_with_subject(organization, &id)), None);
    assert_eq!(
        attest(&endorsed_with_subject(DistinguishedName::new(), &id)),
        None
    );
    // The right CN under an ECDSA signature.
    let key_pair = KeyPair::generate().expect("p-256");
    let mut params = CertificateParams::default();
    params.distinguished_name = cn(&key);
    let ecdsa = params.self_signed(&key_pair).expect("self-signed");
    assert_eq!(attest(ecdsa.der()), None);
}

#[test]
fn attest_on_malformed_der_returns_none_without_panicking() {
    let id = identity();
    let genuine = ChannelCertificate::generate(&id).expect("generate");
    let der = genuine.certificate_der();
    assert_eq!(attest(der).as_deref(), Some(id.peer_id()));

    let mut hostile: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x30],
        vec![0x30, 0x00],
        vec![0x30, 0x80, 0x00, 0x00],
        vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
        vec![
            0x30, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
        [0x30, 0x80].repeat(50_000),
        [0x30, 0x81, 0xFF].repeat(1_000),
        vec![0xFF; 4096],
    ];
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    for length in [1, 2, 7, 64, 300, 1024] {
        hostile.push(
            (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 56) as u8
                })
                .collect(),
        );
    }
    // Every truncation, trailing bytes, and every single-bit flip of a genuine certificate.
    hostile.extend((0..der.len()).map(|n| der[..n].to_vec()));
    hostile.push([der, &[0x00][..]].concat());
    for at in 0..der.len() {
        for bit in [0x01, 0x80] {
            let mut flipped = der.to_vec();
            flipped[at] ^= bit;
            hostile.push(flipped);
        }
    }
    for bytes in &hostile {
        assert_eq!(
            attest(bytes),
            None,
            "{}",
            hex::encode(&bytes[..bytes.len().min(32)])
        );
    }
}

// ---------------------------------------------------------------------------------------------
// cross-checks against the Java reference

/// Kills the child process when the test ends, however it ends.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn java_classpath() -> String {
    let dir = std::env::var("AGENTSPACES_JAVA_SEED_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/java-seed")
        });
    let jars = std::fs::read_to_string(dir.join("target/classpath.txt"))
        .expect("interop/java-seed built: mvn -q -o compile dependency:build-classpath");
    format!("{}:{}", dir.join("target/classes").display(), jars.trim())
}

#[tokio::test]
#[ignore = "needs java and the built interop/java-seed"]
async fn a_tls_dial_to_the_java_seed_attests_its_peer_id() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        probe.local_addr().expect("address").port()
    };
    let mut child = Child(
        Command::new("java")
            .arg("-cp")
            .arg(java_classpath())
            .arg("ai.badmonkey.agentspaces.interop.Seed")
            .arg(port.to_string())
            .arg("--tls")
            .arg("--require-attestation")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("java"),
    );
    let stdout = child.0.stdout.take().expect("stdout");
    let line = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).map(|_| line)
        }),
    )
    .await
    .expect("the seed starts in time")
    .expect("reader")
    .expect("a line");
    let event: serde_json::Value = serde_json::from_str(&line).expect("json");
    let peer = event["peer"]
        .as_str()
        .expect("the seed's PeerID")
        .to_owned();
    assert_eq!(event["tls"], serde_json::Value::Bool(true));

    let seed = Seed::new("127.0.0.1", port, "tls");
    let me = identity();
    let mut dialed = TlsDialer::new()
        .dial(&seed, &me, WAIT)
        .await
        .expect("dial the seed");
    assert_eq!(dialed.attested.as_deref(), Some(peer.as_str()));
    // The seed accepted the handshake, our certificate included: the link stays up.
    let quiet = tokio::time::timeout(Duration::from_millis(500), dialed.receiver.recv()).await;
    assert!(quiet.is_err(), "the seed closed the link: {quiet:?}");
    if let Some(stdin) = child.0.stdin.as_mut() {
        let _ = stdin.write_all(b"quit\n");
    }
}

#[test]
#[ignore = "needs java and the built interop/java-seed"]
fn java_attests_a_rust_channel_certificate_and_refuses_a_forged_one() {
    let source = r#"
import ai.badmonkey.agentspaces.identity.ChannelCertificate;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class AttestCheck {
    public static void main(String[] args) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (String path : args) {
            try (FileInputStream in = new FileInputStream(path)) {
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
                System.out.println(ChannelCertificate.attest(certificate)
                        .map(p -> p.value()).orElse("-"));
            }
        }
    }
}
"#;
    let dir = std::env::temp_dir().join(format!("asrs-attest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let id = identity();
    let genuine = ChannelCertificate::generate(&id).expect("generate");
    let forged = ChannelCertificate::build(id.public_raw(), &identity(), 0).expect("build");
    std::fs::write(dir.join("AttestCheck.java"), source).expect("write");
    std::fs::write(dir.join("genuine.der"), genuine.certificate_der()).expect("write");
    std::fs::write(dir.join("forged.der"), forged.certificate_der()).expect("write");
    let output = std::process::Command::new("java")
        .arg("-cp")
        .arg(java_classpath())
        .arg(dir.join("AttestCheck.java"))
        .arg(dir.join("genuine.der"))
        .arg(dir.join("forged.der"))
        .output()
        .expect("java");
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![id.peer_id(), "-"],
        "Java's ChannelCertificate.attest"
    );
}
