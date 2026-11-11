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

//! The integrated path from settings to a joined peer over real sockets: `PeerConfig::from_settings`
//! (settings, keystore identity, default dialers, system clock), `Peer::join` over `tcp` and over
//! attested `tls`, `Peer::join_from_env` in a child process with its own environment, and the
//! refusals that stop a join before anything is dialed. One ignored test joins the Java seed over
//! attested TLS (`cargo test -p agentspaces --test join -- --ignored`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use agentspaces::clock::{Clock, SystemClock};
use agentspaces::config::{self, ConfigError, PeerSettings};
use agentspaces::group::{GroupSpec, Profile};
use agentspaces::keystore::{self, KeystoreError};
use agentspaces::peer::{LinkInfo, Peer, PeerConfig, PeerError, default_dialers};
use agentspaces::transport::tcp::TcpListener;
use agentspaces::transport::tls::TlsListener;
use agentspaces::transport::{Channel, Closer, FrameSender, Listener};
use agentspaces::wire::bodies::{self, KIND_ACK, KIND_CHANNEL_HELLO, KIND_DIGEST, KIND_PING};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::envelope::{self, Auth};
use agentspaces::wire::hlc::Hlc;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::seed::{Seed, parse_seed};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long a test waits for something that should happen at once.
const PATIENCE: Duration = Duration::from_secs(10);

/// The founding text the socket seeds' group is founded from.
const FOUNDING: &str = "agentspaces-rust-join-test-v1";

/// The marker that turns [`join_from_env_child`] from a no-op into the child half of
/// [`a_peer_joins_from_the_environment`].
const CHILD_MARKER: &str = "AGENTSPACES_JOIN_FROM_ENV_CHILD";

fn fresh() -> Identity {
    Identity::generate().expect("identity")
}

fn group() -> GroupSpec {
    GroupSpec::FoundingText(FOUNDING.to_owned())
}

fn group_id() -> String {
    group().group_id().expect("a text group has an id")
}

/// A fresh, empty directory under the target directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("join-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Settings for the test group through `seed`, with quick redials.
fn settings(seed: &Seed) -> PeerSettings {
    let mut settings = PeerSettings::new(group(), vec![seed.clone()]);
    settings.reconnect_interval = Duration::from_millis(50);
    settings.reconnect_window = Duration::from_secs(10);
    settings
}

/// The stream names a DIGEST asks for.
fn digest_streams(body: &[u8]) -> Vec<String> {
    bodies::parse_digest(body)
        .map(|digests| {
            digests
                .keys()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Waits until `check` holds, polling every 10 ms; panics naming `what` after [`PATIENCE`].
async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + PATIENCE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ------------------------------------------------------------------------------ the seed

/// One verified frame a [`SocketSeed`] received.
#[derive(Debug, Clone)]
struct Got {
    link: usize,
    env: Map,
    auth: Auth,
}

impl Got {
    fn kind(&self) -> &str {
        self.text("kind").unwrap_or_default()
    }

    fn text(&self, field: &str) -> Option<&str> {
        self.env.get(field).and_then(Value::as_str)
    }

    fn body(&self) -> &[u8] {
        self.env
            .get("body")
            .and_then(Value::as_bytes)
            .unwrap_or_default()
    }

    fn rumor_stream(&self) -> Option<String> {
        (self.kind() == bodies::KIND_RUMOR)
            .then(|| bodies::parse_rumor(self.body()))
            .flatten()
            .map(|rumor| rumor.stream_id)
    }
}

#[derive(Default)]
struct SeedState {
    links: Vec<(FrameSender, Closer, Option<String>)>,
    got: Vec<Got>,
    malformed: usize,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A scripted seed on a real socket (`tcp` or `tls`): it accepts links, verifies and records
/// every frame (with how it was authenticated), and sends signed or bare frames it is told to.
struct SocketSeed {
    identity: Identity,
    group: String,
    seed: Seed,
    state: Arc<Mutex<SeedState>>,
    hlc: Mutex<Hlc>,
    accept: JoinHandle<()>,
}

impl SocketSeed {
    fn start(listener: Box<dyn Listener>, identity: Identity, group: &str) -> Self {
        let scheme = listener.scheme();
        let seed = parse_seed(&format!("{scheme}://{}", listener.local_address()), scheme)
            .expect("the listener's seed");
        let state = Arc::new(Mutex::new(SeedState::default()));
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&state)));
        Self {
            hlc: Mutex::new(Hlc::new(identity.peer_id()).expect("a PeerID is a stamp node")),
            identity,
            group: group.to_owned(),
            seed,
            state,
            accept,
        }
    }

    async fn tcp(group: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        Self::start(Box::new(listener), fresh(), group)
    }

    async fn tls(group: &str) -> Self {
        let identity = fresh();
        let listener = TlsListener::bind("127.0.0.1:0", &identity)
            .await
            .expect("bind tls");
        Self::start(Box::new(listener), identity, group)
    }

    fn peer_id(&self) -> &str {
        self.identity.peer_id()
    }

    fn links(&self) -> usize {
        lock(&self.state).links.len()
    }

    fn attested(&self, link: usize) -> Option<String> {
        lock(&self.state)
            .links
            .get(link)
            .and_then(|(_, _, attested)| attested.clone())
    }

    fn link_closed(&self, link: usize) -> bool {
        lock(&self.state)
            .links
            .get(link)
            .is_some_and(|(sender, closer, _)| closer.is_closed() || sender.is_closed())
    }

    fn malformed(&self) -> usize {
        lock(&self.state).malformed
    }

    fn got(&self) -> Vec<Got> {
        lock(&self.state).got.clone()
    }

    async fn wait_for(&self, what: &str, ready: impl Fn(&[Got]) -> bool) -> Vec<Got> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            {
                let state = lock(&self.state);
                if ready(&state.got) {
                    return state.got.clone();
                }
            }
            if Instant::now() >= deadline {
                let kinds: Vec<(usize, String)> = self
                    .got()
                    .iter()
                    .map(|got| (got.link, got.kind().to_owned()))
                    .collect();
                panic!("timed out waiting for {what}; received {kinds:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits for a DIGEST on `link` from `from` asking for `stream`.
    async fn wait_digest(&self, link: usize, from: &str, stream: &str) {
        self.wait_for(&format!("a DIGEST for {stream}"), |got| {
            got.iter().any(|g| {
                g.link == link
                    && g.kind() == KIND_DIGEST
                    && g.text("from") == Some(from)
                    && digest_streams(g.body()).iter().any(|s| s == stream)
            })
        })
        .await;
    }

    fn envelope(&self, kind: &str, body: &[u8], to: Option<&str>) -> Map {
        let stamp = lock(&self.hlc).now(SystemClock.now_ms());
        envelope::envelope(&self.group, kind, self.peer_id(), &stamp, body, to)
    }

    async fn send_raw(&self, link: usize, frame: Vec<u8>) {
        let sender = lock(&self.state)
            .links
            .get(link)
            .map(|(sender, _, _)| sender.clone());
        let sender = sender.unwrap_or_else(|| panic!("no link {link}"));
        sender.send(frame).await.expect("the seed's send");
    }

    async fn ping_signed(&self, link: usize, nonce: i64, to: Option<&str>) {
        let env = self.envelope(KIND_PING, &bodies::ping_body(nonce), to);
        self.send_raw(link, envelope::encode_frame(&env, &self.identity))
            .await;
    }

    async fn ping_bare(&self, link: usize, nonce: i64, to: Option<&str>) {
        let env = self.envelope(KIND_PING, &bodies::ping_body(nonce), to);
        self.send_raw(link, envelope::encode_bare_frame(&env)).await;
    }

    async fn wait_ack(&self, link: usize, nonce: i64) {
        self.wait_for(&format!("the ACK of {nonce}"), |got| {
            got.iter().any(|g| {
                g.link == link && g.kind() == KIND_ACK && bodies::parse_ack(g.body()) == Some(nonce)
            })
        })
        .await;
    }
}

impl Drop for SocketSeed {
    fn drop(&mut self) {
        self.accept.abort();
        for (_, closer, _) in &lock(&self.state).links {
            closer.close();
        }
    }
}

async fn accept_loop(listener: Box<dyn Listener>, state: Arc<Mutex<SeedState>>) {
    while let Some(accepted) = listener.accept().await {
        let Ok(channel) = accepted else { continue };
        let Channel {
            attested,
            sender,
            mut receiver,
            closer,
            ..
        } = channel;
        let link = {
            let mut state = lock(&state);
            state.links.push((sender, closer, attested.clone()));
            state.links.len() - 1
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(frame) = receiver.recv().await {
                let decoded = envelope::decode_frame_detailed(&frame, attested.as_deref(), None);
                let mut state = lock(&state);
                match decoded {
                    Some((env, auth)) => state.got.push(Got { link, env, auth }),
                    None => state.malformed += 1,
                }
            }
        });
    }
}

// ------------------------------------------------------------------------------ settings

#[test]
fn from_settings_carries_the_settings_the_default_dialers_and_the_identity() {
    let seed = parse_seed("tls://127.0.0.1:7500", "tcp").expect("seed");
    let mut settings = PeerSettings::new(group(), vec![seed.clone()]);
    settings.reconnect_interval = Duration::from_millis(250);
    settings.reconnect_window = Duration::from_secs(42);
    settings.peer_ad_interval = Duration::from_secs(7);
    settings.spaces = vec!["tasks".to_owned()];
    let identity = fresh();

    let config = PeerConfig::from_settings(&settings, identity.clone()).expect("valid settings");
    assert_eq!(config.identity.peer_id(), identity.peer_id());
    assert_eq!(config.group, group());
    assert_eq!(config.seeds, [seed]);
    assert_eq!(config.reconnect_interval, Duration::from_millis(250));
    assert_eq!(config.reconnect_window, Duration::from_secs(42));
    assert_eq!(config.peer_ad_interval, Duration::from_secs(7));
    let schemes: Vec<Vec<&str>> = config
        .dialers
        .iter()
        .map(|dialer| dialer.schemes().to_vec())
        .collect();
    assert_eq!(schemes, [["tcp"], ["tls"]]);
    let defaults: Vec<Vec<&str>> = default_dialers()
        .iter()
        .map(|dialer| dialer.schemes().to_vec())
        .collect();
    assert_eq!(schemes, defaults);
    // The wall clock is the system's.
    let drift = (config.clock.now_ms() - SystemClock.now_ms()).abs();
    assert!(
        drift < 60_000,
        "the clock is the system clock ({drift} ms off)"
    );
    // What PeerConfig::new defaults stays.
    let plain = PeerConfig::new(fresh(), group());
    assert_eq!(config.dial_timeout, plain.dial_timeout);
    assert_eq!(config.join_timeout, plain.join_timeout);
    assert_eq!(config.send_queue_bytes, plain.send_queue_bytes);
    assert_eq!(config.founder, None);
}

#[test]
fn from_settings_refuses_a_plaintext_seed_outside_loopback_unless_dev_local() {
    let remote = parse_seed("tcp://10.20.30.40:7500", "tcp").expect("seed");
    let mut settings = PeerSettings::new(group(), vec![remote.clone()]);
    match PeerConfig::from_settings(&settings, fresh()) {
        Err(ConfigError::PlaintextSeed { seed, profile }) => {
            assert_eq!(seed, remote);
            assert_eq!(profile, Profile::Mtls);
        }
        other => panic!("expected PlaintextSeed, got {other:?}"),
    }
    settings.profile = Profile::DevLocal;
    assert!(PeerConfig::from_settings(&settings, fresh()).is_ok());
    // Loopback plaintext is allowed under mtls; so is any tls seed.
    for seed in [
        "tcp://127.0.0.1:7500",
        "tcp://localhost:7500",
        "tls://10.20.30.40:7500",
    ] {
        let settings = PeerSettings::new(group(), vec![parse_seed(seed, "tcp").expect("seed")]);
        assert!(
            PeerConfig::from_settings(&settings, fresh()).is_ok(),
            "{seed} under mtls"
        );
    }
    let mut zero = PeerSettings::new(group(), vec![remote]);
    zero.profile = Profile::DevLocal;
    zero.peer_ad_interval = Duration::ZERO;
    assert!(matches!(
        PeerConfig::from_settings(&zero, fresh()),
        Err(ConfigError::ZeroInterval {
            field: "peer_ad_interval"
        })
    ));
}

#[tokio::test]
async fn join_refuses_bad_settings_and_a_broken_keystore_before_dialing() {
    // A plaintext seed outside loopback: refused before any dial (the address is unroutable, so
    // a dial would hang for the dial timeout instead of answering at once).
    let remote = parse_seed("tcp://10.255.255.1:7500", "tcp").expect("seed");
    let plaintext = PeerSettings::new(group(), vec![remote]);
    let refused = tokio::time::timeout(Duration::from_secs(1), Peer::join_as(&plaintext, fresh()))
        .await
        .expect("refused at once");
    assert!(
        matches!(
            refused,
            Err(PeerError::Config(ConfigError::PlaintextSeed { .. }))
        ),
        "{refused:?}"
    );

    // A half-written keystore: refused, never repaired, nothing dialed.
    let scratch = Scratch::new("half");
    std::fs::create_dir_all(scratch.path()).expect("mkdir");
    std::fs::write(scratch.path().join(keystore::PUBLIC_FILE), [7u8; 32]).expect("write");
    let seed = SocketSeed::tcp(&group_id()).await;
    let mut settings = settings(&seed.seed);
    settings.keystore = Some(scratch.path().to_owned());
    let refused = Peer::join(&settings).await;
    assert!(
        matches!(
            refused,
            Err(PeerError::Keystore(KeystoreError::HalfPair { .. }))
        ),
        "{refused:?}"
    );
    assert!(!scratch.path().join(keystore::PRIVATE_FILE).exists());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(seed.links(), 0, "nothing was dialed");

    // A space the peer cannot open (an empty name) closes the peer it started.
    let mut settings = self::settings(&seed.seed);
    settings.spaces = vec!["tasks".to_owned(), String::new()];
    let refused = Peer::join_as(&settings, fresh()).await;
    assert!(
        matches!(refused, Err(PeerError::InvalidArgument(_))),
        "{refused:?}"
    );
    assert_eq!(seed.links(), 1);
    eventually("the refused peer's link to close", || {
        let closed = seed.link_closed(0);
        async move { closed }
    })
    .await;
}

// ------------------------------------------------------------------------------ joins

#[tokio::test]
async fn a_peer_joins_over_tcp_as_its_keystore_identity_and_pulls_its_spaces() {
    let scratch = Scratch::new("tcp");
    let seed = SocketSeed::tcp(&group_id()).await;
    let mut settings = settings(&seed.seed);
    settings.keystore = Some(scratch.path().join("keys"));
    settings.spaces = vec!["tasks".to_owned(), "results".to_owned()];

    let peer = Peer::join(&settings).await.expect("join");
    let minted = keystore::load_or_create(&scratch.path().join("keys")).expect("the keystore");
    assert_eq!(peer.peer_id(), minted.peer_id(), "the keystore's identity");
    assert_eq!(peer.group_id(), group_id());
    assert_eq!(
        peer.link(),
        Some(LinkInfo {
            scheme: "tcp".to_owned(),
            remote: seed.seed.address(),
            attested: None,
        })
    );
    // The introduction, then a pull of each space.
    seed.wait_for("the introduction", |got| {
        got.iter().any(|g| {
            g.text("from") == Some(peer.peer_id()) && g.rumor_stream().as_deref() == Some("peers")
        })
    })
    .await;
    seed.wait_digest(0, peer.peer_id(), "space:tasks").await;
    seed.wait_digest(0, peer.peer_id(), "space:results").await;
    assert!(seed.got().iter().all(|g| g.auth == Auth::Signed));
    assert_eq!(seed.attested(0), None);
    // The seed's probe is answered, and the seed becomes a member.
    seed.ping_signed(0, 41, Some(peer.peer_id())).await;
    seed.wait_ack(0, 41).await;
    eventually("the seed as a member", || {
        let peer = peer.clone();
        let seed_id = seed.peer_id().to_owned();
        async move { peer.members().await.contains(&seed_id) }
    })
    .await;
    assert_eq!(seed.malformed(), 0);
    let first = peer.peer_id().to_owned();
    peer.close().await.expect("close");

    // A second join on the same keystore is the same peer.
    let again = Peer::join(&settings).await.expect("join again");
    assert_eq!(again.peer_id(), first);
    seed.wait_digest(1, &first, "space:tasks").await;
    again.close().await.expect("close");
}

#[tokio::test]
async fn a_peer_joins_over_attested_tls_and_accepts_bare_frames_from_its_seed() {
    let seed = SocketSeed::tls(&group_id()).await;
    let identity = fresh();
    let mut settings = settings(&seed.seed);
    assert_eq!(settings.profile, Profile::Mtls);
    settings.spaces = vec!["tasks".to_owned()];

    let peer = Peer::join_as(&settings, identity.clone())
        .await
        .expect("join");
    // Both ends attested: the peer holds the seed's PeerID, the seed the peer's.
    assert_eq!(
        peer.link(),
        Some(LinkInfo {
            scheme: "tls".to_owned(),
            remote: seed.seed.address(),
            attested: Some(seed.peer_id().to_owned()),
        })
    );
    seed.wait_digest(0, peer.peer_id(), "space:tasks").await;
    assert_eq!(seed.attested(0).as_deref(), Some(identity.peer_id()));
    // On an attested link the peer announces CHANNEL_HELLO to the seed, fully signed.
    let got = seed
        .wait_for("CHANNEL_HELLO", |got| {
            got.iter().any(|g| g.kind() == KIND_CHANNEL_HELLO)
        })
        .await;
    let hello = got
        .iter()
        .find(|g| g.kind() == KIND_CHANNEL_HELLO)
        .expect("the hello");
    assert_eq!(hello.auth, Auth::Signed);
    assert_eq!(hello.text("to"), Some(seed.peer_id()));
    let body = bodies::parse_channel_hello(hello.body()).expect("a hello body");
    assert!(body.accepts_bare);
    assert_eq!(body.attested_remote, seed.peer_id());
    // A bare frame from the attested seed is accepted on the strength of the TLS attestation.
    seed.ping_bare(0, 77, Some(peer.peer_id())).await;
    seed.wait_ack(0, 77).await;
    let counters = peer.counters().await;
    assert_eq!(counters.attested_frames, 1);
    assert_eq!(counters.malformed, 0);
    assert_eq!(seed.malformed(), 0);
    peer.close().await.expect("close");
}

#[tokio::test]
async fn a_peer_joins_from_the_environment() {
    let scratch = Scratch::new("env");
    let keys = scratch.path().join("keys");
    let expected = keystore::load_or_create(&keys).expect("mint the keystore");
    let seed = SocketSeed::tcp(&group_id()).await;

    let mut command = std::process::Command::new(std::env::current_exe().expect("this test"));
    command.args([
        "--ignored",
        "--exact",
        "join_from_env_child",
        "--nocapture",
        "--test-threads=1",
    ]);
    // Every variable the configuration reads is cleared, and HOME is a scratch directory, so a
    // developer's ~/.config/agentspaces/fleet.yaml is never read by the child.
    for variable in config::CONFIG_VARIABLES {
        command.env_remove(variable);
    }
    command
        .env(config::ENV_HOME, scratch.path())
        .env(CHILD_MARKER, "1")
        // No scheme: the seed dials tcp; loopback plaintext passes the default mtls profile.
        .env(config::ENV_SEEDS, seed.seed.address())
        .env(config::ENV_GROUP, FOUNDING)
        .env(config::ENV_KEYSTORE, &keys)
        .env(config::ENV_SPACES, "tasks, results")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command.spawn().expect("spawn the child");

    seed.wait_digest(0, expected.peer_id(), "space:tasks").await;
    seed.wait_digest(0, expected.peer_id(), "space:results")
        .await;
    // The child waits until the seed is a member before it reports and exits.
    seed.ping_signed(0, 5, Some(expected.peer_id())).await;
    let output = tokio::time::timeout(
        PATIENCE * 2,
        tokio::task::spawn_blocking(move || child.wait_with_output()),
    )
    .await
    .expect("the child exits in time")
    .expect("the waiter")
    .expect("the child's output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child failed: {}\n{stdout}\n{stderr}",
        output.status
    );
    let line = format!(
        "JOINED {} {} {}",
        expected.peer_id(),
        group_id(),
        seed.peer_id()
    );
    assert!(stdout.contains(&line), "{line:?} not in {stdout}");
}

/// The child half of [`a_peer_joins_from_the_environment`]: a no-op unless [`CHILD_MARKER`] is
/// set, so it passes in an ordinary `--ignored` run.
#[tokio::test]
#[ignore = "the child process of a_peer_joins_from_the_environment"]
async fn join_from_env_child() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    let peer = Peer::join_from_env()
        .await
        .expect("join from the environment");
    let deadline = Instant::now() + PATIENCE;
    let seed = loop {
        let other = peer
            .members()
            .await
            .into_iter()
            .find(|member| member != peer.peer_id());
        if let Some(other) = other {
            break other;
        }
        assert!(Instant::now() < deadline, "the seed never became a member");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    println!("JOINED {} {} {seed}", peer.peer_id(), peer.group_id());
    peer.close().await.expect("close");
}

// ------------------------------------------------------------------------------ java

struct JavaSeed {
    child: std::process::Child,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl JavaSeed {
    /// Starts the seed with `args` and returns it with its first line (the `listening` event).
    async fn start(args: &[&str]) -> (Self, serde_json::Value) {
        use std::io::BufRead;
        let dir = std::env::var("AGENTSPACES_JAVA_SEED_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/java-seed")
            });
        let jars = std::fs::read_to_string(dir.join("target/classpath.txt"))
            .expect("interop/java-seed built: mvn -q -o compile dependency:build-classpath");
        let classpath = format!("{}:{}", dir.join("target/classes").display(), jars.trim());
        let mut child = std::process::Command::new("java")
            .arg("-cp")
            .arg(classpath)
            .arg("ai.badmonkey.agentspaces.interop.Seed")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("java");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, lines) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut seed = Self { child, lines };
        let first = tokio::time::timeout(Duration::from_secs(60), seed.lines.recv())
            .await
            .expect("the Java seed starts in time")
            .expect("the Java seed listens");
        let event = serde_json::from_str(&first).expect("the seed's first line is JSON");
        (seed, event)
    }

    async fn ask(&mut self, command: &str) -> serde_json::Value {
        use std::io::Write;
        let stdin = self.child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .expect("write to the seed");
        let line = tokio::time::timeout(Duration::from_secs(30), self.lines.recv())
            .await
            .expect("an answer in time")
            .expect("the seed is running");
        serde_json::from_str(&line).expect("JSON")
    }
}

impl Drop for JavaSeed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
#[ignore = "needs java and the built interop/java-seed"]
async fn a_peer_joins_the_java_seed_over_attested_tls_from_settings() {
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        probe.local_addr().expect("address").port()
    };
    let (mut java, event) = JavaSeed::start(&[
        &port.to_string(),
        "--tls",
        "--require-attestation",
        "--channel-auth",
        "ATTESTED",
        "--founding",
        FOUNDING,
    ])
    .await;
    let java_peer = event["peer"]
        .as_str()
        .expect("the seed's PeerID")
        .to_owned();
    assert_eq!(event["group"].as_str(), Some(group_id().as_str()));

    let scratch = Scratch::new("java");
    let seed = Seed::new("127.0.0.1", port, "tls");
    let mut settings = settings(&seed);
    settings.keystore = Some(scratch.path().join("keys"));
    settings.spaces = vec!["tasks".to_owned()];
    settings.peer_ad_interval = Duration::from_secs(2);
    let peer = Peer::join(&settings).await.expect("join the Java seed");
    assert_eq!(
        peer.link().and_then(|link| link.attested).as_deref(),
        Some(java_peer.as_str())
    );

    // Java lists the Rust peer; the Rust peer learns the Java seed.
    let mut listed = false;
    for _ in 0..100 {
        let members = java.ask("members").await;
        if members["members"]
            .as_array()
            .is_some_and(|m| m.iter().any(|v| v.as_str() == Some(peer.peer_id())))
        {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(listed, "Java lists the Rust peer");
    eventually("the Java seed as the seed peer", || {
        let peer = peer.clone();
        let java_peer = java_peer.clone();
        async move { peer.seed_peer().await.as_deref() == Some(java_peer.as_str()) }
    })
    .await;

    // A Java write folds in Rust.
    let written = java.ask("write-task alpha 3").await;
    assert_eq!(written["written"], "alpha");
    let deadline = Instant::now() + PATIENCE;
    let type_name = loop {
        let states = peer.space_states("tasks").await;
        let found = states.iter().find_map(|state| {
            state
                .get("record")
                .and_then(|record| record.get("type"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        if let Some(found) = found {
            break found;
        }
        assert!(
            Instant::now() < deadline,
            "Java's write never folded in Rust"
        );
        peer.pull_space("tasks").await.expect("pull");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    // A Rust write reaches Java.
    let payload = agentspaces::wire::cbor_map! { "topic" => "beta", "priority" => 5 };
    peer.write_entry("tasks", &type_name, payload, 600_000, Map::new(), None)
        .await
        .expect("write");
    let mut java_has = false;
    for _ in 0..100 {
        let tasks = java.ask("tasks").await;
        if tasks["tasks"]
            .as_array()
            .is_some_and(|t| t.iter().any(|v| v["topic"] == "beta"))
        {
            java_has = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(java_has, "Java reads the Rust write");

    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    let frames = java.ask("frames").await;
    println!("java frames {frames}; rust counters {counters:?}");
    // Under --channel-auth ATTESTED, after the Rust peer's CHANNEL_HELLO, Java sends bare frames
    // on the attested link, and Rust accepts them on the strength of the TLS attestation.
    assert!(
        frames["bare"].as_u64().unwrap_or(0) > 0,
        "Java sent no bare frames: {frames}"
    );
    assert!(
        counters.attested_frames > 0,
        "Java sent bare frames ({frames}) that Rust did not accept: {counters:?}"
    );
    peer.close().await.expect("close");
    let _ = java.ask("quit").await;
}
