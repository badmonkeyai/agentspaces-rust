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

//! The Rust peer against the Java reference node: each test starts its own scripted Java seed
//! (`interop/java-seed`, `ai.badmonkey.agentspaces.interop.Seed`) on a free port, drives it over
//! its standard input (one command per line, one JSON object per line back), and checks what
//! both sides see: membership over `tcp` and attested `tls`, writes crossing both ways, a take
//! and completion made in Java folding in Rust, clean refusals of a mismatched scheme, and a
//! reconnect to a restarted seed.
//!
//! The `x` scenarios drive the Space API ([`agentspaces::space`]) against Java: a Rust take and
//! completion (peer-signed and agent-signed) Java honours, a write renewal and cancellation and
//! a renewed take crossing to Java, a Rust watch of a Java take, and the typed layer
//! (`#[derive(Entry)]` types of the seed's records) both ways.
//!
//! The seed is built on first use with `mvn -q -o` when `target/classes` or
//! `target/classpath.txt` is missing (or the source is newer than its class). When `java` or the
//! build is unavailable each test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set,
//! in which case it fails. `JAVA_HOME` picks the `java` binary when set;
//! `AGENTSPACES_JAVA_SEED_DIR` points at another copy of the seed project.
//!
//! The Java seed's standard error goes to a log file under the target directory; a failing test
//! prints its tail.

use std::fmt::Debug;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use agentspaces::entry;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, PeerError, PeerEvent, default_dialers};
use agentspaces::space::{EventKind, Fleet, Lease, Template, TypedEvent, TypedEvents};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::filters::Matcher;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::seed::Seed;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;

/// The founding text of the seed's group.
const FOUNDING: &str = "agentspaces-rust-interop-v1";
/// The seed's replicated space.
const SPACE: &str = "tasks";
/// The entry type of the seed's `Task(String topic, int priority)` record.
const TASK_TYPE: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
/// The entry type of the seed's `Result(String topic, String summary, String worker)` record.
const RESULT_TYPE: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
/// The seed's main class.
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
/// The seed's class file and source, relative to the seed project.
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
/// The seed's dependency classpath, relative to the seed project.
const SEED_CLASSPATH: &str = "target/classpath.txt";

/// The longest any poll waits for something to happen.
const DEADLINE: Duration = Duration::from_secs(20);
/// The pause between polls.
const POLL: Duration = Duration::from_millis(100);
/// How long a JVM may take to start and print its first line.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one command to the seed may take (`take-task 5000` waits up to five seconds).
const ANSWER: Duration = Duration::from_secs(20);
/// The Rust peer's dial bound in these tests.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
/// The Rust peer's pause between redial rounds in these tests.
const RECONNECT_INTERVAL: Duration = Duration::from_millis(500);
/// The Rust peer's redial window in these tests.
const RECONNECT_WINDOW: Duration = Duration::from_secs(60);
/// What a refused dial may take beyond [`DIAL_TIMEOUT`] (a JVM under load answers slowly).
const REFUSAL_SLACK: Duration = Duration::from_secs(2);
/// How long a member must stay listed through the seed's probe rounds.
const STAYS: Duration = Duration::from_secs(5);

// ------------------------------------------------------------------------------ preparing

/// Whether a test that cannot run the Java seed must fail rather than pass with a note.
fn required() -> bool {
    std::env::var("ASPACE_INTEROP_REQUIRED").as_deref() == Ok("1")
}

/// The seed project directory.
fn seed_dir() -> PathBuf {
    std::env::var_os("AGENTSPACES_JAVA_SEED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/java-seed"))
}

/// The `java` to run: `$JAVA_HOME/bin/java` when that exists, else `java` on the path.
fn java_bin() -> PathBuf {
    std::env::var_os("JAVA_HOME")
        .map(|home| PathBuf::from(home).join("bin/java"))
        .filter(|java| java.is_file())
        .unwrap_or_else(|| PathBuf::from("java"))
}

/// The classpath that runs the seed, or why it cannot run; prepared once per test binary.
fn seed_classpath() -> Result<String, String> {
    static PREPARED: OnceLock<Result<String, String>> = OnceLock::new();
    PREPARED.get_or_init(prepare_seed).clone()
}

/// Checks `java`, builds the seed when it is not built (or older than its source), and reads its
/// classpath.
fn prepare_seed() -> Result<String, String> {
    let java = java_bin();
    match Command::new(&java)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(format!(
                "`{} -version` exited with {status}",
                java.display()
            ));
        }
        Err(error) => return Err(format!("`{}` does not run: {error}", java.display())),
    }
    let dir = seed_dir();
    let class = dir.join(SEED_CLASS);
    let listed = dir.join(SEED_CLASSPATH);
    if !class.is_file() || !listed.is_file() || newer(&dir.join(SEED_SOURCE), &class) {
        mvn(&dir, &["-q", "-o", "compile"])?;
        mvn(
            &dir,
            &[
                "-q",
                "-o",
                "dependency:build-classpath",
                "-Dmdep.outputFile=target/classpath.txt",
            ],
        )?;
    }
    let jars = std::fs::read_to_string(&listed)
        .map_err(|error| format!("{} unreadable: {error}", listed.display()))?;
    Ok(format!(
        "{}:{}",
        dir.join("target/classes").display(),
        jars.trim()
    ))
}

/// Whether `source` was modified after `built` (false when either time is unknown).
fn newer(source: &Path, built: &Path) -> bool {
    let modified =
        |path: &Path| -> Option<SystemTime> { std::fs::metadata(path).ok()?.modified().ok() };
    matches!((modified(source), modified(built)), (Some(source), Some(built)) if source > built)
}

/// Runs `mvn args` in `dir`.
fn mvn(dir: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("mvn")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("`mvn` does not run: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let mut said = String::from_utf8_lossy(&output.stdout).into_owned();
    said.push_str(&String::from_utf8_lossy(&output.stderr));
    Err(format!(
        "`mvn {}` in {} exited with {}: {}",
        args.join(" "),
        dir.display(),
        output.status,
        tail(&said, 20)
    ))
}

/// The last `lines` lines of `text`.
fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// The seed's classpath, or (when the seed cannot run) a note and an early return from the
/// test; a failure under `ASPACE_INTEROP_REQUIRED=1`.
macro_rules! classpath_or_skip {
    () => {
        match seed_classpath() {
            Ok(classpath) => classpath,
            Err(why) => {
                assert!(!required(), "the Java interop seed cannot run: {why}");
                eprintln!("skipping: the Java interop seed cannot run: {why}");
                return;
            }
        }
    };
}

/// A port nothing listens on at the moment.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

// ------------------------------------------------------------------------------ the seed

/// A running Java seed, killed when dropped (also when the test fails).
struct JavaSeed {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::UnboundedReceiver<String>,
    log: PathBuf,
    port: u16,
    peer: String,
    group: String,
}

impl JavaSeed {
    /// Starts a seed with `args` on a free port (another one if the port was taken meanwhile).
    async fn start(classpath: &str, args: &[&str]) -> Self {
        let mut failures = Vec::new();
        for _ in 0..3 {
            match Self::start_on(classpath, free_port(), args).await {
                Ok(seed) => return seed,
                Err(why) => failures.push(why),
            }
        }
        panic!("the Java seed did not start: {}", failures.join("\n---\n"));
    }

    /// Starts a seed with `args` on `port` and reads its `listening` line.
    async fn start_on(classpath: &str, port: u16, args: &[&str]) -> Result<Self, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-java");
        std::fs::create_dir_all(&logs).map_err(|error| format!("log dir: {error}"))?;
        let log = logs.join(format!(
            "seed-{}-{}-{port}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let stderr = std::fs::File::create(&log).map_err(|error| format!("log file: {error}"))?;
        let mut child = Command::new(java_bin())
            .arg("-cp")
            .arg(classpath)
            .arg(SEED_MAIN)
            .arg(port.to_string())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|error| format!("java does not start: {error}"))?;
        let stdin = child.stdin.take();
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("no stdout pipe".to_owned());
        };
        let (tx, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut seed = Self {
            child,
            stdin,
            lines,
            log,
            port,
            peer: String::new(),
            group: String::new(),
        };
        let Some(event) = seed.next_json(STARTUP).await else {
            return Err(format!(
                "the seed on port {port} printed no listening line:\n{}",
                seed.log_tail()
            ));
        };
        if event["event"] != "listening" {
            return Err(format!(
                "the seed's first line is not the listening event: {event}"
            ));
        }
        seed.peer = event["peer"].as_str().unwrap_or_default().to_owned();
        seed.group = event["group"].as_str().unwrap_or_default().to_owned();
        if seed.peer.is_empty() || seed.group.is_empty() {
            return Err(format!(
                "the listening event names no peer or group: {event}"
            ));
        }
        Ok(seed)
    }

    /// The next JSON object the seed prints within `wait` (other lines are skipped); `None` when
    /// it prints none in time or exits.
    async fn next_json(&mut self, wait: Duration) -> Option<Json> {
        let deadline = Instant::now() + wait;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.recv())
                .await
                .ok()??;
            match serde_json::from_str::<Json>(&line) {
                Ok(json) if json.is_object() => return Some(json),
                _ => eprintln!("java seed {}: {line}", self.port),
            }
        }
    }

    /// Sends one command and returns the seed's answer; panics (with the seed's log) when the
    /// seed does not answer in time or answers an error.
    async fn ask(&mut self, command: &str) -> Json {
        let written = match self.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(format!("{command}\n").as_bytes())
                .and_then(|()| stdin.flush()),
            None => Err(std::io::Error::other("the seed's stdin is closed")),
        };
        if let Err(error) = written {
            panic!(
                "cannot send {command:?} to the seed: {error}\n{}",
                self.log_tail()
            );
        }
        let Some(answer) = self.next_json(ANSWER).await else {
            panic!("the seed did not answer {command:?}:\n{}", self.log_tail());
        };
        assert!(
            answer.get("error").is_none(),
            "the seed refused {command:?}: {answer}\n{}",
            self.log_tail()
        );
        answer
    }

    /// The PeerIDs the seed's membership lists (itself excluded).
    async fn members(&mut self) -> Vec<String> {
        texts(&self.ask("members").await["members"])
    }

    /// The tasks the seed's space reads, as `(topic, priority)`.
    async fn tasks(&mut self) -> Vec<(String, i64)> {
        let answer = self.ask("tasks").await;
        answer["tasks"]
            .as_array()
            .map(|tasks| {
                tasks
                    .iter()
                    .map(|task| {
                        (
                            task["topic"].as_str().unwrap_or_default().to_owned(),
                            task["priority"].as_i64().unwrap_or(i64::MIN),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The frames the seed's node has sent, by authentication (`signed`, `bare`, `session`).
    async fn frames(&mut self) -> Json {
        self.ask("frames").await
    }

    /// Kills the seed process and waits for it to end.
    fn kill(&mut self) {
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The tail of the seed's standard error.
    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        format!("--- {} ---\n{}", self.log.display(), tail(&text, 40))
    }
}

impl Drop for JavaSeed {
    fn drop(&mut self) {
        self.kill();
        if std::thread::panicking() {
            eprintln!(
                "java seed on port {} (peer {}):\n{}",
                self.port,
                self.peer,
                self.log_tail()
            );
        }
    }
}

/// The strings of a JSON array.
fn texts(array: &Json) -> Vec<String> {
    array
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------------------ the Rust peer

/// A peer configuration for the seed's group through `seed`, with the default dialers and quick
/// redials.
fn config(seed: Seed) -> PeerConfig {
    let identity = Identity::generate().expect("identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.seeds = vec![seed];
    config.dialers = default_dialers();
    config.dial_timeout = DIAL_TIMEOUT;
    config.reconnect_interval = RECONNECT_INTERVAL;
    config.reconnect_window = RECONNECT_WINDOW;
    config
}

/// Starts a Rust peer through `seed` and checks it joined the seed's group.
async fn join(seed: &JavaSeed, scheme: &str) -> Peer {
    let peer = Peer::start(config(Seed::new("127.0.0.1", seed.port, scheme)))
        .await
        .unwrap_or_else(|error| panic!("the Rust peer joins over {scheme}: {error}"));
    assert_eq!(
        peer.group_id(),
        seed.group,
        "both derive the GroupID from the founding text"
    );
    peer
}

/// One entry of the Rust peer's copy of the space.
#[derive(Debug)]
struct Entry {
    entry_id: String,
    state: Map,
    payload: Option<Map>,
}

impl Entry {
    fn text(&self, field: &str) -> Option<&str> {
        self.payload.as_ref()?.get(field)?.as_str()
    }

    fn completed(&self) -> bool {
        self.state.get("completed").and_then(Value::as_bool) == Some(true)
    }
}

/// The entries of `type_name` the Rust peer holds in the space, with their payloads decoded.
async fn entries(peer: &Peer, type_name: &str) -> Vec<Entry> {
    let mut found = Vec::new();
    for state in peer.space_states(SPACE).await {
        let Some(record) = state.get("record").and_then(Value::as_map) else {
            continue;
        };
        if record.get("type").and_then(Value::as_str) != Some(type_name) {
            continue;
        }
        let entry_id = record
            .get("entryId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let payload = peer
            .payload_of(SPACE, &entry_id)
            .await
            .and_then(|bytes| cbor::decode(&bytes).ok())
            .and_then(Value::into_map);
        found.push(Entry {
            entry_id,
            state,
            payload,
        });
    }
    found
}

/// A Task as the seed's record encodes it: `{topic, priority}` in that order.
fn task(topic: &str, priority: i64) -> Value {
    cbor_map! { "topic" => topic, "priority" => priority }
}

/// A poll with a [`DEADLINE`]: [`Deadline::tick`] panics naming what was awaited and what was
/// last seen once the deadline passes, and otherwise pauses for [`POLL`].
struct Deadline {
    what: &'static str,
    at: Instant,
}

impl Deadline {
    fn new(what: &'static str) -> Self {
        Self {
            what,
            at: Instant::now() + DEADLINE,
        }
    }

    async fn tick(&self, last: impl Debug) {
        assert!(
            Instant::now() < self.at,
            "timed out after {DEADLINE:?} waiting for {}; last saw {last:?}",
            self.what
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Waits until the seed's membership lists `peer_id`.
async fn seed_lists(seed: &mut JavaSeed, peer_id: &str, what: &'static str) {
    let deadline = Deadline::new(what);
    loop {
        let members = seed.members().await;
        if members.iter().any(|member| member == peer_id) {
            return;
        }
        deadline.tick(members).await;
    }
}

/// Waits until the Rust peer counts the seed as a member.
async fn peer_lists(peer: &Peer, seed_peer: &str) {
    let deadline = Deadline::new("the Rust peer to list the seed as a member");
    loop {
        let members = peer.members().await;
        if members.iter().any(|member| member == seed_peer) {
            return;
        }
        deadline.tick(members).await;
    }
}

/// Waits for an event the predicate picks.
async fn event(
    events: &mut broadcast::Receiver<PeerEvent>,
    what: &'static str,
    pick: impl Fn(&PeerEvent) -> bool,
) -> PeerEvent {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(event)) if pick(&event) => return event,
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => panic!("the peer ended before {what}"),
            Err(_) => panic!("timed out after {DEADLINE:?} waiting for {what}"),
        }
    }
}

// ------------------------------------------------------------------------------ scenarios

/// 1. A tcp join: each side lists the other as a member. The Rust peer verifies the seed's own
///    self-advertisement (Java answers an introduction with one) and learns the seed as its
///    relay, and stays a member while Java probes it: an ACK Java did not credit would drop the
///    only member at the first probe's deadline (a one-second probe period, a two-second ping
///    timeout, no other member to ask).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_tcp_join_each_side_lists_the_other() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    assert_eq!(peer.link().map(|link| link.scheme).as_deref(), Some("tcp"));

    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    peer_lists(&peer, &seed.peer).await;

    let deadline = Deadline::new("the seed's verified self-advertisement and relay");
    loop {
        let ad = peer.member_ad(&seed.peer).await;
        let relay = peer.seed_peer().await;
        let issuer = ad
            .as_ref()
            .and_then(|ad| ad.get("issuer"))
            .and_then(Value::as_str);
        if issuer == Some(seed.peer.as_str()) && relay.as_deref() == Some(seed.peer.as_str()) {
            let group = ad
                .as_ref()
                .and_then(|ad| ad.get("group"))
                .and_then(Value::as_str);
            assert_eq!(group, Some(seed.group.as_str()));
            break;
        }
        deadline.tick((ad, relay)).await;
    }

    let held = Instant::now();
    while held.elapsed() < STAYS {
        let members = seed.members().await;
        assert!(
            members.iter().any(|member| member == peer.peer_id()),
            "the seed dropped the Rust peer {:?} after admitting it: {members:?}",
            held.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

/// 2. A Task the Rust peer writes reads in Java with its topic and priority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2_a_rust_task_reads_in_java() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;

    peer.write_entry(
        SPACE,
        TASK_TYPE,
        task("rust-alpha", 7),
        600_000,
        Map::new(),
        None,
    )
    .await
    .expect("write a task");

    let deadline = Deadline::new("the seed to read the Rust task");
    loop {
        let tasks = seed.tasks().await;
        if tasks.contains(&("rust-alpha".to_owned(), 7)) {
            break;
        }
        deadline.tick(tasks).await;
    }
    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

/// 3. A Task the seed wrote before the Rust peer joined arrives with the pull of the space: a
///    state of the Task type whose payload decodes to the topic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_a_java_task_arrives_with_the_pull() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let written = seed.ask("write-task java-beta 4").await;
    assert_eq!(written["written"], "java-beta");

    let peer = join(&seed, "tcp").await;
    peer.pull_space(SPACE).await.expect("pull the space");

    let deadline = Deadline::new("the Java task in the Rust peer's space");
    let entry = loop {
        let tasks = entries(&peer, TASK_TYPE).await;
        if let Some(entry) = tasks
            .into_iter()
            .find(|entry| entry.text("topic") == Some("java-beta"))
        {
            break entry;
        }
        deadline.tick(peer.space_states(SPACE).await).await;
    };
    let payload = entry.payload.as_ref().expect("the payload decodes");
    assert_eq!(payload.get("priority").and_then(Value::as_i64), Some(4));
    assert!(!entry.completed(), "a fresh task is not completed");
    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

/// 4. Java takes a Task the Rust peer wrote and completes it with a Result: the Rust peer holds
///    the Result and sees the Task completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s4_java_takes_and_completes_a_rust_task() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;

    let task_id = peer
        .write_entry(
            SPACE,
            TASK_TYPE,
            task("rust-gamma", 2),
            600_000,
            Map::new(),
            None,
        )
        .await
        .expect("write a task");
    let deadline = Deadline::new("the seed to read the Rust task");
    loop {
        let tasks = seed.tasks().await;
        if tasks.iter().any(|(topic, _)| topic == "rust-gamma") {
            break;
        }
        deadline.tick(tasks).await;
    }

    let took = seed.ask("take-task 5000 java-worker").await;
    assert_eq!(took["took"], "rust-gamma", "Java takes the Rust task");

    let deadline = Deadline::new("the Java result and the completed task in the Rust peer");
    loop {
        let results = entries(&peer, RESULT_TYPE).await;
        let tasks = entries(&peer, TASK_TYPE).await;
        let result = results
            .iter()
            .find(|result| result.text("topic") == Some("rust-gamma"));
        let completed = tasks
            .iter()
            .any(|task| task.entry_id == task_id && task.completed());
        if let Some(result) = result
            && completed
        {
            assert_eq!(result.text("worker"), Some("java-worker"));
            assert_eq!(result.text("summary"), Some("done by java"));
            break;
        }
        deadline.tick((results, tasks)).await;
    }
    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

/// 5. An attested tls join under `--require-attestation --channel-auth ATTESTED`: the link
///    attests the seed, the seed admits the Rust peer, and after the Rust CHANNEL_HELLO the seed
///    sends bare frames the Rust peer accepts on the strength of the attestation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s5_attested_tls_join_carries_bare_frames() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(
        &classpath,
        &[
            "--tls",
            "--require-attestation",
            "--channel-auth",
            "ATTESTED",
        ],
    )
    .await;
    let peer = join(&seed, "tls").await;
    let link = peer.link().expect("a link");
    assert_eq!(link.scheme, "tls");
    assert_eq!(
        link.attested.as_deref(),
        Some(seed.peer.as_str()),
        "the link attests the seed"
    );

    seed_lists(&mut seed, peer.peer_id(), "the seed to admit the Rust peer").await;
    peer_lists(&peer, &seed.peer).await;

    // Some traffic in each direction: a write each way.
    peer.write_entry(
        SPACE,
        TASK_TYPE,
        task("tls-rust", 1),
        600_000,
        Map::new(),
        None,
    )
    .await
    .expect("write a task");
    seed.ask("write-task tls-java 9").await;
    peer.pull_space(SPACE).await.expect("pull the space");

    let deadline = Deadline::new("bare frames from the seed, accepted by the Rust peer");
    loop {
        let frames = seed.frames().await;
        let counters = peer.counters().await;
        if frames["bare"].as_u64().unwrap_or(0) > 0 && counters.attested_frames > 0 {
            assert_eq!(counters.malformed, 0, "{counters:?}");
            break;
        }
        deadline.tick((frames, counters)).await;
    }

    let deadline = Deadline::new("the writes to cross both ways over tls");
    loop {
        let tasks = seed.tasks().await;
        let rust_has = entries(&peer, TASK_TYPE)
            .await
            .iter()
            .any(|entry| entry.text("topic") == Some("tls-java"));
        if rust_has && tasks.contains(&("tls-rust".to_owned(), 1)) {
            break;
        }
        deadline.tick((tasks, rust_has)).await;
    }
    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

/// 6a. A tls dial to a plain tcp seed is refused within the dial bound, and the seed stays well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s6a_tls_to_a_tcp_seed_fails_cleanly() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let started = Instant::now();
    let outcome = Peer::start(config(Seed::new("127.0.0.1", seed.port, "tls"))).await;
    let took = started.elapsed();
    match outcome {
        Err(PeerError::NoSeedAccepted(why)) => println!("refused in {took:?}: {why}"),
        Err(other) => panic!("a tls dial to a tcp seed fails as NoSeedAccepted, not {other}"),
        Ok(peer) => {
            let link = peer.link();
            let _ = peer.close().await;
            panic!("a tls dial to a tcp seed joined: {link:?}");
        }
    }
    assert!(
        took < DIAL_TIMEOUT + REFUSAL_SLACK,
        "the refusal took {took:?}, beyond the {DIAL_TIMEOUT:?} dial bound"
    );
    assert!(seed.members().await.is_empty(), "the seed admits nobody");
}

/// 6b. A tcp dial to a tls seed never joins: the TCP connection opens, the seed drops it at
///     once (its first bytes are no TLS handshake), neither side lists the other, and the peer
///     redials once per reconnect interval, not in a loop, until its reconnect window (which
///     such links do not extend) runs out and it gives up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s6b_tcp_to_a_tls_seed_fails_cleanly() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &["--tls"]).await;
    let window = Duration::from_secs(3);
    let mut config = config(Seed::new("127.0.0.1", seed.port, "tcp"));
    config.reconnect_window = window;
    let started = Instant::now();
    let peer = match Peer::start(config).await {
        Ok(peer) => peer,
        Err(error) => {
            let took = started.elapsed();
            println!("refused in {took:?}: {error}");
            assert!(
                took < DIAL_TIMEOUT + REFUSAL_SLACK,
                "the refusal took {took:?}"
            );
            assert!(seed.members().await.is_empty(), "the seed admits nobody");
            return;
        }
    };
    let mut events = peer.subscribe();
    event(&mut events, "the peer to give up", |event| {
        matches!(event, PeerEvent::GaveUp)
    })
    .await;
    let took = started.elapsed();
    let counters = peer.counters().await;
    println!("gave up after {took:?}: {counters:?}");
    assert!(!peer.is_connected());
    assert!(
        took < window + RECONNECT_INTERVAL + DIAL_TIMEOUT + REFUSAL_SLACK,
        "gave up only after {took:?}"
    );
    // One link per interval over the window, not one per round trip (the storm found here).
    let most = window.as_millis() / RECONNECT_INTERVAL.as_millis() + 2;
    assert!(
        u128::from(counters.reconnects) <= most,
        "{} reconnects in a {window:?} window at a {RECONNECT_INTERVAL:?} interval",
        counters.reconnects
    );
    assert!(
        peer.members().await.is_empty(),
        "nothing joined: {counters:?}"
    );
    assert_eq!(counters.attested_frames, 0, "{counters:?}");
    assert_eq!(counters.malformed, 0, "{counters:?}");
    let closing = Instant::now();
    peer.close().await.expect("close");
    assert!(
        closing.elapsed() < Duration::from_secs(1),
        "close does not wait"
    );
    assert!(seed.members().await.is_empty(), "the seed admits nobody");
}

/// 7. The seed is killed and a new one started on the same port: the Rust peer redials within
///    its reconnect settings (a round every 500 ms), introduces itself to the new seed, sends
///    the write it made while it had no link, and pulls the space again: the new seed writes a
///    task as soon as it listens, before the peer is back in the usual case, so only the pull
///    after the reconnect carries it (gossip does, when the peer was quicker).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s7_the_peer_reconnects_to_a_restarted_seed() {
    let classpath = classpath_or_skip!();
    let mut first = JavaSeed::start(&classpath, &[]).await;
    let port = first.port;
    let peer = join(&first, "tcp").await;
    peer.pull_space(SPACE).await.expect("pull the space");
    seed_lists(
        &mut first,
        peer.peer_id(),
        "the first seed to list the Rust peer",
    )
    .await;
    let mut events = peer.subscribe();

    first.kill();
    event(&mut events, "the lost link", |event| {
        matches!(event, PeerEvent::Disconnected)
    })
    .await;
    assert!(!peer.is_connected());
    peer.write_entry(SPACE, TASK_TYPE, task("held", 6), 600_000, Map::new(), None)
        .await
        .expect("a write without a link is held");

    let mut second = None;
    let mut failures = Vec::new();
    for _ in 0..5 {
        match JavaSeed::start_on(&classpath, port, &[]).await {
            Ok(seed) => {
                second = Some(seed);
                break;
            }
            Err(why) => {
                failures.push(why);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let Some(mut second) = second else {
        panic!(
            "no seed restarted on port {port}: {}",
            failures.join("\n---\n")
        );
    };
    assert_ne!(second.peer, first.peer, "the new seed is a new node");
    let restarted = Instant::now();
    second.ask("write-task restarted 8").await;

    let reconnected = event(&mut events, "the reconnect", |event| {
        matches!(event, PeerEvent::Reconnected { .. })
    })
    .await;
    let took = restarted.elapsed();
    println!("{reconnected:?} {took:?} after the restart");
    assert!(
        took < RECONNECT_INTERVAL + DIAL_TIMEOUT,
        "reconnected {took:?} after the seed listened again, beyond one redial round"
    );
    seed_lists(
        &mut second,
        peer.peer_id(),
        "the new seed to list the Rust peer",
    )
    .await;
    peer_lists(&peer, &second.peer).await;
    assert!(peer.counters().await.reconnects >= 1);

    // The held write reaches the new seed; the new seed's write reaches the Rust peer.
    let deadline = Deadline::new("the writes to cross after the reconnect");
    loop {
        let tasks = second.tasks().await;
        let rust_has = entries(&peer, TASK_TYPE)
            .await
            .iter()
            .any(|entry| entry.text("topic") == Some("restarted"));
        if rust_has && tasks.contains(&("held".to_owned(), 6)) {
            break;
        }
        deadline.tick((tasks, rust_has)).await;
    }
    let counters = peer.counters().await;
    assert_eq!(counters.malformed, 0, "{counters:?}");
    peer.close().await.expect("close");
}

// ------------------------------------------------------------------------------ the Space API

/// The results the seed's space reads, as `(topic, summary, worker)`.
fn results(json: &Json) -> Vec<(String, String, String)> {
    json["results"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|r| {
                    (
                        r["topic"].as_str().unwrap_or_default().to_owned(),
                        r["summary"].as_str().unwrap_or_default().to_owned(),
                        r["worker"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Rust takes a Java task through the Space API and completes it with a result; Java accepts the
/// claim (its own take finds nothing), the completion (the task never reappears after the take
/// lease), and the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x1_rust_takes_and_completes_a_java_task() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    seed.ask("write-task java-delta 9").await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    let fleet = Fleet::from_peer(peer.clone());
    let tasks = fleet.space(SPACE).with_settle(Duration::from_millis(200));
    let template = Template::new(TASK_TYPE).where_("topic", Matcher::Eq("java-delta".into()));
    let taken = tasks
        .take(
            &template,
            Lease::parse("3s").expect("a lease"),
            Duration::from_secs(10),
        )
        .await
        .expect("take")
        .expect("Rust takes the Java task");
    let java_take = seed.ask("take-task 1000 java-worker").await;
    assert_eq!(java_take["took"], Json::Null, "Java honours the Rust claim");
    let result =
        cbor_map! { "topic" => "java-delta", "summary" => "done by rust", "worker" => "rust" };
    taken
        .complete(
            Some((RESULT_TYPE, result)),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await
        .expect("complete");
    let deadline = Deadline::new("Java to read the Rust result");
    loop {
        let found = results(&seed.ask("results").await);
        if found.contains(&("java-delta".into(), "done by rust".into(), "rust".into())) {
            break;
        }
        deadline.tick(found).await;
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let tasks_now = seed.tasks().await;
    assert!(
        !tasks_now.iter().any(|(topic, _)| topic == "java-delta"),
        "the completion landed in Java: {tasks_now:?}"
    );
    let java_take = seed.ask("take-task 500 java-worker").await;
    assert_eq!(
        java_take["took"],
        Json::Null,
        "a completed task is gone in Java"
    );
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// The same as an agent of the Rust peer: an agent-signed claim and completion Java accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x2_an_agent_takes_and_completes_a_java_task() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    seed.ask("write-task java-epsilon 9").await;
    let identity = Identity::generate().expect("identity");
    let mut cfg = config(Seed::new("127.0.0.1", seed.port, "tcp"));
    cfg.identity = identity.clone();
    let peer = Peer::start(cfg).await.expect("join");
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    let now = agentspaces::clock::Clock::now_ms(&agentspaces::clock::SystemClock);
    let agent = identity
        .renewing_subordinate("worker", "PT24H", None, now)
        .expect("agent");
    let tasks = Fleet::from_peer(peer.clone())
        .space(SPACE)
        .with_settle(Duration::from_millis(200))
        .as_agent(agent);
    let template = Template::new(TASK_TYPE).where_("topic", Matcher::Eq("java-epsilon".into()));
    let taken = tasks
        .take(
            &template,
            Lease::parse("3s").expect("a lease"),
            Duration::from_secs(10),
        )
        .await
        .expect("take")
        .expect("the agent takes the Java task");
    let java_take = seed.ask("take-task 1000 java-worker").await;
    assert_eq!(
        java_take["took"],
        Json::Null,
        "Java honours the agent's claim"
    );
    let result =
        cbor_map! { "topic" => "java-epsilon", "summary" => "done by agent", "worker" => "agent" };
    taken
        .complete(
            Some((RESULT_TYPE, result)),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await
        .expect("complete");
    let deadline = Deadline::new("Java to read the agent's result");
    loop {
        let found = results(&seed.ask("results").await);
        if found.iter().any(|(topic, _, _)| topic == "java-epsilon") {
            break;
        }
        deadline.tick(found).await;
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let tasks_now = seed.tasks().await;
    assert!(
        !tasks_now.iter().any(|(topic, _)| topic == "java-epsilon"),
        "{tasks_now:?}"
    );
    peer.close().await.expect("close");
}

/// Rust renews a short write past its lease and then cancels it; Java follows both. And a
/// renewed take outlives its first lease in Java.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_renew_and_cancel_and_renewed_takes_cross_to_java() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    let tasks = Fleet::from_peer(peer.clone())
        .space(SPACE)
        .with_settle(Duration::from_millis(200));
    let id = tasks
        .write_value(
            TASK_TYPE,
            task("rust-renewed", 1),
            Lease::parse("2s").expect("a lease"),
            Map::new(),
        )
        .await
        .expect("write");
    tasks
        .renew_write(&id, Lease::parse("10m").expect("a lease"))
        .await
        .expect("renew");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let listed = seed.tasks().await;
    assert!(
        listed.iter().any(|(topic, _)| topic == "rust-renewed"),
        "renewed in Java: {listed:?}"
    );
    tasks.cancel(&id).await.expect("cancel");
    let deadline = Deadline::new("Java to drop the cancelled task");
    loop {
        let listed = seed.tasks().await;
        if !listed.iter().any(|(topic, _)| topic == "rust-renewed") {
            break;
        }
        deadline.tick(listed).await;
    }
    // a renewed take
    seed.ask("write-task java-zeta 1").await;
    let template = Template::new(TASK_TYPE).where_("topic", Matcher::Eq("java-zeta".into()));
    let mut taken = tasks
        .take(
            &template,
            Lease::parse("1500ms").expect("a lease"),
            Duration::from_secs(10),
        )
        .await
        .expect("take")
        .expect("take java-zeta");
    taken
        .renew(Lease::parse("20s").expect("a lease"))
        .await
        .expect("renew the take");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let java_take = seed.ask("take-task 500 java-worker").await;
    assert_eq!(
        java_take["took"],
        Json::Null,
        "the renewed claim holds in Java"
    );
    taken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    peer.close().await.expect("close");
}

/// Java takes and completes a task while a Rust watch sees Written, Taken, Completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x4_a_rust_watch_sees_java_take_and_complete() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    let tasks = Fleet::from_peer(peer.clone()).space(SPACE);
    let mut events = tasks.watch(&Template::new(TASK_TYPE)).await.expect("watch");
    seed.ask("write-task java-eta 1").await;
    let mut kinds = Vec::new();
    let first = tokio::time::timeout(DEADLINE, events.next())
        .await
        .expect("in time")
        .expect("open");
    kinds.push(first.kind);
    assert_eq!(
        first.entry.payload().get("topic").and_then(Value::as_str),
        Some("java-eta")
    );
    seed.ask("take-task 5000 java-worker").await;
    for _ in 0..2 {
        let e = tokio::time::timeout(DEADLINE, events.next())
            .await
            .expect("in time")
            .expect("open");
        kinds.push(e.kind);
    }
    assert_eq!(
        kinds,
        [EventKind::Written, EventKind::Taken, EventKind::Completed]
    );
    peer.close().await.expect("close");
}

/// The seed's `record Task(String topic, int priority)` as a Rust entry type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
struct SeedTask {
    topic: String,
    priority: i32,
}

/// The seed's `record Result(String topic, String summary, String worker)` as a Rust entry type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Result#v1")]
struct SeedResult {
    topic: String,
    summary: String,
    worker: String,
}

/// The next event of a typed watch, within [`DEADLINE`].
async fn next_typed<T: agentspaces::entry::Entry>(events: &mut TypedEvents<T>) -> TypedEvent<T> {
    tokio::time::timeout(DEADLINE, events.next())
        .await
        .expect("an event in time")
        .expect("the watch is open")
}

/// The typed layer against Java, both ways: a typed Rust write reads in Java, and Java's take
/// completes it with a `Result` that a Rust typed watch decodes; a Java task reads, takes, and
/// completes typed in Rust, with a typed result Java reads. The Rust types re-encode Java's
/// payload byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x5_typed_entries_cross_both_ways() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&seed, "tcp").await;
    seed_lists(&mut seed, peer.peer_id(), "the seed to list the Rust peer").await;
    assert_eq!(
        <SeedTask as agentspaces::entry::Entry>::SCHEMA,
        TASK_TYPE,
        "the derived schema is the Java default registry's"
    );
    assert_eq!(
        <SeedResult as agentspaces::entry::Entry>::SCHEMA,
        RESULT_TYPE
    );
    let tasks = Fleet::from_peer(peer.clone())
        .space(SPACE)
        .with_settle(Duration::from_millis(200));
    let mut task_events = tasks
        .watch_typed::<SeedTask>(&Template::of::<SeedTask>())
        .await
        .expect("watch the tasks");
    let mut result_events = tasks
        .watch_typed::<SeedResult>(&Template::of::<SeedResult>())
        .await
        .expect("watch the results");

    // Rust to Java: a typed write Java reads, takes, and completes.
    let written = SeedTask {
        topic: "rust-typed".to_owned(),
        priority: 4,
    };
    let id = tasks
        .write(&written, Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("a typed write");
    let deadline = Deadline::new("Java to read the typed Rust task");
    loop {
        let listed = seed.tasks().await;
        if listed.contains(&("rust-typed".to_owned(), 4)) {
            break;
        }
        deadline.tick(listed).await;
    }
    let java_take = seed.ask("take-task 5000 java-worker").await;
    assert_eq!(java_take["took"], "rust-typed", "Java takes the typed task");
    let mut kinds = Vec::new();
    for _ in 0..3 {
        let event = next_typed(&mut task_events).await;
        assert_eq!(event.entry.entry_id(), &id);
        assert_eq!(event.entry.value(), &written);
        kinds.push(event.kind);
    }
    assert_eq!(
        kinds,
        [EventKind::Written, EventKind::Taken, EventKind::Completed]
    );
    let java_result = SeedResult {
        topic: "rust-typed".to_owned(),
        summary: "done by java".to_owned(),
        worker: "java-worker".to_owned(),
    };
    let event = next_typed(&mut result_events).await;
    assert_eq!(event.kind, EventKind::Written);
    assert_eq!(event.entry.value(), &java_result, "Java's Result, decoded");
    assert_eq!(
        cbor::encode(event.entry.view().payload()),
        cbor::encode(&entry::to_value(&java_result).expect("a payload")),
        "the Rust type re-encodes Java's payload byte for byte"
    );
    assert_eq!(task_events.skipped() + result_events.skipped(), 0);

    // Java to Rust: a Java task read, taken, and completed typed in Rust.
    seed.ask("write-task java-typed 7").await;
    let template = Template::of::<SeedTask>().where_("topic", Matcher::Eq("java-typed".into()));
    let seen = tasks
        .read_typed::<SeedTask>(&template, DEADLINE)
        .await
        .expect("read_typed")
        .expect("Rust reads the Java task typed");
    let java_task = SeedTask {
        topic: "java-typed".to_owned(),
        priority: 7,
    };
    assert_eq!(seen.value(), &java_task);
    assert_eq!(
        cbor::encode(seen.view().payload()),
        cbor::encode(&entry::to_value(&java_task).expect("a payload")),
        "the Rust type re-encodes Java's payload byte for byte"
    );
    let taken = tasks
        .take_typed::<SeedTask>(
            &template,
            Lease::parse("30s").expect("a lease"),
            Duration::from_secs(10),
        )
        .await
        .expect("take_typed")
        .expect("Rust takes the Java task typed");
    assert_eq!(taken.value(), &java_task);
    let rust_result = SeedResult {
        topic: "java-typed".to_owned(),
        summary: "typed by rust".to_owned(),
        worker: "rust-typed".to_owned(),
    };
    taken
        .complete_with(&rust_result, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete_with");
    let deadline = Deadline::new("Java to read the typed Rust result");
    loop {
        let found = results(&seed.ask("results").await);
        if found.contains(&(
            "java-typed".to_owned(),
            "typed by rust".to_owned(),
            "rust-typed".to_owned(),
        )) {
            break;
        }
        deadline.tick(found).await;
    }
    let deadline = Deadline::new("Java to fold the Rust completion");
    loop {
        let listed = seed.tasks().await;
        if !listed.iter().any(|(topic, _)| topic == "java-typed") {
            break;
        }
        deadline.tick(listed).await;
    }
    let java_take = seed.ask("take-task 500 java-worker").await;
    assert_eq!(java_take["took"], Json::Null, "no task is left in Java");
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}
