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

//! The Space API ([`agentspaces::space`]) against the Java reference: each test starts its own
//! scripted Java seed (`interop/java-seed`, `ai.badmonkey.agentspaces.interop.Seed`) on a free
//! port, drives it over its standard input (one command per line, one JSON object per line back),
//! and checks what the Java `ReplicatedSpace` makes of the Rust verbs:
//!
//! 1. a typed Rust take of a Java task, completed with a typed result Java reads, and the task
//!    completed in Java under the Rust holder's claim (`task-state`);
//! 2. races: (a) a duel of three Rust peers and the seed for one task, whose claims collide and
//!    which exactly one wins; (b) thirty Java tasks taken by three Rust peers and the seed at
//!    once, each completed exactly once, and no Rust completion of a task Java saw another
//!    holder win;
//! 3. a crashed take: a Rust peer closed while it holds a Java task, which Java takes as soon as
//!    the hold lapses;
//! 4. an agent-attested write: a task a renewing subordinate agent of the Rust peer writes (once
//!    under its first certificate, once under a renewed one) reads in Java as AGENT_ATTESTED
//!    with the agent's id;
//! 5. a Rust watch of a task Java writes, takes, and completes: `Written`, `Taken`, `Completed`;
//! 6. scenario 1 over tls under `--require-attestation --channel-auth ATTESTED`;
//! 7. long texts from Java (`write-long-task`): a 10,000-unit topic with surrogate pairs and a
//!    5,000-unit tag on the signed record, which Jackson writes in chunks, read, taken, and
//!    completed in Rust with a 9,000-unit summary and a long tag that Java reads intact
//!    (`long-texts` digests);
//! 8. long texts from Rust: a 12,001-unit topic and a long tag Java reads intact, takes, and
//!    completes, its result's topic read back in Rust;
//! 9. big numbers both ways: the seed's `Priced` records, a `BigDecimal` and a `BigInteger` past 64
//!    bits written by Java (`write-priced`), read in Rust as [`Value::Decimal`] and
//!    [`Value::BigInt`]; and Rust payloads of a decimal and of integers outside Java's `long`
//!    (2^64 - 1 among them, written as a bignum since Java's strict reader drops a plain integer
//!    past `long`), read in Java (`priced`).
//!
//! The seed is built on first use with `mvn -q -o` when `target/classes` or
//! `target/classpath.txt` is missing (or the source is newer than its class). When `java` or the
//! build is unavailable each test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set,
//! in which case it fails. `JAVA_HOME` picks the `java` binary when set;
//! `AGENTSPACES_JAVA_SEED_DIR` points at another copy of the seed project. Every test owns its
//! seed process, which is killed when the test ends (also when it fails).
//!
//! The Java seed's standard error goes to a log file under the target directory; a failing test
//! prints its tail.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentspaces::entry::{self, Entry as _};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, PeerEvent, default_dialers};
use agentspaces::space::{
    Attestation, EventKind, Fleet, Lease, Space, SpaceError, Template, TypedEvent, TypedEvents,
};
use agentspaces::wire::cbor::{self, Map, Value};
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
/// The seed's main class.
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
/// The seed's class file and source, relative to the seed project.
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
/// The seed's dependency classpath, relative to the seed project.
const SEED_CLASSPATH: &str = "target/classpath.txt";
/// The agent name the seed's space writes, takes, and completes as.
const SEED_AGENT: &str = "java-seed";
/// The agent name a Rust peer's space handle acts as by default.
const RUST_AGENT: &str = "rust";

/// The longest any poll waits for something to happen.
const DEADLINE: Duration = Duration::from_secs(20);
/// The pause between polls.
const POLL: Duration = Duration::from_millis(100);
/// How long a JVM may take to start and print its first line.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one command to the seed may take (`take-task 10000` waits up to ten seconds).
const ANSWER: Duration = Duration::from_secs(20);
/// The Rust peer's dial bound in these tests.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
/// The Rust peer's pause between redial rounds in these tests.
const RECONNECT_INTERVAL: Duration = Duration::from_millis(500);
/// The Rust peer's redial window in these tests.
const RECONNECT_WINDOW: Duration = Duration::from_secs(60);
/// The settle window of the Rust takes: the Java space's (the seed runs with its 200 ms default).
const SETTLE: Duration = Duration::from_millis(200);

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

/// The wall clock in epoch milliseconds (the seed's clock on this machine).
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-spaces");
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

    /// The AgentID the seed's space acts as.
    fn agent(&self) -> String {
        format!("{}/{SEED_AGENT}", self.peer)
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

    /// Sends one command and returns the seed's answer within [`ANSWER`].
    async fn ask(&mut self, command: &str) -> Json {
        self.ask_within(command, ANSWER).await
    }

    /// Sends one command and returns the seed's answer; panics (with the seed's log) when the
    /// seed does not answer within `wait` or answers an error.
    async fn ask_within(&mut self, command: &str, wait: Duration) -> Json {
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
        let Some(answer) = self.next_json(wait).await else {
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

    /// The tasks the seed's space reads (available ones), as `(topic, priority)`.
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

    /// The results the seed's space reads, as `(topic, summary, worker)`.
    async fn results(&mut self) -> Vec<(String, String, String)> {
        let answer = self.ask("results").await;
        answer["results"]
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

    /// The available tasks the seed reads with their entry ids, issuers, and attestations.
    async fn entries(&mut self) -> Vec<Json> {
        let answer = self.ask("entries").await;
        answer["entries"].as_array().cloned().unwrap_or_default()
    }

    /// What the seed holds of the task `topic` ([`TaskState`]).
    async fn task_state(&mut self, topic: &str) -> TaskState {
        TaskState::of(&self.ask(&format!("task-state {topic}")).await)
    }

    /// What the seed holds of every task it has seen, by topic.
    async fn task_states(&mut self) -> BTreeMap<String, TaskState> {
        let answer = self.ask("task-states").await;
        answer["states"]
            .as_array()
            .map(|states| {
                states
                    .iter()
                    .map(TaskState::of)
                    .map(|state| (state.topic.clone(), state))
                    .collect()
            })
            .unwrap_or_default()
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

/// What the seed's replica holds of one task (`task-state`): its entry id, its state
/// (`available`, `claimed`, `completed`, `gone`, or `unknown`), the claim in force (kept after
/// a completion), and the transitions the seed's own subscription saw (`"KIND by AGENT"`).
#[derive(Debug, Clone, PartialEq)]
struct TaskState {
    topic: String,
    entry_id: Option<String>,
    state: String,
    holder: Option<String>,
    epoch: Option<i64>,
    events: Vec<String>,
}

impl TaskState {
    fn of(json: &Json) -> Self {
        let text = |field: &str| json[field].as_str().map(str::to_owned);
        Self {
            topic: text("topic").unwrap_or_default(),
            entry_id: text("entryId"),
            state: text("state").unwrap_or_default(),
            holder: text("holder"),
            epoch: json["epoch"].as_i64(),
            events: texts(&json["events"]),
        }
    }

    /// Whether the seed's subscription saw a transition of `kind` (`"COMPLETED"`, ...).
    fn saw(&self, kind: &str) -> bool {
        self.events
            .iter()
            .any(|event| event.split(' ').next() == Some(kind))
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

/// A peer configuration for the seed's group through `seed` with `identity`, the default
/// dialers, and quick redials.
fn config_with(seed: Seed, identity: Identity) -> PeerConfig {
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(FOUNDING.to_owned()));
    config.seeds = vec![seed];
    config.dialers = default_dialers();
    config.dial_timeout = DIAL_TIMEOUT;
    config.reconnect_interval = RECONNECT_INTERVAL;
    config.reconnect_window = RECONNECT_WINDOW;
    config
}

/// Starts a Rust peer with `identity` through `seed` over `scheme`, checks it joined the seed's
/// group, and waits until the seed lists it.
async fn join_as(seed: &mut JavaSeed, scheme: &str, identity: Identity) -> Peer {
    let config = config_with(Seed::new("127.0.0.1", seed.port, scheme), identity);
    let peer = Peer::start(config)
        .await
        .unwrap_or_else(|error| panic!("the Rust peer joins over {scheme}: {error}"));
    assert_eq!(
        peer.group_id(),
        seed.group,
        "both derive the GroupID from the founding text"
    );
    seed_lists(seed, peer.peer_id()).await;
    peer
}

/// [`join_as`] with a fresh identity.
async fn join(seed: &mut JavaSeed, scheme: &str) -> Peer {
    join_as(seed, scheme, Identity::generate().expect("identity")).await
}

/// The tasks space of `peer`, settling its takes as the Java space does.
fn tasks_of(peer: &Peer) -> Space {
    Fleet::from_peer(peer.clone())
        .space(SPACE)
        .with_settle(SETTLE)
}

/// The AgentID a Rust peer's space handle acts as by default.
fn rust_agent(peer: &Peer) -> String {
    format!("{}/{RUST_AGENT}", peer.peer_id())
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
async fn seed_lists(seed: &mut JavaSeed, peer_id: &str) {
    let deadline = Deadline::new("the seed to list the Rust peer");
    loop {
        let members = seed.members().await;
        if members.iter().any(|member| member == peer_id) {
            return;
        }
        deadline.tick(members).await;
    }
}

/// Waits until the seed's replica holds the task `topic` in `state`.
async fn seed_holds(seed: &mut JavaSeed, topic: &str, state: &str) -> TaskState {
    let deadline = Deadline::new("the seed to hold the task in the expected state");
    loop {
        let held = seed.task_state(topic).await;
        if held.state == state {
            return held;
        }
        deadline.tick((state, held)).await;
    }
}

// ------------------------------------------------------------------------------ entry types

/// The seed's `record Task(String topic, int priority)` as a Rust entry type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
struct Task {
    topic: String,
    priority: i32,
}

/// The seed's `record Result(String topic, String summary, String worker)` as a Rust entry type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Result#v1")]
struct TaskResult {
    topic: String,
    summary: String,
    worker: String,
}

impl Task {
    fn new(topic: &str, priority: i32) -> Self {
        Self {
            topic: topic.to_owned(),
            priority,
        }
    }
}

impl TaskResult {
    fn new(topic: &str, summary: &str, worker: &str) -> Self {
        Self {
            topic: topic.to_owned(),
            summary: summary.to_owned(),
            worker: worker.to_owned(),
        }
    }
}

/// The template of the task `topic`.
fn task_named(topic: &str) -> Template {
    Template::of::<Task>().where_("topic", Matcher::Eq(topic.into()))
}

/// The next event of a typed watch, within [`DEADLINE`].
async fn next_typed<T: entry::Entry>(events: &mut TypedEvents<T>) -> TypedEvent<T> {
    tokio::time::timeout(DEADLINE, events.next())
        .await
        .expect("an event in time")
        .expect("the watch is open")
}

// ------------------------------------------------------------------------------ scenarios

/// Scenario 1 against a seed started with `args`, joined over `scheme`: a Rust typed take of a
/// Java task, which Java sees claimed by the Rust holder (and cannot take), completed with a
/// typed result Java reads with worker `rust-worker`; Java then holds the task completed under
/// the Rust claim, once.
async fn typed_take_and_complete(classpath: &str, args: &[&str], scheme: &str) -> (JavaSeed, Peer) {
    let mut seed = JavaSeed::start(classpath, args).await;
    let topic = format!("java-typed-{scheme}");
    seed.ask(&format!("write-task {topic} 5")).await;
    let peer = join(&mut seed, scheme).await;
    let tasks = tasks_of(&peer);

    let taken = tasks
        .take_typed::<Task>(
            &task_named(&topic),
            Lease::parse("30s").expect("a lease"),
            DEADLINE,
        )
        .await
        .expect("take_typed")
        .expect("Rust takes the Java task");
    assert_eq!(taken.value(), &Task::new(&topic, 5));
    assert_eq!(taken.entry().issuer(), seed.agent(), "Java wrote it");
    assert_eq!(taken.entry().attestation(), Attestation::PeerAsserted);
    let holder = rust_agent(&peer);
    assert_eq!(taken.taken().holder(), holder);
    assert_eq!(taken.taken().epoch(), 1);

    // Java sees the Rust claim in force and cannot take the task while it holds.
    let claimed = seed_holds(&mut seed, &topic, "claimed").await;
    assert_eq!(claimed.holder.as_deref(), Some(holder.as_str()));
    assert_eq!(claimed.epoch, Some(1));
    assert_eq!(
        claimed.entry_id.as_deref(),
        Some(taken.entry_id().as_str()),
        "both name the entry alike"
    );
    let java_take = seed.ask("take-task 500 java-worker").await;
    assert_eq!(java_take["took"], Json::Null, "Java honours the Rust claim");

    let result_id = taken
        .complete_with(
            &TaskResult::new(&topic, "done by rust", "rust-worker"),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await
        .expect("complete_with");

    let deadline = Deadline::new("Java to read the typed Rust result");
    loop {
        let results = seed.results().await;
        let mine: Vec<_> = results.iter().filter(|(t, _, _)| *t == topic).collect();
        if !mine.is_empty() {
            assert_eq!(
                mine,
                [&(
                    topic.clone(),
                    "done by rust".to_owned(),
                    "rust-worker".to_owned()
                )],
                "one result, the Rust worker's"
            );
            break;
        }
        deadline.tick(results).await;
    }
    let completed = seed_holds(&mut seed, &topic, "completed").await;
    assert_eq!(
        completed.holder.as_deref(),
        Some(holder.as_str()),
        "Java completed it under the Rust claim: {completed:?}"
    );
    assert_eq!(completed.epoch, Some(1));
    let deadline = Deadline::new("the seed's subscription to see the completion");
    loop {
        let state = seed.task_state(&topic).await;
        if state.saw("COMPLETED") {
            assert_eq!(
                state.events,
                [
                    format!("WRITTEN by {}", seed.agent()),
                    format!("TAKEN by {holder}"),
                    format!("COMPLETED by {holder}"),
                ],
                "Java's own subscription credits the Rust holder"
            );
            break;
        }
        deadline.tick(state).await;
    }
    let java_take = seed.ask("take-task 500 java-worker").await;
    assert_eq!(java_take["took"], Json::Null, "a completed task is gone");

    // The Rust side holds the task completed under its own claim, and its result.
    let view = tasks
        .get_typed::<Task>(taken.entry_id())
        .await
        .expect("get_typed")
        .expect("held");
    assert!(view.view().completed());
    assert_eq!(view.view().holder(), Some(holder.as_str()));
    let result = tasks
        .get_typed::<TaskResult>(&result_id)
        .await
        .expect("get_typed")
        .expect("the result is held");
    assert_eq!(result.value().worker, "rust-worker");
    assert_eq!(
        result.view().issuer(),
        holder,
        "the holder wrote the result"
    );
    assert_eq!(peer.counters().await.malformed, 0);
    (seed, peer)
}

/// 1. A Rust typed take of a Java task, completed with a typed result (over tcp).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_a_typed_rust_take_of_a_java_task_completes_in_java() {
    let classpath = classpath_or_skip!();
    let (_seed, peer) = typed_take_and_complete(&classpath, &[], "tcp").await;
    peer.close().await.expect("close");
}

/// What one Rust worker of the race did.
#[derive(Debug, Default)]
struct Worked {
    /// The topics it completed, with the holder and epoch of its winning claim.
    completed: Vec<(String, String, i64)>,
    /// The topics it took whose completion found the hold lost.
    lost: Vec<String>,
}

/// One Rust worker of the race: takes tasks (typed) until none is left for `idle`, and completes
/// each with a result naming `worker`.
async fn race_worker(tasks: Space, worker: String, idle: Duration) -> Worked {
    let mut worked = Worked::default();
    let template = Template::of::<Task>();
    loop {
        let taken = tasks
            .take_typed::<Task>(&template, Lease::parse("30s").expect("a lease"), idle)
            .await
            .unwrap_or_else(|error| panic!("{worker} takes: {error}"));
        let Some(taken) = taken else {
            return worked;
        };
        let topic = taken.value().topic.clone();
        let result = TaskResult::new(&topic, "done by rust", &worker);
        match taken
            .complete_with(&result, Lease::DEFAULT_RESULT, Map::new())
            .await
        {
            Ok(_) => worked.completed.push((
                topic,
                taken.taken().holder().to_owned(),
                taken.taken().epoch(),
            )),
            Err(SpaceError::NotHeld(_)) => worked.lost.push(topic),
            Err(error) => panic!("{worker} completes {topic}: {error}"),
        }
    }
}

/// The results the seed reads once it reads at least `count`, read again after a pause, so a
/// result (a duplicate one too) still on its way when the count was reached is among them.
async fn settled_results(seed: &mut JavaSeed, count: usize) -> Vec<(String, String, String)> {
    let deadline = Deadline::new("the seed to read the results");
    loop {
        let results = seed.results().await;
        if results.len() >= count {
            break;
        }
        deadline.tick(results).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    seed.results().await
}

/// `count` Rust peers joined to the seed over tcp (each its own `Peer` in this process, linked
/// to the seed alone, so each hears the others' claims through Java's relay), with their tasks
/// spaces opened.
async fn racers(seed: &mut JavaSeed, count: usize) -> (Vec<Peer>, Vec<Space>) {
    let mut peers = Vec::new();
    for _ in 0..count {
        peers.push(join(seed, "tcp").await);
    }
    let spaces: Vec<Space> = peers.iter().map(tasks_of).collect();
    for tasks in &spaces {
        tasks.pull().await.expect("open the space");
    }
    (peers, spaces)
}

/// Waits until each of `spaces` holds `count` available tasks.
async fn each_holds(spaces: &[Space], count: usize) {
    for tasks in spaces {
        let deadline = Deadline::new("each Rust peer to hold the tasks");
        loop {
            let held = tasks
                .read_all_typed::<Task>(&Template::of::<Task>(), count.saturating_mul(2))
                .await
                .expect("read_all_typed");
            if held.len() == count {
                break;
            }
            deadline.tick(held.len()).await;
        }
    }
}

/// The entries for which a claim won the lattice of one peer more than once, from the events
/// `events` has buffered since it subscribed: that peer's own claim and then a rival's with a
/// lower stamp. Nothing renews a claim in these races, so a second winning claim is a rival's.
fn rival_claims(events: &mut broadcast::Receiver<PeerEvent>) -> BTreeSet<String> {
    let mut claims: BTreeMap<String, usize> = BTreeMap::new();
    loop {
        match events.try_recv() {
            Ok(PeerEvent::ClaimFolded { space, entry_id }) if space == SPACE => {
                *claims.entry(entry_id).or_default() += 1;
            }
            Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => break,
        }
    }
    claims
        .into_iter()
        .filter(|(_, folded)| *folded > 1)
        .map(|(entry_id, _)| entry_id)
        .collect()
}

/// 2a. A duel: three Rust peers and the seed go for the one task the space holds at the same
///     moment (one task drives the three Rust takes, so their claims leave within microseconds
///     of one another, well inside the time a claim takes to cross Java's relay). The claims
///     collide (a Rust peer's lattice takes a rival's claim over its own), exactly one racer
///     wins and completes the task, and Java's lattice names the winner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2a_three_rust_peers_and_java_duel_for_one_task() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let (peers, spaces) = racers(&mut seed, 3).await;
    seed.ask("write-task duel 1").await;
    each_holds(&spaces, 1).await;
    // Let each peer's actor finish folding what the write and the pulls brought.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut claim_events: Vec<_> = peers.iter().map(Peer::subscribe).collect();

    let duel = |i: usize| {
        let tasks = spaces[i].clone();
        async move {
            let taken = tasks
                .take_typed::<Task>(
                    &task_named("duel"),
                    Lease::parse("30s").expect("a lease"),
                    Duration::from_secs(3),
                )
                .await
                .expect("take_typed");
            match taken {
                Some(taken) => {
                    let worker = format!("rust-{}", i + 1);
                    taken
                        .complete_with(
                            &TaskResult::new("duel", "done by rust", &worker),
                            Lease::DEFAULT_RESULT,
                            Map::new(),
                        )
                        .await
                        .expect("the winner completes");
                    Some((taken.taken().holder().to_owned(), taken.taken().epoch()))
                }
                None => None,
            }
        }
    };
    let (java, first, second, third) = tokio::join!(
        seed.ask("take-task 3000 java-seed"),
        duel(0),
        duel(1),
        duel(2),
    );
    let rust = [first, second, third];
    let rivals: BTreeSet<String> = claim_events.iter_mut().flat_map(rival_claims).collect();
    println!(
        "java took {}, rust took {rust:?}, rival claims on {rivals:?}",
        java["took"]
    );

    let winners: Vec<_> = rust.iter().flatten().collect();
    let java_won = java["took"] == "duel";
    assert_eq!(
        winners.len() + usize::from(java_won),
        1,
        "exactly one racer wins: java {java}, rust {rust:?}"
    );
    let state = seed_holds(&mut seed, "duel", "completed").await;
    assert_eq!(
        rivals.into_iter().collect::<Vec<_>>(),
        [state.entry_id.clone().expect("an entry id")],
        "the Rust claims collided"
    );
    let (holder, epoch) = match winners.first() {
        Some((holder, epoch)) => (holder.clone(), *epoch),
        None => (seed.agent(), 1),
    };
    assert_eq!(
        (state.holder.as_deref(), state.epoch),
        (Some(holder.as_str()), Some(epoch)),
        "Java's lattice names the winner"
    );
    let results = settled_results(&mut seed, 1).await;
    assert_eq!(results.len(), 1, "one result: {results:?}");
    for peer in &peers {
        assert_eq!(peer.counters().await.malformed, 0);
        peer.close().await.expect("close");
    }
}

/// 2b. A race: the seed writes 30 tasks; three Rust peers (as in 2a) and the seed itself
///     (`take-all`, Java's own take loop) take them all at once. Every task is completed exactly
///     once: the seed reads 30 results with 30 distinct topics and holds every task completed,
///     and each completion (Rust or Java) was made by the holder of the claim Java's lattice
///     holds for that task, at the epoch it won. How many tasks drew rival claims varies from
///     run to run (each peer skips a task it has heard is claimed); 2a makes claims collide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2b_three_rust_peers_and_java_race_for_thirty_tasks() {
    const TASKS: usize = 30;
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let (peers, spaces) = racers(&mut seed, 3).await;
    let topics: BTreeSet<String> = (0..TASKS).map(|i| format!("race-{i:02}")).collect();
    for (i, topic) in topics.iter().enumerate() {
        seed.ask(&format!("write-task {topic} {i}")).await;
    }
    // Every racer starts from the same space, and all start together (one task drives all four).
    each_holds(&spaces, TASKS).await;
    let mut claim_events: Vec<_> = peers.iter().map(Peer::subscribe).collect();
    let idle = Duration::from_secs(3);
    let worker = |i: usize| race_worker(spaces[i].clone(), format!("rust-{}", i + 1), idle);
    let (java, first, second, third) = tokio::join!(
        seed.ask_within("take-all 3000 java-seed", Duration::from_secs(120)),
        worker(0),
        worker(1),
        worker(2),
    );
    let rust = [first, second, third];
    let java_took = texts(&java["took"]);
    let java_lost = texts(&java["lost"]);
    println!(
        "java took {} {java_took:?}, lost {java_lost:?}",
        java_took.len()
    );
    for (i, worked) in rust.iter().enumerate() {
        println!(
            "rust-{} completed {} {:?}, lost {:?}",
            i + 1,
            worked.completed.len(),
            worked
                .completed
                .iter()
                .map(|(topic, _, epoch)| format!("{topic}@{epoch}"))
                .collect::<Vec<_>>(),
            worked.lost
        );
    }

    let contended: BTreeSet<String> = claim_events.iter_mut().flat_map(rival_claims).collect();

    // Each racer's own record: no topic completed twice, all 30 completed.
    let mut completions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for topic in &java_took {
        completions
            .entry(topic.clone())
            .or_default()
            .push("java-seed".to_owned());
    }
    for (i, worked) in rust.iter().enumerate() {
        for (topic, _, _) in &worked.completed {
            completions
                .entry(topic.clone())
                .or_default()
                .push(format!("rust-{}", i + 1));
        }
    }
    let twice: Vec<_> = completions.iter().filter(|(_, by)| by.len() > 1).collect();
    assert!(twice.is_empty(), "completed more than once: {twice:?}");
    assert_eq!(
        completions.keys().cloned().collect::<BTreeSet<_>>(),
        topics,
        "every task completed"
    );

    // What Java holds: 30 results with 30 distinct topics, and every task completed by the holder
    // whose worker wrote its result.
    let deadline = Deadline::new("the seed to hold every completion");
    let states = loop {
        let states = seed.task_states().await;
        let done = states.values().filter(|s| s.state == "completed").count();
        if done >= TASKS {
            break states;
        }
        deadline.tick(done).await;
    };
    let results = settled_results(&mut seed, TASKS).await;
    let rivalled: Vec<&str> = states
        .values()
        .filter(|state| {
            state
                .entry_id
                .as_ref()
                .is_some_and(|id| contended.contains(id))
        })
        .map(|state| state.topic.as_str())
        .collect();
    println!("{} tasks drew rival claims: {rivalled:?}", rivalled.len());
    let mut by_topic: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (topic, _, worker) in &results {
        by_topic.entry(topic).or_default().push(worker);
    }
    let duplicated: Vec<_> = by_topic.iter().filter(|(_, by)| by.len() > 1).collect();
    assert!(
        duplicated.is_empty(),
        "results duplicated in Java: {duplicated:?}"
    );
    assert_eq!(results.len(), TASKS, "{results:?}");
    assert_eq!(
        by_topic
            .keys()
            .map(|topic| (*topic).to_owned())
            .collect::<BTreeSet<_>>(),
        topics
    );
    let mut holder_of_worker: BTreeMap<String, String> = BTreeMap::new();
    holder_of_worker.insert("java-seed".to_owned(), seed.agent());
    for (i, peer) in peers.iter().enumerate() {
        holder_of_worker.insert(format!("rust-{}", i + 1), rust_agent(peer));
    }
    for topic in &topics {
        let state = states
            .get(topic)
            .unwrap_or_else(|| panic!("the seed knows {topic}"));
        assert_eq!(state.state, "completed", "{state:?}");
        let worker = by_topic[topic.as_str()][0];
        assert_eq!(
            state.holder.as_ref(),
            holder_of_worker.get(worker),
            "{topic} completed by {worker}, whose claim Java's lattice must hold: {state:?}"
        );
    }
    // No Rust completion of a task another holder won, in Java's lattice: the claim Java holds
    // is the Rust worker's own, at the epoch it won.
    for worked in &rust {
        for (topic, holder, epoch) in &worked.completed {
            let state = &states[topic];
            assert_eq!(
                (state.holder.as_ref(), state.epoch),
                (Some(holder), Some(*epoch)),
                "a Rust peer completed {topic}, which Java saw another claim win"
            );
        }
    }
    for peer in &peers {
        assert_eq!(peer.counters().await.malformed, 0);
        peer.close().await.expect("close");
    }
}

/// 3. A crashed take: a Rust peer takes a Java task with a 3 s hold and is closed without
///    completing it. Java cannot take it while the hold is live, and takes it (at the next
///    epoch) as soon as the hold lapses, within the 3 s hold and a little slack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_java_takes_a_task_whose_rust_holder_crashed_once_the_hold_lapses() {
    /// What Java's take may take beyond the lapse: its settle window, its 20 ms retries, and a
    /// JVM under load.
    const SLACK_MS: i64 = 2_000;
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let topic = "java-crash";
    seed.ask(&format!("write-task {topic} 3")).await;
    let peer = join(&mut seed, "tcp").await;
    let tasks = tasks_of(&peer);
    let taken = tasks
        .take_typed::<Task>(
            &task_named(topic),
            Lease::parse("3s").expect("a lease"),
            DEADLINE,
        )
        .await
        .expect("take_typed")
        .expect("Rust takes the Java task");
    let expires_at = taken.taken().expires_at_millis();
    let holder = rust_agent(&peer);
    let claimed = seed_holds(&mut seed, topic, "claimed").await;
    assert_eq!(claimed.holder.as_deref(), Some(holder.as_str()));
    let java_take = seed.ask("take-task 300 java-worker").await;
    assert_eq!(java_take["took"], Json::Null, "the hold is live");
    assert!(
        now_ms() < expires_at,
        "the check ran while the hold was live"
    );

    // The crash: the peer goes away holding the take.
    peer.close().await.expect("close");
    drop(taken);

    let java_take = seed
        .ask_within("take-task 10000 java-worker", Duration::from_secs(30))
        .await;
    let took_at = now_ms();
    assert_eq!(java_take["took"], topic, "Java takes the lapsed task");
    println!(
        "Java took the task {} ms after the Rust hold lapsed",
        took_at - expires_at
    );
    assert!(
        took_at >= expires_at,
        "Java took the task {} ms before the hold lapsed",
        expires_at - took_at
    );
    assert!(
        took_at - expires_at <= SLACK_MS,
        "Java took the task {} ms after the hold lapsed",
        took_at - expires_at
    );
    let completed = seed_holds(&mut seed, topic, "completed").await;
    assert_eq!(completed.holder.as_deref(), Some(seed.agent().as_str()));
    assert_eq!(completed.epoch, Some(2), "Java's claim is the next epoch");
    // Java's own subscription: the Rust take, then Java's (a REAPPEARED between the two is up to
    // the timing of Java's sweep).
    let transitions: Vec<&String> = completed
        .events
        .iter()
        .filter(|event| !event.starts_with("REAPPEARED"))
        .collect();
    assert_eq!(
        transitions,
        [
            &format!("WRITTEN by {}", seed.agent()),
            &format!("TAKEN by {holder}"),
            &format!("TAKEN by {}", seed.agent()),
            &format!("COMPLETED by {}", seed.agent()),
        ],
        "{completed:?}"
    );
    let results = seed.results().await;
    assert_eq!(
        results,
        [(
            topic.to_owned(),
            "done by java".to_owned(),
            "java-worker".to_owned()
        )]
    );
}

/// 4. An agent-attested write: a renewing subordinate agent of the Rust peer (a 6 s certificate)
///    writes a task, and after its half-life another, which the peer signs under a renewed
///    certificate. Java reads both, AGENT_ATTESTED, issued by the agent's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s4_an_agent_attested_rust_task_reads_in_java_as_agent_attested() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let identity = Identity::generate().expect("identity");
    let peer = join_as(&mut seed, "tcp", identity.clone()).await;
    let agent = identity
        .renewing_subordinate("writer", "PT6S", None, now_ms())
        .expect("an agent");
    let agent_id = agent.agent_id().to_owned();
    let tasks = tasks_of(&peer).as_agent(agent);

    let first = tasks
        .write(
            &Task::new("agent-first", 3),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the agent writes");
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    let second = tasks
        .write(
            &Task::new("agent-second", 4),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the agent writes after its half-life");

    // The Rust side: both agent-attested, the second under a later certificate.
    let certificate_issued = |state: &Map| {
        state
            .get("agentCertificate")
            .and_then(|certificate| certificate.get("issued"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let mut issued = BTreeMap::new();
    for state in peer.space_states(SPACE).await {
        let entry_id = state
            .get("record")
            .and_then(|record| record.get("entryId"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        issued.insert(entry_id, certificate_issued(&state));
    }
    let (first_issued, second_issued) = (
        issued.get(first.as_str()).cloned().flatten(),
        issued.get(second.as_str()).cloned().flatten(),
    );
    assert!(first_issued.is_some(), "{issued:?}");
    assert!(
        second_issued > first_issued,
        "the second write carries a renewed certificate: {issued:?}"
    );
    for id in [&first, &second] {
        let view = tasks.get(id).await.expect("get").expect("held");
        assert_eq!(view.attestation(), Attestation::AgentAttested);
        assert_eq!(view.issuer(), agent_id);
    }

    let deadline = Deadline::new("Java to read both agent tasks");
    loop {
        let listed = seed.tasks().await;
        if listed.contains(&("agent-first".to_owned(), 3))
            && listed.contains(&("agent-second".to_owned(), 4))
        {
            break;
        }
        deadline.tick(listed).await;
    }
    let entries = seed.entries().await;
    for (topic, id) in [("agent-first", &first), ("agent-second", &second)] {
        let entry = entries
            .iter()
            .find(|entry| entry["topic"] == topic)
            .unwrap_or_else(|| panic!("Java lists {topic}: {entries:?}"));
        assert_eq!(entry["entryId"], id.as_str(), "{entry}");
        assert_eq!(entry["issuer"], agent_id.as_str(), "{entry}");
        assert_eq!(entry["attestation"], "AGENT_ATTESTED", "{entry}");
    }
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// 5. A Rust typed watch of the tasks while the seed writes one and takes and completes it:
///    `Written`, then `Taken` (Java's holder), then `Completed`, of the entry Java names; a watch
///    of another topic hears none of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s5_a_rust_watch_sees_java_write_take_and_complete() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&mut seed, "tcp").await;
    let tasks = tasks_of(&peer);
    let topic = "java-watched";
    let mut events = tasks
        .watch_typed::<Task>(&Template::of::<Task>())
        .await
        .expect("watch the tasks");
    let mut elsewhere = tasks
        .watch_typed::<Task>(&task_named("another-topic"))
        .await
        .expect("watch another topic");

    seed.ask(&format!("write-task {topic} 2")).await;
    let written = next_typed(&mut events).await;
    assert_eq!(written.kind, EventKind::Written);
    assert_eq!(written.entry.value(), &Task::new(topic, 2));
    assert_eq!(written.entry.view().issuer(), seed.agent());
    assert_eq!(written.entry.view().holder(), None);

    let took = seed.ask("take-task 5000 java-worker").await;
    assert_eq!(took["took"], topic);
    let taken = next_typed(&mut events).await;
    let completed = next_typed(&mut events).await;
    assert_eq!(
        [taken.kind, completed.kind],
        [EventKind::Taken, EventKind::Completed]
    );
    assert_eq!(taken.entry.view().holder(), Some(seed.agent().as_str()));
    assert!(!taken.entry.view().completed());
    assert!(completed.entry.view().completed());
    assert_eq!(completed.entry.view().holder(), Some(seed.agent().as_str()));
    let state = seed_holds(&mut seed, topic, "completed").await;
    for event in [&written, &taken, &completed] {
        assert_eq!(
            Some(event.entry.entry_id().as_str()),
            state.entry_id.as_deref(),
            "the events are of the entry Java names"
        );
        assert_eq!(event.entry.value(), &Task::new(topic, 2));
    }
    // Nothing more about it (each transition once), and nothing for another topic.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(events.try_next().is_none(), "one event per transition");
    assert!(elsewhere.try_next().is_none(), "another topic's watch");
    assert_eq!(events.skipped() + events.dropped(), 0);
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// 6. Scenario 1 over tls, the seed under `--require-attestation --channel-auth ATTESTED`: the
///    link attests the seed and carries bare frames the Rust peer accepts on its strength.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s6_the_typed_take_over_attested_tls() {
    let classpath = classpath_or_skip!();
    let (mut seed, peer) = typed_take_and_complete(
        &classpath,
        &[
            "--tls",
            "--require-attestation",
            "--channel-auth",
            "ATTESTED",
        ],
        "tls",
    )
    .await;
    let link = peer.link().expect("a link");
    assert_eq!(link.scheme, "tls");
    assert_eq!(link.attested.as_deref(), Some(seed.peer.as_str()));
    let deadline = Deadline::new("bare frames from the seed, accepted by the Rust peer");
    loop {
        let frames = seed.ask("frames").await;
        let counters = peer.counters().await;
        if frames["bare"].as_u64().unwrap_or(0) > 0 && counters.attested_frames > 0 {
            assert_eq!(counters.malformed, 0, "{counters:?}");
            break;
        }
        deadline.tick((frames, counters)).await;
    }
    peer.close().await.expect("close");
}

// ------------------------------------------------------------------------------ long texts

/// The pieces [`long_text`] cycles through (the seed's `PIECES`): twelve UTF-16 units, every
/// UTF-8 width, two surrogate pairs.
const PIECES: [&str; 10] = [
    "t",
    "o",
    "p",
    "\u{e9}",
    "\u{4e2d}",
    "\u{1f600}",
    "-",
    "\u{20ac}",
    "\u{1d11e}",
    "x",
];

/// The seed's `longText`: a text of exactly `units` UTF-16 units, the characters of `prefix`
/// and then [`PIECES`] over and over, a `z` where a surrogate pair would overshoot.
fn long_text(prefix: &str, units: usize) -> String {
    let mut text = String::new();
    let mut have = 0;
    let head = prefix.chars().map(String::from);
    let cycle = PIECES.iter().cycle().map(|piece| (*piece).to_owned());
    for piece in head.chain(cycle) {
        if have >= units {
            break;
        }
        let width = piece.encode_utf16().count();
        let piece = if have + width > units {
            "z".to_owned()
        } else {
            piece
        };
        have += piece.encode_utf16().count();
        text.push_str(&piece);
    }
    text
}

/// The SHA-256 of a text's UTF-8 bytes in lowercase hex, as the seed prints it.
fn sha256_hex(text: &str) -> String {
    hex::encode(agentspaces::wire::crypto::port().sha256(text.as_bytes()))
}

/// The UTF-16 length of each chunk of the text's encoding (empty for a definite text).
fn chunk_units(text: &str) -> Vec<usize> {
    let bytes = cbor::encode(&Value::from(text));
    let mut lengths = Vec::new();
    if bytes.first() != Some(&0x7F) {
        return lengths;
    }
    let mut at = 1;
    while bytes[at] != 0xFF {
        let (length, width) = match bytes[at] & 0x1F {
            info @ 0..=23 => (usize::from(info), 0),
            24 => (usize::from(bytes[at + 1]), 1),
            _ => (
                usize::from(u16::from_be_bytes([bytes[at + 1], bytes[at + 2]])),
                2,
            ),
        };
        let from = at + 1 + width;
        let chunk = std::str::from_utf8(&bytes[from..from + length]).expect("a UTF-8 chunk");
        lengths.push(chunk.encode_utf16().count());
        at = from + length;
    }
    lengths
}

/// The seed's `long-texts` entry (a task or a result) whose `field` digest is `sha`.
async fn java_long_text(seed: &mut JavaSeed, kind: &str, field: &str, sha: &str) -> Option<Json> {
    let texts = seed.ask("long-texts").await;
    texts[kind]
        .as_array()
        .and_then(|items| items.iter().find(|item| item[field] == sha).cloned())
}

/// 7. Long texts from Java, both ways through a take: the seed writes a task whose topic is
///    10,000 UTF-16 units of every UTF-8 width with surrogate pairs (Jackson chunks it, its first
///    chunk a unit short so as not to split a pair) and whose signed record carries a 5,000-unit
///    tag. Rust reads it intact (the fold verified the record's signature over a sign view
///    re-encoded with the tag in Jackson's chunks), takes it, and completes it with a result of
///    a 9,000-unit summary and a 4,500-unit tag, which Java decodes (its strict reader refuses a
///    text chunked otherwise), verifies, and reads intact: its own digests match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s7_a_long_java_topic_is_taken_and_completed_with_a_long_rust_summary() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let topic = long_text("topic:", 10_000);
    let note = long_text("tag-v:", 5_000);
    assert_eq!(topic.encode_utf16().count(), 10_000);
    assert!(topic.chars().any(|c| c.len_utf16() == 2) && topic.len() > 15_000);
    assert_eq!(chunk_units(&topic), [3995, 3996, 2009]);

    let written = seed.ask("write-long-task 10000 6 5000").await;
    let written = &written["written"];
    assert_eq!(written["topicUnits"], 10_000, "{written}");
    assert_eq!(
        written["topicSha256"],
        sha256_hex(&topic),
        "Java builds the same topic"
    );
    assert_eq!(written["tagUnits"], 5_000, "{written}");
    assert_eq!(written["tagSha256"], sha256_hex(&note), "and the same tag");
    let peer = join(&mut seed, "tcp").await;
    let tasks = tasks_of(&peer);

    let read = tasks
        .read_typed::<Task>(&task_named(&topic), DEADLINE)
        .await
        .expect("read_typed")
        .expect("Rust reads the long Java task");
    assert!(read.value() == &Task::new(&topic, 6), "the topic intact");
    assert!(
        read.view().tag("note") == Some(note.as_str()),
        "the tag intact"
    );
    assert_eq!(read.view().issuer(), seed.agent());
    assert_eq!(written["entryId"], read.entry_id().as_str());

    let taken = tasks
        .take_typed::<Task>(
            &task_named(&topic),
            Lease::parse("30s").expect("a lease"),
            DEADLINE,
        )
        .await
        .expect("take_typed")
        .expect("Rust takes the long Java task");
    assert!(taken.value().topic == topic);
    let summary = long_text("summary-of-it:", 9_000);
    let result_note = long_text("tag-v:", 4_500);
    assert_eq!(chunk_units(&summary), [3995, 3996, 1009]);
    let mut tags = Map::new();
    tags.insert("note", result_note.as_str());
    taken
        .complete_with(
            &TaskResult::new(&topic, &summary, "rust-worker"),
            Lease::DEFAULT_RESULT,
            tags,
        )
        .await
        .expect("complete_with");

    let topic_sha = sha256_hex(&topic);
    let deadline = Deadline::new("Java to read the long Rust result");
    let result = loop {
        if let Some(result) = java_long_text(&mut seed, "results", "topicSha256", &topic_sha).await
        {
            break result;
        }
        deadline.tick("no result yet").await;
    };
    assert_eq!(result["topicUnits"], 10_000, "{result}");
    assert_eq!(result["summaryUnits"], 9_000, "{result}");
    assert_eq!(
        result["summarySha256"],
        sha256_hex(&summary),
        "the summary intact"
    );
    assert_eq!(result["worker"], "rust-worker", "{result}");
    assert_eq!(result["tags"]["note"]["units"], 4_500, "{result}");
    assert_eq!(
        result["tags"]["note"]["sha256"],
        sha256_hex(&result_note),
        "the result's tag intact"
    );
    let completed = seed_holds(&mut seed, &topic, "completed").await;
    assert_eq!(completed.holder, Some(rust_agent(&peer)));
    assert!(
        java_long_text(&mut seed, "tasks", "topicSha256", &topic_sha)
            .await
            .is_none(),
        "the completed task is gone in Java"
    );
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// 8. Long texts from Rust: a task whose topic is 12,001 UTF-16 units with surrogate pairs and
///    whose record carries a 5,000-unit tag, both written in Jackson's chunks, which Java decodes,
///    verifies, and reads intact (its digests match). Java then takes the task and prints the
///    whole topic it decoded, and completes it with a result whose topic Jackson re-encodes,
///    which Rust reads back equal to the topic it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8_a_long_rust_topic_reads_intact_in_java() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&mut seed, "tcp").await;
    let tasks = tasks_of(&peer);
    let topic = long_text("topic:", 12_001);
    let note = long_text("tag-v:", 5_000);
    assert_eq!(chunk_units(&topic), [3995, 3996, 3996, 14]);
    let mut tags = Map::new();
    tags.insert("note", note.as_str());
    let id = tasks
        .write(&Task::new(&topic, 8), Lease::DEFAULT_WRITE, tags)
        .await
        .expect("write");

    let topic_sha = sha256_hex(&topic);
    let deadline = Deadline::new("Java to read the long Rust task");
    let task = loop {
        if let Some(task) = java_long_text(&mut seed, "tasks", "topicSha256", &topic_sha).await {
            break task;
        }
        deadline.tick("no task yet").await;
    };
    assert_eq!(task["entryId"], id.as_str(), "{task}");
    assert_eq!(task["topicUnits"], 12_001, "{task}");
    assert_eq!(task["priority"], 8, "{task}");
    assert_eq!(task["issuer"], rust_agent(&peer), "{task}");
    assert_eq!(task["tags"]["note"]["units"], 5_000, "{task}");
    assert_eq!(
        task["tags"]["note"]["sha256"],
        sha256_hex(&note),
        "the tag intact"
    );

    let took = seed.ask("take-task 5000 java-worker").await;
    assert!(
        took["took"].as_str() == Some(topic.as_str()),
        "Java took the whole topic"
    );
    let result = tasks
        .read_typed::<TaskResult>(
            &Template::of::<TaskResult>().where_("topic", Matcher::Eq(topic.as_str().into())),
            DEADLINE,
        )
        .await
        .expect("read_typed")
        .expect("Rust reads Java's result");
    assert!(
        result.value() == &TaskResult::new(&topic, "done by java", "java-worker"),
        "Jackson's chunks decode to the topic Rust wrote"
    );
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// The seed's `Priced` record: a `BigDecimal` and a `BigInteger`.
const PRICED: &str = "ai.badmonkey.agentspaces.interop.Seed$Priced#v1";

/// The seed's `priced` entry whose item is `item`.
async fn java_priced(seed: &mut JavaSeed, item: &str) -> Option<Json> {
    let priced = seed.ask("priced").await;
    priced["priced"]
        .as_array()
        .and_then(|items| items.iter().find(|entry| entry["item"] == item).cloned())
}

/// 9. Big numbers both ways: Java writes `Priced` records whose amount is a `BigDecimal` (tag 4)
///    and whose serial is a `BigInteger` past 64 bits (tag 2 or 3); Rust reads them on the wire as
///    a [`Value::Decimal`] and a [`Value::BigInt`] that print as Java prints them. Rust writes
///    `Priced` payloads of a decimal and of integers outside Java's `long`, which Java's strict
///    reader accepts and reads to the same values: 2^64 - 1 among them, written as a bignum since
///    Java's strict reader drops a plain integer past `long`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9_big_numbers_cross_between_java_and_rust_both_ways() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let peer = join(&mut seed, "tcp").await;
    let tasks = tasks_of(&peer);

    for (item, amount, serial) in [
        ("java-a", "1.25", "18446744073709551616"),
        (
            "java-b",
            "-12.50",
            "-340282366920938463463374607431768211457",
        ),
        ("java-c", "0.0000125", "9223372036854775808"),
    ] {
        let written = seed
            .ask(&format!("write-priced {item} {amount} {serial}"))
            .await;
        assert!(written["written"]["entryId"].is_string(), "{written}");
    }
    let template = Template::new(PRICED);
    let deadline = Deadline::new("Rust to read Java's priced items");
    let read = loop {
        let read = tasks.read_all(&template, 10).await.expect("read_all");
        if read.len() == 3 {
            break read;
        }
        deadline.tick("not all priced items yet").await;
    };
    let mut seen = BTreeMap::new();
    for entry in &read {
        let payload = entry.payload();
        let item = payload
            .get("item")
            .and_then(Value::as_str)
            .expect("an item");
        let amount = payload
            .get("amount")
            .and_then(Value::as_decimal)
            .map(ToString::to_string)
            .expect("a decimal amount");
        let serial = match payload.get("serial") {
            Some(Value::BigInt(big)) => big.to_string(),
            Some(Value::Int(n)) => n.to_string(),
            other => panic!("{item}: a serial of {other:?}"),
        };
        seen.insert(item.to_owned(), (amount, serial));
    }
    assert_eq!(
        seen,
        BTreeMap::from([
            (
                "java-a".to_owned(),
                ("1.25".to_owned(), "18446744073709551616".to_owned())
            ),
            (
                "java-b".to_owned(),
                (
                    "-12.5".to_owned(),
                    "-340282366920938463463374607431768211457".to_owned()
                )
            ),
            (
                "java-c".to_owned(),
                ("0.0000125".to_owned(), "9223372036854775808".to_owned())
            ),
        ])
    );

    for (item, amount, serial) in [
        ("rust-a", "2.50", Value::Int(i128::from(u64::MAX))),
        ("rust-b", "1E+3", Value::Int(-(1i128 << 63) - 1)),
        (
            "rust-c",
            "-0.001",
            cbor::parse_integer("123456789012345678901234567890").expect("a bignum"),
        ),
    ] {
        let mut payload = Map::new();
        payload.insert("item", item);
        payload.insert("amount", Value::Decimal(amount.parse().expect("a decimal")));
        payload.insert("serial", serial);
        tasks
            .write_value(
                PRICED,
                Value::Map(payload),
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write_value");
    }
    for (item, amount, serial) in [
        ("rust-a", "2.5", "18446744073709551615"),
        ("rust-b", "1E+3", "-9223372036854775809"),
        ("rust-c", "-0.001", "123456789012345678901234567890"),
    ] {
        let deadline = Deadline::new("Java to read a Rust priced item");
        let priced = loop {
            if let Some(priced) = java_priced(&mut seed, item).await {
                break priced;
            }
            deadline.tick("not yet").await;
        };
        assert_eq!(priced["amount"], amount, "{priced}");
        assert_eq!(priced["serial"], serial, "{priced}");
        assert_eq!(priced["issuer"], rust_agent(&peer), "{priced}");
    }
    assert_eq!(peer.counters().await.malformed, 0);
    peer.close().await.expect("close");
}

/// The Rust entry types encode as the seed's records do (schema and field order), so a typed
/// value and Java's payload are the same bytes.
#[test]
fn the_entry_types_are_the_seeds_records() {
    assert_eq!(
        Task::SCHEMA,
        "ai.badmonkey.agentspaces.interop.Seed$Task#v1"
    );
    assert_eq!(
        TaskResult::SCHEMA,
        "ai.badmonkey.agentspaces.interop.Seed$Result#v1"
    );
    let payload = entry::to_value(&Task::new("t", 1)).expect("a payload");
    let fields: Vec<&str> = payload
        .as_map()
        .map(|map| map.keys().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(fields, ["topic", "priority"]);
    assert!(!cbor::encode(&payload).is_empty());
}
