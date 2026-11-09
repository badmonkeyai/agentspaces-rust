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

//! The worker layer ([`agentspaces::agent`], [`agentspaces::remote`], [`agentspaces::catalog`])
//! against the Java reference: each test starts its own scripted Java seed (`interop/java-seed`,
//! `ai.badmonkey.agentspaces.interop.Seed`) on a free port, drives it over its standard input (one
//! command per line, one JSON object per line back), and checks what Java's `AgentBinder`,
//! `DiscoveryService`, and `RemoteActions` make of Rust agents, and what the Rust catalogue makes
//! of Java's:
//!
//! 1. a Rust bound worker's AgentCard is admitted by Java's `DiscoveryService` (attested,
//!    certified, its declared action exactly as Java parses it), and Java's
//!    `RemoteActions.available()` lists its action;
//! 2. Java invokes the Rust action through `RemoteAction.invoke`: the Rust worker takes the task
//!    (writing a decoy result first) and completes it, and Java's invoke answers the result that
//!    correlates by the shared `topic` field;
//! 3. a Java agent bound through the AgentSpaces facade (`@AgentSpec`, `@SpaceTake`) is offered by
//!    the Rust `FleetCatalog`, and a Rust `call` by name and by consumed schema is served by it;
//! 4. replicas collapse across languages: a Java agent and a Rust agent declaring the same action
//!    are one offering with two replicas, which Java and Rust name alike; a Rust action of the
//!    same name producing another schema splits it into two offerings with the Ruby gateway's
//!    stable `research_<8 hex>` names;
//! 6. stopping: (a) a Rust worker stopped mid-handler with a grace period finishes the running
//!    task, which Java reads, and takes nothing Java writes after the stop; (b) a Rust worker
//!    process killed (SIGKILL) mid-task lets the task reappear once its hold lapses, and a Java
//!    agent takes and completes it;
//! 7. scenarios 1 and 2 over `tls` under `--require-attestation --channel-auth ATTESTED`.
//!
//! The `aspace` binary's halves of these scenarios (`aspace cards --json` and `aspace call` of a
//! Java agent, and scenario 5: `aspace work` draining Java tasks against the seed's own takes)
//! are in `crates/aspace/tests/cli_java.rs`, where Cargo builds the binary they run.
//!
//! Scenario 6b runs its worker in a child process: this test binary run again for the ignored
//! test `s6b_child_worker`, which does nothing unless [`CHILD_SEED`] is set.
//!
//! The seed is built on first use with `mvn -q -o` when `target/classes` or
//! `target/classpath.txt` is missing (or the source is newer than its class). When `java` or the
//! build is unavailable each test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set,
//! in which case it fails. `JAVA_HOME` picks the `java` binary when set;
//! `AGENTSPACES_JAVA_SEED_DIR` points at another copy of the seed project. Every seed and child
//! process a test starts is killed when the test ends, also when it fails; a failing test prints
//! the tail of the seed's standard error.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use agentspaces::agent::{Bound, HandlerError, Reply, TakeContext};
use agentspaces::catalog::{FleetCatalog, Principal};
use agentspaces::entry::Entry as _;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, default_dialers};
use agentspaces::remote::{RemoteAction, RemoteActions};
use agentspaces::space::{Attestation, Fleet, Lease};
use agentspaces::wire::cbor::Map;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::seed::Seed;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

/// The founding text of the seed's group.
const FOUNDING: &str = "agentspaces-rust-interop-v1";
/// The seed's replicated space.
const SPACE: &str = "tasks";
/// The schema of the seed's `Task(String topic, int priority)` record.
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
/// The schema of the seed's `Result(String topic, String summary, String worker)` record.
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
/// A schema no Java class has: a rival action's product in scenario 4.
const REPORT: &str = "ai.badmonkey.agentspaces.interop.Seed$Report#v1";
/// The Java classes of the seed's records, as Java's `RemoteActions` resolves them.
const TASK_CLASS: &str = "ai.badmonkey.agentspaces.interop.Seed$Task";
const RESULT_CLASS: &str = "ai.badmonkey.agentspaces.interop.Seed$Result";
/// The Ruby gateway's names (`mcp.rb` `suffixed`, computed with ruby 4.0.9:
/// `Digest::SHA256.hexdigest(JSON.generate([name, consumes, produces, space]))[0, 8]`) of the
/// two `research` actions of scenario 4.
const RESEARCH_RESULT: &str = "research_c2cadaba";
const RESEARCH_REPORT: &str = "research_f6351ddd";
/// The seed's main class.
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
/// The seed's class file and source, relative to the seed project.
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
/// The seed's dependency classpath, relative to the seed project.
const SEED_CLASSPATH: &str = "target/classpath.txt";
/// The agent name the seed's space writes as.
const SEED_AGENT: &str = "java-seed";
/// The variable that makes [`s6b_child_worker`] run: the seed's `host:port`.
const CHILD_SEED: &str = "ASPACE_INTEROP_AGENTS_CHILD_SEED";

/// The longest any poll waits for something to happen.
const DEADLINE: Duration = Duration::from_secs(30);
/// The pause between polls.
const POLL: Duration = Duration::from_millis(100);
/// How long a JVM may take to start and print its first line.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one command to the seed may take (`invoke ... 15000` waits up to fifteen seconds).
const ANSWER: Duration = Duration::from_secs(30);
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

/// Lines of a pipe, read on a thread of their own.
fn lines_of(pipe: impl std::io::Read + Send + 'static) -> mpsc::UnboundedReceiver<String> {
    let (tx, lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    lines
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-agents");
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
        let mut seed = Self {
            child,
            stdin,
            lines: lines_of(stdout),
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

    /// Sends one command and returns the seed's answer, an error answer included; panics (with
    /// the seed's log) when the seed does not answer in time.
    async fn try_ask(&mut self, command: &str) -> Json {
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
        answer
    }

    /// [`JavaSeed::try_ask`], panicking when the seed answers an error.
    async fn ask(&mut self, command: &str) -> Json {
        let answer = self.try_ask(command).await;
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

    /// The results the seed's space reads, as `(topic, summary, worker)`.
    async fn results(&mut self) -> Vec<(String, String, String)> {
        self.ask("results").await["results"]
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

    /// The card of `agent` the seed's `DiscoveryService` admitted, if any.
    async fn card(&mut self, agent: &str) -> Option<Json> {
        self.ask("cards").await["cards"]
            .as_array()
            .and_then(|cards| cards.iter().find(|card| card["agent"] == agent).cloned())
    }

    /// The remote actions of `agent` Java's `RemoteActions.available()` lists.
    async fn remote_actions(&mut self, agent: &str) -> Vec<Json> {
        self.ask("remote-actions").await["actions"]
            .as_array()
            .map(|actions| {
                actions
                    .iter()
                    .filter(|action| action["agent"] == agent)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The seed's `task-state` of `topic`.
    async fn task_state(&mut self, topic: &str) -> Json {
        self.ask(&format!("task-state {topic}")).await
    }

    /// The AgentID the seed's own space acts as.
    fn agent(&self) -> String {
        format!("{}/{SEED_AGENT}", self.peer)
    }

    /// The tail of the seed's standard error.
    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        format!("--- {} ---\n{}", self.log.display(), tail(&text, 40))
    }
}

impl Drop for JavaSeed {
    fn drop(&mut self) {
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
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

/// Whether the seed's `task-state` events of a task include `event`.
fn has_event(state: &Json, event: &str) -> bool {
    state["events"]
        .as_array()
        .is_some_and(|events| events.iter().any(|seen| seen == event))
}

/// Polls `check` until it answers `Some`, or panics naming `what` and the last thing seen.
macro_rules! eventually {
    ($what:expr, $check:expr) => {{
        let deadline = Instant::now() + DEADLINE;
        loop {
            match $check {
                Ok(found) => break found,
                Err(last) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out after {DEADLINE:?} waiting for {}; last saw {last:?}",
                        $what
                    );
                    tokio::time::sleep(POLL).await;
                }
            }
        }
    }};
}

// ------------------------------------------------------------------------------ the Rust side

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
struct Outcome {
    topic: String,
    summary: String,
    worker: String,
}

/// A product no Java class declares (scenario 4's rival action).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Report#v1")]
struct Report {
    topic: String,
    pages: i32,
}

impl Task {
    fn new(topic: &str, priority: i32) -> Self {
        Task {
            topic: topic.to_owned(),
            priority,
        }
    }
}

/// A peer configuration for the seed's group through `seed`, with a fresh identity, the default
/// dialers, and quick redials.
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

/// Starts a Rust peer through the seed over `scheme`, checks it joined the seed's group, and
/// waits until the seed lists it.
async fn join(seed: &mut JavaSeed, scheme: &str) -> Fleet {
    let peer = Peer::start(config(Seed::new("127.0.0.1", seed.port, scheme)))
        .await
        .unwrap_or_else(|error| panic!("the Rust peer joins over {scheme}: {error}"));
    assert_eq!(
        peer.group_id(),
        seed.group,
        "both derive the GroupID from the founding text"
    );
    let id = peer.peer_id().to_owned();
    eventually!("the seed to list the Rust peer", {
        let members = seed.members().await;
        if members.contains(&id) {
            Ok(())
        } else {
            Err(members)
        }
    });
    Fleet::from_peer(peer)
}

/// Binds the Rust agent `name`: a `research` take of the seed's tasks producing results. With
/// `decoy`, the handler first writes a result for another topic (`<topic>-decoy`), which shares
/// the `worker` field with the real one but not the `topic`.
async fn rust_researcher(fleet: &Fleet, name: &str, decoy: bool) -> Bound {
    fleet
        .agent(name)
        .describe("Researches tasks in Rust")
        .goal("research a topic")
        .settle(SETTLE)
        .take(
            SPACE,
            Lease::parse("30s").expect("a lease"),
            move |task: Task, ctx: TakeContext| async move {
                if decoy {
                    let decoy = Outcome {
                        topic: format!("{}-decoy", task.topic),
                        summary: "a decoy".to_owned(),
                        worker: ctx.agent_id().to_owned(),
                    };
                    ctx.space()
                        .write(&decoy, Lease::parse("10m")?, Map::new())
                        .await?;
                }
                Ok::<_, HandlerError>(Reply::from(Outcome {
                    topic: task.topic.clone(),
                    summary: format!("researched in rust: {}", task.topic),
                    worker: ctx.agent_id().to_owned(),
                }))
            },
        )
        .action("research")
        .action_description("Researches a task in Rust")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind the Rust agent")
}

/// Waits until Java's `DiscoveryService` admitted the card of `agent`, and answers it.
async fn admitted(seed: &mut JavaSeed, agent: &str) -> Json {
    eventually!("Java to admit the card", {
        match seed.card(agent).await {
            Some(card) => Ok(card),
            None => Err(seed.ask("cards").await),
        }
    })
}

/// The remote actions the Rust peer of `remote` lists for `agent`, once there are `count`.
async fn rust_actions(remote: &RemoteActions, agent: &str, count: usize) -> Vec<RemoteAction> {
    eventually!("the Rust peer to list the agent's actions", {
        let _ = remote.fleet().peer().pull_ads().await;
        let listed: Vec<RemoteAction> = remote
            .available()
            .await
            .into_iter()
            .filter(|action| action.agent() == agent)
            .collect();
        if listed.len() == count {
            Ok(listed)
        } else {
            Err(listed)
        }
    })
}

/// The offerings of `catalog` once `check` holds of them.
async fn offerings_when(
    catalog: &FleetCatalog,
    what: &str,
    check: impl Fn(&[agentspaces::catalog::Offering]) -> bool,
) -> Vec<agentspaces::catalog::Offering> {
    eventually!(what, {
        let _ = catalog.remote().fleet().peer().pull_ads().await;
        catalog.refresh().await;
        let offerings = catalog.offerings();
        if check(&offerings) {
            Ok(offerings)
        } else {
            Err(offerings
                .iter()
                .map(|o| format!("{} x{} by {}", o.name(), o.replicas(), o.action().agent()))
                .collect::<Vec<_>>())
        }
    })
}

// ------------------------------------------------------------------------------ scenarios 1, 2

/// Scenario 1 on a joined `fleet`: binds a Rust researcher, and checks Java admits its card and
/// lists its remote action. Answers the bound agent.
async fn rust_card_in_java(seed: &mut JavaSeed, fleet: &Fleet) -> Bound {
    let bound = rust_researcher(fleet, "rust-researcher", true).await;
    let agent = bound.agent_id().to_owned();
    let issuer = fleet.peer().peer_id().to_owned();
    let card = admitted(seed, &agent).await;
    println!("Java's DiscoveryService admitted: {card}");
    // As Java parses the card (`AgentCard`, `CardAction`).
    assert_eq!(card["issuer"], issuer.as_str(), "{card}");
    assert_eq!(
        card["attested"], true,
        "the card carries the agent's key: {card}"
    );
    assert_eq!(
        card["certified"], true,
        "and the certificate covering it: {card}"
    );
    assert_eq!(card["agentKey"], true, "{card}");
    assert_eq!(card["description"], "Researches tasks in Rust", "{card}");
    assert_eq!(card["goals"], json!(["research a topic"]), "{card}");
    assert_eq!(card["consumes"], json!([TASK]), "{card}");
    assert_eq!(card["produces"], json!([RESULT]), "{card}");
    assert_eq!(card["spaceBindings"], json!({ TASK: SPACE }), "{card}");
    assert_eq!(
        card["actions"],
        json!([{
            "name": "research",
            "kind": "take",
            "space": SPACE,
            "description": "Researches a task in Rust",
            "consumes": [TASK],
            "produces": [RESULT],
        }]),
        "{card}"
    );
    // Java's RemoteActions resolves both schemas to the seed's classes and lists the action.
    let actions = eventually!("Java's RemoteActions to list the Rust action", {
        let actions = seed.remote_actions(&agent).await;
        if actions.is_empty() {
            Err(seed.ask("remote-actions").await)
        } else {
            Ok(actions)
        }
    });
    println!("Java's RemoteActions.available(): {actions:?}");
    assert_eq!(actions.len(), 1, "{actions:?}");
    let action = &actions[0];
    assert_eq!(action["name"], "rust-researcher_Task", "{action}");
    assert_eq!(action["declared"], "research", "{action}");
    assert_eq!(action["kind"], "take", "{action}");
    assert_eq!(action["issuer"], issuer.as_str(), "{action}");
    assert_eq!(action["input"], TASK_CLASS, "{action}");
    assert_eq!(action["output"], RESULT_CLASS, "{action}");
    assert_eq!(action["space"], SPACE, "{action}");
    assert_eq!(action["resultSpace"], SPACE, "{action}");
    assert_eq!(
        action["description"], "Researches a task in Rust",
        "{action}"
    );
    bound
}

/// Scenario 2: Java invokes the Rust action through `RemoteAction.invoke`; the Rust worker takes
/// the task, writes a decoy, and completes the task with its result, which Java's invoke answers
/// (correlated by `topic`, past the decoy).
async fn java_invokes_rust(seed: &mut JavaSeed, bound: &Bound, topic: &str) {
    let agent = bound.agent_id().to_owned();
    let invoked = seed.ask(&format!("invoke research {topic} 4 15000")).await;
    println!("Java's RemoteAction.invoke answered: {invoked}");
    assert_eq!(invoked["agent"], agent.as_str(), "{invoked}");
    assert_eq!(invoked["action"], "rust-researcher_Task", "{invoked}");
    assert_eq!(
        invoked["result"],
        json!({
            "topic": topic,
            "summary": format!("researched in rust: {topic}"),
            "worker": agent,
        }),
        "Java's invoke answers the Rust result, not the decoy"
    );
    // The decoy reached Java too, and was passed over by the correlation.
    let decoy = format!("{topic}-decoy");
    let results = seed.results().await;
    assert!(
        results.iter().any(|(t, _, w)| *t == decoy && *w == agent),
        "{results:?}"
    );
    // Java folds the take and completion of the input it wrote, by the Rust agent.
    let state = eventually!("Java to fold the Rust completion", {
        let state = seed.task_state(topic).await;
        if state["state"] == "completed" {
            Ok(state)
        } else {
            Err(state)
        }
    });
    assert_eq!(state["holder"], agent.as_str(), "{state}");
    assert!(
        has_event(&state, &format!("WRITTEN by {}", seed.agent())),
        "{state}"
    );
    assert!(has_event(&state, &format!("TAKEN by {agent}")), "{state}");
    assert!(
        has_event(&state, &format!("COMPLETED by {agent}")),
        "{state}"
    );
    assert!(bound.handled() >= 1);
}

/// 1. A Rust bound worker's AgentCard is admitted by Java and listed by its `RemoteActions`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_java_admits_the_rust_card_and_lists_its_action() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let fleet = join(&mut seed, "tcp").await;
    let bound = rust_card_in_java(&mut seed, &fleet).await;
    assert!(bound.stop(Duration::from_secs(5)).await);
    fleet.close().await.expect("close");
}

/// 2. Java invokes the Rust action through `RemoteActions` and gets the correlated result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2_java_invokes_the_rust_action_and_gets_the_correlated_result() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let fleet = join(&mut seed, "tcp").await;
    let bound = rust_researcher(&fleet, "rust-researcher", true).await;
    let agent = bound.agent_id().to_owned();
    eventually!("Java's RemoteActions to list the Rust action", {
        let actions = seed.remote_actions(&agent).await;
        if actions.is_empty() { Err(()) } else { Ok(()) }
    });
    java_invokes_rust(&mut seed, &bound, "java-calls-rust").await;
    assert!(bound.stop(Duration::from_secs(5)).await);
    fleet.close().await.expect("close");
}

/// 7. Scenarios 1 and 2 over `tls` under `--require-attestation --channel-auth ATTESTED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7_scenarios_1_and_2_over_attested_tls() {
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
    let fleet = join(&mut seed, "tls").await;
    let link = fleet.peer().link().expect("a link");
    assert_eq!(link.scheme, "tls", "{link:?}");
    let bound = rust_card_in_java(&mut seed, &fleet).await;
    java_invokes_rust(&mut seed, &bound, "java-calls-rust-over-tls").await;
    assert!(bound.stop(Duration::from_secs(5)).await);
    fleet.close().await.expect("close");
}

// ------------------------------------------------------------------------------ scenario 3

/// 3. A Java agent bound through the AgentSpaces facade is offered by the Rust catalogue, whose
///    calls (by name and by consumed schema) it serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_the_rust_catalogue_finds_and_calls_the_java_agent() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let bound = seed.ask("bind-agent java-researcher").await;
    let java_agent = format!("{}/java-researcher", seed.peer);
    assert_eq!(bound["bound"], java_agent.as_str(), "{bound}");
    // Java's own discovery holds its card: subordinate-signed, its key certified.
    let card = admitted(&mut seed, &java_agent).await;
    assert_eq!(card["certified"], true, "{card}");

    let fleet = join(&mut seed, "tcp").await;
    let remote = RemoteActions::new(&fleet);
    let actions = rust_actions(&remote, &java_agent, 1).await;
    let action = &actions[0];
    println!("Rust's RemoteActions lists: {action}");
    assert_eq!(action.issuer(), seed.peer);
    assert_eq!(action.name(), "research");
    assert_eq!(action.planner_name(), "java-researcher_Task");
    assert_eq!(action.kind(), Some("take"));
    assert_eq!(action.consumes(), TASK);
    assert_eq!(action.produces(), RESULT);
    assert_eq!(action.space(), SPACE);
    assert_eq!(action.result_space(), SPACE);
    assert_eq!(action.description(), "Researches a task in Java");
    assert_eq!(action.goals(), ["research a topic"]);
    assert_eq!(
        action.card().agent_public_key().map(<[u8]>::len),
        Some(32),
        "the Java card names its agent's own key"
    );

    let catalog = FleetCatalog::new(&fleet);
    let offerings = offerings_when(&catalog, "the Java offering", |offerings| {
        offerings.iter().any(|o| o.action().agent() == java_agent)
    })
    .await;
    assert_eq!(offerings.len(), 1, "{offerings:?}");
    let offering = &offerings[0];
    assert_eq!(offering.name(), "research");
    assert_eq!(offering.replicas(), 1);
    assert_eq!(offering.consumes(), TASK);
    assert_eq!(offering.produces(), RESULT);
    assert_eq!(offering.space(), SPACE);

    for (target, topic) in [
        ("research", "rust-calls-java"),
        (TASK, "rust-calls-java-by-schema"),
    ] {
        let input = Task::new(topic, 5).to_payload().expect("a payload");
        let outcome = catalog
            .call(target, input, &Principal::local(), Duration::from_secs(20))
            .await
            .unwrap_or_else(|error| panic!("call {target}: {error}"));
        println!(
            "Rust's call of {target} answered: {:?}",
            outcome.result_json()
        );
        assert_eq!(outcome.offering, "research");
        let result = outcome.result.as_ref().expect("a result in time");
        assert_eq!(result.schema(), RESULT);
        assert_eq!(result.issuer(), java_agent, "signed by the Java agent");
        assert_eq!(result.attestation(), Attestation::AgentAttested);
        assert_eq!(
            outcome.result_json(),
            Some(json!({
                "topic": topic,
                "summary": format!("researched in java: {topic}"),
                "worker": java_agent,
            }))
        );
        let state = eventually!("Java to hold the call's input completed", {
            let state = seed.task_state(topic).await;
            if state["state"] == "completed" {
                Ok(state)
            } else {
                Err(state)
            }
        });
        assert_eq!(state["holder"], java_agent.as_str(), "{state}");
        let caller = format!("{}/rust", fleet.peer().peer_id());
        assert!(
            has_event(&state, &format!("WRITTEN by {caller}")),
            "{state}"
        );
        assert!(
            has_event(&state, &format!("COMPLETED by {java_agent}")),
            "{state}"
        );
    }
    fleet.close().await.expect("close");
    let _ = seed.ask("unbind-agent java-researcher").await;
}

// ------------------------------------------------------------------------------ scenario 4

/// 4. Replicas collapse across languages, and a rival action under the same name gets the Ruby
///    gateway's stable suffixed name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_replicas_collapse_across_languages_and_a_rival_is_suffixed() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    // The Java replica signs as its peer (no key of its own): that card shape parses too.
    let bound = seed.ask("bind-agent java-twin peer-signed").await;
    let java_twin = format!("{}/java-twin", seed.peer);
    assert_eq!(bound["bound"], java_twin.as_str(), "{bound}");
    let card = admitted(&mut seed, &java_twin).await;
    assert_eq!(card["certified"], false, "{card}");
    assert_eq!(card["agentKey"], false, "{card}");

    // The Rust replica on one peer, the catalogue on another.
    let workers = join(&mut seed, "tcp").await;
    let rust_twin = rust_researcher(&workers, "rust-twin", false).await;
    let caller = join(&mut seed, "tcp").await;
    let catalog = FleetCatalog::new(&caller);
    let twins = [java_twin.as_str(), rust_twin.agent_id()];
    let offerings = offerings_when(&catalog, "one offering of two replicas", |offerings| {
        offerings.len() == 1 && offerings[0].replicas() == 2
    })
    .await;
    assert_eq!(offerings[0].name(), "research", "one name: no suffix");
    assert!(twins.contains(&offerings[0].action().agent()));
    // Both replicas, as the Rust peer and Java name them for a planner.
    let remote = catalog.remote().clone();
    let java_listed = rust_actions(&remote, &java_twin, 1).await;
    assert_eq!(java_listed[0].planner_name(), "java-twin_Task");
    assert!(java_listed[0].card().agent_public_key().is_none());
    let rust_listed = rust_actions(&remote, rust_twin.agent_id(), 1).await;
    let java_names_rust = eventually!("Java's RemoteActions to list the Rust replica", {
        let actions = seed.remote_actions(rust_twin.agent_id()).await;
        if actions.is_empty() {
            Err(())
        } else {
            Ok(actions)
        }
    });
    assert_eq!(
        java_names_rust[0]["name"],
        rust_listed[0].planner_name().as_str()
    );
    assert_eq!(
        java_names_rust[0]["declared"],
        rust_listed[0].name().as_str()
    );

    // A call reaches whichever replica takes the task.
    let outcome = catalog
        .call(
            "research",
            Task::new("either-twin", 2).to_payload().expect("a payload"),
            &Principal::local(),
            Duration::from_secs(20),
        )
        .await
        .expect("call the collapsed offering");
    let worker = outcome
        .result_json()
        .and_then(|result| result["worker"].as_str().map(str::to_owned))
        .expect("a result in time");
    println!("the collapsed offering was served by {worker}");
    assert!(twins.contains(&worker.as_str()), "{worker}");

    // A rival: the same action name producing another schema. Two offerings now, each with the
    // Ruby gateway's name for its key. Both consume the same tasks in the same space, so a call
    // of either may be served by the other's agents; the rival takes only urgent tasks (a filter
    // its card does not show), which the calls below are not.
    let rival = workers
        .agent("rust-rival")
        .settle(SETTLE)
        .take(
            SPACE,
            Lease::parse("30s").expect("a lease"),
            |task: Task, _ctx: TakeContext| async move {
                Ok::<_, HandlerError>(Reply::from(Report {
                    topic: task.topic,
                    pages: 3,
                }))
            },
        )
        .action("research")
        .produces::<Report>()
        .where_clause("priority>=100")
        .bind()
        .await
        .expect("bind the rival");
    let offerings = offerings_when(&catalog, "two suffixed offerings", |offerings| {
        offerings.len() == 2
    })
    .await;
    let named: Vec<(String, usize, String)> = offerings
        .iter()
        .map(|o| (o.name().to_owned(), o.replicas(), o.produces().to_owned()))
        .collect();
    println!("offerings after the rival bound: {named:?}");
    assert_eq!(
        named,
        [
            (RESEARCH_RESULT.to_owned(), 2, RESULT.to_owned()),
            (RESEARCH_REPORT.to_owned(), 1, REPORT.to_owned()),
        ]
    );
    // Stable: a refresh lists the same names, and so does a second catalogue.
    assert!(!catalog.refresh().await, "the names did not change");
    let again = FleetCatalog::new(&caller);
    again.refresh().await;
    assert_eq!(again.names(), [RESEARCH_RESULT, RESEARCH_REPORT]);
    // Java lists only what resolves to its classes: the twin, not the rival's Report.
    assert!(
        seed.remote_actions(rival.agent_id()).await.is_empty(),
        "Java has no Report class to invoke the rival with"
    );
    // The suffixed name calls the replicated action.
    let outcome = catalog
        .call(
            RESEARCH_RESULT,
            Task::new("suffixed-call", 1)
                .to_payload()
                .expect("a payload"),
            &Principal::local(),
            Duration::from_secs(20),
        )
        .await
        .expect("call by the suffixed name");
    let served = outcome.result.expect("a result in time");
    assert_eq!(served.schema(), RESULT);

    assert!(rust_twin.stop(Duration::from_secs(5)).await);
    assert!(rival.stop(Duration::from_secs(5)).await);
    caller.close().await.expect("close");
    workers.close().await.expect("close");
}

// ------------------------------------------------------------------------------ scenario 6

/// 6a. A Rust worker stopped mid-handler with a grace period finishes the running task (Java
///     reads its result) and takes nothing Java writes after the stop, with two take loops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s6a_a_stopped_worker_finishes_its_running_task_and_takes_nothing_new() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let fleet = join(&mut seed, "tcp").await;
    let (started_tx, mut started) = mpsc::unbounded_channel::<String>();
    let (release, released) = watch::channel(false);
    let bound = fleet
        .agent("rust-stopper")
        .settle(SETTLE)
        .take(
            SPACE,
            Lease::parse("30s").expect("a lease"),
            move |task: Task, ctx: TakeContext| {
                let started = started_tx.clone();
                let mut released = released.clone();
                async move {
                    let _ = started.send(task.topic.clone());
                    released.wait_for(|go| *go).await?;
                    Ok::<_, HandlerError>(Reply::from(Outcome {
                        summary: format!("finished after the stop: {}", task.topic),
                        topic: task.topic,
                        worker: ctx.agent_id().to_owned(),
                    }))
                }
            },
        )
        .action("research")
        .produces::<Outcome>()
        .parallel(2)
        .bind()
        .await
        .expect("bind");
    let agent = bound.agent_id().to_owned();
    admitted(&mut seed, &agent).await;

    seed.ask("write-task running 1").await;
    let first = tokio::time::timeout(DEADLINE, started.recv())
        .await
        .expect("the handler starts in time")
        .expect("a topic");
    assert_eq!(first, "running");

    // Stop with a grace period while the handler runs; then Java writes another task, which the
    // idle loop must not take.
    let stopping = {
        let bound = bound.clone();
        tokio::spawn(async move { bound.stop(Duration::from_secs(20)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!bound.is_running(), "a stop was asked for");
    seed.ask("write-task after-stop 1").await;
    // Longer than the take loops' poll (1 s) and settle window.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        started.try_recv().is_err(),
        "a handler started after the stop"
    );
    release.send_replace(true);
    let finished = tokio::time::timeout(DEADLINE, stopping)
        .await
        .expect("the stop ends in time")
        .expect("the stop task");
    assert!(finished, "the running handler finished within the grace");

    // Java reads the result of the running task, completed by the agent.
    let state = eventually!("Java to fold the running task's completion", {
        let state = seed.task_state("running").await;
        if state["state"] == "completed" {
            Ok(state)
        } else {
            Err(state)
        }
    });
    assert_eq!(state["holder"], agent.as_str(), "{state}");
    let results = seed.results().await;
    assert!(
        results.contains(&(
            "running".to_owned(),
            "finished after the stop: running".to_owned(),
            agent.clone()
        )),
        "{results:?}"
    );
    // The task written after the stop was never taken by the agent: still available, and Java
    // takes it at once.
    let after = seed.task_state("after-stop").await;
    assert_eq!(after["state"], "available", "{after}");
    assert!(!has_event(&after, &format!("TAKEN by {agent}")), "{after}");
    let took = seed.ask("take-task 5000 java-after-stop").await;
    assert_eq!(took["took"], "after-stop", "{took}");
    assert_eq!(bound.handled(), 1);
    fleet.close().await.expect("close");
}

/// A child process running [`s6b_child_worker`], killed when dropped.
struct ChildWorker {
    child: Child,
    lines: mpsc::UnboundedReceiver<String>,
}

impl ChildWorker {
    /// Waits for the child's line carrying `prefix` (libtest may print its `test ... ` before
    /// it on the same line), and answers what follows it.
    async fn line(&mut self, prefix: &str) -> String {
        let deadline = Instant::now() + STARTUP;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.recv())
                .await
                .unwrap_or_else(|_| panic!("the child printed no {prefix:?} line in time"))
                .unwrap_or_else(|| panic!("the child exited before a {prefix:?} line"));
            if let Some((_, rest)) = line.split_once(prefix) {
                return rest.trim().to_owned();
            }
            eprintln!("child: {line}");
        }
    }
}

impl Drop for ChildWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 6b. A Rust worker process killed (SIGKILL) mid-task lets the task reappear once its 3 s hold
///     lapses, and a Java agent bound through the facade takes and completes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s6b_a_killed_worker_lets_the_task_reappear_for_the_java_agent() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath, &[]).await;
    let mut command = Command::new(std::env::current_exe().expect("this test"));
    command
        .args([
            "--ignored",
            "--exact",
            "s6b_child_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_SEED, format!("127.0.0.1:{}", seed.port))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn the child worker");
    let stdout = child.stdout.take().expect("the child's stdout");
    let mut worker = ChildWorker {
        child,
        lines: lines_of(stdout),
    };
    let agent = worker.line("BOUND ").await;
    admitted(&mut seed, &agent).await;

    seed.ask("write-task doomed 1").await;
    assert_eq!(worker.line("TOOK ").await, "doomed");
    let taken = format!("TAKEN by {agent}");
    eventually!("Java to see the child's take", {
        let state = seed.task_state("doomed").await;
        if has_event(&state, &taken) {
            Ok(())
        } else {
            Err(state)
        }
    });
    let taken_seen = Instant::now();
    // The kill: no stop, no completion, no goodbye.
    worker.child.kill().expect("SIGKILL the child");
    let status = worker.child.wait().expect("the child ends");
    assert!(!status.success(), "{status:?}");

    let java_agent = format!("{}/java-rescuer", seed.peer);
    seed.ask("bind-agent java-rescuer").await;
    let state = eventually!("the Java agent to complete the reappeared task", {
        let state = seed.task_state("doomed").await;
        if state["state"] == "completed" {
            Ok(state)
        } else {
            Err(state)
        }
    });
    let waited = taken_seen.elapsed();
    println!("the Java agent completed the task {waited:?} after the Rust take was seen: {state}");
    assert!(
        waited >= Duration::from_secs(2),
        "Java completed it before the 3 s hold could lapse ({waited:?})"
    );
    // The Java agent's claim is the next epoch after the Rust one; its holder and completion
    // name the agent (the seed's own TAKEN event of a local take through a per-agent view names
    // the space's agent, `java-seed`: how the Java reference reports it).
    assert_eq!(state["holder"], java_agent.as_str(), "{state}");
    assert_eq!(state["epoch"], 2, "{state}");
    assert!(has_event(&state, &taken), "{state}");
    assert!(
        has_event(&state, &format!("COMPLETED by {java_agent}")),
        "{state}"
    );
    let results = seed.results().await;
    assert_eq!(
        results,
        [(
            "doomed".to_owned(),
            "researched in java: doomed".to_owned(),
            java_agent.clone()
        )],
        "one result, by Java"
    );
    let _ = seed.ask("unbind-agent java-rescuer").await;
}

/// The child half of [`s6b_a_killed_worker_lets_the_task_reappear_for_the_java_agent`]: a no-op
/// unless [`CHILD_SEED`] is set, so it passes in an ordinary `--ignored` run. Binds a worker whose
/// handler never ends, prints `BOUND <agent>` and then `TOOK <topic>`, and waits to be killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "the child process of s6b_a_killed_worker_lets_the_task_reappear_for_the_java_agent"]
async fn s6b_child_worker() {
    let Some(address) = std::env::var_os(CHILD_SEED) else {
        return;
    };
    let address = address.to_string_lossy().into_owned();
    let (host, port) = address.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("a port");
    let peer = Peer::start(config(Seed::new(host, port, "tcp")))
        .await
        .expect("the child joins");
    let fleet = Fleet::from_peer(peer);
    let bound = fleet
        .agent("rust-doomed")
        .settle(SETTLE)
        .take(
            SPACE,
            Lease::parse("3s").expect("a lease"),
            |task: Task, _ctx: TakeContext| async move {
                println!("TOOK {}", task.topic);
                std::future::pending::<()>().await;
                Ok::<_, HandlerError>(Reply::none())
            },
        )
        .action("research")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind");
    println!("BOUND {}", bound.agent_id());
    // Killed by the parent long before this.
    tokio::time::sleep(Duration::from_secs(120)).await;
}
