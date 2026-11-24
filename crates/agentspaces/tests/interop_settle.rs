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

//! The settle guarantee of SPEC §7.4 (v0.1.35) between a Rust dial-only peer and the Java
//! reference node, over TCP, with the scripted Java seed of `interop/java-seed`. The Rust peer's
//! link holds frames in one direction past a settle window ([`HoldingDialer`]), so the Rust peer
//! and the Java node each judge themselves the winner of one task:
//!
//! - the Rust claim is earlier and held from Java: Java completes first, and the Rust take, still
//!   in its window, acknowledges Java's completion and comes back empty, with Java's result the
//!   only one everywhere;
//! - the Rust claim is earlier and held from Java, and both complete: the Rust peer, whose claim
//!   won, counts the duplicate once, Java counts nothing, and both results stand;
//! - the Java claim is earlier and held from the Rust peer, and the Java node's window is long:
//!   the Rust completion reaches Java within it, and Java acknowledges it and takes nothing;
//! - the Java claim is earlier and held from the Rust peer, and both complete: Java counts the
//!   duplicate (`duplicateCompletions`), the Rust peer counts nothing;
//! - the Rust claim is earlier and held from Java, and the frame carrying Java's completion with
//!   its claim is lost: the Rust winner pairs the evidence from other frames (SPEC v0.1.36 §7.4,
//!   *Pairing the evidence*), Java's claim alone and its re-offer of it, and Java's completion
//!   under the Rust claim from a later pull, and its take stands down.
//!
//! The seed is built on first use with `mvn -q -o` when its classes are missing or older than its
//! source. When `java` or the build is unavailable the test says why and passes, unless
//! `ASPACE_INTEROP_REQUIRED=1` is set, in which case it fails. `JAVA_HOME` picks the `java`
//! binary when set.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentspaces::clock::SystemClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, default_dialers};
use agentspaces::space::{Fleet, Lease, Space, Template};
use agentspaces::transport::Dialer;
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::identity::Identity;
use serde_json::Value as Json;
use support::HoldingDialer;
use tokio::sync::mpsc;
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-interop-v1";
const SPACE: &str = "tasks";
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";
/// How long anything here may take.
const DEADLINE: Duration = Duration::from_secs(45);
/// How long a JVM may take to start.
const STARTUP: Duration = Duration::from_secs(60);
/// A window long enough for the rival's whole take and completion to land inside it.
const LONG_SETTLE: Duration = Duration::from_secs(3);
/// The Rust peer's window otherwise (the seed's is 200 ms unless a test says otherwise).
const SHORT_SETTLE: Duration = Duration::from_millis(200);

fn required() -> bool {
    std::env::var("ASPACE_INTEROP_REQUIRED").as_deref() == Ok("1")
}

fn seed_dir() -> PathBuf {
    std::env::var_os("AGENTSPACES_JAVA_SEED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/java-seed"))
}

fn java_bin() -> PathBuf {
    std::env::var_os("JAVA_HOME")
        .map(|home| PathBuf::from(home).join("bin/java"))
        .filter(|java| java.is_file())
        .unwrap_or_else(|| PathBuf::from("java"))
}

fn newer(source: &Path, built: &Path) -> bool {
    let modified =
        |path: &Path| -> Option<SystemTime> { std::fs::metadata(path).ok()?.modified().ok() };
    matches!((modified(source), modified(built)), (Some(source), Some(built)) if source > built)
}

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
    Err(format!(
        "`mvn {}` exited with {}: {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout)
    ))
}

/// The seed's classpath (built when needed), or why it cannot run.
fn seed_classpath() -> Result<String, String> {
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

/// The classpath, or `None` after saying why the test passes without Java (a failure when
/// `ASPACE_INTEROP_REQUIRED=1`).
fn classpath_or_skip() -> Option<String> {
    match seed_classpath() {
        Ok(classpath) => Some(classpath),
        Err(why) => {
            assert!(!required(), "the Java interop seed cannot run: {why}");
            eprintln!("skipping: the Java interop seed cannot run: {why}");
            None
        }
    }
}

/// A Java node, killed when dropped.
struct JavaNode {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::UnboundedReceiver<String>,
    log: PathBuf,
    peer: String,
    port: u16,
}

impl JavaNode {
    /// Starts the seed listening on a free port, with `args` after the port.
    async fn listen(classpath: &str, args: &[&str], name: &str) -> JavaNode {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port();
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-settle");
        std::fs::create_dir_all(&logs).expect("a log directory");
        let log = logs.join(format!("{name}-{}.log", std::process::id()));
        let stderr = std::fs::File::create(&log).expect("a log file");
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
            .expect("java starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("a stdout pipe");
        let (tx, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut node = JavaNode {
            child,
            stdin,
            lines,
            log,
            peer: String::new(),
            port,
        };
        let event = node
            .next_json(STARTUP)
            .await
            .unwrap_or_else(|| panic!("the Java node printed nothing:\n{}", node.log_tail()));
        assert_eq!(event["event"], "listening", "{event}");
        node.peer = event["peer"].as_str().unwrap_or_default().to_owned();
        node
    }

    async fn next_json(&mut self, wait: Duration) -> Option<Json> {
        let deadline = Instant::now() + wait;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.recv())
                .await
                .ok()??;
            if let Ok(json) = serde_json::from_str::<Json>(&line)
                && json.is_object()
            {
                return Some(json);
            }
        }
    }

    /// Sends a command without waiting for its answer ([`JavaNode::answer`]).
    fn send(&mut self, command: &str) {
        let stdin = self.stdin.as_mut().expect("stdin");
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .expect("a command reaches the node");
    }

    /// The answer to the command sent last.
    async fn answer(&mut self, command: &str) -> Json {
        let answer = self
            .next_json(DEADLINE)
            .await
            .unwrap_or_else(|| panic!("no answer to {command:?}:\n{}", self.log_tail()));
        assert!(answer.get("error").is_none(), "{command:?}: {answer}");
        answer
    }

    async fn ask(&mut self, command: &str) -> Json {
        self.send(command);
        self.answer(command).await
    }

    /// The topics and summaries of the results this replica reads, sorted.
    async fn results(&mut self) -> Vec<(String, String)> {
        let answer = self.ask("results").await;
        let mut results: Vec<(String, String)> = answer["results"]
            .as_array()
            .map(|results| {
                results
                    .iter()
                    .map(|result| {
                        (
                            result["topic"].as_str().unwrap_or_default().to_owned(),
                            result["summary"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        results.sort();
        results
    }

    /// The task's state at the Java node (`available`, `claimed`, `completed`, ...).
    async fn task_state(&mut self, topic: &str) -> String {
        self.ask(&format!("task-state {topic}")).await["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    async fn duplicate_completions(&mut self) -> i64 {
        self.ask("settle").await["duplicateCompletions"]
            .as_i64()
            .expect("a count")
    }

    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

impl Drop for JavaNode {
    fn drop(&mut self) {
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("java node {}:\n{}", self.peer, self.log_tail());
        }
    }
}

/// A Rust dial-only peer of the Java node at `port`, its link through `holding`.
async fn dial_only(port: u16, holding: &HoldingDialer) -> Peer {
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding);
    config.clock = Arc::new(SystemClock);
    config.seeds = vec![format!("tcp://127.0.0.1:{port}").parse().expect("seed")];
    config.dialers = vec![Arc::new(holding.clone()) as Arc<dyn Dialer>];
    config.reconnect_interval = Duration::from_millis(200);
    config.listen.anti_entropy_period = Some(Duration::from_millis(300));
    Peer::start(config).await.expect("the Rust peer starts")
}

fn holding_tcp() -> HoldingDialer {
    let tcp = default_dialers()
        .into_iter()
        .find(|dialer| dialer.schemes().contains(&"tcp"))
        .expect("a tcp dialer");
    HoldingDialer::new(tcp)
}

fn tasks(peer: &Peer, settle: Duration) -> Space {
    Fleet::from_peer(peer.clone())
        .space(SPACE)
        .with_settle(settle)
}

/// The seed's `Result(topic, summary, worker)`, its fields in the record's order (SPEC §9.1).
fn result(topic: &str, summary: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("summary", summary);
    payload.insert("worker", "rust-worker");
    Value::Map(payload)
}

fn take_lease() -> Lease {
    Lease::from_millis(30_000).expect("lease")
}

/// Polls `check` until it holds, for at most [`DEADLINE`].
async fn until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + DEADLINE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The Java node writes the contested task and the Rust peer holds it.
async fn contested(java: &mut JavaNode, peer: &Peer) {
    java.ask("write-task contested 1").await;
    let space = tasks(peer, SHORT_SETTLE);
    space.pull().await.expect("pull");
    let held = space
        .read(&Template::new(TASK), DEADLINE)
        .await
        .expect("read");
    assert!(held.is_some(), "the Rust peer holds the Java task");
}

/// The summaries of the results the Rust peer reads, sorted.
async fn rust_results(peer: &Peer) -> Vec<(String, String)> {
    let space = tasks(peer, SHORT_SETTLE);
    let _ = space.pull().await;
    let mut results: Vec<(String, String)> = space
        .read_all(&Template::new(RESULT), 10)
        .await
        .unwrap_or_default()
        .iter()
        .map(|view| {
            let text = |field: &str| {
                view.payload()
                    .get(field)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (text("topic"), text("summary"))
        })
        .collect();
    results.sort();
    results
}

/// Both replicas hold the task completed and read exactly `want`.
async fn converge(java: &mut JavaNode, peer: &Peer, want: &[(&str, &str)]) {
    let want: Vec<(String, String)> = want
        .iter()
        .map(|(topic, summary)| ((*topic).to_owned(), (*summary).to_owned()))
        .collect();
    let deadline = Instant::now() + DEADLINE;
    loop {
        let java_state = java.task_state("contested").await;
        let java_results = java.results().await;
        let rust_results = rust_results(peer).await;
        let rust_completed = peer
            .space_states(SPACE)
            .await
            .iter()
            .any(|state| state.get("completed").and_then(Value::as_bool) == Some(true));
        if java_state == "completed"
            && java_results == want
            && rust_results == want
            && rust_completed
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no convergence on {want:?}: Java {java_state} {java_results:?}, Rust completed \
             {rust_completed} {rust_results:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The Rust claim is the earlier one, held from Java past Java's window: Java judges itself the
/// winner and completes, and its completion reaches the Rust take within the Rust window, which
/// acknowledges it and comes back empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_java_completion_in_the_rust_window_makes_the_rust_take_stand_down() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "rust-window").await;
    let holding = holding_tcp();
    let peer = dial_only(java.port, &holding).await;
    contested(&mut java, &peer).await;

    holding.hold();
    let space = tasks(&peer, LONG_SETTLE);
    let take = tokio::spawn(async move {
        space
            .take(&Template::new(TASK), take_lease(), Duration::ZERO)
            .await
    });
    until("the Rust claim", || async {
        !peer.space_claims(SPACE).await.is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let took = java.ask("take-task 0 java-worker").await;
    assert_eq!(
        took["took"], "contested",
        "Java never heard of the Rust claim"
    );

    let taken = take.await.expect("the take").expect("take");
    assert!(
        taken.is_none(),
        "the work is done: the Rust take stands down"
    );
    assert_eq!(peer.counters().await.outbid_acknowledged, 1);

    holding.release();
    converge(&mut java, &peer, &[("contested", "done by java")]).await;
    assert_eq!(java.duplicate_completions().await, 0);
    assert_eq!(peer.counters().await.duplicate_completions, 0);
    let _ = peer.close().await;
}

/// The Rust claim is the earlier one, held from Java, and both complete before either hears of
/// the other: the Rust peer counts the duplicate once; Java, displaced, counts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_completion_is_counted_where_the_rust_claim_won() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "rust-duplicate").await;
    let holding = holding_tcp();
    let peer = dial_only(java.port, &holding).await;
    contested(&mut java, &peer).await;

    holding.hold();
    let winning = tasks(&peer, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the Rust peer judged its take alone");
    winning
        .complete(
            Some((RESULT, result("contested", "done by rust"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the Rust peer completes");
    let took = java.ask("take-task 0 java-worker").await;
    assert_eq!(
        took["took"], "contested",
        "Java never heard of the Rust claim"
    );
    until("the Rust peer to count the duplicate", || async {
        peer.counters().await.duplicate_completions == 1
    })
    .await;

    holding.release();
    converge(
        &mut java,
        &peer,
        &[("contested", "done by java"), ("contested", "done by rust")],
    )
    .await;
    assert_eq!(peer.counters().await.duplicate_completions, 1, "once");
    assert_eq!(java.duplicate_completions().await, 0, "Java was displaced");
    assert_eq!(peer.counters().await.outbid_acknowledged, 0);
    let _ = peer.close().await;
}

/// The Java claim is the earlier one, held from the Rust peer, and the Java window is long: the
/// Rust completion reaches Java within it, and Java acknowledges it and takes nothing, so the
/// Rust result is the only one everywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rust_completion_in_the_java_window_makes_the_java_take_stand_down() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &["--settle-ms", "3000"], "java-window").await;
    let holding = holding_tcp();
    let peer = dial_only(java.port, &holding).await;
    contested(&mut java, &peer).await;

    holding.hold_inbound();
    let command = "take-task 0 java-worker";
    java.send(command);
    // Java's claim goes out at once; the Rust peer's link holds it.
    until("the Java claim to reach the Rust link", || async {
        holding.held_inbound() > 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await; // the Rust claim is stamped later
    let displaced = tasks(&peer, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the Rust peer never heard of the Java claim");
    displaced
        .complete(
            Some((RESULT, result("contested", "done by rust"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the Rust peer completes");
    let took = java.answer(command).await;
    assert_eq!(
        took["took"],
        Json::Null,
        "Java acknowledged the Rust completion"
    );

    holding.release_inbound();
    converge(&mut java, &peer, &[("contested", "done by rust")]).await;
    assert_eq!(java.duplicate_completions().await, 0);
    let counters = peer.counters().await;
    assert_eq!(counters.duplicate_completions, 0);
    assert_eq!(counters.outbid_acknowledged, 0);
    let _ = peer.close().await;
}

/// The Java claim is the earlier one, held from the Rust peer, and both complete: Java, whose
/// claim won, counts the duplicate; the Rust peer counts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_completion_is_counted_where_the_java_claim_won() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "java-duplicate").await;
    let holding = holding_tcp();
    let peer = dial_only(java.port, &holding).await;
    contested(&mut java, &peer).await;

    holding.hold_inbound();
    let took = java.ask("take-task 0 java-worker").await;
    assert_eq!(took["took"], "contested");
    let displaced = tasks(&peer, SHORT_SETTLE)
        .take(&Template::new(TASK), take_lease(), Duration::ZERO)
        .await
        .expect("take")
        .expect("the Rust peer never heard of the Java claim");
    displaced
        .complete(
            Some((RESULT, result("contested", "done by rust"))),
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("the Rust peer completes");
    let deadline = Instant::now() + DEADLINE;
    while java.duplicate_completions().await != 1 {
        assert!(
            Instant::now() < deadline,
            "Java never counted the duplicate:\n{}",
            java.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    holding.release_inbound();
    converge(
        &mut java,
        &peer,
        &[("contested", "done by java"), ("contested", "done by rust")],
    )
    .await;
    assert_eq!(java.duplicate_completions().await, 1, "once");
    let counters = peer.counters().await;
    assert_eq!(
        counters.duplicate_completions, 0,
        "the Rust peer was displaced"
    );
    assert_eq!(counters.outbid_acknowledged, 0);
    let _ = peer.close().await;
}

/// The Rust claim is the earlier one, held from Java; Java judges itself the winner and
/// completes, and the frame carrying its completion with its claim never reaches the Rust peer
/// (every space state Java sends is dropped meanwhile). Once Java has merged the Rust claim, the
/// evidence reaches the Rust winner only in separate frames: Java's claim alone (as it claimed,
/// and as it offers it again once displaced, SPEC v0.1.36 §7.4) and Java's completion under the
/// Rust claim, from a later pull, which does not authenticate on its own. The Rust winner pairs
/// them, acknowledges Java's completion, and its take, still in its window, stands down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_java_completion_in_another_frame_than_its_claim_is_paired_by_the_rust_winner() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "rust-pairing").await;
    let holding = holding_tcp();
    let peer = dial_only(java.port, &holding).await;
    contested(&mut java, &peer).await;

    holding.hold();
    holding.drop_inbound_states(true);
    let space = tasks(&peer, Duration::from_secs(6));
    let take = tokio::spawn(async move {
        space
            .take(&Template::new(TASK), take_lease(), Duration::ZERO)
            .await
    });
    until("the Rust claim", || async {
        !peer.space_claims(SPACE).await.is_empty()
    })
    .await;
    let took = java.ask("take-task 0 java-worker").await;
    assert_eq!(
        took["took"], "contested",
        "Java never heard of the Rust claim"
    );

    // Java hears of the Rust claim, which displaces its own completed one.
    holding.release();
    let rust = peer.peer_id().to_owned();
    let deadline = Instant::now() + DEADLINE;
    loop {
        let state = java.ask("task-state contested").await;
        if state["holder"]
            .as_str()
            .is_some_and(|holder| holder.starts_with(rust.as_str()))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java never merged the Rust claim: {state}\n{}",
            java.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        holding.dropped_inbound() >= 1,
        "the frame carrying Java's completion was dropped"
    );
    // From now on Java offers its completion under the Rust claim only.
    holding.drop_inbound_states(false);

    let taken = take.await.expect("the take").expect("take");
    assert!(
        taken.is_none(),
        "the work is done: the Rust take stands down"
    );
    assert_eq!(peer.counters().await.outbid_acknowledged, 1);
    converge(&mut java, &peer, &[("contested", "done by java")]).await;
    assert_eq!(java.duplicate_completions().await, 0);
    assert_eq!(peer.counters().await.duplicate_completions, 0);
    let _ = peer.close().await;
}
