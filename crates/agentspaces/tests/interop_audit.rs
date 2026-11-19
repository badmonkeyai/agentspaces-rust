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

//! The trie audit of SPEC annex I.6 between a Rust peer and the Java reference node, over TCP,
//! with the scripted Java seed of `interop/java-seed`:
//!
//! - Java asks Rust: a Java node joins a Rust listening peer that already holds a space's
//!   entries, and receives them by its audit (the Rust peer answers the root, the requests within
//!   a session, and the fetch by ids);
//! - Rust asks Java: a Rust listening peer joins a Java node that already holds a space's entries
//!   and, never pulling the space, receives them by its own audit;
//! - a member without the hint (`--no-audit` on the Java side, `PeerConfig::audit` off on the
//!   Rust side) reconciles by today's digests, and no audit field ever reaches it.
//!
//! Each side's audit counters prove which form carried the entries. The seed is built on first
//! use with `mvn -q -o` when its classes are missing or older than its source. When `java` or the
//! build is unavailable each test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set,
//! in which case it fails. `JAVA_HOME` picks the `java` binary when set.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentspaces::clock::SystemClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, default_dialers};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::identity::Identity;
use serde_json::Value as Json;
use tokio::sync::mpsc;
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-interop-v1";
const SPACE: &str = "tasks";
const TASK_TYPE: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";
/// How long anything here may take.
const DEADLINE: Duration = Duration::from_secs(45);
/// How long a JVM may take to start.
const STARTUP: Duration = Duration::from_secs(60);
/// The entries each test reconciles: more than 32, so every root is an inner node.
const ENTRIES: usize = 100;

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
    /// Starts the seed with `args` after the port, and reads its first line.
    async fn start(classpath: &str, port: u16, args: &[&str], name: &str) -> JavaNode {
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-audit");
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
        assert!(
            event["event"] == "dialing" || event["event"] == "listening",
            "{event}"
        );
        node.peer = event["peer"].as_str().unwrap_or_default().to_owned();
        node
    }

    /// A Java node listening on a free port.
    async fn listen(classpath: &str, extra: &[&str], name: &str) -> JavaNode {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port();
        JavaNode::start(classpath, port, extra, name).await
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

    async fn ask(&mut self, command: &str) -> Json {
        let stdin = self.stdin.as_mut().expect("stdin");
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .expect("a command reaches the node");
        let answer = self
            .next_json(DEADLINE)
            .await
            .unwrap_or_else(|| panic!("no answer to {command:?}:\n{}", self.log_tail()));
        assert!(answer.get("error").is_none(), "{command:?}: {answer}");
        answer
    }

    async fn task_count(&mut self) -> usize {
        self.ask("tasks").await["tasks"]
            .as_array()
            .map_or(0, Vec::len)
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

/// A Rust listening peer on TCP, dialing `seed` when given, with the audit on or off.
async fn rust_peer(seed: Option<u16>, audit: bool) -> Peer {
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding)
        .listen_on(ListenerSpec::tcp("127.0.0.1:0"));
    config.clock = Arc::new(SystemClock);
    config.listen.anti_entropy_period = Some(Duration::from_millis(500));
    config.audit = audit;
    if let Some(port) = seed {
        config.seeds = vec![format!("tcp://127.0.0.1:{port}").parse().expect("seed")];
        config.dialers = default_dialers();
        config.reconnect_interval = Duration::from_millis(200);
    }
    Peer::start(config).await.expect("the Rust peer starts")
}

/// Writes a `Seed$Task` the Java seed reads, without pulling the space first.
async fn write_task(peer: &Peer, topic: &str, priority: i64) {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("priority", priority);
    peer.write_entry(
        SPACE,
        TASK_TYPE,
        Value::Map(payload),
        1_800_000,
        Map::new(),
        None,
    )
    .await
    .expect("write");
}

async fn held(peer: &Peer) -> usize {
    peer.space_states(SPACE).await.len()
}

async fn until_java_holds(java: &mut JavaNode, count: usize) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let held = java.task_count().await;
        if held >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Java holds {held} of {count} tasks:\n{}",
            java.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn until_rust_holds(peer: &Peer, count: usize) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let have = held(peer).await;
        if have >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Rust holds {have} of {count} entries: {:?}",
            peer.counters().await.audit
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn number(json: &Json, field: &str) -> u64 {
    json[field].as_u64().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn java_asks_rust_and_reconciles_by_the_audit() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let hub = rust_peer(None, true).await;
    for n in 0..ENTRIES {
        write_task(&hub, &format!("rust-{n}"), n as i64).await;
    }
    let address = hub.listen_addrs()[0].address();
    let mut java = JavaNode::start(&classpath, 0, &["--dial", &address], "java-asks").await;
    until_java_holds(&mut java, ENTRIES).await;
    let signals = java.ask("audit").await;
    assert_eq!(signals["forms"][hub.peer_id()], "TREE", "{signals}");
    assert!(
        number(&signals, "idsFetched") >= ENTRIES as u64,
        "{signals}"
    );
    assert!(number(&signals, "answersReceived") >= 1, "{signals}");
    for bad in [
        "undecodable",
        "fingerprint-mismatch",
        "shape-mismatch",
        "lacks-hint",
    ] {
        assert!(signals["refusals"].get(bad).is_none(), "{bad}: {signals}");
    }
    let partner = hub.counters().await.audit;
    assert!(partner.roots_answered >= 1, "{partner:?}");
    assert!(partner.sessions_opened >= 1, "{partner:?}");
    assert!(partner.requests_answered >= 1, "{partner:?}");
    assert!(partner.fetches_answered >= 1, "{partner:?}");
    assert!(!partner.refusals.contains_key("undecodable"), "{partner:?}");
    drop(java);
    let _ = hub.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_asks_java_and_reconciles_by_the_audit() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "rust-asks").await;
    java.ask(&format!("write-tasks java- {ENTRIES}")).await;
    let peer = rust_peer(Some(java.port), true).await;
    write_task(&peer, "rust-opens", 1).await; // opens the space without pulling it
    until_rust_holds(&peer, ENTRIES + 1).await;
    until_java_holds(&mut java, ENTRIES + 1).await;
    let asker = peer.counters().await.audit;
    assert!(asker.openings_sent >= 1, "{asker:?}");
    assert!(asker.roots_received >= 1, "{asker:?}");
    assert!(asker.requests_sent >= 1, "{asker:?}");
    assert!(asker.ids_requested >= ENTRIES as u64, "{asker:?}");
    for bad in [
        "undecodable",
        "fingerprint-mismatch",
        "shape-mismatch",
        "unsolicited-answer",
    ] {
        assert!(!asker.refusals.contains_key(bad), "{bad}: {asker:?}");
    }
    let signals = java.ask("audit").await;
    assert_eq!(signals["forms"][peer.peer_id()], "TREE", "{signals}");
    assert!(number(&signals, "rootsAnswered") >= 1, "{signals}");
    assert!(number(&signals, "fetchesAnswered") >= 1, "{signals}");
    assert!(
        signals["refusals"].get("undecodable").is_none(),
        "{signals}"
    );
    let _ = peer.close().await;
    drop(java);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_form_java_node_reconciles_with_a_rust_peer() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let hub = rust_peer(None, true).await;
    for n in 0..ENTRIES {
        write_task(&hub, &format!("rust-{n}"), n as i64).await;
    }
    let address = hub.listen_addrs()[0].address();
    let mut java = JavaNode::start(
        &classpath,
        0,
        &["--dial", &address, "--no-audit"],
        "old-java",
    )
    .await;
    until_java_holds(&mut java, ENTRIES).await;
    java.ask("write-task java-old 1").await;
    until_rust_holds(&hub, ENTRIES + 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await; // several rounds each way
    let signals = java.ask("audit").await;
    assert_eq!(signals["forms"][hub.peer_id()], "TEXT", "{signals}");
    assert_eq!(number(&signals, "idsFetched"), 0, "{signals}");
    assert!(
        signals["refusals"]
            .as_object()
            .is_none_or(|refusals| refusals.is_empty()),
        "no audit field reached the old-form node: {signals}"
    );
    let partner = hub.counters().await.audit;
    assert_eq!(partner.openings_sent, 0, "{partner:?}");
    assert_eq!(partner.roots_answered, 0, "{partner:?}");
    assert!(partner.refusals.is_empty(), "{partner:?}");
    drop(java);
    let _ = hub.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_form_rust_peer_reconciles_with_an_auditing_java_node() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "old-rust").await;
    java.ask(&format!("write-tasks java- {ENTRIES}")).await;
    let peer = rust_peer(Some(java.port), false).await;
    write_task(&peer, "rust-old", 1).await;
    until_rust_holds(&peer, ENTRIES + 1).await;
    until_java_holds(&mut java, ENTRIES + 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let signals = java.ask("audit").await;
    assert_eq!(signals["forms"][peer.peer_id()], "TEXT", "{signals}");
    assert_eq!(number(&signals, "rootsAnswered"), 0, "{signals}");
    let counters = peer.counters().await;
    assert_eq!(counters.audit.openings_sent, 0, "{:?}", counters.audit);
    assert!(
        counters.audit.refusals.is_empty(),
        "no audit field reached it: {:?}",
        counters.audit
    );
    assert_eq!(counters.deltas_undecodable, 0);
    let _ = peer.close().await;
    drop(java);
}
