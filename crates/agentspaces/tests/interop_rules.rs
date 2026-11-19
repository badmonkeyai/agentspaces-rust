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

//! The replication rules of SPEC §7.2 and §7.3 (v0.1.35) between a Rust peer and the Java
//! reference node, over TCP, with the scripted Java seed of `interop/java-seed`:
//!
//! - a renewal for less than a lease has left changes nothing on either side, and a longer one
//!   crosses both ways with the expiry the renewing side set;
//! - each side reads the other's `wire.horizon=1`, and both engage the per-entry horizon with
//!   the other in view;
//! - a member without the hint (`--no-horizon` on the Java side, `PeerConfig::horizon` off on
//!   the Rust side) keeps both on the legacy horizon;
//! - a task Java took and completed reaches a late Rust watcher as `Completed` alone.
//!
//! The seed is built on first use with `mvn -q -o` when its classes are missing or older than its
//! source. When `java` or the build is unavailable each test says why and passes, unless
//! `ASPACE_INTEROP_REQUIRED=1` is set, in which case it fails. `JAVA_HOME` picks the `java`
//! binary when set.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentspaces::clock::SystemClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, default_dialers};
use agentspaces::space::{EntryId, EventKind, Fleet, Lease, Template};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::horizon::{self, Mode};
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-rules");
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

/// A Rust listening peer on TCP, dialing `seed` when given, with the per-entry horizon on or off.
async fn rust_peer(seed: Option<u16>, horizon: bool) -> Peer {
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding)
        .listen_on(ListenerSpec::tcp("127.0.0.1:0"));
    config.clock = Arc::new(SystemClock);
    config.listen.anti_entropy_period = Some(Duration::from_millis(500));
    config.horizon = horizon;
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

/// Polls `check` every quarter second until it holds, within [`DEADLINE`].
async fn until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + DEADLINE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Asks Java `command` every quarter second until its answer meets `ready`, within
/// [`DEADLINE`]; answers the last answer.
async fn java_until(
    java: &mut JavaNode,
    what: &str,
    command: &str,
    ready: impl Fn(&Json) -> bool,
) -> Json {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let answer = java.ask(command).await;
        if ready(&answer) {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {answer}\n{}",
            java.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn task(topic: &str, priority: i64) -> Value {
    let mut payload = Map::new();
    payload.insert("topic", topic);
    payload.insert("priority", priority);
    Value::Map(payload)
}

async fn java_expiry(java: &mut JavaNode, topic: &str) -> Option<i64> {
    java.ask(&format!("expiry {topic}")).await["expiry"].as_i64()
}

async fn rust_expiry(peer: &Peer, topic: &str) -> Option<i64> {
    let space = Fleet::from_peer(peer.clone()).space(SPACE);
    let views = space
        .read_all(&Template::new(TASK_TYPE), 1000)
        .await
        .expect("read");
    views
        .iter()
        .find(|view| view.payload().get("topic").and_then(Value::as_str) == Some(topic))
        .map(|view| view.expires_at_millis())
}

/// A renewal for less than the lease has left changes nothing on either side; a longer one
/// crosses both ways with the expiry the renewing side set (SPEC §7.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewals_cross_both_ways_and_never_shorten() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "renew-java").await;
    let rust = rust_peer(Some(java.port), true).await;
    let space = Fleet::from_peer(rust.clone()).space(SPACE);
    let id: EntryId = space
        .write_value(
            TASK_TYPE,
            task("rust-renew", 1),
            Lease::from_millis(600_000).expect("lease"),
            Map::new(),
        )
        .await
        .expect("write");
    let written = rust_expiry(&rust, "rust-renew").await.expect("held");
    java_until(
        &mut java,
        "the Rust task's expiry in Java",
        "expiry rust-renew",
        |answer| answer["expiry"].as_i64() == Some(written),
    )
    .await;
    // Shorter: nothing changes, nothing goes out.
    space
        .renew_write(&id, Lease::from_millis(1_000).expect("lease"))
        .await
        .expect("renew");
    assert_eq!(rust_expiry(&rust, "rust-renew").await, Some(written));
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(java_expiry(&mut java, "rust-renew").await, Some(written));
    // Longer: Java follows the expiry Rust set.
    space
        .renew_write(&id, Lease::from_millis(1_800_000).expect("lease"))
        .await
        .expect("renew");
    let renewed = rust_expiry(&rust, "rust-renew").await.expect("held");
    assert!(renewed > written);
    java_until(
        &mut java,
        "Java to follow the Rust renewal",
        "expiry rust-renew",
        |answer| answer["expiry"].as_i64() == Some(renewed),
    )
    .await;

    // Java's own renewals: shorter changes nothing, longer reaches Rust.
    java.ask("write-task java-renew 2").await;
    let java_written = java_until(
        &mut java,
        "the Java task's expiry",
        "expiry java-renew",
        |answer| answer["expiry"].as_i64().is_some(),
    )
    .await["expiry"]
        .as_i64()
        .expect("an expiry");
    until("Rust to hold the Java task", || async {
        rust_expiry(&rust, "java-renew").await == Some(java_written)
    })
    .await;
    let answer = java.ask("renew java-renew 1").await;
    assert_eq!(answer["expiry"].as_i64(), Some(java_written), "{answer}");
    let answer = java.ask("renew java-renew 3600").await;
    let java_renewed = answer["expiry"].as_i64().expect("an expiry");
    assert!(java_renewed > java_written);
    until("Rust to follow the Java renewal", || async {
        rust_expiry(&rust, "java-renew").await == Some(java_renewed)
    })
    .await;
    assert_eq!(rust.counters().await.renew_shortenings, 1);
    rust.close().await.expect("close");
}

/// Each side reads the other's `wire.horizon=1`, and both engage the per-entry horizon with the
/// other in view (SPEC §7.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_sides_read_the_hint_and_engage_the_per_entry_horizon() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "horizon-java").await;
    let rust = rust_peer(Some(java.port), true).await;
    write_task(&rust, "opens-the-space", 1).await;
    until_java_holds(&mut java, 1).await;
    until("Rust to hold Java's hinted card", || async {
        rust.member_ad(&java.peer)
            .await
            .is_some_and(|ad| horizon::hints_horizon(ad.get("resourceHints")))
    })
    .await;
    let command = format!("horizon {}", rust.peer_id());
    let answer = java_until(
        &mut java,
        "Java to engage the per-entry horizon with Rust in view",
        &command,
        |answer| answer["peerHinted"] == Json::Bool(true) && answer["mode"] == "SETTLING",
    )
    .await;
    assert_eq!(answer["selfHinted"], Json::Bool(true), "{answer}");
    assert_eq!(answer["engagements"].as_u64(), Some(1), "{answer}");
    until(
        "Rust to engage the per-entry horizon with Java in view",
        || async {
            rust.space_horizon(SPACE)
                .await
                .is_some_and(|status| status.mode == Mode::Settling)
        },
    )
    .await;
    rust.close().await.expect("close");
}

/// A member without the hint keeps both sides on the legacy horizon, whichever side it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_the_hint_keeps_both_sides_legacy() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    for (java_args, rust_hint) in [(&["--no-horizon"][..], true), (&[][..], false)] {
        let mut java = JavaNode::listen(&classpath, java_args, "legacy-java").await;
        let rust = rust_peer(Some(java.port), rust_hint).await;
        write_task(&rust, "opens-the-space", 1).await;
        until_java_holds(&mut java, 1).await;
        let command = format!("horizon {}", rust.peer_id());
        let answer = java.ask(&command).await;
        assert_eq!(
            answer["selfHinted"],
            Json::Bool(java_args.is_empty()),
            "{answer}"
        );
        until("each side to hold the other's card", || async {
            rust.member_ad(&java.peer)
                .await
                .is_some_and(|ad| !ad.is_empty())
        })
        .await;
        // Six seconds: twice the three rounds the hint would need to engage.
        for _ in 0..24 {
            let answer = java.ask(&command).await;
            assert_eq!(answer["mode"], "LEGACY", "{answer}");
            assert_eq!(answer["engagements"].as_u64(), Some(0), "{answer}");
            assert_eq!(answer["peerHinted"], Json::Bool(rust_hint), "{answer}");
            let status = rust.space_horizon(SPACE).await.expect("open");
            assert_eq!(status.mode, Mode::Legacy, "{status:?}");
            assert_eq!(status.engagements, 0);
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        rust.close().await.expect("close");
    }
}

/// A task Java took and completed reaches a Rust watcher that joins afterwards as `Completed`
/// alone, never `Written` or `Taken` (SPEC §7.2, *Completed on arrival*).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_task_java_completed_reaches_a_late_rust_watcher_as_completed_alone() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "arrival-java").await;
    java.ask("write-task java-done 1").await;
    let took = java.ask("take-task 5000 java-worker").await;
    assert_eq!(took["took"], "java-done", "{took}");
    let rust = rust_peer(Some(java.port), true).await;
    let space = Fleet::from_peer(rust.clone()).space(SPACE);
    let mut events = space.watch(&Template::new(TASK_TYPE)).await.expect("watch");
    space.pull().await.expect("pull");
    let event = tokio::time::timeout(DEADLINE, events.next())
        .await
        .expect("an event in time")
        .expect("open");
    assert_eq!(event.kind, EventKind::Completed);
    assert_eq!(
        event.entry.payload().get("topic").and_then(Value::as_str),
        Some("java-done")
    );
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert!(events.try_next().is_none(), "Completed alone");
    rust.close().await.expect("close");
}
