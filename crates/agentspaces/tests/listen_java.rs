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

//! A Java node joining a Rust listening peer: the scripted Java seed of `interop/java-seed` runs
//! in its dial mode (`--dial`), joins the group through the Rust hub, and writes a task that a
//! Rust dial-only peer behind the same hub takes and completes; the Java node reads the result.
//! On the way it checks that each side admits the other, that the Java node's anti-entropy rounds
//! are answered in Java's formats (it learns the Rust member from the hub's view), and that the
//! hub relays the frames Java addresses to the Rust member behind it.
//!
//! The seed is built on first use with `mvn -q -o` inside its own project when its classes or
//! classpath are missing (or older than its source). When `java` or the build is unavailable the
//! test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set, in which case it fails.
//! `JAVA_HOME` picks the `java` binary when set.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentspaces::clock::SystemClock;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{ListenerSpec, Peer, PeerConfig, default_dialers};
use agentspaces::space::{Fleet, Lease, Template};
use agentspaces::wire::cbor::{Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::identity::Identity;
use serde_json::Value as Json;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// The founding text of the Java seed's group (its default).
const FOUNDING: &str = "agentspaces-rust-interop-v1";
const SPACE: &str = "tasks";
const TASK_TYPE: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT_TYPE: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";
/// How long anything here may take.
const DEADLINE: Duration = Duration::from_secs(30);
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
        Ok(())
    } else {
        Err(format!(
            "`mvn {}` exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
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

/// A Java node in dial mode, killed when dropped.
struct JavaNode {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::UnboundedReceiver<String>,
    log: PathBuf,
    peer: String,
}

impl JavaNode {
    /// Starts the seed dialing `seed` (`host:port`) and reads its `dialing` line.
    async fn dial(classpath: &str, seed: &str) -> JavaNode {
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-java");
        std::fs::create_dir_all(&logs).expect("a log directory");
        let log = logs.join(format!("dialing-{}.log", std::process::id()));
        let stderr = std::fs::File::create(&log).expect("a log file");
        let mut child = Command::new(java_bin())
            .arg("-cp")
            .arg(classpath)
            .arg(SEED_MAIN)
            .arg("0")
            .args(["--dial", seed])
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
        };
        let event = node
            .next_json(STARTUP)
            .await
            .unwrap_or_else(|| panic!("the Java node printed nothing:\n{}", node.log_tail()));
        assert_eq!(event["event"], "dialing", "{event}");
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

/// Polls `check` every 200 ms until it holds; panics naming `what` after [`DEADLINE`].
async fn until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + DEADLINE;
    while !check().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_java_node_joins_a_rust_listening_peer_and_its_task_is_done_in_rust() {
    let classpath = match seed_classpath() {
        Ok(classpath) => classpath,
        Err(why) => {
            assert!(!required(), "the Java interop seed cannot run: {why}");
            eprintln!("skipping: the Java interop seed cannot run: {why}");
            return;
        }
    };
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding.clone())
        .listen_on(ListenerSpec::tcp("127.0.0.1:0"));
    config.clock = Arc::new(SystemClock);
    config.listen.replicate = vec![SPACE.to_owned()];
    let hub = Peer::start(config).await.expect("the Rust hub starts");
    let address = hub.listen_addrs()[0].address();

    let mut member_config = PeerConfig::new(Identity::generate().expect("identity"), founding);
    member_config.seeds = vec![format!("tcp://{address}").parse().expect("seed")];
    member_config.dialers = default_dialers();
    member_config.reconnect_interval = Duration::from_millis(200);
    let worker = Fleet::from_peer(Peer::start(member_config).await.expect("the Rust member"));

    let mut java = JavaNode::dial(&classpath, &address).await;
    let java_peer = java.peer.clone();
    let hub_peer = hub.clone();
    until("the hub admits the Java node", || {
        let hub_peer = hub_peer.clone();
        let java_peer = java_peer.clone();
        async move { hub_peer.linked_members().await.contains(&java_peer) }
    })
    .await;
    let hub_id = hub.peer_id().to_owned();
    let deadline = Instant::now() + DEADLINE;
    loop {
        let members = java.ask("members").await;
        let listed: Vec<&str> = members["members"]
            .as_array()
            .map(|list| list.iter().filter_map(Json::as_str).collect())
            .unwrap_or_default();
        if listed.contains(&hub_id.as_str()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java never listed the hub: {members}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Java writes; the Rust member behind the same hub takes and completes it.
    java.ask("write-task java-wrote 7").await;
    let tasks = worker.space(SPACE).with_settle(Duration::from_millis(300));
    let taken = tasks
        .take(&Template::new(TASK_TYPE), Lease::DEFAULT_TAKE, DEADLINE)
        .await
        .expect("take")
        .expect("the Rust member takes Java's task");
    assert_eq!(
        taken.entry().payload().get("topic").and_then(Value::as_str),
        Some("java-wrote")
    );
    let result = cbor_map! {
        "topic" => "java-wrote",
        "summary" => "done in rust",
        "worker" => worker.peer().peer_id(),
    };
    taken
        .complete(
            Some((RESULT_TYPE, result)),
            Lease::DEFAULT_RESULT,
            Map::new(),
        )
        .await
        .expect("complete");

    // Java reads the result and sees the task completed.
    let deadline = Instant::now() + DEADLINE;
    loop {
        let results = java.ask("results").await;
        let done = results["results"].as_array().is_some_and(|list| {
            list.iter().any(|result| {
                result["topic"] == "java-wrote" && result["summary"] == "done in rust"
            })
        });
        if done {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java never read the result: {results}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let state = java.ask("task-state java-wrote").await;
    assert_eq!(state["state"], "completed", "{state}");

    // The Java node runs anti-entropy against the hub, which answers in Java's formats.
    let hub_peer = hub.clone();
    until("the hub answers Java's digests", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.pulls_answered >= 1 }
    })
    .await;
    // Java learns the Rust member from the hub's view and probes it through the hub's relay.
    let worker_id = worker.peer().peer_id().to_owned();
    let deadline = Instant::now() + DEADLINE;
    loop {
        let members = java.ask("members").await;
        let listed = members["members"]
            .as_array()
            .is_some_and(|list| list.iter().any(|member| member == worker_id.as_str()));
        if listed {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java never listed the Rust member: {members}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let hub_peer = hub.clone();
    until("the hub relays between Java and the Rust member", || {
        let hub_peer = hub_peer.clone();
        async move { hub_peer.counters().await.listen.relays_forwarded >= 1 }
    })
    .await;
    let counters = hub.counters().await;
    assert_eq!(counters.listen.refused.total(), 0, "{counters:?}");
    assert_eq!(counters.deltas_undecodable, 0, "{counters:?}");
    drop(java);
    worker.close().await.expect("close");
    let _ = hub.close().await;
}
