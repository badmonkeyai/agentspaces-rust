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

//! The periodic rounds of a Rust dial-only peer toward the Java reference node (SPEC §5.3, the
//! idle floor), over TCP, with the scripted Java seed of `interop/java-seed`: the link drops the
//! Java node's rumor of a write, and the Rust peer, which neither reconnects nor reads, comes to
//! hold the entry by its own rounds, answered by the Java node.
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
use agentspaces::transport::Dialer;
use agentspaces::wire::bodies::STREAM_SPACE_PREFIX;
use agentspaces::wire::identity::Identity;
use serde_json::Value as Json;
use support::LossyDialer;
use tokio::sync::mpsc;
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-interop-v1";
const SPACE: &str = "tasks";
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-rounds");
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

/// A Rust dial-only peer of the Java node at `port`, its links through `lossy`, its rounds every
/// `period`.
async fn dial_only(port: u16, lossy: &LossyDialer, period: Duration) -> Peer {
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding);
    config.clock = Arc::new(SystemClock);
    config.seeds = vec![format!("tcp://127.0.0.1:{port}").parse().expect("seed")];
    config.dialers = vec![Arc::new(lossy.clone()) as Arc<dyn Dialer>];
    config.reconnect_interval = Duration::from_millis(200);
    config.listen.anti_entropy_period = Some(period);
    Peer::start(config).await.expect("the Rust peer starts")
}

fn topics(peer_states: &[agentspaces::wire::cbor::Map]) -> Vec<String> {
    peer_states
        .iter()
        .filter_map(|state| {
            let payload = state.get("record")?.get("payload")?;
            Some(format!("{payload:?}"))
        })
        .collect()
}

async fn until_rust_holds(peer: &Peer, count: usize, limit: Duration) {
    let deadline = Instant::now() + limit;
    loop {
        let held = peer.space_states(SPACE).await;
        if held.len() >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Rust holds {} of {count} entries {:?}: {:?}",
            held.len(),
            topics(&held),
            peer.counters().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rust_dial_only_peer_converges_on_a_java_write_it_missed() {
    let Some(classpath) = classpath_or_skip() else {
        return;
    };
    let mut java = JavaNode::listen(&classpath, &[], "dial-rounds").await;
    java.ask("write-task before 1").await;
    let tcp = default_dialers()
        .into_iter()
        .find(|dialer| dialer.schemes().contains(&"tcp"))
        .expect("a tcp dialer");
    let lossy = LossyDialer::new(tcp, &format!("{STREAM_SPACE_PREFIX}{SPACE}"));
    let period = Duration::from_millis(200);
    let peer = dial_only(java.port, &lossy, period).await;
    peer.pull_space(SPACE).await.expect("pull");
    until_rust_holds(&peer, 1, DEADLINE).await;

    // Every round from here on may bring it; none before could.
    let rounds = peer.counters().await.dial_rounds;
    lossy.set_dropping(true);
    java.ask("write-task missed 2").await;
    let deadline = Instant::now() + DEADLINE;
    while lossy.dropped() == 0 {
        assert!(
            Instant::now() < deadline,
            "the Java node's rumor never came:\n{}",
            java.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    lossy.set_dropping(false);
    // An idle peer's period is at most 32 times the base: a couple of such periods suffice.
    until_rust_holds(&peer, 2, period * 32 * 2).await;
    let counters = peer.counters().await;
    assert_eq!(counters.reconnects, 0, "no reconnect brought it");
    assert!(
        counters.dial_rounds > rounds,
        "a round brought it: {counters:?}"
    );
    let _ = peer.close().await;
    drop(java);
}
