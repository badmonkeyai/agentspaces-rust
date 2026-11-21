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

//! The Groovy console's file share between a Rust dial-only peer and the Java reference node
//! (`agentspaces-pdt` and `agentspaces-content`), over TCP, with the scripted Java seed of
//! `interop/java-seed` started with `--content`. The seed's `share-put` does what the console's
//! Add to space does: a blob held in the content swarm, the `file-share` tree ref swapped under
//! `<space>/<path>`, and a `SharedFile` record in the space. The Rust peer reads that map and
//! fetches the file, writes its own entry and record that Java reads and fetches, and the two
//! write at once with neither entry lost.
//!
//! The seed is built on first use with `mvn -q -o` when its classes are missing or older than its
//! source or pom. When `java` or the build is unavailable the test says why and passes, unless
//! `ASPACE_INTEROP_REQUIRED=1` is set, in which case it fails. `JAVA_HOME` picks the `java`
//! binary when set.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agentspaces::clock::SystemClock;
use agentspaces::content::{Content, ContentConfig, FetchOptions};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, default_dialers};
use agentspaces::space::{Lease, Template};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::file_entry::{FileEntry, REGULAR};
use agentspaces::wire::pdt::store::{Flusher, MemoryNodes};
use agentspaces::wire::pdt::{blob, sha256};
use agentspaces_pdt::{Pdt, PdtConfig, Ref};
use serde_json::Value as Json;
use tokio::sync::mpsc;
use tokio::time::Instant;

const FOUNDING: &str = "agentspaces-rust-interop-v1";
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";
const DEADLINE: Duration = Duration::from_secs(60);
const STARTUP: Duration = Duration::from_secs(60);
const SPACE: &str = "catalogue";
const SHARED_FILE: &str = "ai.badmonkey.agentspaces.groovy.console.files.SharedFile#v1";

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

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
    if !class.is_file() || !listed.is_file() || newer(&dir.join(SEED_SOURCE), &class) || newer(&dir.join("pom.xml"), &listed) {
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-refs");
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

async fn dial_only(port: u16) -> Peer {
    let founding = GroupSpec::FoundingText(FOUNDING.to_owned());
    let mut config = PeerConfig::new(Identity::generate().expect("identity"), founding);
    config.clock = Arc::new(SystemClock);
    config.seeds = vec![format!("tcp://127.0.0.1:{port}").parse().expect("seed")];
    config.dialers = default_dialers();
    config.reconnect_interval = Duration::from_millis(200);
    Peer::start(config).await.expect("the Rust peer starts")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(t: &str) -> Vec<u8> {
    cbor::encode(&Value::from(t))
}

async fn entry_of(share: &Ref, pdt: &Pdt, key: &str) -> Option<FileEntry> {
    let map = share.deref_map().await.ok()?;
    let item = map.get(&**pdt.nodes(), &text(key)).ok()??;
    FileEntry::decode(&item).ok()
}

/// The console's `SharedFile` record, fields in its declared order.
fn shared_file(key: &str, name: &str, root: &str, size: u64) -> Value {
    let mut m = Map::new();
    m.insert("location", "file-share");
    m.insert("key", key);
    m.insert("name", name);
    m.insert("root", root);
    m.insert("size", Value::Int(i128::from(size)));
    m.insert("mediaType", "application/octet-stream");
    m.insert("sharedAt", Value::Int(1_792_320_000_000));
    Value::Map(m)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_file_share_map_moves_both_ways_between_rust_and_java() {
    let Some(classpath) = classpath_or_skip() else { return };
    let mut java = JavaNode::listen(&classpath, &["--content", "--space", SPACE], "share").await;
    let peer = dial_only(java.port).await;
    let nodes = Arc::new(MemoryNodes::new());
    let content = Content::start(peer.clone(), nodes.clone(), ContentConfig { tick: Duration::from_millis(100), ..ContentConfig::default() })
        .await
        .expect("content");
    let pdt = Pdt::new(content.clone(), PdtConfig::default());
    pdt.spawn_ticker(Duration::from_millis(500));
    let share = pdt.tree_ref("file-share").expect("ref");
    let java_peer = java.peer.clone();
    eventually("the Java node advertises trees", || {
        let (content, java_peer) = (content.clone(), java_peer.clone());
        async move { content.tree_members().await.unwrap_or_default().contains(&java_peer) }
    })
    .await;

    // Java adds a file as the console's Add to space does; the Rust peer reads the map and fetches it
    let put = java.ask("share-put docs/report.csv 200000 1").await;
    let key = format!("{SPACE}/docs/report.csv");
    assert_eq!(put["key"].as_str(), Some(key.as_str()));
    eventually("the Rust peer reads Java's entry", || {
        let (share, pdt, key) = (share.clone(), pdt.clone(), key.clone());
        async move { entry_of(&share, &pdt, &key).await.is_some() }
    })
    .await;
    let entry = entry_of(&share, &pdt, &key).await.expect("the entry");
    assert_eq!(entry.root, put["root"].as_str().expect("root"));
    assert_eq!(entry.size, 200_000);
    assert_eq!(entry.mode, REGULAR);
    content
        .fetch_tree(&entry.root, FetchOptions { prefer: vec![java_peer.clone()], timeout: Some(Duration::from_secs(60)), ..Default::default() })
        .await
        .expect("the file's blob");
    let bytes = blob::read_all(&*nodes, &entry.root).expect("bytes");
    assert_eq!(hex(&sha256(&bytes)), put["sha"].as_str().expect("sha"));
    let template = Template::new(SHARED_FILE).tag_eq("key", &key);
    eventually("Java's SharedFile record reads at the Rust peer", || {
        let (space, template) = (peer.space(SPACE), template.clone());
        async move { space.read_all(&template, 10).await.is_ok_and(|r| r.len() == 1) }
    })
    .await;
    let records = peer.space(SPACE).read_all(&template, 10).await.expect("records");
    assert_eq!(records[0].payload().get("root").and_then(Value::as_str), Some(entry.root.as_str()));

    // the Rust peer adds a file the same way; Java reads the map and the record, and fetches it
    let ours: Vec<u8> = (0..150_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let written = blob::write_bytes(&ours, &mut Flusher::new(&*nodes)).expect("blob");
    content.hold_tree(&written.root).await.expect("hold");
    let rust_key = format!("{SPACE}/notes/plan.md");
    let rust_entry = FileEntry::new(&written.root, ours.len() as u64, REGULAR, "application/octet-stream").expect("entry");
    let item = rust_entry.encode();
    share.swap_map(|n, m| m.assoc(n, &text(&rust_key), &item)).await.expect("swap");
    let mut tags = Map::new();
    tags.insert("key", rust_key.as_str());
    tags.insert("location", "file-share");
    peer.space(SPACE)
        .write_value(SHARED_FILE, shared_file(&rust_key, "plan.md", &written.root, ours.len() as u64), Lease::from_millis(30 * 60 * 1000).expect("lease"), cbor::canonical_map(&tags))
        .await
        .expect("record");
    let mut listed = Json::Null;
    for _ in 0..60 {
        listed = java.ask("share-list").await;
        let files = &listed["files"];
        let records = listed["records"].as_array().cloned().unwrap_or_default();
        if files.get(&rust_key).is_some() && files.get(&key).is_some() && records.iter().any(|r| r == &Json::from(rust_key.clone())) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(listed["files"][&rust_key]["root"].as_str(), Some(written.root.as_str()), "{listed}");
    assert!(listed["files"].get(&key).is_some(), "Java keeps its own entry: {listed}");
    assert!(listed["records"].as_array().is_some_and(|r| r.contains(&Json::from(rust_key.clone()))), "Java reads the Rust record: {listed}");
    let got = java.ask(&format!("share-get {rust_key} 30000")).await;
    assert_eq!(got["ok"], true, "{got}");
    assert_eq!(got["sha"].as_str(), Some(hex(&sha256(&ours)).as_str()));

    // both add a file at once: neither entry is lost on either side
    let (java_put, rust_swap) = tokio::join!(java.ask("share-put docs/second.bin 50000 2"), async {
        let at_once = FileEntry::new(&written.root, ours.len() as u64, REGULAR, "text/markdown").expect("entry").encode();
        share.swap_map(|n, m| m.assoc(n, &text(&format!("{SPACE}/notes/again.md")), &at_once)).await
    });
    rust_swap.expect("rust swap");
    let second = java_put["key"].as_str().expect("key").to_owned();
    let again = format!("{SPACE}/notes/again.md");
    eventually("the Rust peer reads all four entries", || {
        let (share, pdt, keys) = (share.clone(), pdt.clone(), vec![key.clone(), rust_key.clone(), second.clone(), again.clone()]);
        async move {
            let mut all = true;
            for k in &keys {
                all &= entry_of(&share, &pdt, k).await.is_some();
            }
            all
        }
    })
    .await;
    let mut last = Json::Null;
    for _ in 0..60 {
        last = java.ask("share-list").await;
        if [&key, &rust_key, &second, &again].iter().all(|k| last["files"].get(k.as_str()).is_some()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(last["count"], 4, "{last}");
    assert_eq!(share.stats().await.heads_ignored, 0);
    content.close().await.expect("close");
    let _ = peer.close().await;
}
