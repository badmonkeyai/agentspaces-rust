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

//! The Rust file share (`FileShare`) against the Java reference node over TCP, with the scripted
//! Java seed of `interop/java-seed` started with `--content`, whose `share-put` does what the
//! Groovy console's Add to space does: the Rust member lists and downloads a file Java shared,
//! shares a file of its own that Java lists and fetches, withdraws it, and refuses the paths a
//! share or a download must refuse.
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
use agentspaces::content::{Content, ContentConfig};
use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, default_dialers};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::store::MemoryNodes;
use agentspaces::wire::pdt::sha256;
use agentspaces_pdt::{FileShare, FileShareConfig, Pdt, PdtConfig, ShareError};
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("interop-files");
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

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("files-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rust_file_share_works_with_the_java_node() {
    let Some(classpath) = classpath_or_skip() else { return };
    let mut java = JavaNode::listen(&classpath, &["--content", "--space", SPACE], "files").await;
    let peer = dial_only(java.port).await;
    let content = Content::start(peer.clone(), Arc::new(MemoryNodes::new()), ContentConfig { tick: Duration::from_millis(100), ..ContentConfig::default() })
        .await
        .expect("content");
    let pdt = Pdt::new(content.clone(), PdtConfig::default());
    pdt.spawn_ticker(Duration::from_millis(500));
    let files = FileShare::new(pdt.clone(), FileShareConfig { max_bytes: 1024 * 1024, ..FileShareConfig::default() }).expect("share");
    let java_peer = java.peer.clone();
    eventually("the Java node advertises trees", || {
        let (content, java_peer) = (content.clone(), java_peer.clone());
        async move { content.tree_members().await.unwrap_or_default().contains(&java_peer) }
    })
    .await;

    // Java shares the console's way; the Rust member lists it with its sharer and downloads it
    let put = java.ask("share-put docs/report.csv 300000 5").await;
    let key = put["key"].as_str().expect("key").to_owned();
    eventually("the Rust member lists Java's file with its record", || {
        let (files, key) = (files.clone(), key.clone());
        async move {
            files.list(SPACE).await.is_ok_and(|l| l.iter().any(|f| f.key == key && f.sharer.is_some()))
        }
    })
    .await;
    let listed = files.list(SPACE).await.expect("list");
    let report = listed.iter().find(|f| f.key == key).expect("listed");
    assert_eq!((report.relative.as_str(), report.entry.size), ("docs/report.csv", 300_000));
    assert_eq!(report.sharer.as_deref(), Some(java_peer.as_str()));
    assert!(!report.mine);
    let downloads = scratch("downloads");
    let path = files.download(SPACE, &key, &downloads, false, |_| {}).await.expect("download");
    assert_eq!(path, downloads.canonicalize().expect("dir").join("docs/report.csv"));
    let bytes = std::fs::read(&path).expect("the file");
    assert_eq!(hex(&sha256(&bytes)), put["sha"].as_str().expect("sha"));
    assert!(matches!(files.download(SPACE, &key, &downloads, false, |_| {}).await, Err(ShareError::Exists(_))));
    files.download(SPACE, &key, &downloads, true, |_| {}).await.expect("overwrite");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).expect("meta").permissions().mode() & 0o111, 0, "never executable");
    }

    // the Rust member shares a file; Java lists the entry and the record and fetches it
    let project = scratch("project");
    std::fs::create_dir_all(project.join("notes")).expect("dir");
    let ours: Vec<u8> = (0..250_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 9) as u8).collect();
    std::fs::write(project.join("notes/plan.md"), &ours).expect("write");
    let receipt = files.publish(SPACE, &project, &project.join("notes/plan.md"), |_| {}).await.expect("publish");
    assert_eq!(receipt.key, format!("{SPACE}/notes/plan.md"));
    let mut listed = Json::Null;
    for _ in 0..60 {
        listed = java.ask("share-list").await;
        let has_record = listed["records"].as_array().is_some_and(|r| r.contains(&Json::from(receipt.key.clone())));
        if listed["files"].get(&receipt.key).is_some() && has_record {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(listed["files"][&receipt.key]["root"].as_str(), Some(receipt.root.as_str()), "{listed}");
    let got = java.ask(&format!("share-get {} 30000", receipt.key)).await;
    assert_eq!(got["ok"], true, "{got}");
    assert_eq!(got["sha"].as_str(), Some(hex(&sha256(&ours)).as_str()));
    assert!(files.list(SPACE).await.expect("list").iter().any(|f| f.key == receipt.key && f.mine));

    // withdrawn: gone from the map at Java
    files.withdraw(SPACE, &receipt.key).await.expect("withdraw");
    let mut after = Json::Null;
    for _ in 0..60 {
        after = java.ask("share-list").await;
        if after["files"].get(&receipt.key).is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(after["files"].get(&receipt.key).is_none(), "{after}");
    assert!(after["files"].get(&key).is_some(), "Java's file stays: {after}");

    // what a share refuses
    let outside = scratch("outside");
    std::fs::write(outside.join("secret.txt"), b"x").expect("write");
    assert!(matches!(files.inspect(SPACE, &project, &outside.join("secret.txt")), Err(ShareError::Refused(_))));
    std::fs::write(project.join("big.bin"), vec![0u8; 2 * 1024 * 1024]).expect("write");
    assert!(matches!(files.inspect(SPACE, &project, &project.join("big.bin")), Err(ShareError::Refused(_))));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(project.join("notes/plan.md"), project.join("link.md")).expect("link");
        assert!(matches!(files.inspect(SPACE, &project, &project.join("link.md")), Err(ShareError::Refused(_))));
    }
    content.close().await.expect("close");
    let _ = peer.close().await;
}
