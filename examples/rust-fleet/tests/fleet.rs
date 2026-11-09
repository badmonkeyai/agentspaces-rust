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

//! Example 32's fleet test: `run.sh` over `tcp` and over `tls`, checked line by line.
//!
//! `run.sh` puts Rust members on example 02's Java research fleet:
//!
//! - a long-lived Java seed (`interop/java-seed`) founds example 02's group and keeps its cards;
//! - the Rust worker (`rust-worker`, this example's binary) and a shell script under
//!   `aspace work` (`research.sh`, the agent `script-worker`) serve the `research` action;
//! - example 02's `ResearchFleet` coordinator (the installed `example-02-research-fleet` artifact,
//!   resolved by `java/pom.xml`) publishes six `ResearchTask`s and tallies the `Finding`s;
//! - `aspace cards` lists the fleet's offerings, and `aspace call` by the consumed schema prints
//!   a `Finding` for the topic `rust`.
//!
//! A test passes when:
//!
//! - the coordinator recorded findings from `rust-worker` and from `script-worker` for all six
//!   topics;
//! - the catalogue folded the two workers into one offering with two replicas;
//! - the call printed a `Finding` for `rust`, written by one of the workers and AGENT_ATTESTED;
//! - both workers stopped cleanly;
//! - over `tls`, every link the seed held was `tls` and attested, and the seed sent bare frames.
//!
//! The test runs the script with this build's binaries (`ASPACE_BIN`, `RUST_WORKER_BIN`). It
//! also resolves both Java classpaths and compiles the seed first, so `run.sh` builds nothing,
//! and the two tests, which run at once, never run Maven at the same time.
//!
//! The test is gated like the interop tests. When `java`, Maven's offline resolution, or the
//! built `aspace` is missing, it says why and passes. Under `ASPACE_INTEROP_REQUIRED=1` it fails
//! instead. `run.sh` leads a process group of its own, which is killed when the test ends (also
//! on failure), so no JVM or member outlives it.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value as Json;

/// Example 02's result schema.
const FINDING: &str = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1";
/// The topics example 02's coordinator publishes (`run.sh` asks for six).
const TOPICS: [&str; 6] = [
    "topic-1", "topic-2", "topic-3", "topic-4", "topic-5", "topic-6",
];
/// The longest one run of `run.sh` may take: two JVMs, the 15 s the coordinator waits for a
/// `tls attested` link it cannot name, and the members.
const RUN_LIMIT: Duration = Duration::from_secs(300);

fn required() -> bool {
    std::env::var("ASPACE_INTEROP_REQUIRED").is_ok_and(|value| value == "1")
}

fn example_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn seed_dir() -> PathBuf {
    example_dir().join("../../interop/java-seed")
}

/// The `java` to run: `$JAVA_HOME/bin/java` when that exists, else `java` on the path.
fn java_bin() -> PathBuf {
    std::env::var_os("JAVA_HOME")
        .map(|home| PathBuf::from(home).join("bin/java"))
        .filter(|java| java.is_file())
        .unwrap_or_else(|| PathBuf::from("java"))
}

/// Runs Maven offline in `dir`.
fn mvn(dir: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("mvn")
        .arg("-q")
        .arg("-o")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("`mvn` does not run: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "`mvn -q -o {}` failed in {} (are the AgentSpaces 0.5.0 artifacts, example 02's \
         included, in ~/.m2?): {}{}",
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Whether `file` is missing or older than `than`.
fn stale(file: &Path, than: &Path) -> bool {
    let modified = |path: &Path| path.metadata().and_then(|meta| meta.modified()).ok();
    match (modified(file), modified(than)) {
        (Some(file), Some(than)) => file < than,
        (None, _) => true,
        (Some(_), None) => false,
    }
}

/// The workspace's `aspace` binary: `ASPACE_BIN`, else beside this test's profile directory.
fn aspace_bin() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("ASPACE_BIN") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(|error| format!("this test's path: {error}"))?;
    // target/<profile>/deps/fleet-<hash> -> target/<profile>/aspace
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("no profile directory above {}", exe.display()))?;
    let aspace = profile.join("aspace");
    if aspace.is_file() {
        Ok(aspace)
    } else {
        Err(format!(
            "{} is not built: run `cargo build -p aspace` (`cargo test --workspace` builds it)",
            aspace.display()
        ))
    }
}

/// What `run.sh` needs, prepared once per test binary: `java` runs, example 02's classpath is
/// resolved, the seed is compiled with its classpath, and `aspace` is built.
fn prepare() -> Result<PathBuf, String> {
    static PREPARED: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    PREPARED
        .get_or_init(|| {
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
            let fleet = example_dir().join("java");
            if stale(&fleet.join("target/classpath.txt"), &fleet.join("pom.xml")) {
                mvn(
                    &fleet,
                    &[
                        "dependency:build-classpath",
                        "-Dmdep.outputFile=target/classpath.txt",
                    ],
                )?;
            }
            let seed = seed_dir();
            let source = seed.join("src/main/java/ai/badmonkey/agentspaces/interop/Seed.java");
            let class = seed.join("target/classes/ai/badmonkey/agentspaces/interop/Seed.class");
            if stale(&class, &source) {
                mvn(&seed, &["compile"])?;
            }
            if stale(&seed.join("target/classpath.txt"), &seed.join("pom.xml")) {
                mvn(
                    &seed,
                    &[
                        "dependency:build-classpath",
                        "-Dmdep.outputFile=target/classpath.txt",
                    ],
                )?;
            }
            aspace_bin()
        })
        .clone()
}

/// Skips (or, under `ASPACE_INTEROP_REQUIRED=1`, fails) when the fleet cannot run.
macro_rules! ready_or_skip {
    () => {
        match prepare() {
            Ok(aspace) => aspace,
            Err(why) => {
                assert!(!required(), "example 32's fleet cannot run: {why}");
                eprintln!("skipping: example 32's fleet cannot run: {why}");
                return;
            }
        }
    };
}

/// A scratch directory (`run.sh`'s TMPDIR) under Cargo's per-target space, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "rust-fleet-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `run.sh` running as the leader of its own process group; the whole group (the JVMs and the
/// members it started) is sent SIGTERM, then SIGKILL, when this is dropped.
struct Fleet {
    child: Child,
}

impl Fleet {
    fn signal_group(&self, signal: &str) {
        let _ = Command::new("kill")
            .args(["-s", signal, "--", &format!("-{}", self.child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.signal_group("TERM");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Whatever of the group is still alive (run.sh's cleanup stops its children first).
        self.signal_group("KILL");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `run.sh` (with `--tls` when `tls`) and answers its exit code and its output lines.
fn run(aspace: &Path, tls: bool) -> (Option<i32>, Vec<String>) {
    let scratch = Scratch::new(if tls { "tls" } else { "tcp" });
    let mut command = Command::new(example_dir().join("run.sh"));
    if tls {
        command.arg("--tls");
    }
    command
        .env("ASPACE_BIN", aspace)
        .env("RUST_WORKER_BIN", env!("CARGO_BIN_EXE_rust-worker"))
        .env("JAVA", java_bin())
        .env("TMPDIR", &scratch.0)
        .env_remove("TASKS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().expect("run.sh starts");
    let (tx, lines) = mpsc::channel();
    for pipe in [
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let mut fleet = Fleet { child };
    let deadline = Instant::now() + RUN_LIMIT;
    let mut seen = Vec::new();
    // Both pipes close when run.sh and every process holding them have ended.
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines.recv_timeout(left) {
            Ok(line) => {
                eprintln!("{line}");
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("run.sh did not finish within {RUN_LIMIT:?}: {seen:#?}")
            }
        }
    }
    let status = loop {
        match fleet.child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => panic!("run.sh did not exit within {RUN_LIMIT:?}: {seen:#?}"),
            Err(error) => panic!("run.sh cannot be waited for: {error}"),
        }
    };
    (status.code(), seen)
}

/// The lines a process of the run said, without their `[name] ` prefix.
fn said<'a>(lines: &'a [String], name: &str) -> Vec<&'a str> {
    let prefix = format!("[{name}] ");
    lines
        .iter()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .collect()
}

/// The one line of `name` that is a JSON object with `key`.
fn json_line(lines: &[String], name: &str, key: &str) -> Json {
    said(lines, name)
        .into_iter()
        .filter(|line| line.starts_with('{'))
        .filter_map(|line| serde_json::from_str::<Json>(line).ok())
        .find(|json| json.get(key).is_some())
        .unwrap_or_else(|| panic!("{name} printed no JSON object with {key:?}: {lines:#?}"))
}

/// Checks one run of `run.sh`.
fn check(code: Option<i32>, lines: &[String], tls: bool) {
    let scheme = if tls { "tls" } else { "tcp" };
    assert_eq!(code, Some(0), "run.sh failed over {scheme}: {lines:#?}");
    assert_eq!(
        lines.last().map(String::as_str),
        Some(format!("example 32: ok ({scheme})").as_str()),
        "{lines:#?}"
    );

    // The coordinator recorded findings from both workers, one for each of its topics.
    let coordinator = said(lines, "coordinator");
    let findings: Vec<(&str, &str)> = coordinator
        .iter()
        .filter_map(|line| line.strip_prefix("finding: "))
        .filter_map(|finding| finding.split_once(" by "))
        .collect();
    let workers: BTreeSet<&str> = findings.iter().map(|(_, worker)| *worker).collect();
    assert!(
        workers.contains("rust-worker"),
        "no finding by rust-worker: {coordinator:#?}"
    );
    assert!(
        workers.contains("script-worker"),
        "no finding by script-worker: {coordinator:#?}"
    );
    assert!(
        workers.is_subset(&BTreeSet::from(["rust-worker", "script-worker"])),
        "{coordinator:#?}"
    );
    let topics: BTreeSet<&str> = findings.iter().map(|(topic, _)| *topic).collect();
    assert_eq!(topics, BTreeSet::from(TOPICS), "{coordinator:#?}");
    assert!(
        coordinator.iter().any(|line| line.starts_with("tally: {")),
        "{coordinator:#?}"
    );

    // The catalogue folded the library worker and the script worker into one offering.
    let cards = said(lines, "cards");
    assert!(
        cards
            .iter()
            .any(|line| line.starts_with("research ") && line.ends_with(", 2 replicas)")),
        "one offering, research, with two replicas: {cards:#?}"
    );

    // The call printed the Finding that answered it.
    let call = json_line(lines, "call", "offering");
    assert_eq!(call["offering"], "research", "{call}");
    assert_eq!(call["schema"], FINDING, "{call}");
    assert_eq!(call["space"], "tasks", "{call}");
    assert_eq!(call["entry"]["topic"], "rust", "{call}");
    let worker = call["entry"]["worker"].as_str().unwrap_or_default();
    assert!(
        ["rust-worker", "script-worker"].contains(&worker),
        "a worker of the example answered: {call}"
    );
    assert!(
        call["issuer"]
            .as_str()
            .is_some_and(|issuer| issuer.ends_with(&format!("/{worker}"))),
        "the Finding is signed by the agent named in it: {call}"
    );
    assert!(
        call["entry"]["summary"]
            .as_str()
            .is_some_and(|summary| summary.ends_with(": rust")),
        "{call}"
    );
    assert_eq!(call["attestation"], "AGENT_ATTESTED", "{call}");

    // Both workers stopped cleanly after their work.
    let rust = said(lines, "rust-worker");
    assert!(
        rust.iter().any(|line| line.contains("researched 'topic-")),
        "{rust:#?}"
    );
    assert!(
        rust.iter()
            .any(|line| line.starts_with("rust-worker: stopped after ")),
        "{rust:#?}"
    );
    let script = said(lines, "script-worker");
    assert!(
        script
            .iter()
            .any(|line| line.starts_with("aspace: completed ")),
        "{script:#?}"
    );
    assert!(
        script
            .iter()
            .any(|line| line.starts_with("aspace: stopped: ") && line.ends_with(", 0 failed")),
        "{script:#?}"
    );

    // Every link the seed held was of the run's binding; over tls, attested, with bare frames.
    let links = json_line(lines, "seed", "links");
    let links = links["links"].as_array().cloned().unwrap_or_default();
    assert!(
        links.len() >= 2,
        "the seed held both workers' links: {links:?}"
    );
    for link in &links {
        assert_eq!(link["scheme"], scheme, "{links:?}");
        if tls {
            assert_eq!(link["mode"], "attested", "{links:?}");
        }
    }
    if tls {
        let frames = json_line(lines, "seed", "bare");
        assert!(
            frames["bare"].as_u64().is_some_and(|bare| bare > 0),
            "the seed sent bare frames on attested channels: {frames}"
        );
        assert!(
            coordinator
                .iter()
                .any(|line| line.starts_with("transport: tls on ")),
            "{coordinator:#?}"
        );
    }
}

#[test]
fn rust_members_work_and_call_on_the_java_research_fleet_over_tcp() {
    let aspace = ready_or_skip!();
    let (code, lines) = run(&aspace, false);
    check(code, &lines, false);
}

#[test]
fn rust_members_work_and_call_on_the_java_research_fleet_over_tls() {
    let aspace = ready_or_skip!();
    let (code, lines) = run(&aspace, true);
    check(code, &lines, true);
}
