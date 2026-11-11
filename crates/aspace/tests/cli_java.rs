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

//! The `aspace` command against the Java reference: each test starts its own
//! scripted Java seed (`interop/java-seed`, `ai.badmonkey.agentspaces.interop.Seed`) on a free
//! port, runs the built `aspace` binary against it (the command has no listening seed of its own
//! yet), and checks what the Java `ReplicatedSpace` makes of each command:
//!
//! 1. `id` creates, then shows, the same identity, its key owner-only;
//! 2. `write` then `read` (and a Java task read), through a fleet YAML file as well as variables;
//! 3. `take` in one invocation and `complete` (with a result Java reads) in another;
//! 4. `watch --count` of a task Java writes and completes;
//! 5. `work` with a `#!/bin/sh` program completing Java tasks with results the seed reads, in a
//!    minimal environment, stopped by SIGTERM;
//! 6. exit codes: 2 for not found, 3 for a timeout;
//! 7. `work` with a failing program, whose task reappears and Java takes;
//! 8. `write`, `read`, and `doctor` over `tls` under `--require-attestation --channel-auth
//!    ATTESTED`;
//! 9. `work` publishes its AgentCard, which Java's `DiscoveryService` admits, and `cards`,
//!    `status`, and `call` (by name and by schema) from another keystore find and invoke it,
//!    while a visitor on the worker's own keystore is warned that it shares its PeerID;
//! 10. `call` exits 2 without an offering, and 3 when no result comes in time (its input stays
//!     leased, held by the worker), and the worker kills the program it then stops with;
//! 11. a Java agent bound through the AgentSpaces facade (the seed's `bind-agent`) is listed by
//!     `cards --json` and answers `call`;
//! 12. `work` with a `#!/bin/sh` program drains ten Java tasks while the seed's own `take-all`
//!     races it: every task completed exactly once, and the running worker's card listed by
//!     Java's `DiscoveryService` and `RemoteActions`;
//! 13. `call` joins while nothing offers its target and waits, within its join window, for the
//!     card of a worker that binds after it joined (example 32's callers can join first);
//! 14. big numbers through the JSON bridge both ways: a script's `$int` of 2^64 - 1 and its
//!     `$decimal` are held by the seed's strict reader, and Java's `Priced` reads as `$decimal`
//!     and `$int`.
//!
//! The seed is built on first use with `mvn -q -o` when `target/classes` or
//! `target/classpath.txt` is missing (or the source is newer than its class). When `java` or the
//! build is unavailable each test says why and passes, unless `ASPACE_INTEROP_REQUIRED=1` is set,
//! in which case it fails. `JAVA_HOME` picks the `java` binary; `AGENTSPACES_JAVA_SEED_DIR`
//! points at another copy of the seed project. Every seed and every `aspace` process a test
//! starts is killed when the test ends, also when it fails.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value as Json;

/// The founding text of the seed's group.
const FOUNDING: &str = "agentspaces-rust-interop-v1";
/// The seed's task and result schemas.
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
/// The agent (and action) name `aspace work` takes by default: the task schema's simple name.
const DEFAULT_WORKER: &str = "Task";
/// The seed's main class, class file, source, and classpath list, relative to the project.
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";

/// How long a JVM may take to start and print its first line.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one seed command may take.
const ANSWER: Duration = Duration::from_secs(20);
/// How long one `aspace` visitor may take.
const VISIT: Duration = Duration::from_secs(40);
/// The longest any poll waits for something to happen.
const DEADLINE: Duration = Duration::from_secs(30);

/// Every variable the configuration reads, removed from each `aspace` run first.
const CONFIG_VARIABLES: [&str; 13] = [
    "ASPACE_SEEDS",
    "ASPACE_INVITE",
    "ASPACE_LISTEN",
    "ASPACE_ADVERTISE",
    "ASPACE_GROUP",
    "ASPACE_JOIN",
    "ASPACE_KEYSTORE",
    "ASPACE_PROFILE",
    "ASPACE_SPACES",
    "ASPACE_CONFIG",
    "ASPACE_SOCKET",
    "XDG_CONFIG_HOME",
    "HOME",
];

// ------------------------------------------------------------------------------ preparing

/// Whether a test that cannot run the Java seed must fail rather than pass with a note.
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

/// The classpath that runs the seed, or why it cannot run; prepared once per test binary.
fn seed_classpath() -> Result<String, String> {
    static PREPARED: OnceLock<Result<String, String>> = OnceLock::new();
    PREPARED.get_or_init(prepare_seed).clone()
}

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
        "`mvn {}` in {} exited with {}: {}{}",
        args.join(" "),
        dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// Lines of a pipe, read on a thread of their own.
fn lines_of(pipe: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// A scratch directory under Cargo's per-target space (a HOME, a keystore, scripts), removed on
/// drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "cli-java-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("home")).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }

    /// An executable `#!/bin/sh` script.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.0.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write the script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------------------------ the seed

/// A running Java seed, killed when dropped.
struct JavaSeed {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    log: PathBuf,
    port: u16,
    peer: String,
    tls: bool,
}

impl JavaSeed {
    fn start(classpath: &str, args: &[&str]) -> Self {
        let mut failures = Vec::new();
        for _ in 0..3 {
            match Self::start_on(classpath, free_port(), args) {
                Ok(seed) => return seed,
                Err(why) => failures.push(why),
            }
        }
        panic!("the Java seed did not start: {}", failures.join("\n---\n"));
    }

    fn start_on(classpath: &str, port: u16, args: &[&str]) -> Result<Self, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-java");
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
            tls: args.contains(&"--tls"),
        };
        let Some(event) = seed.next_json(STARTUP) else {
            return Err(format!("no listening line on {port}:\n{}", seed.log_tail()));
        };
        if event["event"] != "listening" {
            return Err(format!(
                "the first line is not the listening event: {event}"
            ));
        }
        seed.peer = event["peer"].as_str().unwrap_or_default().to_owned();
        Ok(seed)
    }

    fn next_json(&mut self, wait: Duration) -> Option<Json> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let line = self.lines.recv_timeout(left).ok()?;
            match serde_json::from_str::<Json>(&line) {
                Ok(json) if json.is_object() => return Some(json),
                _ => eprintln!("java seed {}: {line}", self.port),
            }
        }
    }

    /// Sends one command and returns the seed's answer.
    fn ask(&mut self, command: &str) -> Json {
        let written = match self.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(format!("{command}\n").as_bytes())
                .and_then(|()| stdin.flush()),
            None => Err(std::io::Error::other("the seed's stdin is closed")),
        };
        if let Err(error) = written {
            panic!("cannot send {command:?}: {error}\n{}", self.log_tail());
        }
        let Some(answer) = self.next_json(ANSWER) else {
            panic!("the seed did not answer {command:?}:\n{}", self.log_tail());
        };
        assert!(
            answer.get("error").is_none(),
            "the seed refused {command:?}: {answer}\n{}",
            self.log_tail()
        );
        answer
    }

    fn write_task(&mut self, topic: &str, priority: i64) {
        self.ask(&format!("write-task {topic} {priority}"));
    }

    /// The available tasks, as `(topic, priority)`.
    fn tasks(&mut self) -> Vec<(String, i64)> {
        self.ask("tasks")["tasks"]
            .as_array()
            .map(|tasks| {
                tasks
                    .iter()
                    .map(|t| {
                        (
                            t["topic"].as_str().unwrap_or_default().to_owned(),
                            t["priority"].as_i64().unwrap_or(i64::MIN),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The results, as `(topic, summary, worker)`.
    fn results(&mut self) -> Vec<(String, String, String)> {
        self.ask("results")["results"]
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

    fn task_state(&mut self, topic: &str) -> Json {
        self.ask(&format!("task-state {topic}"))
    }

    /// Polls `check` against the seed until it holds, or panics with `what`.
    fn wait_for(&mut self, what: &str, mut check: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            if check(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for {what}\n{}", self.log_tail());
    }

    fn seed(&self) -> String {
        let scheme = if self.tls { "tls" } else { "tcp" };
        format!("{scheme}://127.0.0.1:{}", self.port)
    }

    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

impl Drop for JavaSeed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------------------ aspace

/// An `aspace` command with a clean configuration: no inherited `ASPACE_*`, `HOME` in the
/// scratch directory (so no real fleet file or keystore is touched), and the variables of the
/// seed's group.
fn aspace(scratch: &Scratch, seed: &JavaSeed) -> Command {
    let mut command = bare_aspace(scratch);
    command
        .env("ASPACE_SEEDS", seed.seed())
        .env("ASPACE_GROUP", FOUNDING)
        .env("ASPACE_KEYSTORE", scratch.keys())
        .env("ASPACE_SPACES", "tasks");
    command
}

/// An `aspace` command with nothing configured but `HOME`.
fn bare_aspace(scratch: &Scratch) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aspace"));
    for variable in CONFIG_VARIABLES {
        command.env_remove(variable);
    }
    command
        .env("HOME", scratch.home())
        // The daemon socket a visitor probes is the scratch directory's, never the user's.
        .env("XDG_RUNTIME_DIR", scratch.path().join("run"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// A running `aspace`, killed when dropped, its output lines read as they come.
struct Running {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
    seen_err: Vec<String>,
}

impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().expect("aspace starts");
        let stdout = lines_of(child.stdout.take().expect("stdout"));
        let stderr = lines_of(child.stderr.take().expect("stderr"));
        Running {
            child,
            stdout,
            stderr,
            seen_err: Vec::new(),
        }
    }

    /// Waits for a line of standard error containing `needle`.
    fn wait_err(&mut self, needle: &str) {
        let deadline = Instant::now() + DEADLINE;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.stderr.recv_timeout(left) {
                Ok(line) => {
                    eprintln!("aspace: {line}");
                    let found = line.contains(needle);
                    self.seen_err.push(line);
                    if found {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        panic!("no {needle:?} on standard error: {:?}", self.seen_err);
    }

    /// Sends SIGTERM.
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill -TERM failed");
    }

    /// Waits for the exit and answers its code, the remaining stdout lines, and all of stderr.
    fn finish(mut self) -> (Option<i32>, Vec<String>, Vec<String>) {
        let deadline = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "aspace did not exit: {:?}",
                self.seen_err
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let out: Vec<String> = self.stdout.try_iter().collect();
        let mut err = std::mem::take(&mut self.seen_err);
        // The reader threads see the pipes close shortly after the exit.
        std::thread::sleep(Duration::from_millis(100));
        err.extend(self.stderr.try_iter());
        (status.code(), out, err)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs a visitor to its end within [`VISIT`], killing it past that.
fn visit(mut command: Command) -> Output {
    let mut child = command.spawn().expect("aspace starts");
    let stdout = lines_of(child.stdout.take().expect("stdout"));
    let stderr = lines_of(child.stderr.take().expect("stderr"));
    let deadline = Instant::now() + VISIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "aspace did not finish within {VISIT:?}: {:?}",
                stderr.try_iter().collect::<Vec<_>>()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let collect = |rx: Receiver<String>| -> Vec<u8> {
        let mut text = String::new();
        while let Ok(line) = rx.recv_timeout(Duration::from_secs(2)) {
            text.push_str(&line);
            text.push('\n');
        }
        text.into_bytes()
    };
    Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    }
}

/// Runs a visitor that must succeed and answers its JSON lines.
fn ok_lines(command: Command) -> Vec<Json> {
    let output = visit(command);
    assert!(
        output.status.success(),
        "aspace failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect()
}

/// Runs a visitor that must succeed with one JSON object.
fn ok_json(command: Command) -> Json {
    let mut lines = ok_lines(command);
    assert_eq!(lines.len(), 1, "one object: {lines:?}");
    lines.remove(0)
}

fn with(mut command: Command, args: &[&str]) -> Command {
    command.args(args);
    command
}

/// `aspace id`'s PeerID of the scratch keystore.
fn peer_id(scratch: &Scratch, seed: &JavaSeed) -> String {
    let id = ok_json(with(aspace(scratch, seed), &["id"]));
    id["peerId"].as_str().expect("a PeerID").to_owned()
}

// ------------------------------------------------------------------------------ the scenarios

#[test]
fn id_creates_then_shows_the_same_identity() {
    let scratch = Scratch::new("id");
    let keys = scratch.keys();
    let keys_text = keys.display().to_string();
    let first = ok_json(with(
        bare_aspace(&scratch),
        &["id", "--keystore", &keys_text],
    ));
    assert_eq!(first["created"], true);
    assert_eq!(first["keystore"], keys_text.as_str());
    let peer = first["peerId"].as_str().expect("a PeerID").to_owned();
    assert!(peer.starts_with('z'), "{peer}");
    let mut again = bare_aspace(&scratch);
    again.env("ASPACE_KEYSTORE", &keys).arg("id");
    let second = ok_json(again);
    assert_eq!(second["created"], false);
    assert_eq!(second["peerId"], peer.as_str());
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(keys.join("peer.key"))
        .expect("peer.key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // No keystore named: the default under HOME.
    let default = ok_json(with(bare_aspace(&scratch), &["id"]));
    assert_eq!(
        default["keystore"],
        scratch
            .home()
            .join(".config/agentspaces/keys")
            .display()
            .to_string()
            .as_str()
    );
}

#[test]
fn write_then_read_through_the_java_seed() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("write-read");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&scratch, &seed);

    let written = ok_json(with(
        aspace(&scratch, &seed),
        &[
            "write",
            TASK,
            "--json",
            r#"{"topic":"cli-write","priority":4}"#,
            "--tag",
            "origin=cli",
        ],
    ));
    assert_eq!(written["schema"], TASK);
    assert_eq!(written["space"], "tasks");
    let id = written["id"].as_str().expect("an entry id").to_owned();
    // The visitor confirmed the seed holds it before it left.
    assert!(
        seed.tasks().contains(&("cli-write".to_owned(), 4)),
        "Java reads the write"
    );
    let entries = seed.ask("entries");
    let entry = entries["entries"]
        .as_array()
        .and_then(|entries| entries.iter().find(|e| e["entryId"] == id.as_str()))
        .cloned()
        .expect("the entry in Java");
    assert_eq!(entry["issuer"], format!("{peer}/rust").as_str());
    assert_eq!(entry["attestation"], "PEER_ASSERTED");

    // A Java task and the Rust one, read back (JSON Lines), filtered.
    seed.write_task("from-java", 9);
    let lines = ok_lines(with(
        aspace(&scratch, &seed),
        &["read", TASK, "--where", "priority>=4"],
    ));
    let topics: Vec<&str> = lines
        .iter()
        .filter_map(|line| line["entry"]["topic"].as_str())
        .collect();
    assert!(
        topics.contains(&"cli-write") && topics.contains(&"from-java"),
        "{lines:?}"
    );
    let mine = lines
        .iter()
        .find(|line| line["id"] == id.as_str())
        .expect("the written entry");
    assert_eq!(mine["entry"]["priority"], 4);
    assert_eq!(mine["tags"]["origin"], "cli");
    assert_eq!(mine["schema"], TASK);
    assert_eq!(mine["space"], "tasks");
    let java = lines
        .iter()
        .find(|line| line["entry"]["topic"] == "from-java")
        .expect("the Java entry");
    assert_eq!(java["issuer"], format!("{}/java-seed", seed.peer).as_str());

    // The same through a fleet file, nothing else configured.
    let file = scratch.path().join("fleet.yaml");
    std::fs::write(
        &file,
        format!(
            "agentspaces:\n  keystore: {}\n  bind: 0.0.0.0:9\n  groups:\n    - name: interop\n      \
             founding: {FOUNDING}\n      seeds: [ '{}' ]\n      spaces: [ {{ name: tasks }} ]\n",
            scratch.keys().display(),
            seed.seed()
        ),
    )
    .expect("write the fleet file");
    let file_text = file.display().to_string();
    let lines = ok_lines(with(
        bare_aspace(&scratch),
        &[
            "--config",
            &file_text,
            "read",
            TASK,
            "--where",
            "topic=from-java",
        ],
    ));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["entry"]["priority"], 9);
}

#[test]
fn take_in_one_invocation_and_complete_in_another() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("take-complete");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&scratch, &seed);
    seed.write_task("handoff", 5);

    let taken = ok_json(with(
        aspace(&scratch, &seed),
        &["take", TASK, "--lease", "2m", "--timeout", "10s"],
    ));
    assert_eq!(taken["entry"]["topic"], "handoff");
    assert_eq!(taken["holder"], format!("{peer}/rust").as_str());
    assert!(
        taken["epoch"].as_i64().is_some_and(|epoch| epoch >= 1),
        "{taken}"
    );
    assert!(taken["expiresAt"].as_i64().is_some(), "{taken}");
    let id = taken["id"].as_str().expect("an id").to_owned();
    seed.wait_for("Java to see the claim", |seed| {
        let state = seed.task_state("handoff");
        state["state"] == "claimed" && state["holder"] == format!("{peer}/rust").as_str()
    });

    let completed = ok_json(with(
        aspace(&scratch, &seed),
        &[
            "complete",
            &id,
            "--json",
            r#"{"topic":"handoff","summary":"done by aspace","worker":"aspace"}"#,
            "--produces",
            RESULT,
        ],
    ));
    assert_eq!(completed["id"], id.as_str());
    assert_eq!(completed["completed"], true);
    assert!(completed["result"].as_str().is_some(), "{completed}");
    let state = seed.task_state("handoff");
    assert_eq!(state["state"], "completed", "{state}");
    assert_eq!(state["holder"], format!("{peer}/rust").as_str());
    assert!(
        seed.results().contains(&(
            "handoff".to_owned(),
            "done by aspace".to_owned(),
            "aspace".to_owned()
        )),
        "Java reads the result"
    );

    // Completed: a second completion is refused at once.
    let output = visit(with(aspace(&scratch, &seed), &["complete", &id]));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("already completed"));
}

#[test]
fn watch_streams_written_and_completed_until_its_count() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("watch");
    let mut seed = JavaSeed::start(&classpath, &[]);
    peer_id(&scratch, &seed);
    let mut watch = Running::spawn(with(
        aspace(&scratch, &seed),
        &[
            "watch",
            TASK,
            "--kinds",
            "written,completed",
            "--count",
            "2",
        ],
    ));
    watch.wait_err("watching");
    seed.write_task("watched", 1);
    let took = seed.ask("take-task 10000 java-watch");
    assert_eq!(took["took"], "watched");
    let (code, out, err) = watch.finish();
    assert_eq!(code, Some(0), "{err:?}");
    let events: Vec<Json> = out
        .iter()
        .map(|line| serde_json::from_str(line).expect("JSON Lines"))
        .collect();
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["kind"].as_str()).collect();
    assert_eq!(kinds, ["WRITTEN", "COMPLETED"], "{events:?}");
    assert!(events.iter().all(|e| e["entry"]["topic"] == "watched"));
    assert_eq!(
        events[1]["holder"],
        format!("{}/java-seed", seed.peer).as_str()
    );
}

#[test]
fn work_runs_a_script_per_java_task_and_completes_with_its_results() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("work");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&scratch, &seed);
    // The script is the program, run without a shell wrapper: it reads the entry on stdin and
    // prints the result; SECRET_TOKEN must not reach it, PASSED must.
    let script = scratch.script(
        "research.sh",
        r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
echo "researching $topic ($ASPACE_ENTRY_ID in $ASPACE_SPACE)" >&2
printf 'a log line before the result\n'
printf '{"topic":"%s","summary":"%s/%s/%s","worker":"script"}\n' "$topic" "${SECRET_TOKEN:-unset}" "${PASSED:-missing}" "$ASPACE_SCHEMA"
"#,
    );
    for (topic, priority) in [("w-one", 1), ("w-two", 2), ("w-three", 3)] {
        seed.write_task(topic, priority);
    }
    let mut command = aspace(&scratch, &seed);
    command
        .env("SECRET_TOKEN", "hunter2")
        .env("PASSED", "yes")
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--parallel",
            "2",
            "--env",
            "PASSED",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working");
    seed.wait_for("three script results", |seed| {
        seed.results()
            .iter()
            .filter(|(_, _, worker)| worker == "script")
            .count()
            == 3
    });
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(err.iter().any(|line| line.contains("stopped")), "{err:?}");
    assert!(
        err.iter()
            .any(|line| line.starts_with('[') && line.contains("researching w-")),
        "the program's standard error passes through, prefixed: {err:?}"
    );
    let results = seed.results();
    for topic in ["w-one", "w-two", "w-three"] {
        assert!(
            results.contains(&(
                topic.to_owned(),
                format!("unset/yes/{TASK}"),
                "script".to_owned()
            )),
            "{topic}: {results:?}"
        );
        let state = seed.task_state(topic);
        assert_eq!(state["state"], "completed", "{state}");
        // The worker acts as its own agent (the default name), not as the peer's default agent.
        assert_eq!(state["holder"], format!("{peer}/{DEFAULT_WORKER}").as_str());
    }
}

#[test]
fn not_found_exits_2_and_a_timeout_exits_3() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("exit-codes");
    let seed = JavaSeed::start(&classpath, &[]);
    peer_id(&scratch, &seed);
    let output = visit(with(
        aspace(&scratch, &seed),
        &[
            "complete",
            "00000000-0000-4000-8000-000000000000",
            "--timeout",
            "1s",
        ],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not held"));
    let output = visit(with(aspace(&scratch, &seed), &["read", "x.Nothing#v1"]));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    let output = visit(with(aspace(&scratch, &seed), &["take", "x.Nothing#v1"]));
    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let started = Instant::now();
    let output = visit(with(
        aspace(&scratch, &seed),
        &["take", "x.Nothing#v1", "--timeout", "1s"],
    ));
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(started.elapsed() >= Duration::from_secs(1));
    let output = visit(with(
        aspace(&scratch, &seed),
        &["read", "x.Nothing#v1", "--timeout", "500ms"],
    ));
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn a_failing_program_lets_the_task_reappear_for_java() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("work-fails");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&scratch, &seed);
    let script = scratch.script(
        "fail.sh",
        "cat > /dev/null\necho 'cannot do this one' >&2\nexit 7\n",
    );
    seed.write_task("doomed", 1);
    let mut command = aspace(&scratch, &seed);
    command
        .args([
            "work", "--take", TASK, "--space", "tasks", "--lease", "3s", "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("failed: it ended with exit status: 7");
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        seed.task_state("doomed")["events"]
            .as_array()
            .is_some_and(|events| events
                .iter()
                .any(|e| e == format!("TAKEN by {peer}/{DEFAULT_WORKER}").as_str())),
        "the Rust worker took it first"
    );
    // The hold lapses (3 s) and the task reappears: Java takes and completes it.
    let took = seed.ask("take-task 15000 java-after");
    assert_eq!(took["took"], "doomed");
    assert!(seed.results().contains(&(
        "doomed".to_owned(),
        "done by java".to_owned(),
        "java-after".to_owned()
    )));
    assert!(
        !seed
            .results()
            .iter()
            .any(|(topic, _, worker)| topic == "doomed" && worker != "java-after")
    );
}

#[test]
fn tls_seeds_run_attested_channels() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("tls");
    let mut seed = JavaSeed::start(
        &classpath,
        &[
            "--tls",
            "--require-attestation",
            "--channel-auth",
            "ATTESTED",
        ],
    );
    peer_id(&scratch, &seed);
    let written = ok_json(with(
        aspace(&scratch, &seed),
        &[
            "write",
            TASK,
            "--json",
            r#"{"topic":"over-tls","priority":2}"#,
        ],
    ));
    assert!(written["id"].as_str().is_some());
    assert!(seed.tasks().contains(&("over-tls".to_owned(), 2)));
    let lines = ok_lines(with(aspace(&scratch, &seed), &["read", TASK]));
    assert!(
        lines
            .iter()
            .any(|line| line["entry"]["topic"] == "over-tls")
    );

    let status = ok_json(with(aspace(&scratch, &seed), &["status", "--json"]));
    assert_eq!(status["link"]["scheme"], "tls");
    assert_eq!(status["link"]["attested"], seed.peer.as_str());
    assert!(status.get("catalogue").is_some(), "{status}");

    let output = visit(with(aspace(&scratch, &seed), &["doctor", "--json"]));
    assert!(output.status.success(), "{output:?}");
    let report: Json = serde_json::from_slice(&output.stdout).expect("a report");
    assert_eq!(report["ok"], true, "{report}");
    let seed_check = report["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|c| c["check"].as_str().is_some_and(|n| n.starts_with("seed ")))
        })
        .cloned()
        .expect("a seed check");
    assert!(
        seed_check["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&format!("TLS attests {}", seed.peer))),
        "{seed_check}"
    );
}

/// The card of `agent` the seed's discovery service admitted, if any.
fn admitted_card(seed: &mut JavaSeed, agent: &str) -> Option<Json> {
    seed.ask("cards")["cards"]
        .as_array()
        .and_then(|cards| cards.iter().find(|card| card["agent"] == agent).cloned())
}

#[test]
fn work_publishes_its_card_and_call_invokes_it_through_the_catalogue() {
    let classpath = classpath_or_skip!();
    let worker = Scratch::new("card-worker");
    let caller = Scratch::new("card-caller");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&worker, &seed);
    let script = worker.script(
        "research.sh",
        r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
printf '{"topic":"%s","summary":"called %s","worker":"script"}\n' "$topic" "$topic"
"#,
    );
    let mut command = aspace(&worker, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--action",
            "research",
            "--name",
            "script-worker",
            "--description",
            "Researches a topic with a shell script",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    let agent = format!("{peer}/script-worker");

    // Java's DiscoveryService admits the card: attested by its issuer, its agent key certified,
    // declaring the one take action.
    seed.wait_for("Java admits the worker's card", |seed| {
        admitted_card(seed, &agent).is_some()
    });
    let card = admitted_card(&mut seed, &agent).expect("the card");
    assert_eq!(card["issuer"], peer.as_str(), "{card}");
    assert_eq!(card["attested"], Json::Bool(true), "{card}");
    assert_eq!(card["certified"], Json::Bool(true), "{card}");
    let actions = card["actions"].as_array().expect("actions");
    assert_eq!(actions.len(), 1, "{card}");
    assert_eq!(actions[0]["name"], "research");
    assert_eq!(actions[0]["kind"], "take");
    assert_eq!(actions[0]["space"], "tasks");
    assert_eq!(actions[0]["consumes"], serde_json::json!([TASK]));
    assert_eq!(actions[0]["produces"], serde_json::json!([RESULT]));

    // Another keystore's `cards` lists it as one offering, in JSON Lines and in text.
    let offerings = ok_lines(with(aspace(&caller, &seed), &["cards", "--json"]));
    let offering = offerings
        .iter()
        .find(|offering| offering["name"] == "research")
        .unwrap_or_else(|| panic!("no research offering: {offerings:?}"));
    assert_eq!(offering["consumes"], TASK);
    assert_eq!(offering["produces"], RESULT);
    assert_eq!(offering["space"], "tasks");
    assert_eq!(offering["kind"], "take");
    assert_eq!(offering["agent"], agent.as_str());
    assert_eq!(offering["issuer"], peer.as_str());
    assert_eq!(offering["replicas"], 1);
    assert_eq!(
        offering["description"],
        "Researches a topic with a shell script"
    );
    let output = visit(with(
        aspace(&caller, &seed),
        &["cards", "--only", "research"],
    ));
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("research") && text.contains(TASK) && text.contains(&agent),
        "{text}"
    );
    let output = visit(with(
        aspace(&caller, &seed),
        &["cards", "--only", "nothing*"],
    ));
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");

    // `status --json` carries the catalogue.
    let status = ok_json(with(aspace(&caller, &seed), &["status", "--json"]));
    assert!(
        status["catalogue"]
            .as_array()
            .is_some_and(|all| all.iter().any(|o| o["name"] == "research")),
        "{status}"
    );

    // `call` by the offering's name, then by the schema it consumes: the script's result,
    // correlated by the shared `topic` field, signed by the worker's agent.
    for (target, topic) in [("research", "by-name"), (TASK, "by-schema")] {
        let input = format!(r#"{{"topic":"{topic}","priority":2}}"#);
        let called = ok_json(with(
            aspace(&caller, &seed),
            &["call", target, "--json", &input, "--timeout", "30s"],
        ));
        assert_eq!(called["offering"], "research", "{called}");
        assert_eq!(called["schema"], RESULT, "{called}");
        assert_eq!(called["space"], "tasks", "{called}");
        assert_eq!(called["entry"]["topic"], topic, "{called}");
        assert_eq!(
            called["entry"]["summary"],
            format!("called {topic}").as_str()
        );
        assert_eq!(called["issuer"], agent.as_str(), "{called}");
        assert_eq!(called["attestation"], "AGENT_ATTESTED", "{called}");
        assert!(called["input"].as_str().is_some_and(|id| !id.is_empty()));
        // Java folds the input taken and completed by the worker's agent.
        seed.wait_for("Java folds the call's completion", |seed| {
            seed.task_state(topic)["state"] == "completed"
        });
        assert_eq!(seed.task_state(topic)["holder"], agent.as_str());
    }

    // A visitor on the worker's own keystore is the same PeerID, which the seed takes for the
    // same member: it is told so, and how to fix it.
    let output = visit(with(aspace(&worker, &seed), &["status", "--json"]));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("is a member with this keystore's PeerID"),
        "{output:?}"
    );

    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        err.iter()
            .any(|line| line.contains("stopped: 2 tasks completed")),
        "{err:?}"
    );
    // The worker's mark on its keystore goes with it.
    let marks: Vec<String> = std::fs::read_dir(worker.keys())
        .expect("the keystore")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".aspace-resident-"))
        .collect();
    assert!(marks.is_empty(), "{marks:?}");
}

#[test]
fn call_exits_2_without_an_offering_and_3_when_no_result_comes() {
    let classpath = classpath_or_skip!();
    let worker = Scratch::new("slow-worker");
    let caller = Scratch::new("slow-caller");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&worker, &seed);

    // Nothing offers it: refused once the join window ends without a matching card.
    let output = visit(with(
        aspace(&caller, &seed),
        &[
            "--join-timeout",
            "4s",
            "call",
            "x.Nothing#v1",
            "--json",
            "{}",
        ],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("no offering is named"));

    // A worker whose program outlasts the call.
    let script = worker.script("slow.sh", "cat > /dev/null\nsleep 60\n");
    let mut command = aspace(&worker, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--action",
            "slow",
            "--grace",
            "1s",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    let started = Instant::now();
    let output = visit(with(
        aspace(&caller, &seed),
        &[
            "call",
            "slow",
            "--json",
            r#"{"topic":"too-slow","priority":1}"#,
            "--timeout",
            "2s",
        ],
    ));
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stays leased"),
        "{output:?}"
    );
    // The input stayed: Java sees it taken by the worker's agent, and not completed.
    let taken_by = format!("TAKEN by {peer}/slow");
    seed.wait_for("the worker holds the call's input", |seed| {
        seed.task_state("too-slow")["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|e| e == taken_by.as_str()))
    });
    assert_ne!(seed.task_state("too-slow")["state"], "completed");

    // SIGTERM: the program outlasts the 1 s grace, so its group is killed and nothing completes.
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        err.iter()
            .any(|line| line.contains("the worker stopped before it ended; it was killed")),
        "{err:?}"
    );
    assert_ne!(seed.task_state("too-slow")["state"], "completed");
}

#[test]
fn call_waits_within_its_join_window_for_a_card_published_after_it_joined() {
    let classpath = classpath_or_skip!();
    let worker = Scratch::new("late-worker");
    let caller = Scratch::new("early-caller");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let caller_peer = peer_id(&caller, &seed);

    // The caller joins while nothing offers `research`, and waits within its join window.
    let call = Running::spawn(with(
        aspace(&caller, &seed),
        &[
            "--join-timeout",
            "60s",
            "call",
            "research",
            "--json",
            r#"{"topic":"late-card","priority":1}"#,
            "--timeout",
            "30s",
        ],
    ));
    seed.wait_for("the caller joins", |seed| {
        seed.ask("members")["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m == caller_peer.as_str()))
    });
    assert_eq!(
        seed.ask("cards")["cards"],
        serde_json::json!([]),
        "nothing offers research yet"
    );
    // Past the 1.5 s in which a visitor's first look settles the cards it pulled, so the card
    // below can only reach the call while it waits for one.
    std::thread::sleep(Duration::from_secs(3));

    // Only now does a worker bind and publish its card: the seed passes it on to the caller,
    // whose call then finds the offering, writes its input, and prints the result.
    let script = worker.script(
        "research.sh",
        r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
printf '{"topic":"%s","summary":"late %s","worker":"script"}\n' "$topic" "$topic"
"#,
    );
    let mut command = aspace(&worker, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--action",
            "research",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working as");

    let (code, out, err) = call.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert_eq!(out.len(), 1, "one result: {out:?} {err:?}");
    let called: Json = serde_json::from_str(&out[0]).expect("a JSON result");
    assert_eq!(called["offering"], "research", "{called}");
    assert_eq!(called["schema"], RESULT, "{called}");
    assert_eq!(called["entry"]["topic"], "late-card", "{called}");
    assert_eq!(called["entry"]["summary"], "late late-card", "{called}");
    assert_eq!(called["attestation"], "AGENT_ATTESTED", "{called}");

    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
}

#[test]
fn a_java_agent_is_listed_by_cards_and_answers_call() {
    let classpath = classpath_or_skip!();
    let caller = Scratch::new("java-agent-caller");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let bound = seed.ask("bind-agent java-researcher");
    let agent = format!("{}/java-researcher", seed.peer);
    assert_eq!(bound["bound"], agent.as_str(), "{bound}");
    seed.wait_for("Java's own card", |seed| {
        admitted_card(seed, &agent).is_some()
    });

    let offerings = ok_lines(with(aspace(&caller, &seed), &["cards", "--json"]));
    println!("aspace cards --json: {offerings:?}");
    assert_eq!(offerings.len(), 1, "{offerings:?}");
    let offering = &offerings[0];
    assert_eq!(offering["name"], "research", "{offering}");
    assert_eq!(offering["consumes"], TASK, "{offering}");
    assert_eq!(offering["produces"], RESULT, "{offering}");
    assert_eq!(offering["space"], "tasks", "{offering}");
    assert_eq!(offering["kind"], "take", "{offering}");
    assert_eq!(offering["agent"], agent.as_str(), "{offering}");
    assert_eq!(offering["issuer"], seed.peer.as_str(), "{offering}");
    assert_eq!(offering["replicas"], 1, "{offering}");
    assert_eq!(
        offering["description"], "Researches a task in Java",
        "{offering}"
    );

    let called = ok_json(with(
        aspace(&caller, &seed),
        &[
            "call",
            "research",
            "--json",
            r#"{"topic":"cli-calls-java","priority":2}"#,
            "--timeout",
            "30s",
        ],
    ));
    println!("aspace call research: {called}");
    assert_eq!(called["offering"], "research", "{called}");
    assert_eq!(called["schema"], RESULT, "{called}");
    assert_eq!(called["space"], "tasks", "{called}");
    assert_eq!(
        called["entry"],
        serde_json::json!({
            "topic": "cli-calls-java",
            "summary": "researched in java: cli-calls-java",
            "worker": agent,
        }),
        "{called}"
    );
    assert_eq!(called["issuer"], agent.as_str(), "{called}");
    assert_eq!(called["attestation"], "AGENT_ATTESTED", "{called}");
    seed.wait_for("Java folds its agent's completion", |seed| {
        seed.task_state("cli-calls-java")["state"] == "completed"
    });
    assert_eq!(seed.task_state("cli-calls-java")["holder"], agent.as_str());
    seed.ask("unbind-agent java-researcher");
}

#[test]
fn work_drains_ten_java_tasks_racing_take_all_and_java_lists_its_card() {
    const TOPICS: usize = 10;
    let classpath = classpath_or_skip!();
    let worker = Scratch::new("racer");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&worker, &seed);
    let script = worker.script(
        "race.sh",
        r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
sleep 0.3
printf '{"topic":"%s","summary":"raced %s","worker":"script"}\n' "$topic" "$topic"
"#,
    );
    let mut command = aspace(&worker, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--action",
            "research",
            "--name",
            "script-racer",
            "--parallel",
            "2",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    let agent = format!("{peer}/script-racer");

    // The running worker's card: admitted by Java's DiscoveryService, and its action listed by
    // Java's RemoteActions (both schemas resolve to the seed's classes).
    seed.wait_for("Java admits the worker's card", |seed| {
        admitted_card(seed, &agent).is_some()
    });
    let listed = |seed: &mut JavaSeed| -> Option<Json> {
        seed.ask("remote-actions")["actions"]
            .as_array()
            .and_then(|all| all.iter().find(|a| a["agent"] == agent.as_str()).cloned())
    };
    seed.wait_for("Java's RemoteActions lists the worker", |seed| {
        listed(seed).is_some()
    });
    let action = listed(&mut seed).expect("the action");
    println!("Java's RemoteActions lists: {action}");
    assert_eq!(action["name"], "script-racer_Task", "{action}");
    assert_eq!(action["declared"], "research", "{action}");
    assert_eq!(action["kind"], "take", "{action}");
    assert_eq!(action["space"], "tasks", "{action}");

    // Ten tasks, and the seed's own take-all racing the worker for them.
    let topics: Vec<String> = (0..TOPICS).map(|n| format!("race-{n:02}")).collect();
    for topic in &topics {
        seed.write_task(topic, 1);
    }
    let raced = seed.ask("take-all 1500 java-racer");
    let java_took = {
        let mut took: Vec<String> = raced["took"]
            .as_array()
            .map(|all| {
                all.iter()
                    .filter_map(|t| t.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        took.sort();
        took
    };
    let java_lost: Vec<&Json> = raced["lost"]
        .as_array()
        .map(|l| l.iter().collect())
        .unwrap_or_default();
    assert!(java_lost.is_empty(), "Java lost no hold it won: {raced}");

    // Every task completed exactly once, by whichever side won it.
    seed.wait_for("ten completed tasks", |seed| {
        topics
            .iter()
            .all(|topic| seed.task_state(topic)["state"] == "completed")
    });
    let results = seed.results();
    let mut script_did: Vec<String> = Vec::new();
    for topic in &topics {
        let answers: Vec<&(String, String, String)> =
            results.iter().filter(|(t, _, _)| t == topic).collect();
        assert_eq!(answers.len(), 1, "{topic} answered once: {results:?}");
        let (_, summary, by) = answers[0];
        let holder = seed.task_state(topic)["holder"].clone();
        if by == "script" {
            assert_eq!(summary, &format!("raced {topic}"));
            assert_eq!(holder, agent.as_str(), "{topic}");
            assert!(!java_took.contains(topic), "{topic} taken by both");
            script_did.push(topic.clone());
        } else {
            assert_eq!(by, "java-racer", "{topic}");
            assert_eq!(
                holder,
                format!("{}/java-seed", seed.peer).as_str(),
                "{topic}"
            );
            assert!(java_took.contains(topic), "{topic}");
        }
    }
    println!(
        "the worker completed {} ({script_did:?}), the seed's take-all {} ({java_took:?})",
        script_did.len(),
        java_took.len()
    );
    assert_eq!(script_did.len() + java_took.len(), TOPICS);
    assert!(!script_did.is_empty(), "the worker took part in the race");
    assert!(!java_took.is_empty(), "the seed took part in the race");

    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    let stopped = format!("stopped: {} tasks completed, 0 failed", script_did.len());
    assert!(
        err.iter().any(|line| line.contains(&stopped)),
        "{stopped:?} in {err:?}"
    );
}

// ------------------------------------------------------------------------------ edge cases

/// The topic of a task line on standard input, as the scripts below read it.
const READ_TOPIC: &str = r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
"#;

/// The resident marks left in a keystore.
fn resident_marks(keys: &Path) -> Vec<String> {
    std::fs::read_dir(keys)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(".aspace-resident-"))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether process `pid` is still alive (`kill -0`).
fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid.trim()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A payload over 64 KiB travels as a block its writer serves. `write` leaves only once the
/// seed holds the block, so a 3 MB entry written by a visitor that then left is read by Java
/// and by a second visitor. Against a seed that keeps no blocks, `write` says so with exit 3
/// instead of reporting a success no member could read.
#[test]
fn a_large_write_is_held_by_the_seed_before_the_visitor_leaves() {
    let classpath = classpath_or_skip!();
    let writer = Scratch::new("big-writer");
    let reader = Scratch::new("big-reader");
    let mut seed = JavaSeed::start(&classpath, &["--blocks"]);
    let topic = format!("big-{}", "x".repeat(3_000_000));
    let input = writer.path().join("big.json");
    std::fs::write(&input, format!(r#"{{"topic":"{topic}","priority":7}}"#)).expect("write");
    let input = format!("@{}", input.display());
    let written = ok_json(with(
        aspace(&writer, &seed),
        &["write", TASK, "--json", &input],
    ));
    let id = written["id"].as_str().expect("an id").to_owned();
    // The writer has left; the seed holds the payload.
    let sizes = seed.ask("sizes");
    let held = sizes["sizes"]
        .as_array()
        .and_then(|sizes| sizes.iter().find(|entry| entry["entryId"] == id.as_str()))
        .unwrap_or_else(|| panic!("the seed reads {id}: {sizes}"));
    assert_eq!(held["topicLength"], topic.len(), "{held}");
    assert_eq!(held["priority"], 7, "{held}");
    // Another visitor reads it, fetched from the seed.
    let read = ok_lines(with(aspace(&reader, &seed), &["read", TASK]));
    let entry = read
        .iter()
        .find(|line| line["id"] == id.as_str())
        .unwrap_or_else(|| panic!("the second visitor reads {id}"));
    assert_eq!(entry["entry"]["topic"].as_str(), Some(topic.as_str()));

    // A seed with no block exchange never holds it: the write is not confirmed (exit 3).
    let mut plain = JavaSeed::start(&classpath, &[]);
    let small = format!(r#"{{"topic":"{}","priority":1}}"#, "y".repeat(100_000));
    let output = visit(with(
        aspace(&writer, &plain),
        &["write", TASK, "--json", &small],
    ));
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("did not fetch the payload"),
        "{output:?}"
    );
    assert!(
        plain.ask("sizes")["sizes"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

/// Scenario 14: `aspace write --json` of `{"$int": "18446744073709551615"}` and a `$decimal`
/// are written as Java writes a `BigInteger` and a `BigDecimal` (the seed's strict reader drops
/// a plain integer past Java's `long`), so the seed holds the payload and reads the values; and
/// a `Priced` Java writes reads back as `$decimal` and `$int`.
#[test]
fn big_numbers_cross_the_json_bridge_both_ways() {
    const PRICED: &str = "ai.badmonkey.agentspaces.interop.Seed$Priced#v1";
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("priced");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let written = ok_json(with(
        aspace(&scratch, &seed),
        &[
            "write",
            PRICED,
            "--json",
            r#"{"item":"cli","amount":{"$decimal":"2.50"},"serial":{"$int":"18446744073709551615"}}"#,
        ],
    ));
    let id = written["id"].as_str().expect("an id").to_owned();
    let started = Instant::now();
    let held = loop {
        let priced = seed.ask("priced");
        let found = priced["priced"].as_array().and_then(|items| {
            items
                .iter()
                .find(|item| item["entryId"] == id.as_str())
                .cloned()
        });
        if let Some(found) = found {
            break found;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "the seed reads {id}: {priced}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(held["item"], "cli", "{held}");
    assert_eq!(held["amount"], "2.5", "{held}");
    assert_eq!(held["serial"], "18446744073709551615", "{held}");

    let java = seed.ask("write-priced java 1.25 -18446744073709551617");
    assert!(java["written"]["entryId"].is_string(), "{java}");
    let read = ok_lines(with(aspace(&scratch, &seed), &["read", PRICED]));
    let entry = read
        .iter()
        .find(|line| line["entry"]["item"] == "java")
        .unwrap_or_else(|| panic!("aspace reads Java's priced item: {read:?}"));
    assert_eq!(
        entry["entry"]["amount"],
        serde_json::json!({"$decimal": "1.25"})
    );
    assert_eq!(
        entry["entry"]["serial"],
        serde_json::json!({"$int": "-18446744073709551617"})
    );
}

/// A worker whose standard error is a closed pipe (its log reader died) still runs
/// its programs and completes their tasks (a failed diagnostic write is no panic in the
/// handler); and a program that exits 0 with its result while a child it left holds its
/// standard output completes its task (the group is killed and what was printed counts).
#[test]
fn work_survives_a_closed_stderr_and_a_program_that_leaves_a_child() {
    let classpath = classpath_or_skip!();
    let quiet = Scratch::new("closed-stderr");
    let busy = Scratch::new("background");
    let mut seed = JavaSeed::start(&classpath, &[]);
    peer_id(&quiet, &seed);
    peer_id(&busy, &seed);

    let talker = quiet.script(
        "talker.sh",
        &format!(
            "{READ_TOPIC}echo \"working on $topic\" >&2\n\
             printf '{{\"topic\":\"%s\",\"summary\":\"quiet\",\"worker\":\"closed-stderr\"}}\\n' \"$topic\"\n"
        ),
    );
    let (reader, closed) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut command = aspace(&quiet, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--where",
            "topic=quiet-1",
            "--",
        ])
        .arg(&talker)
        .stderr(Stdio::from(closed));
    let mut work = command.spawn().expect("aspace starts");
    seed.write_task("quiet-1", 1);
    seed.wait_for("the closed-stderr worker's result", |seed| {
        seed.results().contains(&(
            "quiet-1".to_owned(),
            "quiet".to_owned(),
            "closed-stderr".to_owned(),
        ))
    });
    assert_eq!(seed.task_state("quiet-1")["state"], "completed");
    let _ = Command::new("kill")
        .args(["-TERM", &work.id().to_string()])
        .status();
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = work.try_wait().expect("try_wait") {
            break status;
        }
        assert!(Instant::now() < deadline, "the worker did not stop");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0), "{status}");

    let leaver = busy.script(
        "leaver.sh",
        &format!(
            "{READ_TOPIC}sleep 30 &\n\
             printf '{{\"topic\":\"%s\",\"summary\":\"left a child\",\"worker\":\"background\"}}\\n' \"$topic\"\n"
        ),
    );
    let mut command = aspace(&busy, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--where",
            "topic=bg-1",
            "--",
        ])
        .arg(&leaver);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    seed.write_task("bg-1", 1);
    seed.wait_for("the result of the program that left a child", |seed| {
        seed.results().contains(&(
            "bg-1".to_owned(),
            "left a child".to_owned(),
            "background".to_owned(),
        ))
    });
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        !err.iter().any(|line| line.contains(" failed: ")),
        "no attempt failed: {err:?}"
    );
}

/// SIGHUP (a closed terminal or ssh session) stops the worker as SIGTERM does: the running
/// program gets SIGTERM at the end of the grace (it can clean up), its group ends, nothing is
/// left orphaned, and the keystore's resident mark goes with the worker.
#[test]
fn sighup_stops_the_worker_and_ends_its_programs() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("sighup");
    let mut seed = JavaSeed::start(&classpath, &[]);
    peer_id(&scratch, &seed);
    let pidfile = scratch.path().join("program.pid");
    let mark = scratch.path().join("got-term");
    let slow = scratch.script(
        "slow.sh",
        "echo $$ > \"$PIDFILE\"\n\
         trap 'echo term > \"$MARK\"; exit 3' TERM\n\
         cat > /dev/null\n\
         sleep 60 &\n\
         wait\n",
    );
    let mut command = aspace(&scratch, &seed);
    command
        .args(["work", "--take", TASK, "--space", "tasks", "--grace", "1s"])
        .arg("--env")
        .arg(format!("PIDFILE={}", pidfile.display()))
        .arg("--env")
        .arg(format!("MARK={}", mark.display()))
        .arg("--")
        .arg(&slow);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    seed.write_task("hangup", 1);
    work.wait_err("took ");
    let deadline = Instant::now() + DEADLINE;
    let pid = loop {
        if let Ok(pid) = std::fs::read_to_string(&pidfile)
            && !pid.trim().is_empty()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the program did not start");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !resident_marks(&scratch.keys()).is_empty(),
        "the worker marks its keystore"
    );
    let status = Command::new("kill")
        .args(["-HUP", &work.child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success());
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        err.iter().any(|line| line.contains("stopping")),
        "a hangup is a stop request: {err:?}"
    );
    assert!(
        std::fs::read_to_string(&mark).is_ok_and(|text| text.contains("term")),
        "the program got SIGTERM: {err:?}"
    );
    assert!(!alive(&pid), "the program {pid} is not orphaned");
    assert!(resident_marks(&scratch.keys()).is_empty());
    assert_ne!(seed.task_state("hangup")["state"], "completed");
}

/// A program run with `--produces` that prints more than 8 MiB fails its task with a note
/// that names the cap (not a bare SIGKILL); without `--produces` its output is discarded and the
/// task completes.
#[test]
fn the_stdout_cap_is_named_and_applies_only_to_results() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("flood");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&scratch, &seed);
    let flood = scratch.script(
        "flood.sh",
        &format!(
            "{READ_TOPIC}head -c 9437184 /dev/zero | tr '\\0' 'x'\n\
             printf '\\n{{\"topic\":\"%s\",\"summary\":\"flooded\",\"worker\":\"flood\"}}\\n' \"$topic\"\n"
        ),
    );
    let mut command = aspace(&scratch, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--produces",
            RESULT,
            "--where",
            "topic=flood-result",
            "--lease",
            "2s",
            "--",
        ])
        .arg(&flood);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    seed.write_task("flood-result", 1);
    work.wait_err("printed more than 8388608 bytes on standard output");
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        !err.iter()
            .any(|line| line.contains("SIGKILL)") && line.contains("ended with")),
        "the cap is named, not the signal: {err:?}"
    );
    assert_ne!(seed.task_state("flood-result")["state"], "completed");

    let mut command = aspace(&scratch, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "tasks",
            "--where",
            "topic=flood-log",
            "--",
        ])
        .arg(&flood);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    seed.write_task("flood-log", 1);
    seed.wait_for("the flooding program's task completes", |seed| {
        seed.task_state("flood-log")["state"] == "completed"
    });
    assert_eq!(
        seed.task_state("flood-log")["holder"],
        format!("{peer}/Task").as_str()
    );
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
}

/// A worker restarted on the same keystore notes only its own run's completions, not the
/// earlier run's that the space's history folds back at its start.
#[test]
fn a_restarted_worker_notes_only_its_own_completions() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("restart");
    let mut seed = JavaSeed::start(&classpath, &[]);
    peer_id(&scratch, &seed);
    let script = scratch.script(
        "done.sh",
        &format!(
            "{READ_TOPIC}printf '{{\"topic\":\"%s\",\"summary\":\"first run\",\"worker\":\"restart\"}}\\n' \"$topic\"\n"
        ),
    );
    let worker = |seed: &JavaSeed| {
        let mut command = aspace(&scratch, seed);
        command
            .args([
                "work",
                "--take",
                TASK,
                "--space",
                "tasks",
                "--produces",
                RESULT,
                "--",
            ])
            .arg(&script);
        command
    };
    let mut first = Running::spawn(worker(&seed));
    first.wait_err("working as");
    seed.write_task("r-1", 1);
    seed.write_task("r-2", 2);
    first.wait_err("completed");
    seed.wait_for("both results", |seed| {
        seed.results()
            .iter()
            .filter(|(_, summary, _)| summary == "first run")
            .count()
            == 2
    });
    first.terminate();
    let (code, _, err) = first.finish();
    assert_eq!(code, Some(0), "{err:?}");

    let mut second = Running::spawn(worker(&seed));
    second.wait_err("working as");
    // Long enough for the pull's answer, the space's history, to fold.
    std::thread::sleep(Duration::from_secs(3));
    second.terminate();
    let (code, _, err) = second.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(
        !err.iter().any(|line| line.starts_with("aspace: completed")),
        "the first run's completions are not this run's: {err:?}"
    );
    assert!(
        err.iter()
            .any(|line| line.contains("stopped: 0 tasks completed")),
        "{err:?}"
    );
}

/// The space a card routes a call to is the card's publisher's choice; a caller
/// whose configuration names the group's spaces follows only those (Java follows only its
/// registered spaces): an offering in another space is not listed, until the caller names it.
#[test]
fn the_catalogue_follows_only_the_configured_spaces() {
    let classpath = classpath_or_skip!();
    let worker = Scratch::new("elsewhere-worker");
    let caller = Scratch::new("elsewhere-caller");
    let mut seed = JavaSeed::start(&classpath, &[]);
    let peer = peer_id(&worker, &seed);
    let script = worker.script("noop.sh", "cat > /dev/null\n");
    let mut command = aspace(&worker, &seed);
    command
        .args([
            "work",
            "--take",
            TASK,
            "--space",
            "elsewhere",
            "--produces",
            RESULT,
            "--action",
            "detour",
            "--",
        ])
        .arg(&script);
    let mut work = Running::spawn(command);
    work.wait_err("working as");
    let agent = format!("{peer}/detour");
    seed.wait_for("Java admits the worker's card", |seed| {
        admitted_card(seed, &agent).is_some()
    });
    // The caller's group names one space, `tasks` (ASPACE_SPACES).
    let offerings = ok_lines(with(aspace(&caller, &seed), &["cards", "--json"]));
    assert!(
        !offerings
            .iter()
            .any(|offering| offering["name"] == "detour"),
        "{offerings:?}"
    );
    let output = visit(with(
        aspace(&caller, &seed),
        &[
            "--join-timeout",
            "3s",
            "call",
            "detour",
            "--json",
            "{}",
            "--timeout",
            "1s",
        ],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    // Named in the configuration, it is followed.
    let mut command = aspace(&caller, &seed);
    command.env("ASPACE_SPACES", "tasks,elsewhere");
    let offerings = ok_lines(with(command, &["cards", "--json"]));
    let detour = offerings
        .iter()
        .find(|offering| offering["name"] == "detour")
        .unwrap_or_else(|| panic!("no detour offering: {offerings:?}"));
    assert_eq!(detour["space"], "elsewhere");
    work.terminate();
    let (code, _, err) = work.finish();
    assert_eq!(code, Some(0), "{err:?}");
}
