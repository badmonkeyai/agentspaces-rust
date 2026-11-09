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

//! `aspace daemon` and the owner-only file rules.
//!
//! Without a fleet (always run):
//!
//! 1. `aspace daemon --help` carries examples;
//! 2. a visitor with no daemon says so in one line and joins itself; `--no-daemon` and
//!    `ASPACE_NO_DAEMON=1` say nothing; a refusal of its arguments comes before the daemon is
//!    asked; `--json -` is read once, by whichever path runs the command;
//! 3. a socket directory writable by others, a socket path that is not a socket, and a path too
//!    long for a Unix socket are refused by the daemon (exit 4, 2, 2), and the visitor will not
//!    use such a socket;
//! 4. a stale socket (a daemon that died) is removed before the daemon joins;
//! 5. a readable private key is refused (exit 4, naming the file and the `chmod 600` fix) unless
//!    `--allow-readable-key` or `ASPACE_ALLOW_READABLE_KEY=1` allows it;
//! 6. a scripted daemon (a socket the test serves) shows the visitor's side of the protocol:
//!    the request it sends (its `--json -` read from standard input), the frames it prints, the
//!    exit codes it passes on, a daemon that dies mid-request (exit 1), and the hellos it will
//!    not use (another protocol, another group, another keystore, a refusal: it joins itself);
//!    a daemon of its group and keystore under a weaker profile is not used and not joined
//!    around either (exit 2: a join of its own would share the daemon's PeerID);
//!
//! Against the scripted Java seed (`interop/java-seed`, gated as `cli_java.rs` is: each test
//! passes with a note when `java` or the build is unavailable, unless
//! `ASPACE_INTEROP_REQUIRED=1`):
//!
//! 7. a daemon started on a scratch `XDG_RUNTIME_DIR` greets on standard output, keeps its
//!    directory 0700, its socket and lock file 0600, and serves `status`, `write`, `read`,
//!    `take`, `complete`, `watch`, `cards`, and `call` to visitors (Java reading and answering
//!    what they do) without a word on their standard error; a take through it is completed
//!    through it; the latency of a write through it and of a write that joins itself is
//!    measured and printed; SIGTERM ends it with exit 0 and removes its socket;
//! 8. a second daemon is refused (exit 2) by the lock and, with the lock file removed under the
//!    first, by the first's hello; a daemon killed with SIGKILL leaves a stale socket the next
//!    daemon removes;
//! 9. a watch through the daemon ends with exit 0 when interrupted, and with exit 1 when the
//!    daemon stops.
//!
//! Another user's connection cannot be made without root: the uid check is unit-tested with
//! injected credentials (`daemon::server::authorize`). Every process a test starts is killed
//! when the test ends, also when it fails.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value as Json, json};

/// The founding text of the Java seed's group.
const FOUNDING: &str = "agentspaces-rust-interop-v1";
/// The founding text the scripted daemons serve.
const FAKE_FOUNDING: &str = "aspace-daemon-test-v1";
/// The seed's task and result schemas.
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
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

/// What a visitor that found no daemon says.
const NO_DAEMON: &str = "no daemon answered";
/// The end of every line of a visitor that joins itself.
const JOINING: &str = "joining the group itself";

/// Every variable the configuration (and the daemon's location) reads, removed from each
/// `aspace` run first.
const CLEARED: [&str; 14] = [
    "ASPACE_SEEDS",
    "ASPACE_GROUP",
    "ASPACE_JOIN",
    "ASPACE_KEYSTORE",
    "ASPACE_PROFILE",
    "ASPACE_SPACES",
    "ASPACE_CONFIG",
    "ASPACE_SOCKET",
    "ASPACE_NO_DAEMON",
    "ASPACE_ALLOW_READABLE_KEY",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
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

/// A scratch directory under `/tmp` (short, so a socket path in it fits a Unix socket's
/// limit): `home`, `run` (the runtime directory, 0700), `tmp`, and `keys`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new("/tmp").join(format!(
            "asd-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        for dir in ["home", "run", "tmp"] {
            std::fs::create_dir_all(path.join(dir)).expect("scratch directory");
        }
        chmod(&path.join("run"), 0o700);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn run(&self) -> PathBuf {
        self.0.join("run")
    }

    fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }

    /// The daemon's default socket in this scratch runtime directory.
    fn socket(&self) -> PathBuf {
        self.run().join("aspace/daemon.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
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
}

impl JavaSeed {
    fn start(classpath: &str) -> Self {
        let mut failures = Vec::new();
        for _ in 0..3 {
            match Self::start_on(classpath, free_port()) {
                Ok(seed) => return seed,
                Err(why) => failures.push(why),
            }
        }
        panic!("the Java seed did not start: {}", failures.join("\n---\n"));
    }

    fn start_on(classpath: &str, port: u16) -> Result<Self, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("daemon");
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

    /// The available tasks' topics.
    fn task_topics(&mut self) -> Vec<String> {
        self.ask("tasks")["tasks"]
            .as_array()
            .map(|tasks| {
                tasks
                    .iter()
                    .filter_map(|t| t["topic"].as_str().map(str::to_owned))
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

    fn seed(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
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

/// An `aspace` command with nothing configured but `HOME`, the runtime and temporary
/// directories (all in the scratch directory, so no real fleet file, keystore, or daemon is
/// touched).
fn bare_aspace(scratch: &Scratch) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aspace"));
    for variable in CLEARED {
        command.env_remove(variable);
    }
    command
        .env("HOME", scratch.home())
        .env("XDG_RUNTIME_DIR", scratch.run())
        .env("TMPDIR", scratch.path().join("tmp"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// An `aspace` command of the seed's group, with the scratch keystore.
fn aspace(scratch: &Scratch, seeds: &str, founding: &str) -> Command {
    let mut command = bare_aspace(scratch);
    command
        .env("ASPACE_SEEDS", seeds)
        .env("ASPACE_GROUP", founding)
        .env("ASPACE_KEYSTORE", scratch.keys())
        .env("ASPACE_SPACES", "tasks");
    command
}

/// An `aspace` command of the Java seed's group.
fn of_seed(scratch: &Scratch, seed: &JavaSeed) -> Command {
    aspace(scratch, &seed.seed(), FOUNDING)
}

/// A seed address nothing listens on.
fn closed_seed() -> String {
    format!("tcp://127.0.0.1:{}", free_port())
}

fn with(mut command: Command, args: &[&str]) -> Command {
    command.args(args);
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

    /// A daemon, started and greeting: its hello (the first line of its standard output).
    fn daemon(command: Command) -> (Self, Json) {
        let mut running = Running::spawn(with(command, &["daemon"]));
        let hello = running.next_out();
        (running, hello)
    }

    /// The next line of standard output, as JSON.
    fn next_out(&mut self) -> Json {
        match self.stdout.recv_timeout(DEADLINE) {
            Ok(line) => serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line}")),
            Err(_) => {
                self.drain_err();
                panic!("no line on standard output: {:?}", self.seen_err)
            }
        }
    }

    fn drain_err(&mut self) {
        self.seen_err.extend(self.stderr.try_iter());
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

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill {signal} failed");
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
        // The reader threads see the pipes close shortly after the exit.
        std::thread::sleep(Duration::from_millis(100));
        let out: Vec<String> = self.stdout.try_iter().collect();
        let mut err = std::mem::take(&mut self.seen_err);
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

/// Runs a visitor to its end within [`VISIT`], killing it past that, with `input` on its
/// standard input when given.
fn visit_with(mut command: Command, input: Option<&str>) -> Output {
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("aspace starts");
    if let Some(input) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(input.as_bytes()).expect("stdin");
    }
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
        std::thread::sleep(Duration::from_millis(5));
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

fn visit(command: Command) -> Output {
    visit_with(command, None)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_lines(output: &Output) -> Vec<Json> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect()
}

/// Runs a visitor through the daemon: it must succeed and say nothing on standard error.
fn through(command: Command) -> Vec<Json> {
    let output = visit(command);
    let err = stderr(&output);
    assert!(
        output.status.success(),
        "aspace failed with {}: {err}",
        output.status
    );
    assert!(
        !err.contains(JOINING),
        "the visitor joined itself instead of using the daemon: {err}"
    );
    stdout_lines(&output)
}

/// [`through`], with one JSON object answered.
fn through_one(command: Command) -> Json {
    let mut lines = through(command);
    assert_eq!(lines.len(), 1, "one object: {lines:?}");
    lines.remove(0)
}

/// How many lines of `text` contain `needle`.
fn count(text: &str, needle: &str) -> usize {
    text.lines().filter(|line| line.contains(needle)).count()
}

// ------------------------------------------------------------------------------ without a fleet

#[test]
fn daemon_help_carries_examples() {
    let scratch = Scratch::new("help");
    let output = visit(with(bare_aspace(&scratch), &["daemon", "--help"]));
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    for part in ["Examples:", "aspace daemon", "0600", "--no-daemon"] {
        assert!(help.contains(part), "{part:?} missing from: {help}");
    }
    let output = visit(with(bare_aspace(&scratch), &["--help"]));
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--no-daemon"), "{help}");
}

#[test]
fn a_visitor_without_a_daemon_says_so_once_and_joins_itself() {
    let scratch = Scratch::new("nodaemon");
    let seeds = closed_seed();
    let read = |extra: &[&str], vars: &[(&str, &str)]| {
        let mut command = aspace(&scratch, &seeds, FAKE_FOUNDING);
        for (name, value) in vars {
            command.env(name, value);
        }
        command
            .args(extra)
            .args(["read", "x.T#v1", "--join-timeout", "1s"]);
        visit(command)
    };
    let output = read(&[], &[]);
    let err = stderr(&output);
    assert!(
        matches!(output.status.code(), Some(1 | 3)),
        "the join of an unreachable seed fails: {err}"
    );
    assert_eq!(count(&err, NO_DAEMON), 1, "{err}");
    assert_eq!(count(&err, JOINING), 1, "{err}");
    assert!(
        err.contains(&scratch.socket().display().to_string()),
        "the note names the socket: {err}"
    );
    // --no-daemon and ASPACE_NO_DAEMON=1 skip the daemon without a word; the exit is the same.
    for (extra, vars) in [
        (&["--no-daemon"][..], &[][..]),
        (&[][..], &[("ASPACE_NO_DAEMON", "1")][..]),
    ] {
        let skipped = read(extra, vars);
        let err = stderr(&skipped);
        assert_eq!(skipped.status.code(), output.status.code(), "{err}");
        assert!(!err.contains(NO_DAEMON), "{err}");
    }
    // A refusal of the arguments comes first, as without a daemon.
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["write", "shop.Order", "--json", "{}"],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!stderr(&output).contains(NO_DAEMON), "{output:?}");
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["write", "shop.Order#v1", "--json", "[1]"],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!stderr(&output).contains(NO_DAEMON), "{output:?}");
    // `--json -` is read by the join of its own when no daemon answers: the object arrives
    // whole (the join then fails), not as an empty standard input (a refusal, exit 2).
    let output = visit_with(
        with(
            aspace(&scratch, &seeds, FAKE_FOUNDING),
            &["write", "x.T#v1", "--json", "-", "--join-timeout", "1s"],
        ),
        Some("{\"topic\":\"stdin\"}"),
    );
    assert!(
        matches!(output.status.code(), Some(1 | 3)),
        "{}",
        stderr(&output)
    );
    // Commands that never use a daemon never ask for one.
    let output = visit(with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["id"]));
    assert!(output.status.success(), "{output:?}");
    assert!(!stderr(&output).contains(NO_DAEMON), "{output:?}");
}

#[test]
fn unsafe_socket_paths_are_refused_by_the_daemon_and_the_visitor() {
    let scratch = Scratch::new("unsafe");
    let seeds = closed_seed();
    // A socket directory others may write: another user could put a socket of theirs there.
    let dir = scratch.run().join("aspace");
    std::fs::create_dir_all(&dir).expect("dir");
    chmod(&dir, 0o777);
    let output = visit(with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["daemon"]));
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let err = stderr(&output);
    assert!(err.contains("writable by its group or others"), "{err}");
    assert!(
        err.contains(&format!("chmod 700 {}", dir.display())),
        "{err}"
    );
    assert!(!scratch.socket().exists());
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["read", "x.T#v1", "--join-timeout", "1s"],
    ));
    let err = stderr(&output);
    assert!(err.contains("the daemon socket is refused"), "{err}");
    assert_eq!(count(&err, JOINING), 1, "{err}");
    chmod(&dir, 0o700);

    // A socket path that is a plain file.
    let plain = scratch.path().join("plain.sock");
    std::fs::write(&plain, b"not a socket").expect("file");
    let plain_text = plain.display().to_string();
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["daemon", "--socket", &plain_text],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(stderr(&output).contains("is not a socket"), "{output:?}");
    assert_eq!(
        std::fs::read(&plain).expect("kept"),
        b"not a socket",
        "a file that is not a socket is never removed"
    );

    // A path too long for a Unix socket.
    let long = scratch.path().join("x".repeat(120)).join("d.sock");
    let long_text = long.display().to_string();
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["daemon", "--socket", &long_text],
    ));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        stderr(&output).contains("longer than a Unix domain socket takes"),
        "{output:?}"
    );
}

#[test]
fn a_stale_socket_is_removed_before_the_join() {
    let scratch = Scratch::new("stale");
    let socket = scratch.socket();
    std::fs::create_dir_all(socket.parent().expect("dir")).expect("dir");
    chmod(socket.parent().expect("dir"), 0o700);
    // A daemon that died: its socket stays, and nothing answers it.
    drop(UnixListener::bind(&socket).expect("bind"));
    assert!(socket.exists());
    let output = visit(with(
        aspace(&scratch, &closed_seed(), FAKE_FOUNDING),
        &["daemon", "--join-timeout", "1s"],
    ));
    let err = stderr(&output);
    assert!(err.contains("removed the stale socket"), "{err}");
    assert!(
        matches!(output.status.code(), Some(1 | 3)),
        "the join of an unreachable seed fails: {err}"
    );
    assert!(!socket.exists(), "the stale socket is gone");
    assert_eq!(
        mode(socket.parent().expect("dir")),
        0o700,
        "the directory stays owner-only"
    );
    let lock = scratch.run().join("aspace/daemon.sock.lock");
    assert_eq!(mode(&lock), 0o600, "the lock file is owner-only");
}

#[test]
fn a_readable_key_is_refused_unless_allowed() {
    let scratch = Scratch::new("readable");
    let seeds = closed_seed();
    let keys_text = scratch.keys().display().to_string();
    let created = visit(with(
        bare_aspace(&scratch),
        &["id", "--keystore", &keys_text],
    ));
    assert!(created.status.success(), "{created:?}");
    let key = scratch.keys().join("peer.key");
    assert_eq!(mode(&key), 0o600, "a minted key is owner-only");
    assert_eq!(
        mode(&scratch.keys()),
        0o700,
        "a created keystore is owner-only"
    );
    chmod(&key, 0o640);
    let key_text = key.display().to_string();
    for args in [&["daemon"][..], &["id"][..], &["status"][..]] {
        let output = visit(with(aspace(&scratch, &seeds, FAKE_FOUNDING), args));
        assert_eq!(output.status.code(), Some(4), "{args:?}: {output:?}");
        let err = stderr(&output);
        for part in [
            key_text.as_str(),
            "readable by group or others",
            &format!("chmod 600 {key_text}"),
            "--allow-readable-key",
            "ASPACE_ALLOW_READABLE_KEY",
        ] {
            assert!(err.contains(part), "{part:?} missing from: {err}");
        }
    }
    // Allowed by the flag or the variable: past the key, to the join (which fails here).
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["--allow-readable-key", "daemon", "--join-timeout", "1s"],
    ));
    assert!(
        matches!(output.status.code(), Some(1 | 3)),
        "{}",
        stderr(&output)
    );
    let mut allowed = with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["id"]);
    allowed.env("ASPACE_ALLOW_READABLE_KEY", "1");
    let output = visit(allowed);
    assert!(output.status.success(), "{output:?}");
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["id", "--allow-readable-key"],
    ));
    assert!(output.status.success(), "{output:?}");
    let mut refused = with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["id"]);
    refused.env("ASPACE_ALLOW_READABLE_KEY", "0");
    assert_eq!(visit(refused).status.code(), Some(4));
    let mut garbled = with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["id"]);
    garbled.env("ASPACE_ALLOW_READABLE_KEY", "maybe");
    let output = visit(garbled);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        stderr(&output).contains("ASPACE_ALLOW_READABLE_KEY=\"maybe\" is not a boolean"),
        "{output:?}"
    );
}

// ------------------------------------------------------------------------------ a scripted daemon

/// What a scripted daemon was sent: the request line, when one came.
type Sent = Receiver<Option<Json>>;

/// Serves one connection on `socket` (its directory made 0700) from a thread: writes `hello`,
/// reads one request line (passed back), writes `frames`, and closes the connection (with no
/// frames, a daemon that goes away mid-request).
fn scripted_daemon(socket: &Path, hello: Json, frames: Vec<Json>) -> Sent {
    let dir = socket.parent().expect("dir");
    std::fs::create_dir_all(dir).expect("dir");
    chmod(dir, 0o700);
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).expect("bind");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(DEADLINE));
        let mut writer = stream.try_clone().expect("clone");
        let _ = writeln!(writer, "{hello}");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let request = match reader.read_line(&mut line) {
            Ok(read) if read > 0 => serde_json::from_str(&line).ok(),
            _ => None,
        };
        let _ = tx.send(request);
        for frame in frames {
            let _ = writeln!(writer, "{frame}");
        }
        let _ = writer.flush();
    });
    rx
}

/// The hello of a daemon serving the scripted group with `scratch`'s keystore, as `mtls`.
fn matching_hello(scratch: &Scratch) -> Json {
    std::fs::create_dir_all(scratch.keys()).expect("keys");
    let keystore = std::fs::canonicalize(scratch.keys()).expect("canonical keystore");
    json!({"hello": {
        "protocol": 1,
        "version": "0.5.0",
        "group": agentspaces::wire::ids::group_id_from_founding(FAKE_FOUNDING.as_bytes()),
        "groupName": null,
        "peerId": "zScriptedPeer",
        "keystore": keystore.display().to_string(),
        "profile": "mtls",
        "pid": 1,
        "socket": scratch.socket().display().to_string(),
        "verbs": ["status", "write", "read", "take", "complete", "watch", "cards", "call"],
    }})
}

#[test]
fn the_visitor_sends_its_request_and_prints_the_daemons_frames() {
    let scratch = Scratch::new("scripted");
    let seeds = closed_seed();
    let hello = matching_hello(&scratch);
    let sent = scripted_daemon(
        &scratch.socket(),
        hello.clone(),
        vec![
            json!({"note": "from the daemon"}),
            json!({"out": {"id": "e-1", "schema": "x.T#v1", "space": "tasks"}}),
            json!({"text": "plain text"}),
            json!({"exit": 0}),
        ],
    );
    let output = visit_with(
        with(
            aspace(&scratch, &seeds, FAKE_FOUNDING),
            &[
                "write", "x.T#v1", "--json", "-", "--lease", "2m", "--tag", "k=v",
            ],
        ),
        Some("{\"topic\":\"from stdin\",\"n\":2}"),
    );
    let err = stderr(&output);
    assert!(output.status.success(), "{err}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "{\"id\":\"e-1\",\"schema\":\"x.T#v1\",\"space\":\"tasks\"}\nplain text\n"
    );
    assert_eq!(err.trim(), "aspace: from the daemon");
    let request = sent
        .recv_timeout(DEADLINE)
        .expect("served")
        .expect("a request");
    assert_eq!(request["protocol"], 1, "{request}");
    assert_eq!(request["verb"], "write", "{request}");
    assert_eq!(
        request["args"],
        json!({
            "schema": "x.T#v1",
            "entry": {"topic": "from stdin", "n": 2},
            "space": "tasks",
            "leaseMillis": 120_000,
            "tags": [["k", "v"]],
        })
    );

    // Every exit code passes through, with its message.
    for code in [1, 2, 3, 4] {
        let sent = scripted_daemon(
            &scratch.socket(),
            hello.clone(),
            vec![json!({"exit": code, "error": format!("failed with {code}")})],
        );
        let output = visit(with(
            aspace(&scratch, &seeds, FAKE_FOUNDING),
            &["take", "x.T#v1", "--timeout", "1s"],
        ));
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        assert_eq!(
            stderr(&output).trim(),
            format!("aspace: failed with {code}")
        );
        let request = sent.recv_timeout(DEADLINE).expect("served").expect("sent");
        assert_eq!(request["verb"], "take");
        assert_eq!(request["args"]["timeoutMillis"], 1000);
    }

    // A daemon that goes away mid-request: exit 1, and no join of its own (the request may
    // have run). A read-only verb may run again; a write may have taken effect, so
    // the visitor says so instead of advising a blind rerun.
    let sent = scripted_daemon(&scratch.socket(), hello.clone(), vec![]);
    let output = visit(with(aspace(&scratch, &seeds, FAKE_FOUNDING), &["status"]));
    assert!(sent.recv_timeout(DEADLINE).expect("served").is_some());
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{err}");
    assert!(err.contains("ended the request without an answer"), "{err}");
    assert!(err.contains("run the command again"), "{err}");
    assert!(!err.contains(JOINING), "{err}");
    let sent = scripted_daemon(&scratch.socket(), hello.clone(), vec![]);
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["write", "x.T#v1", "--json", "{\"k\":1}"],
    ));
    assert!(sent.recv_timeout(DEADLINE).expect("served").is_some());
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{err}");
    assert!(err.contains("the write may have taken effect"), "{err}");
    assert!(!err.contains("run the command again"), "{err}");
    assert!(!err.contains(JOINING), "{err}");
}

/// A visitor reads `--json -` before it connects, so a slow producer holds no
/// connection (or permit) of the daemon's, whose wait for a request is bounded: no connection
/// arrives while standard input is still open, and the object read reaches the request.
#[test]
fn the_json_of_standard_input_is_read_before_the_daemon_is_asked() {
    let scratch = Scratch::new("read-ahead");
    let seeds = closed_seed();
    let hello = matching_hello(&scratch);
    let socket = scratch.socket();
    let dir = socket.parent().expect("dir");
    std::fs::create_dir_all(dir).expect("dir");
    chmod(dir, 0o700);
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind");
    let (connected_tx, connected) = mpsc::channel::<()>();
    let (accepted_tx, accepted) = mpsc::channel::<Option<Json>>();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let _ = connected_tx.send(());
        let _ = stream.set_read_timeout(Some(DEADLINE));
        let mut writer = stream.try_clone().expect("clone");
        let _ = writeln!(writer, "{hello}");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let request = match reader.read_line(&mut line) {
            Ok(read) if read > 0 => serde_json::from_str(&line).ok(),
            _ => None,
        };
        let _ = accepted_tx.send(request);
        let _ = writeln!(writer, "{}", json!({"out": {"id": "e-1"}}));
        let _ = writeln!(writer, "{}", json!({"exit": 0}));
        let _ = writer.flush();
    });
    let mut command = with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["write", "x.T#v1", "--json", "-"],
    );
    command.stdin(Stdio::piped());
    let mut child = command.spawn().expect("aspace starts");
    let mut stdin = child.stdin.take().expect("stdin");
    // The producer is slow: nothing is written yet, and nothing reaches the daemon meanwhile.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        matches!(connected.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "the visitor connected before its standard input was read"
    );
    stdin
        .write_all(b"{\"topic\":\"slow producer\"}")
        .expect("stdin");
    drop(stdin);
    let request = accepted
        .recv_timeout(DEADLINE)
        .expect("a connection once the input was read")
        .expect("a request");
    assert_eq!(request["args"]["entry"], json!({"topic": "slow producer"}));
    let output = child.wait_with_output().expect("output");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn the_visitor_joins_itself_when_the_daemon_is_not_one_it_can_use() {
    let scratch = Scratch::new("mismatch");
    let seeds = closed_seed();
    let hello = matching_hello(&scratch);
    let with_hello = |change: &dyn Fn(&mut Json)| {
        let mut hello = hello.clone();
        change(&mut hello);
        hello
    };
    for (hello, says) in [
        (
            with_hello(&|hello| hello["hello"]["protocol"] = json!(99)),
            "speaks protocol 99",
        ),
        (
            with_hello(&|hello| hello["hello"]["group"] = json!("zAnotherGroup")),
            "serves group zAnotherGroup",
        ),
        (
            with_hello(&|hello| hello["hello"]["keystore"] = json!("/elsewhere/keys")),
            "runs with the keystore /elsewhere/keys",
        ),
        (
            json!({"exit": 4, "error": "this daemon serves only its own user"}),
            "refused: this daemon serves only its own user",
        ),
        (json!({"nonsense": true}), "did not answer"),
    ] {
        let sent = scripted_daemon(&scratch.socket(), hello, vec![json!({"exit": 0})]);
        let output = visit(with(
            aspace(&scratch, &seeds, FAKE_FOUNDING),
            &["status", "--join-timeout", "1s"],
        ));
        let err = stderr(&output);
        assert!(err.contains(says), "{says:?} missing from: {err}");
        assert_eq!(count(&err, JOINING), 1, "{err}");
        assert!(
            matches!(output.status.code(), Some(1 | 3)),
            "it joined itself (and failed): {err}"
        );
        assert_eq!(
            sent.recv_timeout(DEADLINE).expect("served"),
            None,
            "no request is sent to a daemon not used"
        );
    }
    // A daemon of this group with this keystore under a weaker profile is not used,
    // and no join of its own is made either (it would share the daemon's PeerID and see
    // nothing): exit 2, naming the remedies, and no request sent.
    let sent = scripted_daemon(
        &scratch.socket(),
        with_hello(&|hello| hello["hello"]["profile"] = json!("dev-local")),
        vec![json!({"exit": 0})],
    );
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["status", "--join-timeout", "1s"],
    ));
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(
        err.contains("weaker than this configuration's mtls"),
        "{err}"
    );
    assert!(err.contains("share the daemon's PeerID"), "{err}");
    assert!(err.contains("--profile dev-local"), "{err}");
    assert_eq!(count(&err, JOINING), 0, "{err}");
    assert_eq!(
        sent.recv_timeout(DEADLINE).expect("served"),
        None,
        "no request is sent to a daemon not used"
    );

    // A dev-local visitor may use an mtls daemon (a stricter profile).
    let sent = scripted_daemon(
        &scratch.socket(),
        hello,
        vec![json!({"out": {"ok": true}}), json!({"exit": 0})],
    );
    let output = visit(with(
        aspace(&scratch, &seeds, FAKE_FOUNDING),
        &["--profile", "dev-local", "cards", "--json"],
    ));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout_lines(&output), [json!({"ok": true})]);
    let request = sent.recv_timeout(DEADLINE).expect("served").expect("sent");
    assert_eq!(request["verb"], "cards");
    assert_eq!(request["args"]["spaces"], json!(["tasks"]));
}

// ------------------------------------------------------------------------------ against Java

/// The daemon's socket, lock, and directory as they must be, and the hello naming them.
fn assert_owner_only(scratch: &Scratch, hello: &Json) {
    let socket = scratch.socket();
    assert_eq!(hello["socket"], socket.display().to_string().as_str());
    assert_eq!(hello["protocol"], 1);
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(&socket)
            .expect("socket")
            .file_type()
            .is_socket()
    );
    assert_eq!(mode(&socket), 0o600, "the socket is owner-only");
    assert_eq!(
        mode(socket.parent().expect("dir")),
        0o700,
        "its directory is owner-only"
    );
    let lock = scratch.run().join("aspace/daemon.sock.lock");
    assert_eq!(mode(&lock), 0o600, "the lock file is owner-only");
    assert_eq!(
        std::fs::read_to_string(&lock).expect("lock").trim(),
        hello["pid"].to_string(),
        "the lock names the daemon's pid"
    );
}

/// The median of `samples`, in milliseconds.
fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

/// Times `runs` writes of `command`, each of which must succeed.
fn time_writes(runs: usize, mut command: impl FnMut() -> Command) -> Vec<f64> {
    (0..runs)
        .map(|_| {
            let started = Instant::now();
            let output = visit(command());
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            assert!(output.status.success(), "{output:?}");
            elapsed
        })
        .collect()
}

#[test]
fn the_daemon_serves_every_visitor_verb_and_stops_cleanly() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("serve");
    let mut seed = JavaSeed::start(&classpath);
    let (mut daemon, hello) = Running::daemon(of_seed(&scratch, &seed));
    println!("daemon hello: {hello}");
    daemon.wait_err("serving");
    assert_owner_only(&scratch, &hello);
    let daemon_peer = hello["peerId"].as_str().expect("a PeerID").to_owned();
    let me = format!("{daemon_peer}/rust");

    // status, through the daemon: its socket and pid, and the seed among the members.
    let status = through_one(with(of_seed(&scratch, &seed), &["status", "--json"]));
    assert_eq!(status["daemon"]["pid"], hello["pid"], "{status}");
    assert_eq!(status["peerId"], daemon_peer.as_str());
    assert!(
        status["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m == seed.peer.as_str())),
        "{status}"
    );
    let text = visit(with(of_seed(&scratch, &seed), &["status"]));
    assert!(
        String::from_utf8_lossy(&text.stdout).contains("daemon   "),
        "{text:?}"
    );

    // write: Java reads it.
    let written = through_one(with(
        of_seed(&scratch, &seed),
        &[
            "write",
            TASK,
            "--json",
            r#"{"topic":"via-daemon","priority":5}"#,
        ],
    ));
    assert_eq!(written["space"], "tasks");
    assert!(seed.task_topics().contains(&"via-daemon".to_owned()));

    // read: a Java task (rumored to the resident peer as Java writes it) and the daemon's,
    // filtered.
    seed.ask("write-task from-java 7");
    let deadline = Instant::now() + DEADLINE;
    let lines = loop {
        let lines = through(with(
            of_seed(&scratch, &seed),
            &["read", TASK, "--where", "priority>=5"],
        ));
        let folded = lines
            .iter()
            .any(|line| line["entry"]["topic"] == "from-java");
        if folded || Instant::now() >= deadline {
            break lines;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let topics: Vec<&str> = lines
        .iter()
        .filter_map(|line| line["entry"]["topic"].as_str())
        .collect();
    assert!(
        topics.contains(&"via-daemon") && topics.contains(&"from-java"),
        "{topics:?}"
    );

    // take through the daemon, held by its identity; complete through it, with a result Java
    // reads.
    let taken = through_one(with(
        of_seed(&scratch, &seed),
        &["take", TASK, "--where", "topic=from-java", "--lease", "2m"],
    ));
    assert_eq!(taken["holder"], me.as_str(), "{taken}");
    let id = taken["id"].as_str().expect("an id").to_owned();
    let completed = through_one(with(
        of_seed(&scratch, &seed),
        &[
            "complete",
            &id,
            "--json",
            r#"{"topic":"from-java","summary":"done through the daemon","worker":"daemon"}"#,
            "--produces",
            RESULT,
        ],
    ));
    assert_eq!(completed["completed"], true, "{completed}");
    assert!(seed.results().contains(&(
        "from-java".to_owned(),
        "done through the daemon".to_owned(),
        "daemon".to_owned()
    )));
    // Completed once: again is refused, exit 2, through the daemon too.
    let again = visit(with(of_seed(&scratch, &seed), &["complete", &id]));
    assert_eq!(again.status.code(), Some(2), "{again:?}");
    assert!(stderr(&again).contains("already completed"), "{again:?}");
    assert!(!stderr(&again).contains(JOINING), "{again:?}");

    // watch through the daemon: a task Java writes.
    let mut watch = Running::spawn(with(
        of_seed(&scratch, &seed),
        &["watch", TASK, "--kinds", "written", "--count", "1"],
    ));
    watch.wait_err("watching");
    seed.ask("write-task watched 2");
    let (code, out, err) = watch.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert_eq!(out.len(), 1, "{out:?}");
    let event: Json = serde_json::from_str(&out[0]).expect("JSON");
    assert_eq!(event["kind"], "WRITTEN");
    assert_eq!(event["entry"]["topic"], "watched");

    // The latency of a write through the daemon, and of one that joins itself (before the Java
    // agent below binds: it takes every task) (with a keystore
    // of its own: the daemon's PeerID is the daemon's).
    let other_keys = scratch.path().join("other-keys");
    let through_daemon = time_writes(5, || {
        with(
            of_seed(&scratch, &seed),
            &["write", TASK, "--json", r#"{"topic":"timed","priority":1}"#],
        )
    });
    let joining = time_writes(3, || {
        let mut command = with(
            of_seed(&scratch, &seed),
            &[
                "--no-daemon",
                "write",
                TASK,
                "--json",
                r#"{"topic":"timed-self","priority":1}"#,
            ],
        );
        command.env("ASPACE_KEYSTORE", &other_keys);
        command
    });
    let reads = time_writes(5, || {
        with(of_seed(&scratch, &seed), &["read", TASK, "--limit", "1"])
    });
    println!(
        "latency (ms, whole process): write through the daemon {:?} (median {:.1}); write \
         joining itself {:?} (median {:.1}); read through the daemon {:?} (median {:.1})",
        through_daemon
            .iter()
            .map(|ms| ms.round())
            .collect::<Vec<_>>(),
        median(through_daemon.clone()),
        joining.iter().map(|ms| ms.round()).collect::<Vec<_>>(),
        median(joining.clone()),
        reads.iter().map(|ms| ms.round()).collect::<Vec<_>>(),
        median(reads.clone()),
    );
    assert!(
        median(through_daemon) < median(joining),
        "a write through the daemon is faster than one that joins"
    );

    // cards and call through the daemon: a Java agent bound after the daemon joined.
    let bound = seed.ask("bind-agent java-researcher");
    let agent = format!("{}/java-researcher", seed.peer);
    assert_eq!(bound["bound"], agent.as_str(), "{bound}");
    let deadline = Instant::now() + DEADLINE;
    let offerings = loop {
        let offerings = through(with(of_seed(&scratch, &seed), &["cards", "--json"]));
        if !offerings.is_empty() || Instant::now() >= deadline {
            break offerings;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(offerings.len(), 1, "{offerings:?}");
    assert_eq!(offerings[0]["name"], "research");
    assert_eq!(offerings[0]["agent"], agent.as_str());
    let called = through_one(with(
        of_seed(&scratch, &seed),
        &[
            "call",
            "research",
            "--json",
            r#"{"topic":"called-through-the-daemon","priority":2}"#,
            "--timeout",
            "30s",
        ],
    ));
    assert_eq!(called["offering"], "research", "{called}");
    assert_eq!(called["schema"], RESULT, "{called}");
    assert_eq!(called["entry"]["topic"], "called-through-the-daemon");

    // SIGTERM: exit 0, the socket removed, the lock file left (its lock gone with the process).
    daemon.signal("-TERM");
    let (code, _, err) = daemon.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(err.iter().any(|line| line.contains("stopped")), "{err:?}");
    assert!(!scratch.socket().exists(), "the socket is removed");
    // And visitors join themselves again (the results: the Java agent took every task).
    let output = visit(with(
        of_seed(&scratch, &seed),
        &["read", RESULT, "--limit", "1"],
    ));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(count(&stderr(&output), NO_DAEMON), 1, "{output:?}");
}

#[test]
fn a_second_daemon_is_refused_and_a_stale_socket_is_cleared() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("second");
    let seed = JavaSeed::start(&classpath);
    let (mut first, hello) = Running::daemon(of_seed(&scratch, &seed));
    first.wait_err("serving");
    let pid = hello["pid"].to_string();

    // The lock refuses a second daemon at once, naming the first.
    let started = Instant::now();
    let second = visit(with(of_seed(&scratch, &seed), &["daemon"]));
    assert_eq!(second.status.code(), Some(2), "{second:?}");
    let err = stderr(&second);
    assert!(err.contains("already running"), "{err}");
    assert!(err.contains(&format!("pid {pid}")), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "refused before any join"
    );

    // With the lock file removed under the first, its hello refuses the next one.
    std::fs::remove_file(scratch.run().join("aspace/daemon.sock.lock")).expect("unlock");
    let third = visit(with(of_seed(&scratch, &seed), &["daemon"]));
    assert_eq!(third.status.code(), Some(2), "{third:?}");
    assert!(stderr(&third).contains("already running"), "{third:?}");
    assert!(scratch.socket().exists(), "the first's socket stays");

    // SIGKILL leaves the socket behind; the next daemon finds it answering nothing and removes
    // it.
    first.signal("-KILL");
    let (code, _, _) = first.finish();
    assert_eq!(code, None, "killed by a signal");
    assert!(
        scratch.socket().exists(),
        "a killed daemon leaves its socket"
    );
    let output = visit(with(
        of_seed(&scratch, &seed),
        &["read", TASK, "--join-timeout", "3s"],
    ));
    assert_eq!(
        count(&stderr(&output), NO_DAEMON),
        1,
        "a stale socket is no daemon: {output:?}"
    );
    let (mut next, next_hello) = Running::daemon(of_seed(&scratch, &seed));
    next.wait_err("serving");
    assert!(
        next.seen_err
            .iter()
            .any(|line| line.contains("removed the stale socket")),
        "{:?}",
        next.seen_err
    );
    assert_ne!(next_hello["pid"], hello["pid"]);
    assert_eq!(next_hello["peerId"], hello["peerId"], "the same identity");
    assert_owner_only(&scratch, &next_hello);
    let status = through_one(with(of_seed(&scratch, &seed), &["status", "--json"]));
    assert_eq!(status["daemon"]["pid"], next_hello["pid"]);
    next.signal("-INT");
    let (code, _, err) = next.finish();
    assert_eq!(code, Some(0), "{err:?}");
    assert!(!scratch.socket().exists());
}

#[test]
fn a_watch_through_the_daemon_ends_when_interrupted_or_when_the_daemon_stops() {
    let classpath = classpath_or_skip!();
    let scratch = Scratch::new("watch");
    let seed = JavaSeed::start(&classpath);
    let (mut daemon, _) = Running::daemon(of_seed(&scratch, &seed));
    daemon.wait_err("serving");

    let mut watch = Running::spawn(with(of_seed(&scratch, &seed), &["watch", TASK]));
    watch.wait_err("watching");
    watch.signal("-INT");
    let (code, _, err) = watch.finish();
    assert_eq!(code, Some(0), "an interrupted watch exits 0: {err:?}");

    let mut watch = Running::spawn(with(of_seed(&scratch, &seed), &["watch", TASK]));
    watch.wait_err("watching");
    daemon.signal("-HUP");
    let (code, _, err) = watch.finish();
    assert_eq!(code, Some(1), "{err:?}");
    assert!(
        err.iter().any(|line| line.contains("the daemon stopped")),
        "{err:?}"
    );
    let (code, _, err) = daemon.finish();
    assert_eq!(code, Some(0), "SIGHUP stops the daemon: {err:?}");
    assert!(!scratch.socket().exists());
}
