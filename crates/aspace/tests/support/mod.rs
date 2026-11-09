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

//! What the `aspace` integration tests `mcp.rs`, `mcp_clients.rs`, and `daemon_e2e.rs` share:
//! the scripted Java seed (`interop/java-seed`, gated as `cli_java.rs` and `daemon.rs` gate it: a
//! test passes with a note when `java` or the build is unavailable, unless
//! `ASPACE_INTEROP_REQUIRED=1`), scratch
//! directories under `/tmp` that hold `HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, and `TMPDIR`
//! (so no real fleet file, keystore, daemon, or tool configuration is touched), `aspace` runs
//! killed when dropped, a small HTTP/1.1 client, and the drivers of MCP clients that share no
//! code with rmcp (`interop/mcp-clients`: the TypeScript SDK under Node, the Ruby SDK), found as
//! [`typescript_sdk`] and [`ruby_sdk`] say and gated like the seed.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value as Json;

/// The founding text of the Java seed's group.
pub const FOUNDING: &str = "agentspaces-rust-interop-v1";
/// The seed's main class, class file, source, and classpath list, relative to the project.
const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
const SEED_CLASSPATH: &str = "target/classpath.txt";

/// How long a JVM may take to start and print its first line.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one seed command may take.
const ANSWER: Duration = Duration::from_secs(20);
/// How long one `aspace` run to its end may take.
pub const VISIT: Duration = Duration::from_secs(40);
/// The longest any wait for a line or an exit takes.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// Every variable the configuration (and the daemon's and the gateway's files) reads, removed
/// from each `aspace` run first.
const CLEARED: [&str; 17] = [
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
    "ASPACE_MCP_TOKENS",
    "ASPACE_MCP_POLICY",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "HOME",
    "RUST_LOG",
];

// ------------------------------------------------------------------------------ the Java seed

/// Whether a test that cannot run the Java seed must fail rather than pass with a note.
pub fn required() -> bool {
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
pub fn seed_classpath() -> Result<String, String> {
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

/// The seed's classpath, or a return from the test with a note (a failure under
/// `ASPACE_INTEROP_REQUIRED=1`).
macro_rules! classpath_or_skip {
    () => {
        match support::seed_classpath() {
            Ok(classpath) => classpath,
            Err(why) => {
                assert!(
                    !support::required(),
                    "the Java interop seed cannot run: {why}"
                );
                eprintln!("skipping: the Java interop seed cannot run: {why}");
                return;
            }
        }
    };
}

/// A port nothing listens on now.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// Lines of a pipe, read on a thread of their own.
pub fn lines_of(pipe: impl std::io::Read + Send + 'static) -> Receiver<String> {
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

/// A running Java seed, killed when dropped.
pub struct JavaSeed {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    log: PathBuf,
    port: u16,
    peer: String,
    tls: bool,
}

impl JavaSeed {
    /// Starts a seed on a free port (three tries).
    pub fn start(classpath: &str) -> Self {
        Self::start_with(classpath, &[])
    }

    /// Starts a seed on a free port (three tries) with the seed's arguments after the port
    /// (`--tls`, `--require-attestation`, `--channel-auth ATTESTED`, ...).
    pub fn start_with(classpath: &str, args: &[&str]) -> Self {
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
        let logs = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcp");
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

    /// The seed's PeerID.
    pub fn peer(&self) -> &str {
        &self.peer
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
    pub fn ask(&mut self, command: &str) -> Json {
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

    /// The seed's address (`tls://` when it was started with `--tls`).
    pub fn seed(&self) -> String {
        let scheme = if self.tls { "tls" } else { "tcp" };
        format!("{scheme}://127.0.0.1:{}", self.port)
    }

    /// Polls `check` against the seed until it holds, or panics with `what`.
    pub fn wait_for(&mut self, what: &str, mut check: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            if check(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for {what}\n{}", self.log_tail());
    }

    /// The last lines of the seed's log.
    pub fn log_tail(&self) -> String {
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

// ------------------------------------------------------------------------------ scratch

/// A scratch directory under `/tmp` holding `home`, `xdg`, `run` (0700), `tmp`, and `keys`,
/// removed on drop.
pub struct Scratch(PathBuf);

impl Scratch {
    /// A new, empty scratch directory.
    pub fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new("/tmp").join(format!(
            "asm-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        for dir in ["home", "xdg", "run", "tmp"] {
            std::fs::create_dir_all(path.join(dir)).expect("scratch directory");
        }
        chmod(&path.join("run"), 0o700);
        Self(path)
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The keystore directory.
    pub fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }

    /// Writes `name` with `text` and `mode`.
    pub fn write(&self, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("written");
        chmod(&path, mode);
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sets `path`'s permission bits.
pub fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// ------------------------------------------------------------------------------ aspace

/// An `aspace` command with nothing configured but the scratch `HOME`, `XDG_CONFIG_HOME`,
/// `XDG_RUNTIME_DIR`, and `TMPDIR`.
pub fn bare_aspace(scratch: &Scratch) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aspace"));
    for variable in CLEARED {
        command.env_remove(variable);
    }
    command
        .env("HOME", scratch.path().join("home"))
        .env("XDG_CONFIG_HOME", scratch.path().join("xdg"))
        .env("XDG_RUNTIME_DIR", scratch.path().join("run"))
        .env("TMPDIR", scratch.path().join("tmp"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// An `aspace` command of the group of `founding` at `seeds`, with the scratch keystore and
/// the `tasks` space.
pub fn aspace(scratch: &Scratch, seeds: &str, founding: &str) -> Command {
    let mut command = bare_aspace(scratch);
    command
        .env("ASPACE_SEEDS", seeds)
        .env("ASPACE_GROUP", founding)
        .env("ASPACE_KEYSTORE", scratch.keys())
        .env("ASPACE_SPACES", "tasks");
    command
}

/// `command` with `args` added.
pub fn with(mut command: Command, args: &[&str]) -> Command {
    command.args(args);
    command
}

/// Runs `command` to its end within [`VISIT`], killing it past that.
pub fn visit(mut command: Command) -> Output {
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

/// Standard error of an output.
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A running `aspace`, killed when dropped, its output lines read as they come.
pub struct Running {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
    /// Every line of standard output read so far.
    pub seen_out: Vec<String>,
    /// Every line of standard error read so far.
    pub seen_err: Vec<String>,
}

impl Running {
    /// Starts `command` with a piped standard input.
    pub fn spawn(mut command: Command) -> Self {
        command.stdin(Stdio::piped());
        let mut child = command.spawn().expect("aspace starts");
        let stdin = child.stdin.take();
        let stdout = lines_of(child.stdout.take().expect("stdout"));
        let stderr = lines_of(child.stderr.take().expect("stderr"));
        Running {
            child,
            stdin,
            stdout,
            stderr,
            seen_out: Vec::new(),
            seen_err: Vec::new(),
        }
    }

    /// The process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Writes one line to its standard input.
    pub fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("standard input is open");
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .expect("written to aspace");
    }

    /// Closes its standard input.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The next line of standard output within `wait`, as JSON.
    pub fn next_out(&mut self, wait: Duration) -> Option<Json> {
        let line = self.stdout.recv_timeout(wait).ok()?;
        self.seen_out.push(line.clone());
        Some(serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line}")))
    }

    /// The first line of standard output `wanted` accepts, within [`DEADLINE`]; panics with
    /// what was seen otherwise.
    pub fn out_until(&mut self, what: &str, wanted: impl Fn(&Json) -> bool) -> Json {
        let deadline = Instant::now() + DEADLINE;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.next_out(left) {
                Some(json) if wanted(&json) => return json,
                Some(_) => {}
                None => break,
            }
        }
        self.drain_err();
        panic!(
            "no {what} on standard output: {:?}\nstderr: {:?}",
            self.seen_out, self.seen_err
        );
    }

    /// Reads what standard error holds now.
    pub fn drain_err(&mut self) {
        self.seen_err.extend(self.stderr.try_iter());
    }

    /// Waits for a line of standard error containing `needle`.
    pub fn wait_err(&mut self, needle: &str) {
        let deadline = Instant::now() + DEADLINE;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.stderr.recv_timeout(left) {
                Ok(line) => {
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

    /// Sends `signal` (`-TERM`, `-INT`) to the process.
    pub fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill {signal} failed");
    }

    /// Waits for the exit and answers its code and how long it took, with every remaining line
    /// of both outputs read into [`Running::seen_out`] and [`Running::seen_err`].
    pub fn finish(&mut self) -> (Option<i32>, Duration) {
        let started = Instant::now();
        let deadline = started + DEADLINE;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "aspace did not exit: {:?}",
                self.seen_err
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let took = started.elapsed();
        while let Ok(line) = self.stdout.recv_timeout(Duration::from_secs(2)) {
            self.seen_out.push(line);
        }
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_secs(2)) {
            self.seen_err.push(line);
        }
        (status.code(), took)
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

// ------------------------------------------------------------------------------ HTTP

/// What one HTTP request answered.
#[derive(Debug)]
pub struct HttpAnswer {
    /// The status code.
    pub status: u16,
    /// The headers, names in lower case.
    pub headers: Vec<(String, String)>,
    /// The body, de-chunked.
    pub body: String,
}

impl HttpAnswer {
    /// The value of header `name` (lower case), or empty.
    pub fn header(&self, name: &str) -> String {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    /// The JSON-RPC response the body carries: JSON, or the `data:` lines of an event stream.
    pub fn rpc(&self) -> Json {
        if let Ok(json) = serde_json::from_str::<Json>(&self.body) {
            return json;
        }
        self.body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Json>(data.trim()).ok())
            .find(|message| message.get("result").is_some() || message.get("error").is_some())
            .unwrap_or(Json::Null)
    }
}

/// POSTs `body` to `http://<address><path>` with `headers`, over one connection closed after the
/// answer.
pub fn http_post(
    address: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpAnswer {
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).expect("the gateway accepts");
    stream
        .set_read_timeout(Some(DEADLINE))
        .expect("a read timeout");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .expect("the request is sent");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("the answer is read");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header block");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let rest = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    HttpAnswer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// A chunked body's bytes.
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(end) = rest.windows(2).position(|window| window == b"\r\n") {
        let size_text = String::from_utf8_lossy(&rest[..end]);
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            break;
        };
        rest = &rest[end + 2..];
        if size == 0 || rest.len() < size {
            body.extend_from_slice(&rest[..size.min(rest.len())]);
            break;
        }
        body.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    body
}

// ------------------------------------------------------------------------------ independent clients

/// The scripted MCP clients (`interop/mcp-clients`): drivers over SDKs that share no code with
/// rmcp or `aspace`.
fn clients_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/mcp-clients")
}

/// The directory holding this workspace and its sibling projects.
fn projects_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// An independent MCP client, and how its driver runs.
#[derive(Debug, Clone)]
pub struct ClientKind {
    /// What it is, for messages: the SDK and its version.
    pub name: String,
    program: PathBuf,
    leading: Vec<std::ffi::OsString>,
    env: Vec<(String, String)>,
    ruby: bool,
}

/// `name` on the `PATH` (the first that is a file), else `None`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// Whether a dotted `version` is at least `major.minor`.
fn at_least(version: &str, major: u64, minor: u64) -> bool {
    let mut parts = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    found >= (major, minor)
}

/// The official TypeScript SDK (`@modelcontextprotocol/sdk` 1.20 or later) under Node, read in
/// place from `ASPACE_MCP_NODE_SDK` (the package directory), else from the `node_modules` of a
/// sibling project (`agentspaces-typescript` first, then the others by name), the first that
/// loads at 1.20 or later; `node` from `ASPACE_MCP_NODE`, else the `PATH`. Probed once per
/// test binary.
pub fn typescript_sdk() -> Result<ClientKind, String> {
    static FOUND: OnceLock<Result<ClientKind, String>> = OnceLock::new();
    FOUND.get_or_init(find_typescript_sdk).clone()
}

fn find_typescript_sdk() -> Result<ClientKind, String> {
    let node = std::env::var_os("ASPACE_MCP_NODE")
        .map(PathBuf::from)
        .or_else(|| on_path("node"))
        .ok_or("no `node` on the PATH (or ASPACE_MCP_NODE)")?;
    let package = "node_modules/@modelcontextprotocol/sdk";
    let candidates: Vec<PathBuf> = match std::env::var_os("ASPACE_MCP_NODE_SDK") {
        Some(dir) => vec![PathBuf::from(dir)],
        None => {
            let mut projects: Vec<PathBuf> = std::fs::read_dir(projects_dir())
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|project| !project.ends_with("agentspaces-typescript"))
                .collect();
            projects.sort();
            projects.insert(0, projects_dir().join("agentspaces-typescript"));
            projects
                .iter()
                .map(|project| project.join(package))
                .collect()
        }
    };
    let mut refused = Vec::new();
    for sdk in candidates
        .iter()
        .filter(|dir| dir.join("package.json").is_file())
    {
        match probe_typescript_sdk(&node, sdk) {
            Ok(found) => return Ok(found),
            Err(why) => refused.push(why),
        }
    }
    if refused.is_empty() {
        Err("no @modelcontextprotocol/sdk in a sibling project (set ASPACE_MCP_NODE_SDK)".into())
    } else {
        Err(refused.join("; "))
    }
}

/// The TypeScript SDK at `sdk` under `node`, if it loads and is 1.20 or later.
fn probe_typescript_sdk(node: &Path, sdk: &Path) -> Result<ClientKind, String> {
    let driver = clients_dir().join("node_client.mjs");
    let probe = Command::new(node)
        .arg(&driver)
        .arg(sdk)
        .arg("probe")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("`{}` does not run: {error}", node.display()))?;
    let found: Json = serde_json::from_slice(&probe.stdout).map_err(|_| {
        format!(
            "the TypeScript SDK at {} does not load: {}",
            sdk.display(),
            String::from_utf8_lossy(&probe.stderr)
        )
    })?;
    let version = found["sdk"].as_str().unwrap_or_default().to_owned();
    if !at_least(&version, 1, 20) {
        return Err(format!(
            "the TypeScript SDK at {} is {version}; 1.20 or later is needed",
            sdk.display()
        ));
    }
    Ok(ClientKind {
        name: format!(
            "TypeScript SDK {version} (Node {})",
            found["node"].as_str().unwrap_or("?")
        ),
        program: node.to_path_buf(),
        leading: vec![driver.into_os_string(), sdk.as_os_str().to_owned()],
        env: Vec::new(),
        ruby: false,
    })
}

/// The Ruby SDK (the `mcp` gem 1.8 or later): the first `ruby` that loads it, of
/// `ASPACE_MCP_RUBY`, the `PATH`, `/opt/homebrew/bin`, and `/usr/local/bin`, run with the gem
/// path it has here (the tests move `HOME`). Probed once per test binary.
pub fn ruby_sdk() -> Result<ClientKind, String> {
    static FOUND: OnceLock<Result<ClientKind, String>> = OnceLock::new();
    FOUND.get_or_init(find_ruby_sdk).clone()
}

fn find_ruby_sdk() -> Result<ClientKind, String> {
    let mut candidates: Vec<PathBuf> = std::env::var_os("ASPACE_MCP_RUBY")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    candidates.extend(on_path("ruby"));
    candidates.push(PathBuf::from("/opt/homebrew/bin/ruby"));
    candidates.push(PathBuf::from("/usr/local/bin/ruby"));
    let mut tried = Vec::new();
    for ruby in candidates.iter().filter(|ruby| ruby.is_file()) {
        let probe = Command::new(ruby)
            .args([
                "-e",
                "require 'json'; require 'mcp'; \
                 print JSON.generate({mcp: MCP::VERSION, ruby: RUBY_VERSION, path: Gem.path.join(':')})",
            ])
            .stdin(Stdio::null())
            .output();
        let found = probe
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<Json>(&output.stdout).ok());
        let Some(found) = found else {
            tried.push(format!("{} (no mcp gem)", ruby.display()));
            continue;
        };
        let version = found["mcp"].as_str().unwrap_or_default();
        if !at_least(version, 1, 8) {
            tried.push(format!("{} (mcp {version})", ruby.display()));
            continue;
        }
        return Ok(ClientKind {
            name: format!(
                "Ruby SDK mcp {version} (Ruby {})",
                found["ruby"].as_str().unwrap_or("?")
            ),
            program: ruby.clone(),
            leading: vec![clients_dir().join("ruby_client.rb").into_os_string()],
            env: vec![(
                "GEM_PATH".to_owned(),
                found["path"].as_str().unwrap_or_default().to_owned(),
            )],
            ruby: true,
        });
    }
    Err(format!(
        "no ruby with the mcp gem 1.8 or later: tried {tried:?} (set ASPACE_MCP_RUBY)"
    ))
}

/// An independent client, or a return from the test with a note (a failure under
/// `ASPACE_INTEROP_REQUIRED=1`).
#[allow(unused_macros)]
macro_rules! client_or_skip {
    ($found:expr) => {
        match $found {
            Ok(client) => client,
            Err(why) => {
                assert!(
                    !support::required(),
                    "an independent MCP client cannot run: {why}"
                );
                eprintln!("skipping: an independent MCP client cannot run: {why}");
                return;
            }
        }
    };
}

/// A running client driver, killed when dropped with the server it spawned.
pub struct Driver {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    errors: Receiver<String>,
    /// The client, for messages.
    pub name: String,
    server: Option<u32>,
    server_err: Option<PathBuf>,
    ruby: bool,
}

impl Driver {
    /// A driver that spawns `server` (an `aspace` command: its program, arguments, and
    /// environment) over standard input and output; the driver runs in `server`'s environment.
    pub fn stdio(kind: &ClientKind, server: &Command, scratch: &Scratch) -> Driver {
        let mut command = Command::new(&kind.program);
        command.args(&kind.leading);
        let server_err = scratch.path().join(format!(
            "server-{}.err",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        if kind.ruby {
            command.arg(&server_err);
        } else {
            command.arg("stdio");
        }
        command.arg(server.get_program()).args(server.get_args());
        for (name, value) in server.get_envs() {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        Driver::spawn(kind, command, kind.ruby.then_some(server_err))
    }

    /// A driver of the Streamable HTTP endpoint `url`, run in `scratch`'s environment.
    pub fn http(kind: &ClientKind, url: &str, scratch: &Scratch) -> Driver {
        assert!(!kind.ruby, "the Ruby driver speaks stdio only");
        let environment = bare_aspace(scratch);
        let mut driver = Command::new(&kind.program);
        driver.args(&kind.leading).args(["http", url]);
        for (name, value) in environment.get_envs() {
            match value {
                Some(value) => driver.env(name, value),
                None => driver.env_remove(name),
            };
        }
        Driver::spawn(kind, driver, None)
    }

    fn spawn(kind: &ClientKind, mut command: Command, server_err: Option<PathBuf>) -> Driver {
        for (name, value) in &kind.env {
            command.env(name, value);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("the {} driver does not start: {error}", kind.name));
        let stdin = child.stdin.take();
        let lines = lines_of(child.stdout.take().expect("stdout"));
        let errors = lines_of(child.stderr.take().expect("stderr"));
        Driver {
            child,
            stdin,
            lines,
            errors,
            name: kind.name.clone(),
            server: None,
            server_err,
            ruby: kind.ruby,
        }
    }

    /// Sends one operation and answers the driver's answer, within [`DEADLINE`] plus the
    /// operation's own `timeoutMs`.
    pub fn op(&mut self, op: Json) -> Json {
        let line = format!("{op}\n");
        let sent = match self.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush()),
            None => Err(std::io::Error::other("the driver's stdin is closed")),
        };
        if let Err(error) = sent {
            panic!(
                "{}: cannot send {op}: {error}\n{}",
                self.name,
                self.driver_err()
            );
        }
        let wait = DEADLINE + Duration::from_millis(op["timeoutMs"].as_u64().unwrap_or(0));
        let Ok(answer) = self.lines.recv_timeout(wait) else {
            panic!("{}: no answer to {op}\n{}", self.name, self.driver_err());
        };
        let answer: Json = serde_json::from_str(&answer)
            .unwrap_or_else(|_| panic!("{}: not JSON: {answer}", self.name));
        if op["op"] == "connect"
            && let Some(pid) = answer["pid"].as_u64()
        {
            self.server = u32::try_from(pid).ok();
        }
        answer
    }

    /// [`Driver::op`], which must succeed.
    pub fn ok(&mut self, op: Json) -> Json {
        let answer = self.op(op.clone());
        if answer["ok"] != true {
            let err = self.server_stderr();
            panic!(
                "{}: {op} failed: {answer}\nserver stderr: {err:?}",
                self.name
            );
        }
        answer
    }

    /// The tool names the client lists now.
    pub fn tool_names(&mut self) -> Vec<String> {
        let listed = self.ok(serde_json::json!({"op": "tools"}));
        listed["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Lists until the names are `expected`, within [`DEADLINE`].
    pub fn wait_for_tools(&mut self, expected: &[&str]) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let names = self.tool_names();
            if names == expected {
                return;
            }
            if Instant::now() >= deadline {
                let err = self.server_stderr();
                panic!(
                    "{}: the tools are {names:?}, not {expected:?}\nserver stderr: {err:?}",
                    self.name
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Calls `name` with `input` (the default `input` argument) and a 20 s timeout; answers the
    /// call's `result`, which must not be a tool error.
    pub fn call(&mut self, name: &str, input: Json) -> Json {
        let answer = self.ok(serde_json::json!({
            "op": "call", "name": name,
            "arguments": {"input": input, "timeout": "20s"},
        }));
        let result = answer["result"].clone();
        assert_eq!(
            result["isError"], false,
            "{}: calling {name} failed: {answer}",
            self.name
        );
        result
    }

    /// The server's standard error lines so far (the stdio server this driver spawned).
    pub fn server_stderr(&mut self) -> Vec<String> {
        if let Some(path) = &self.server_err {
            return std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
        }
        if self.ruby || self.stdin.is_none() {
            return Vec::new();
        }
        let line = "{\"op\":\"stderr\"}\n";
        let sent = self.stdin.as_mut().map(|stdin| {
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush())
        });
        if !matches!(sent, Some(Ok(()))) {
            return Vec::new();
        }
        self.lines
            .recv_timeout(DEADLINE)
            .ok()
            .and_then(|answer| serde_json::from_str::<Json>(&answer).ok())
            .and_then(|answer| answer["lines"].as_array().cloned())
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|line| line.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What the driver itself wrote on standard error so far.
    pub fn driver_err(&self) -> String {
        self.errors.try_iter().collect::<Vec<_>>().join("\n")
    }

    /// Ends the driver: closes its standard input and waits for its exit.
    pub fn finish(&mut self) -> Option<i32> {
        self.stdin = None;
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status.code();
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl ClientKind {
    /// The interpreter the driver runs on (`node`, `ruby`).
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Runs `code` with the interpreter (`-e`), answering its standard output.
    pub fn eval(&self, code: &str) -> String {
        let mut command = Command::new(&self.program);
        command.args(["-e", code]).stdin(Stdio::null());
        for (name, value) in &self.env {
            command.env(name, value);
        }
        let output = command.output().expect("the interpreter runs");
        assert!(output.status.success(), "{code}: {output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }
}

/// Whether process `pid` is alive.
pub fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(pid) = self.server.filter(|pid| alive(*pid)) {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
    }
}
