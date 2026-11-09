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

//! `aspace daemon` end to end against the Java reference (a visitor uses the daemon when
//! present), and what it buys a hook.
//!
//! 1. A daemon on a scratch `XDG_RUNTIME_DIR` serves `status`, `write`, `read`, `take`,
//!    `complete`, `watch`, `cards`, and `call` to visitors, each saying nothing on standard error
//!    (Java reading, completing, and answering what they do); killed with SIGKILL, it leaves its
//!    socket, and the next visitor (a write Java reads, then a call Java answers) joins itself
//!    with the one-line note `no daemon answered at <socket>; joining the group itself`; a
//!    restarted daemon removes the stale socket, keeps its directory 0700 and its socket 0600,
//!    and serves visitors again (a call through it answered by Java); SIGTERM removes its socket.
//! 2. Hook latency: 20 sequential `aspace write` invocations joining the group themselves (no
//!    daemon: what a hook costs without one), then 20 through the daemon; the median and p95 of
//!    each are printed, and the daemon's median is the lower.
//!
//! 3. Ending waits and never joining around a daemon: a visitor killed
//!    while its take waits through the daemon leaves nothing taking, so the next matching entry
//!    stays available; a visitor of the daemon's group and keystore that cannot use it (a weaker
//!    profile: exit 2; a daemon stopped with SIGSTOP: exit 1) refuses to join with the daemon's
//!    PeerID instead of answering "nothing matched"; SIGTERM ends a take waiting through the
//!    daemon at once (exit 3, "nothing was taken"), and a write still waiting for its
//!    confirmation at the end of the grace is told it may have taken effect (exit 3).
//! 4. Room for new spaces: past the daemon's bound of open spaces (requests on 1030
//!    distinct spaces, sent on the daemon's protocol), a brand-new space is still read and
//!    written through it.
//!
//! Each test passes with a note when `java` or the seed's build is unavailable, unless
//! `ASPACE_INTEROP_REQUIRED=1`. Every process a test starts is killed when the test ends, also
//! when it fails; every `aspace` runs with `HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, and
//! `TMPDIR` in a scratch directory.

#[macro_use]
mod support;

use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value as Json, json};
use support::*;

/// The seed's schemas.
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";

/// A visitor of the seed's group under `dev-local`, with `args`.
fn visitor(scratch: &Scratch, seed: &JavaSeed, args: &[&str]) -> Command {
    let mut command = with(
        aspace(scratch, &seed.seed(), FOUNDING),
        &["--profile", "dev-local"],
    );
    command.args(args);
    command
}

/// The daemon's socket in the scratch runtime directory.
fn socket(scratch: &Scratch) -> PathBuf {
    scratch.path().join("run/aspace/daemon.sock")
}

/// The permission bits of `path`.
fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// Starts a daemon: its hello, once it serves.
fn daemon(scratch: &Scratch, seed: &JavaSeed) -> (Running, Json) {
    let mut daemon = Running::spawn(visitor(scratch, seed, &["daemon"]));
    let hello = daemon
        .next_out(DEADLINE)
        .unwrap_or_else(|| panic!("no daemon hello: {:?}", daemon.seen_err));
    daemon.wait_err("serving");
    assert_eq!(
        hello["socket"],
        socket(scratch).display().to_string(),
        "{hello}"
    );
    (daemon, hello)
}

/// Runs a visitor through the daemon: exit 0 and not a word on standard error. Answers the JSON
/// lines of its standard output.
fn through(command: Command) -> Vec<Json> {
    let output = visit(command);
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stderr.is_empty(),
        "a visitor through the daemon said something: {}",
        stderr(&output)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect()
}

/// [`through`], one line.
fn through_one(command: Command) -> Json {
    let lines = through(command);
    assert_eq!(lines.len(), 1, "{lines:?}");
    lines.into_iter().next().unwrap_or(Json::Null)
}

/// Runs a visitor with no daemon answering: exit 0, and standard error exactly the one note.
fn joining_itself(command: Command, socket: &Path) -> Vec<Json> {
    let output = visit(command);
    assert!(output.status.success(), "{output:?}");
    let err = stderr(&output);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(
        lines,
        [format!(
            "aspace: no daemon answered at {}; joining the group itself",
            socket.display()
        )],
        "{err}"
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect()
}

/// The topics of the seed's available tasks.
fn task_topics(seed: &mut JavaSeed) -> Vec<String> {
    seed.ask("tasks")["tasks"]
        .as_array()
        .map(|tasks| {
            tasks
                .iter()
                .filter_map(|task| task["topic"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The `(topic, summary, worker)` of the seed's results.
fn results(seed: &mut JavaSeed) -> Vec<(String, String, String)> {
    seed.ask("results")["results"]
        .as_array()
        .map(|all| {
            all.iter()
                .map(|r| {
                    let text = |key: &str| r[key].as_str().unwrap_or_default().to_owned();
                    (text("topic"), text("summary"), text("worker"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A `call` of the research action with `topic`, within 30 s.
fn call_research(scratch: &Scratch, seed: &JavaSeed, topic: &str) -> Command {
    let input = json!({"topic": topic, "priority": 2}).to_string();
    visitor(
        scratch,
        seed,
        &["call", "research", "--json", &input, "--timeout", "30s"],
    )
}

/// Checks a call's answer: Java's research agent answered `topic`.
fn assert_java_answered(called: &Json, seed: &JavaSeed, topic: &str) {
    assert_eq!(called["offering"], "research", "{called}");
    assert_eq!(called["schema"], RESULT, "{called}");
    assert_eq!(called["entry"]["topic"], topic, "{called}");
    assert_eq!(
        called["entry"]["summary"],
        format!("researched in java: {topic}"),
        "{called}"
    );
    assert_eq!(
        called["issuer"],
        format!("{}/researcher", seed.peer()),
        "{called}"
    );
}

#[test]
fn the_daemon_serves_dies_by_sigkill_and_restarts_clean() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("e2e");
    let socket = socket(&scratch);
    let (mut first, hello) = daemon(&scratch, &seed);
    let me = format!("{}/rust", hello["peerId"].as_str().expect("a PeerID"));

    // status: the daemon used, the seed a member.
    let status = through_one(visitor(&scratch, &seed, &["status", "--json"]));
    assert_eq!(status["daemon"]["pid"], hello["pid"], "{status}");
    assert_eq!(status["daemon"]["used"], true, "{status}");
    assert!(
        status["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m == seed.peer())),
        "{status}"
    );

    // write: Java reads it.
    let written = through_one(visitor(
        &scratch,
        &seed,
        &[
            "write",
            TASK,
            "--json",
            r#"{"topic":"e2e-write","priority":5}"#,
        ],
    ));
    assert!(written["id"].as_str().is_some(), "{written}");
    assert!(task_topics(&mut seed).contains(&"e2e-write".to_owned()));

    // read: a task Java writes.
    seed.ask("write-task e2e-from-java 7");
    let deadline = Instant::now() + DEADLINE;
    loop {
        let lines = through(visitor(
            &scratch,
            &seed,
            &["read", TASK, "--where", "topic=e2e-from-java"],
        ));
        if lines.len() == 1 {
            assert_eq!(lines[0]["entry"]["priority"], 7, "{lines:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never read Java's task"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // take and complete: held by the daemon's identity, the result read by Java.
    let taken = through_one(visitor(
        &scratch,
        &seed,
        &[
            "take",
            TASK,
            "--where",
            "topic=e2e-from-java",
            "--lease",
            "2m",
        ],
    ));
    assert_eq!(taken["holder"], me.as_str(), "{taken}");
    let id = taken["id"].as_str().expect("an id").to_owned();
    let completed = through_one(visitor(
        &scratch,
        &seed,
        &[
            "complete",
            &id,
            "--json",
            r#"{"topic":"e2e-from-java","summary":"completed through the daemon","worker":"e2e"}"#,
            "--produces",
            RESULT,
        ],
    ));
    assert_eq!(completed["completed"], true, "{completed}");
    seed.wait_for("Java folds the completion", |seed| {
        seed.ask("task-state e2e-from-java")["state"] == "completed"
    });
    assert!(results(&mut seed).contains(&(
        "e2e-from-java".to_owned(),
        "completed through the daemon".to_owned(),
        "e2e".to_owned()
    )));

    // watch: a task Java writes.
    let mut watch = Running::spawn(visitor(
        &scratch,
        &seed,
        &["watch", TASK, "--kinds", "written", "--count", "1"],
    ));
    watch.wait_err("watching");
    seed.ask("write-task e2e-watched 2");
    let (code, _) = watch.finish();
    assert_eq!(code, Some(0), "{:?}", watch.seen_err);
    assert_eq!(watch.seen_out.len(), 1, "{:?}", watch.seen_out);
    let event: Json = serde_json::from_str(&watch.seen_out[0]).expect("JSON");
    assert_eq!(event["kind"], "WRITTEN", "{event}");
    assert_eq!(event["entry"]["topic"], "e2e-watched", "{event}");

    // cards and call: a Java agent bound now (it takes every task from here on).
    seed.ask("bind-agent researcher");
    let deadline = Instant::now() + DEADLINE;
    let offerings = loop {
        let offerings = through(visitor(&scratch, &seed, &["cards", "--json"]));
        if !offerings.is_empty() || Instant::now() >= deadline {
            break offerings;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(offerings.len(), 1, "{offerings:?}");
    assert_eq!(offerings[0]["name"], "research", "{offerings:?}");
    let called = through_one(call_research(&scratch, &seed, "e2e-call"));
    assert_java_answered(&called, &seed, "e2e-call");

    // SIGKILL: no cleanup, the socket stays behind.
    first.signal("-KILL");
    let (code, _) = first.finish();
    assert_eq!(code, None, "killed by a signal");
    assert!(
        std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()),
        "a killed daemon leaves its socket"
    );

    // The next visitor joins itself, saying so in one line, and works: a write Java reads, a call
    // Java answers.
    let started = Instant::now();
    let written = joining_itself(
        visitor(
            &scratch,
            &seed,
            &[
                "write",
                TASK,
                "--json",
                r#"{"topic":"e2e-fallback","priority":3}"#,
            ],
        ),
        &socket,
    );
    let fallback = started.elapsed();
    assert_eq!(written.len(), 1, "{written:?}");
    seed.wait_for("Java folds the fallback write", |seed| {
        seed.ask("task-state e2e-fallback")["state"] != "unknown"
    });
    let called = joining_itself(call_research(&scratch, &seed, "e2e-fallback-call"), &socket);
    assert_eq!(called.len(), 1, "{called:?}");
    assert_java_answered(&called[0], &seed, "e2e-fallback-call");
    println!("a write that fell back to joining itself took {fallback:?}");

    // A restarted daemon removes the stale socket and serves again.
    let (mut second, next) = daemon(&scratch, &seed);
    assert!(
        second
            .seen_err
            .iter()
            .any(|line| line.contains("removed the stale socket")),
        "{:?}",
        second.seen_err
    );
    assert_ne!(next["pid"], hello["pid"]);
    assert_eq!(next["peerId"], hello["peerId"], "the keystore's identity");
    assert_eq!(mode(&socket), 0o600, "the socket is owner-only");
    assert_eq!(
        mode(socket.parent().expect("a directory")),
        0o700,
        "its directory is owner-only"
    );
    let status = through_one(visitor(&scratch, &seed, &["status", "--json"]));
    assert_eq!(status["daemon"]["pid"], next["pid"], "{status}");
    let called = through_one(call_research(&scratch, &seed, "e2e-restarted"));
    assert_java_answered(&called, &seed, "e2e-restarted");

    second.signal("-TERM");
    let (code, _) = second.finish();
    assert_eq!(code, Some(0), "{:?}", second.seen_err);
    assert!(!socket.exists(), "SIGTERM removes the socket");
}

/// The `q` quantile (nearest rank) of `samples`, in milliseconds.
fn quantile(samples: &[f64], q: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (q * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// Times `runs` sequential runs of `run` (each answering its milliseconds).
fn time_writes(runs: usize, mut run: impl FnMut(usize) -> f64) -> Vec<f64> {
    (0..runs).map(&mut run).collect()
}

#[test]
fn hook_latency_through_the_daemon_and_joining_itself() {
    const RUNS: usize = 20;
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("latency");
    let socket = socket(&scratch);
    let write = |topic: String| {
        let input = json!({"topic": topic, "priority": 1}).to_string();
        visitor(&scratch, &seed, &["write", TASK, "--json", &input])
    };

    // No daemon: each write joins the group itself (and says so).
    let joining = time_writes(RUNS, |i| {
        let started = Instant::now();
        joining_itself(write(format!("hook-self-{i}")), &socket);
        started.elapsed().as_secs_f64() * 1000.0
    });

    // A daemon of the same keystore: each write goes through it.
    let (mut daemon, _) = daemon(&scratch, &seed);
    let through_daemon = time_writes(RUNS, |i| {
        let started = Instant::now();
        through(write(format!("hook-daemon-{i}")));
        started.elapsed().as_secs_f64() * 1000.0
    });
    let topics = task_topics(&mut seed);
    for i in 0..RUNS {
        for kind in ["self", "daemon"] {
            let topic = format!("hook-{kind}-{i}");
            assert!(topics.contains(&topic), "Java misses {topic}");
        }
    }
    daemon.signal("-TERM");
    let (code, _) = daemon.finish();
    assert_eq!(code, Some(0), "{:?}", daemon.seen_err);

    let summary = |samples: &[f64]| {
        format!(
            "median {:.1} ms, p95 {:.1} ms, min {:.1} ms, max {:.1} ms",
            quantile(samples, 0.5),
            quantile(samples, 0.95),
            quantile(samples, 0.0),
            quantile(samples, 1.0)
        )
    };
    println!(
        "hook latency, {RUNS} sequential `aspace write` processes each (whole process, {} build): \
         joining itself: {}; through the daemon: {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        summary(&joining),
        summary(&through_daemon)
    );
    assert!(
        quantile(&through_daemon, 0.5) < quantile(&joining, 0.5),
        "a write through the daemon is faster than one that joins"
    );
}

/// Ending waits, and never joining around a daemon; see the [module docs](self).
#[test]
fn the_daemon_ends_waits_cleanly_and_is_never_joined_around() {
    let classpath = classpath_or_skip!();
    let seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("e2e-waits");
    let (mut daemon, _hello) = daemon(&scratch, &seed);
    const GHOST: &str = "ghost.Task#v1";

    // A take waiting through the daemon, its visitor killed. The entry written next is not
    // taken by the request nobody waits for: reads through the daemon still find it.
    let mut waiting = Running::spawn(visitor(
        &scratch,
        &seed,
        &["take", GHOST, "--timeout", "60s", "--lease", "5m"],
    ));
    std::thread::sleep(Duration::from_millis(1500));
    waiting.signal("-TERM");
    let _ = waiting.finish();
    std::thread::sleep(Duration::from_millis(500));
    through_one(visitor(
        &scratch,
        &seed,
        &["write", GHOST, "--json", r#"{"k":"ghost"}"#],
    ));
    // Longer than a take's settle window: a ghost take would have claimed it by now.
    std::thread::sleep(Duration::from_secs(2));
    let found = through(visitor(&scratch, &seed, &["read", GHOST]));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["entry"]["k"], "ghost", "{found:?}");

    // The daemon serves this group with this keystore under dev-local; a visitor wanting
    // mtls neither uses it nor joins with its PeerID (exit 2, the remedies named).
    let stricter = visit(with(
        aspace(&scratch, &seed.seed(), FOUNDING),
        &["read", GHOST],
    ));
    let err = stderr(&stricter);
    assert_eq!(stricter.status.code(), Some(2), "{err}");
    assert!(
        err.contains("weaker than this configuration's mtls"),
        "{err}"
    );
    assert!(err.contains("share the daemon's PeerID"), "{err}");
    assert!(!err.contains("joining the group itself"), "{err}");

    // A visitor looking at another socket (cron, without the runtime directory) does not
    // join with the daemon's PeerID either: exit 2, naming the socket the daemon listens on.
    let mut elsewhere = visitor(&scratch, &seed, &["read", GHOST]);
    elsewhere.env("XDG_RUNTIME_DIR", scratch.path().join("elsewhere"));
    let missed = visit(elsewhere);
    let err = stderr(&missed);
    assert_eq!(missed.status.code(), Some(2), "{err}");
    assert!(
        err.contains(&format!("--socket {}", socket(&scratch).display())),
        "{err}"
    );
    assert!(!err.contains("joining the group itself"), "{err}");

    // A daemon that does not answer (stopped): exit 1, retry advised, no join of its own.
    daemon.signal("-STOP");
    let stopped = visit(visitor(&scratch, &seed, &["read", GHOST]));
    daemon.signal("-CONT");
    let err = stderr(&stopped);
    assert_eq!(stopped.status.code(), Some(1), "{err}");
    assert!(err.contains("did not answer"), "{err}");
    assert!(
        err.contains("share the PeerID of the running aspace daemon"),
        "{err}"
    );
    assert!(!err.contains("joining the group itself"), "{err}");
    let found = through(visitor(&scratch, &seed, &["read", GHOST]));
    assert_eq!(found.len(), 1, "served again once continued: {found:?}");

    // SIGTERM with a take waiting through the daemon and a write waiting for the seed's
    // confirmation (a space the Java seed does not hold, so it never confirms): the take ends
    // at once, having taken nothing (exit 3); the write has the grace, then is told it may have
    // taken effect (exit 3), never to run it again blindly.
    let mut waiting = Running::spawn(visitor(
        &scratch,
        &seed,
        &["take", "stop.Task#v1", "--timeout", "30s"],
    ));
    let mut confirming = Running::spawn(visitor(
        &scratch,
        &seed,
        &[
            "write",
            "stop.Task#v1",
            "--json",
            r#"{"k":"unconfirmed"}"#,
            "--space",
            "no-host-opened-this",
        ],
    ));
    // The write waits up to 10 s for the seed's confirmation, longer than the stop's grace.
    std::thread::sleep(Duration::from_millis(1500));
    daemon.signal("-TERM");
    let (code, took) = waiting.finish();
    assert_eq!(code, Some(3), "{:?}", waiting.seen_err);
    assert!(
        took < Duration::from_secs(3),
        "the take waited {took:?} after the stop"
    );
    assert!(
        waiting
            .seen_err
            .iter()
            .any(|line| line.contains("the daemon stopped; nothing was taken")),
        "{:?}",
        waiting.seen_err
    );
    let (code, _) = confirming.finish();
    assert_eq!(code, Some(3), "{:?}", confirming.seen_err);
    let said = confirming.seen_err.join("\n");
    assert!(said.contains("may have taken effect"), "{said}");
    assert!(!said.contains("run the command again"), "{said}");
    let (code, took) = daemon.finish();
    assert_eq!(code, Some(0), "{:?}", daemon.seen_err);
    assert!(
        took < Duration::from_secs(8),
        "the daemon took {took:?} to stop"
    );
}

/// One request on the daemon's protocol: connects to `socket`, reads the hello, sends `verb`
/// with `args`, and answers the exit frame's code.
fn raw_request(socket: &Path, verb: &str, args: Json) -> Option<i64> {
    use std::io::{BufRead as _, BufReader, Write as _};
    let stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(DEADLINE)).ok()?;
    let mut writer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let request = json!({"protocol": 1, "verb": verb, "args": args});
    writeln!(writer, "{request}").ok()?;
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let frame: Json = serde_json::from_str(&line).ok()?;
        if let Some(code) = frame.get("exit").and_then(Json::as_i64) {
            return Some(code);
        }
    }
}

/// Room for new spaces; see the [module docs](self).
#[test]
fn the_daemon_makes_room_for_new_spaces() {
    let classpath = classpath_or_skip!();
    let seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("e2e-spaces");
    let socket = socket(&scratch);
    let (mut daemon, _hello) = daemon(&scratch, &seed);
    // 1030 distinct spaces, 128 requests at a time (each an empty space: a miss, exit 2).
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let workers: Vec<_> = (0..128)
        .map(|_| {
            let (next, failures, socket) = (
                std::sync::Arc::clone(&next),
                std::sync::Arc::clone(&failures),
                socket.clone(),
            );
            std::thread::spawn(move || {
                loop {
                    let n = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n >= 1030 {
                        return;
                    }
                    let args = json!({"schema": "x.T#v1", "limit": 1, "space": format!("job-{n}")});
                    let code = raw_request(&socket, "read", args);
                    if code != Some(2) {
                        failures.lock().expect("failures").push((n, code));
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join();
    }
    let failures = failures.lock().expect("failures").clone();
    assert!(
        failures.is_empty(),
        "requests that were not a miss: {failures:?}"
    );

    // A brand-new space still works through the daemon: a miss is a miss, a write lands.
    let output = visit(visitor(
        &scratch,
        &seed,
        &["read", "x.T#v1", "--space", "brand-new-space"],
    ));
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("no x.T#v1 entry matches"), "{err}");
    // The write is made in the new space (the Java seed holds only the spaces its hosts open,
    // so it may not confirm it: exit 3, "did not confirm"), never refused as a space that
    // cannot be opened.
    let output = visit(visitor(
        &scratch,
        &seed,
        &[
            "write",
            "x.T#v1",
            "--json",
            r#"{"k":"room"}"#,
            "--space",
            "brand-new-space2",
        ],
    ));
    let err = stderr(&output);
    assert!(!err.contains("cannot open space"), "{err}");
    assert!(
        output.status.code() == Some(0)
            || (output.status.code() == Some(3) && err.contains("did not confirm")),
        "{output:?}"
    );
    let written: Json = serde_json::from_slice(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default(),
    )
    .unwrap_or(Json::Null);
    assert_eq!(written["space"], "brand-new-space2", "{output:?}");
    daemon.signal("-TERM");
    let (code, _) = daemon.finish();
    assert_eq!(code, Some(0), "{:?}", daemon.seen_err);
}
