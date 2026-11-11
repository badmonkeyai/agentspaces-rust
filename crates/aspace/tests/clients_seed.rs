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

//! Python, TypeScript, Ruby, and Rust around a Rust seed (SPEC §5.1 to §5.4, §7). `aspace seed`
//! listens; the Python, TypeScript, and Ruby clients, each a dial-only peer through its public
//! API (the drivers in `interop/clients`), and a Rust peer of this build join it. Then layer 3
//! together:
//!
//! - each writes three tasks, and every peer reads all twelve;
//! - all four race to take them: each task is taken and completed exactly once, and its result
//!   is read by the peers of the other languages;
//! - a watch in each language hears the other languages' writes and completions.
//!
//! Twice: over `tcp` under dev-local, the group founded with `--found` and joined by id (the
//! founding fetched from the seed and verified), and over `tls` with required attestation, the
//! group founded from a text. The TypeScript driver waits out the settle window its client's
//! take cuts short, keeping a take only while its claim still wins (`interop/clients/README.md`),
//! and the test prints how often that guard gave a take up. The clients run read-only from their
//! checkouts beside this one
//! (`AGENTSPACES_PYTHON`, `AGENTSPACES_TS`, `AGENTSPACES_RB` name others). Gated as the other
//! interop tests: a client that cannot run makes the test pass with a note, unless
//! `ASPACE_INTEROP_REQUIRED=1`.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentspaces::Entry;
use agentspaces::group::GroupSpec;
use agentspaces::peer::{PeerConfig, default_dialers};
use agentspaces::space::{EventKind, Fleet, Lease, Template};
use agentspaces::wire::cbor::Map;
use agentspaces::wire::identity::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use support::*;

const SPACE: &str = "tasks";
const TASK: &str = "interop.Task#v1";
const RESULT: &str = "interop.Result#v1";
/// Tasks each peer writes.
const EACH: usize = 3;
/// The languages around the seed.
const LANGUAGES: [&str; 4] = ["python", "typescript", "ruby", "rust"];
/// How long a client may take to start and join.
const STARTUP: Duration = Duration::from_secs(60);
/// How long one answer of a client may take (a race takes a few seconds).
const ANSWER: Duration = Duration::from_secs(90);
/// How long replication may take to converge.
const CONVERGE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Entry)]
#[entry(schema = "interop.Task#v1")]
struct Task {
    task: String,
    from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Entry)]
#[entry(schema = "interop.Result#v1")]
#[serde(rename_all = "camelCase")]
struct Outcome {
    task: String,
    task_id: String,
    by: String,
}

// ------------------------------------------------------------------------------ the clients

/// How one client's driver runs.
#[derive(Debug, Clone)]
struct Runtime {
    lang: &'static str,
    program: PathBuf,
    leading: Vec<OsString>,
    env: Vec<(String, String)>,
}

/// The directory holding this workspace and its sibling projects.
fn projects() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn drivers() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/clients")
}

/// `name` on the `PATH`, else `None`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn dir_from(variable: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(variable).map_or(default, PathBuf::from)
}

/// Runs `command` (in a scratch directory, nothing on standard input) and answers its standard
/// output, or why it failed.
fn probe(mut command: Command, what: &str) -> Result<String, String> {
    let output = command
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{what} does not run: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "{what} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// The Python client: a Python with its dependency (`/tmp/aspace-venv4`, else the checkout's
/// `.venv`, or `AGENTSPACES_PYTHON_BIN`), run isolated (`-I`) over the checkout.
fn python() -> Result<Runtime, String> {
    let checkout = dir_from("AGENTSPACES_PYTHON", projects().join("agentspaces-python"));
    let candidates: Vec<PathBuf> = std::env::var_os("AGENTSPACES_PYTHON_BIN")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/tmp/aspace-venv4/bin/python"),
            checkout.join(".venv/bin/python"),
        ])
        .filter(|path| path.is_file())
        .collect();
    let mut failures = Vec::new();
    for program in candidates {
        let mut command = Command::new(&program);
        command
            .args([
                "-I",
                "-c",
                "import os, sys; sys.path.insert(0, os.environ['AGENTSPACES_PYTHON']); \
                 import agentspaces.peer, agentspaces.space",
            ])
            .env("AGENTSPACES_PYTHON", &checkout);
        match probe(command, &format!("{} with the client", program.display())) {
            Ok(_) => {
                return Ok(Runtime {
                    lang: "python",
                    program,
                    leading: vec!["-I".into(), drivers().join("python/peer.py").into()],
                    env: vec![(
                        "AGENTSPACES_PYTHON".to_owned(),
                        checkout.display().to_string(),
                    )],
                });
            }
            Err(why) => failures.push(why),
        }
    }
    Err(format!(
        "no Python runs the client in {}: {}",
        checkout.display(),
        if failures.is_empty() {
            "neither /tmp/aspace-venv4 nor the checkout's .venv exists".to_owned()
        } else {
            failures.join("; ")
        }
    ))
}

/// The TypeScript client's built output under Node 22 or later.
fn typescript() -> Result<Runtime, String> {
    let built = dir_from(
        "AGENTSPACES_TS",
        projects().join("agentspaces-typescript/build/src"),
    );
    for file in ["index.js", "node/index.js"] {
        if !built.join(file).is_file() {
            return Err(format!("{} is not built", built.join(file).display()));
        }
    }
    let node = on_path("node").ok_or("node is not on the PATH")?;
    let version = probe(
        {
            let mut command = Command::new(&node);
            command.arg("--version");
            command
        },
        "node --version",
    )?;
    let major: u64 = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or(0);
    if major < 22 {
        return Err(format!("node {} is older than 22", version.trim()));
    }
    Ok(Runtime {
        lang: "typescript",
        program: node,
        leading: vec![drivers().join("typescript/peer.mjs").into()],
        env: vec![("AGENTSPACES_TS".to_owned(), built.display().to_string())],
    })
}

/// The Ruby gem, from its checkout's `lib`.
fn ruby() -> Result<Runtime, String> {
    let lib = dir_from(
        "AGENTSPACES_RB",
        projects().join("agentspaces-rb/gems/agentspaces/lib"),
    );
    let ruby = on_path("ruby").ok_or("ruby is not on the PATH")?;
    let mut command = Command::new(&ruby);
    command
        .arg("-I")
        .arg(&lib)
        .args(["-e", "require 'agentspaces'; print AgentSpaces::VERSION"]);
    probe(command, "ruby with the gem")?;
    Ok(Runtime {
        lang: "ruby",
        program: ruby,
        leading: vec![
            "-I".into(),
            lib.into(),
            drivers().join("ruby/peer.rb").into(),
        ],
        env: Vec::new(),
    })
}

/// Every client, or why one cannot run.
fn runtimes() -> Result<Vec<Runtime>, String> {
    Ok(vec![python()?, typescript()?, ruby()?])
}

/// A running driver, killed when dropped.
struct Driver {
    lang: &'static str,
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    log: PathBuf,
    /// The watch events it printed so far.
    events: Vec<Json>,
}

impl Driver {
    fn start(runtime: &Runtime, scratch: &Scratch, seed: &str, group: &str) -> Driver {
        let keys = scratch.path().join(format!("keys-{}", runtime.lang));
        let log = scratch.path().join(format!("{}.log", runtime.lang));
        let stderr = std::fs::File::create(&log).expect("a log");
        let mut command = Command::new(&runtime.program);
        command
            .args(&runtime.leading)
            .args([seed, group])
            .arg(&keys)
            .current_dir(scratch.path())
            .env("HOME", scratch.path().join("home"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr);
        for (name, value) in &runtime.env {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("the driver starts");
        let stdin = child.stdin.take();
        let lines = lines_of(child.stdout.take().expect("stdout"));
        let mut driver = Driver {
            lang: runtime.lang,
            child,
            stdin,
            lines,
            log,
            events: Vec::new(),
        };
        let ready = driver.next(STARTUP, |json| {
            json.get("ready").is_some() || json.get("error").is_some()
        });
        assert_eq!(
            ready["ready"],
            true,
            "{} did not join: {ready}\n{}",
            driver.lang,
            driver.log_tail()
        );
        driver
    }

    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    /// The next line `wanted` accepts within `wait`; watch events met on the way are kept.
    fn next(&mut self, wait: Duration, wanted: impl Fn(&Json) -> bool) -> Json {
        let deadline = Instant::now() + wait;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let Ok(line) = self.lines.recv_timeout(left) else {
                break;
            };
            let Ok(json) = serde_json::from_str::<Json>(&line) else {
                eprintln!("{}: {line}", self.lang);
                continue;
            };
            if json.get("event").is_some() {
                self.events.push(json);
            } else if wanted(&json) {
                return json;
            } else {
                eprintln!("{}: unexpected {json}", self.lang);
            }
        }
        panic!(
            "{} answered nothing in {wait:?}\n{}",
            self.lang,
            self.log_tail()
        );
    }

    fn send(&mut self, command: &Json) {
        let stdin = self.stdin.as_mut().expect("standard input is open");
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|error| panic!("{} took no command: {error}", self.lang));
    }

    /// The answer to the command sent last.
    fn answer(&mut self, op: &str) -> Json {
        let answer = self.next(ANSWER, |json| json["op"] == op);
        assert!(
            answer.get("error").is_none(),
            "{} refused {op}: {answer}\n{}",
            self.lang,
            self.log_tail()
        );
        answer
    }

    fn ask(&mut self, command: Json) -> Json {
        let op = command["op"].as_str().unwrap_or_default().to_owned();
        self.send(&command);
        self.answer(&op)
    }

    /// Entries of `schema` it holds, asked until `done` holds of them or [`CONVERGE`] passes.
    fn entries_until(&mut self, schema: &str, done: impl Fn(&[Json]) -> bool) -> Vec<Json> {
        let deadline = Instant::now() + CONVERGE;
        loop {
            let answer = self.ask(json!({"op": "count", "schema": schema}));
            let entries = answer["entries"].as_array().cloned().unwrap_or_default();
            if done(&entries) || Instant::now() >= deadline {
                return entries;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn quit(mut self) {
        self.send(&json!({"op": "quit"}));
        let _ = self.next(Duration::from_secs(15), |json| json["bye"] == true);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------------------ the Rust peer

/// The Rust member: joined through the seed, and a watch of the tasks folded into `events`.
struct RustPeer {
    runtime: tokio::runtime::Runtime,
    fleet: Fleet,
    events: Arc<Mutex<Vec<(EventKind, Task)>>>,
}

impl RustPeer {
    fn join(seed: &str, group: GroupSpec) -> RustPeer {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let events = Arc::new(Mutex::new(Vec::new()));
        let fleet = runtime.block_on(async {
            let mut config =
                PeerConfig::new(Identity::generate().expect("an identity"), group.clone());
            config.seeds = vec![seed.parse().expect("a seed")];
            config.dialers = default_dialers();
            config.join_timeout = Duration::from_secs(15);
            let fleet = Fleet::join(config).await.expect("the Rust peer joins");
            let mut watch = fleet
                .space(SPACE)
                .watch_typed::<Task>(&Template::of::<Task>())
                .await
                .expect("a watch");
            let seen = Arc::clone(&events);
            tokio::spawn(async move {
                while let Some(event) = watch.next().await {
                    if let Ok(mut seen) = seen.lock() {
                        seen.push((event.kind, event.entry.value().clone()));
                    }
                }
            });
            fleet
        });
        RustPeer {
            runtime,
            fleet,
            events,
        }
    }

    fn write(&self, task: &Task) -> String {
        self.runtime.block_on(async {
            self.fleet
                .space(SPACE)
                .write(task, Lease::DEFAULT_WRITE, Map::new())
                .await
                .expect("the Rust peer writes")
                .to_string()
        })
    }

    /// The live tasks or results it holds, asked until `done` holds of them.
    fn read_until<T: Entry + Clone>(
        &self,
        done: impl Fn(&[(String, T)]) -> bool,
    ) -> Vec<(String, T)> {
        self.runtime.block_on(async {
            let space = self.fleet.space(SPACE);
            let deadline = Instant::now() + CONVERGE;
            loop {
                let _ = space.pull().await;
                tokio::time::sleep(Duration::from_millis(250)).await;
                let found: Vec<(String, T)> = space
                    .read_all_typed::<T>(&Template::of::<T>(), 1000)
                    .await
                    .expect("a read")
                    .into_iter()
                    .map(|view| (view.entry_id().to_string(), view.value().clone()))
                    .collect();
                if done(&found) || Instant::now() >= deadline {
                    return found;
                }
            }
        })
    }
}

/// The Rust peer's side of the race, on its runtime: takes until three takes in a row find none.
async fn rust_race(fleet: Fleet) -> Vec<(String, String)> {
    let space = fleet.space(SPACE);
    let tasks = Template::of::<Task>();
    let mut took = Vec::new();
    let mut idle = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while idle < 3 && Instant::now() < deadline {
        match space
            .take_typed::<Task>(&tasks, Lease::DEFAULT_TAKE, Duration::from_secs(1))
            .await
        {
            Ok(Some(taken)) => {
                idle = 0;
                let id = taken.entry_id().to_string();
                let outcome = Outcome {
                    task: taken.value().task.clone(),
                    task_id: id.clone(),
                    by: "rust".to_owned(),
                };
                space
                    .write(&outcome, Lease::DEFAULT_WRITE, Map::new())
                    .await
                    .expect("the Rust peer writes its result");
                taken
                    .complete(None, Lease::DEFAULT_RESULT, Map::new())
                    .await
                    .expect("the Rust peer completes its take");
                took.push((id, outcome.task));
            }
            Ok(None) => idle += 1,
            Err(error) => panic!("the Rust peer's take failed: {error}"),
        }
    }
    took
}

// ------------------------------------------------------------------------------ the scenario

/// One run around a seed started with `seed_args`, the drivers joining with `group`.
fn scenario(tag: &str, runtimes: &[Runtime], seed_args: &[&str], group: Option<&str>) {
    let scratch = Scratch::new(tag);
    let mut command = bare_aspace(&scratch);
    command.args(seed_args);
    let mut seed = Running::spawn(command);
    let line = seed.out_until("the listening line", |json| json["event"] == "listening");
    let address = line["listen"][0].as_str().expect("an address").to_owned();
    let group = group.map_or_else(
        || line["join"].as_str().expect("a join URI").to_owned(),
        str::to_owned,
    );
    let spec = if group.starts_with("aspace://") {
        GroupSpec::Join(group.clone())
    } else {
        GroupSpec::FoundingText(group.clone())
    };

    let mut drivers: Vec<Driver> = runtimes
        .iter()
        .map(|runtime| Driver::start(runtime, &scratch, &address, &group))
        .collect();
    let rust = RustPeer::join(&address, spec);
    for driver in &mut drivers {
        driver.ask(json!({"op": "watch", "schema": TASK}));
    }

    // Each writes its tasks; every peer then holds all of them.
    let mut written: BTreeMap<String, String> = BTreeMap::new();
    for driver in &mut drivers {
        for n in 1..=EACH {
            let task = format!("{}-{n}", driver.lang);
            let answer = driver.ask(json!({
                "op": "write",
                "schema": TASK,
                "entry": {"task": task, "from": driver.lang},
            }));
            written.insert(task, answer["id"].as_str().expect("an id").to_owned());
        }
    }
    for n in 1..=EACH {
        let task = Task {
            task: format!("rust-{n}"),
            from: "rust".to_owned(),
        };
        written.insert(task.task.clone(), rust.write(&task));
    }
    let total = written.len();
    assert_eq!(total, EACH * LANGUAGES.len());
    for driver in &mut drivers {
        let held = driver.entries_until(TASK, |entries| entries.len() >= total);
        assert_eq!(held.len(), total, "{} holds {held:?}", driver.lang);
    }
    let held = rust.read_until::<Task>(|found| found.len() >= total);
    assert_eq!(held.len(), total, "the Rust peer holds {held:?}");

    // The race: all four take at once.
    let race = json!({"op": "race", "schema": TASK, "result": RESULT, "idle": 3});
    for driver in &mut drivers {
        driver.send(&race);
    }
    let rust_took = rust.runtime.block_on(rust_race(rust.fleet.clone()));
    let mut takes: Vec<(String, String, String)> = rust_took
        .into_iter()
        .map(|(id, task)| (id, task, "rust".to_owned()))
        .collect();
    let mut lost = 0;
    for driver in &mut drivers {
        let answer = driver.answer("race");
        for took in answer["took"].as_array().expect("took") {
            takes.push((
                took["id"].as_str().expect("an id").to_owned(),
                took["task"].as_str().expect("a task").to_owned(),
                driver.lang.to_owned(),
            ));
        }
        // The TypeScript driver's guard against its client's short settle window (see
        // interop/clients/README.md): takes it gave up, which another member holds.
        lost += answer["lost"].as_array().map_or(0, Vec::len);
    }
    eprintln!("{tag}: takes the TypeScript driver gave up after the settle window: {lost}");
    let per_language: BTreeMap<&str, usize> = LANGUAGES
        .iter()
        .map(|lang| (*lang, takes.iter().filter(|(_, _, by)| by == lang).count()))
        .collect();
    eprintln!("{tag}: tasks taken per language: {per_language:?}");
    let ids: BTreeSet<&str> = takes.iter().map(|(id, _, _)| id.as_str()).collect();
    assert_eq!(ids.len(), takes.len(), "a task was taken twice: {takes:?}");
    let expected: BTreeSet<&str> = written.values().map(String::as_str).collect();
    assert_eq!(ids, expected, "every task taken exactly once: {takes:?}");
    for (id, task, _) in &takes {
        assert_eq!(written.get(task), Some(id), "{task} is {id}");
    }
    let taker: BTreeMap<&str, &str> = takes
        .iter()
        .map(|(_, task, by)| (task.as_str(), by.as_str()))
        .collect();

    // Every result, read by every peer, so by the peers of the other languages; and no task is
    // left: each was completed.
    for driver in &mut drivers {
        let results = driver.entries_until(RESULT, |entries| entries.len() >= total);
        assert_eq!(results.len(), total, "{} reads {results:?}", driver.lang);
        for result in &results {
            let task = result["entry"]["task"].as_str().expect("a task");
            assert_eq!(
                Some(result["entry"]["by"].as_str().expect("by")),
                taker.get(task).copied(),
                "{} reads {result}",
                driver.lang
            );
        }
        let left = driver.entries_until(TASK, <[Json]>::is_empty);
        assert!(
            left.is_empty(),
            "{} still holds tasks: {left:?}",
            driver.lang
        );
    }
    let results = rust.read_until::<Outcome>(|found| found.len() >= total);
    assert_eq!(results.len(), total, "the Rust peer reads {results:?}");
    for (_, outcome) in &results {
        assert_eq!(
            Some(outcome.by.as_str()),
            taker.get(outcome.task.as_str()).copied()
        );
        assert_eq!(written.get(&outcome.task), Some(&outcome.task_id));
    }
    let left = rust.read_until::<Task>(<[(String, Task)]>::is_empty);
    assert!(left.is_empty(), "the Rust peer still holds tasks: {left:?}");

    // The watches heard the other languages' writes and completions.
    for driver in &mut drivers {
        let _ = driver.ask(json!({"op": "count", "schema": TASK}));
        let heard = |kind: &str| -> BTreeSet<String> {
            driver
                .events
                .iter()
                .filter(|event| event["event"] == kind)
                .filter_map(|event| event["entry"]["from"].as_str().map(str::to_owned))
                .collect()
        };
        let written_by = heard("WRITTEN");
        for other in LANGUAGES.iter().filter(|lang| **lang != driver.lang) {
            assert!(
                written_by.contains(*other),
                "{}'s watch heard no write of {other}: {:?}",
                driver.lang,
                driver.events
            );
        }
        let completed: Vec<&Json> = driver
            .events
            .iter()
            .filter(|event| event["event"] == "COMPLETED")
            .filter(|event| {
                event["entry"]["task"]
                    .as_str()
                    .and_then(|task| taker.get(task))
                    .is_some_and(|by| *by != driver.lang)
            })
            .collect();
        assert!(
            !completed.is_empty(),
            "{}'s watch heard no completion by another language: {:?}",
            driver.lang,
            driver.events
        );
        eprintln!(
            "{tag}: {}'s watch heard writes of {written_by:?} and {} completions by others",
            driver.lang,
            completed.len()
        );
    }
    let rust_heard: BTreeSet<String> = rust
        .events
        .lock()
        .expect("the events")
        .iter()
        .filter(|(kind, _)| *kind == EventKind::Written)
        .map(|(_, task)| task.from.clone())
        .collect();
    for other in ["python", "typescript", "ruby"] {
        assert!(
            rust_heard.contains(other),
            "the Rust watch heard no write of {other}: {rust_heard:?}"
        );
    }

    for driver in drivers {
        driver.quit();
    }
    rust.runtime
        .block_on(rust.fleet.close())
        .expect("the Rust peer closes");
    seed.signal("-TERM");
    let (code, _) = seed.finish();
    assert_eq!(code, Some(0), "the seed's exit: {:?}", seed.seen_err);
    let admitted = seed
        .seen_err
        .iter()
        .filter(|line| line.starts_with("aspace: admitted z"))
        .count();
    assert!(admitted >= LANGUAGES.len(), "{:?}", seed.seen_err);
}

/// The clients, or a return from the test with a note (a failure under
/// `ASPACE_INTEROP_REQUIRED=1`).
fn clients_or_skip() -> Option<Vec<Runtime>> {
    match runtimes() {
        Ok(runtimes) => Some(runtimes),
        Err(why) => {
            assert!(!required(), "a client cannot run: {why}");
            eprintln!("skipping: a client cannot run: {why}");
            None
        }
    }
}

#[test]
fn python_typescript_ruby_and_rust_share_layer_3_through_a_rust_seed_over_tcp() {
    let Some(runtimes) = clients_or_skip() else {
        return;
    };
    scenario(
        "clients-tcp",
        &runtimes,
        &[
            "--profile",
            "dev-local",
            "seed",
            "--found",
            "interop",
            "--listen",
            "tcp://127.0.0.1:0",
        ],
        None,
    );
}

#[test]
fn python_typescript_ruby_and_rust_share_layer_3_through_a_rust_seed_over_tls() {
    let Some(runtimes) = clients_or_skip() else {
        return;
    };
    scenario(
        "clients-tls",
        &runtimes,
        &[
            "seed",
            "--group",
            "interop-tls-v1",
            "--listen",
            "tls://127.0.0.1:0",
            "--require-attestation",
        ],
        Some("interop-tls-v1"),
    );
}
