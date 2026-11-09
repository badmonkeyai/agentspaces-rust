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

//! The Streamable HTTP gateway ([`serve_http`]) against an MCP client that shares no code with
//! rmcp: the official TypeScript SDK (`@modelcontextprotocol/sdk`) under Node, driven by
//! `interop/mcp-clients/node_client.mjs` over real loopback sockets, the fleet in memory
//! (`common`):
//!
//! 1. the SDK lists the tools under the names the Ruby gateway gives them (two actions named
//!    `research` become `research_854bb186` and `research_9bae3fcd`), and its calls reach each
//!    worker;
//! 2. a call that waits reports progress to the SDK's `onprogress`, and the SDK's cancellation
//!    (`AbortSignal`, sent as `notifications/cancelled`) ends it: the input stays in the space,
//!    held by the worker's take, and the worker still completes it later;
//! 3. a worker binding a new action is heard on the session's SSE stream as
//!    `notifications/tools/list_changed`, and the new tool is listed and called;
//! 4. a session token-authenticated (a static token) and judged (a scoped policy): a call
//!    outside the token's scopes is refused 403 with the scope that would allow it;
//! 5. [`HttpServer::shutdown`](agentspaces_mcp::HttpServer::shutdown) with a call in flight: the
//!    SDK hears on the call's stream that the gateway stopped, instead of waiting out its own
//!    request timeout.
//!
//! The SDK is read in place from `ASPACE_MCP_NODE_SDK` (the package directory), else from the
//! `node_modules` of a sibling project (`agentspaces-typescript` first, then the others by
//! name), the first that loads at 1.20 or later; the test passes with a note when it or `node`
//! is missing, unless `ASPACE_INTEROP_REQUIRED=1`. The driver is killed when the test ends,
//! also when it fails.

#[path = "../../agentspaces/tests/support/mod.rs"]
mod support;

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use agentspaces::Entry as _;
use agentspaces::agent::{Reply, TakeContext};
use agentspaces::space::Template;
use agentspaces_mcp::{FleetMcpServer, HttpOptions, Policy, StaticTokens, serve_http};
use common::*;
use serde_json::{Value as Json, json};
use support::eventually;
use tokio::sync::Notify;

const ANA: &str = "ana-fleet-token-0123456789";
const BOB: &str = "bob-research-token-0123456789";
const LIST_CHANGED: &str = "notifications/tools/list_changed";

/// How long one driver operation may take beyond its own `timeoutMs`.
const ANSWER: Duration = Duration::from_secs(30);

/// The SDK's package directory and `node`, or why they cannot run.
fn typescript_sdk() -> Result<(PathBuf, PathBuf), String> {
    let node = std::env::var_os("ASPACE_MCP_NODE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join("node"))
                    .find(|node| node.is_file())
            })
        })
        .ok_or("no `node` on the PATH (or ASPACE_MCP_NODE)")?;
    let projects = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let candidates: Vec<PathBuf> = match std::env::var_os("ASPACE_MCP_NODE_SDK") {
        Some(dir) => vec![PathBuf::from(dir)],
        None => {
            let mut siblings: Vec<PathBuf> = std::fs::read_dir(&projects)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|project| !project.ends_with("agentspaces-typescript"))
                .collect();
            siblings.sort();
            siblings.insert(0, projects.join("agentspaces-typescript"));
            siblings
                .iter()
                .map(|project| project.join("node_modules/@modelcontextprotocol/sdk"))
                .collect()
        }
    };
    let driver =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/mcp-clients/node_client.mjs");
    let mut refused = Vec::new();
    for sdk in candidates
        .into_iter()
        .filter(|dir| dir.join("package.json").is_file())
    {
        let probe = Command::new(&node)
            .arg(&driver)
            .arg(&sdk)
            .arg("probe")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("`{}` does not run: {error}", node.display()))?;
        let version = serde_json::from_slice::<Json>(&probe.stdout)
            .ok()
            .and_then(|found| found["sdk"].as_str().map(str::to_owned));
        match version {
            Some(version) if at_least_1_20(&version) => return Ok((node, sdk)),
            Some(version) => refused.push(format!(
                "the TypeScript SDK at {} is {version}; 1.20 or later is needed",
                sdk.display()
            )),
            None => refused.push(format!(
                "the TypeScript SDK at {} does not load: {}",
                sdk.display(),
                String::from_utf8_lossy(&probe.stderr)
            )),
        }
    }
    if refused.is_empty() {
        Err("no @modelcontextprotocol/sdk in a sibling project (set ASPACE_MCP_NODE_SDK)".into())
    } else {
        Err(refused.join("; "))
    }
}

/// Whether a dotted SDK `version` is 1.20 or later.
fn at_least_1_20(version: &str) -> bool {
    let mut parts = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= (1, 20)
}

/// The scripted TypeScript SDK client, killed when dropped.
struct Node {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
}

impl Node {
    /// A client of the Streamable HTTP endpoint `url`.
    fn http(node: &Path, sdk: &Path, url: &str) -> Node {
        let driver =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/mcp-clients/node_client.mjs");
        let mut child = Command::new(node)
            .arg(driver)
            .arg(sdk)
            .args(["http", url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("node starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Node {
            child,
            stdin,
            lines,
        }
    }

    /// One operation and its answer; blocks this worker thread only (`block_in_place`), so the
    /// fleet and the gateway keep running.
    fn op(&mut self, op: Json) -> Json {
        tokio::task::block_in_place(|| {
            let stdin = self.stdin.as_mut().expect("the driver's stdin");
            stdin
                .write_all(format!("{op}\n").as_bytes())
                .and_then(|()| stdin.flush())
                .expect("sent to the driver");
            let wait = ANSWER + Duration::from_millis(op["timeoutMs"].as_u64().unwrap_or(0));
            let answer = self
                .lines
                .recv_timeout(wait)
                .unwrap_or_else(|_| panic!("no answer to {op}"));
            serde_json::from_str(&answer).unwrap_or_else(|_| panic!("not JSON: {answer}"))
        })
    }

    /// [`Node::op`], which must succeed.
    fn ok(&mut self, op: Json) -> Json {
        let answer = self.op(op.clone());
        assert_eq!(answer["ok"], true, "{op}: {answer}");
        answer
    }

    fn tool_names(&mut self) -> Vec<String> {
        self.ok(json!({"op": "tools"}))["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Calls `name` with `input`: the call's result, which must not be a tool error.
    fn call(&mut self, name: &str, input: Json) -> Json {
        let answer = self.ok(json!({"op": "call", "name": name,
            "arguments": {"input": input, "timeout": "20s"}}));
        assert_eq!(answer["result"]["isError"], false, "{answer}");
        answer["result"].clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stdin = None;
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// A scratch directory of this test process, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "asrs-mcp-ts-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_typescript_sdk_lists_calls_follows_and_cancels() {
    let (node, sdk) = match typescript_sdk() {
        Ok(found) => found,
        Err(why) => {
            assert!(
                std::env::var("ASPACE_INTEROP_REQUIRED").as_deref() != Ok("1"),
                "the TypeScript SDK client cannot run: {why}"
            );
            eprintln!("skipping: the TypeScript SDK client cannot run: {why}");
            return;
        }
    };
    let net = Net::new();
    let researcher = net.member().await;
    let librarian = net.member().await;
    let gateway = net.member().await;
    let research = research_task(&researcher, "researcher").await;
    let other = research_other(&librarian, "librarian").await;

    // A worker that holds what it takes until released, noting the input's id.
    let taken = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let input = Arc::new(std::sync::Mutex::new(None));
    let (on_take, on_release, seen) =
        (Arc::clone(&taken), Arc::clone(&release), Arc::clone(&input));
    let holder = librarian
        .agent("holder")
        .settle(SETTLE)
        .take(SPACE, lease(), move |task: Weigh, ctx: TakeContext| {
            let (on_take, on_release) = (Arc::clone(&on_take), Arc::clone(&on_release));
            *seen.lock().expect("input") = Some(ctx.entry_id().clone());
            async move {
                on_take.notify_one();
                on_release.notified().await;
                Ok(Reply::from(Outcome {
                    topic: task.topic,
                    worker: ctx.agent_id().to_owned(),
                }))
            }
        })
        .action("hold")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind");

    // Ana's token may call everything; bob's only the research tools.
    let scratch = Scratch::new("tokens");
    let tokens = scratch.0.join("tokens.yaml");
    std::fs::write(
        &tokens,
        format!(
            "tokens:\n  - token: {ANA}\n    principal: ana\n    scopes: [fleet]\n  \
             - token: {BOB}\n    principal: bob\n    scopes: [research]\n"
        ),
    )
    .expect("the token file");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tokens, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let server = FleetMcpServer::new(
        &gateway,
        options().policy(
            Policy::scoped()
                .allow("fleet", ["*"])
                .allow("research", ["research*"]),
        ),
    );
    let http = serve_http(
        server,
        HttpOptions::new()
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .verifier(StaticTokens::load(&tokens).expect("the tokens")),
    )
    .await
    .expect("serving");
    let mut client = Node::http(&node, &sdk, &http.url());
    let connected = client.ok(json!({"op": "connect",
        "headers": {"Authorization": format!("Bearer {ANA}")}}));
    assert_eq!(connected["capabilities"]["tools"]["listChanged"], true);

    // 1. The Ruby gateway's names, and a call to each worker.
    let expected = ["hold", RESEARCH_TASK, RESEARCH_OTHER];
    eventually("the three tools", || {
        let names = client.tool_names();
        async move { names == expected }
    })
    .await;
    let result = client.call(RESEARCH_TASK, json!({"topic": "ts-task"}));
    assert_eq!(result["structuredContent"]["topic"], "ts-task");
    assert!(
        result["structuredContent"]["worker"]
            .as_str()
            .is_some_and(|worker| worker.ends_with("/researcher")),
        "{result}"
    );
    let result = client.call(RESEARCH_OTHER, json!({"topic": "ts-other"}));
    assert!(
        result["structuredContent"]["worker"]
            .as_str()
            .is_some_and(|worker| worker.ends_with("/librarian")),
        "{result}"
    );

    // 2. Progress while the call waits, then the SDK cancels it.
    let answer = client.ok(json!({"op": "call", "name": "hold",
        "arguments": {"input": {"topic": "held", "weight": 1.5}, "timeout": "2m"},
        "progress": true, "cancelAfterMs": 1500}));
    assert_eq!(answer["cancelled"], true, "{answer}");
    let progress = answer["progress"].as_array().cloned().unwrap_or_default();
    assert!(progress.len() >= 2, "{answer}");
    assert!(
        progress
            .windows(2)
            .all(|pair| pair[0]["progress"].as_f64() <= pair[1]["progress"].as_f64()),
        "{answer}"
    );
    assert_eq!(progress[0]["total"], 120, "{answer}");
    tokio::time::timeout(WAIT, taken.notified())
        .await
        .expect("the worker took the input");
    let input_id = input
        .lock()
        .expect("input")
        .clone()
        .expect("the worker saw the input");
    let tasks = gateway.space(SPACE);
    tasks.pull().await.expect("pull");
    let held = tasks
        .get(&input_id)
        .await
        .expect("get")
        .expect("the input stays in the space");
    assert!(!held.completed());
    assert!(held.holder().is_some(), "the worker's take holds it");
    assert_eq!(
        held.payload().get("topic").and_then(|value| value.as_str()),
        Some("held")
    );
    // The session goes on: a call after the cancellation is answered.
    let result = client.call(RESEARCH_TASK, json!({"topic": "after-cancel"}));
    assert_eq!(result["structuredContent"]["topic"], "after-cancel");

    // 3. A new action binds: list_changed on the SSE stream, then listed and called.
    let before =
        client
            .ok(json!({"op": "await", "method": LIST_CHANGED, "after": 1_000_000, "timeoutMs": 0}))
            ["count"]
            .as_u64()
            .unwrap_or(0);
    let audit = researcher
        .agent("auditor")
        .settle(SETTLE)
        .take(
            SPACE,
            lease(),
            |task: Summary, ctx: TakeContext| async move {
                Ok(Reply::from(Outcome {
                    topic: task.topic,
                    worker: ctx.agent_id().to_owned(),
                }))
            },
        )
        .action("audit")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind");
    let heard = client
        .ok(json!({"op": "await", "method": LIST_CHANGED, "after": before, "timeoutMs": 20000}));
    assert!(heard["timedOut"].is_null(), "{heard}");
    assert_eq!(
        client.tool_names(),
        ["audit", "hold", RESEARCH_TASK, RESEARCH_OTHER]
    );
    let result = client.call("audit", json!({"topic": "audited", "words": 2}));
    assert!(
        result["structuredContent"]["worker"]
            .as_str()
            .is_some_and(|worker| worker.ends_with("/auditor")),
        "{result}"
    );

    // 4. Bob's token reaches research, and is refused 403 elsewhere, naming the scope.
    client.ok(json!({"op": "connect", "headers": {"Authorization": format!("Bearer {BOB}")}}));
    let result = client.call(RESEARCH_TASK, json!({"topic": "bob"}));
    assert_eq!(result["structuredContent"]["topic"], "bob");
    let refused = client.op(json!({"op": "call", "name": "audit",
        "arguments": {"input": {"topic": "nope", "words": 1}}}));
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["status"], 403, "{refused}");
    let challenge = refused["challenge"].as_str().unwrap_or_default();
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(challenge.contains("scope=\"fleet\""), "{challenge}");

    // The late worker still answers the cancelled call's input.
    release.notify_one();
    eventually("the late completion", || async {
        tasks
            .read_all(&Template::new(Outcome::SCHEMA), 50)
            .await
            .is_ok_and(|results| {
                results.iter().any(|result| {
                    result
                        .payload()
                        .get("topic")
                        .and_then(|value| value.as_str())
                        == Some("held")
                })
            })
    })
    .await;

    // 5. The gateway stops with a call in flight: the SDK hears, on the call's stream, that it
    // stopped (the input left held by the worker), instead of waiting out its own timeout.
    client.ok(json!({"op": "connect", "headers": {"Authorization": format!("Bearer {ANA}")}}));
    client.ok(json!({"op": "call", "name": "hold", "background": true,
        "arguments": {"input": {"topic": "held-at-stop", "weight": 2.5}, "timeout": "2m"}}));
    tokio::time::timeout(WAIT, taken.notified())
        .await
        .expect("the worker takes the second input");
    http.shutdown().await.expect("shut down");
    let outcome = client.ok(json!({"op": "outcome"}));
    let stopped = &outcome["outcomes"][0];
    assert_eq!(stopped["ok"], true, "{outcome}");
    assert_eq!(stopped["result"]["isError"], true, "{outcome}");
    assert_eq!(
        stopped["result"]["content"][0]["text"],
        agentspaces_mcp::STOPPED_WHILE_WAITING,
        "{outcome}"
    );
    release.notify_one();
    drop(client);
    for bound in [research, other, holder, audit] {
        bound.stop(Duration::from_secs(5)).await;
    }
}
