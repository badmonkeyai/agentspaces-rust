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

//! What the MCP tests share: a relaying fake seed on a fresh in-memory network (the peer's own
//! test support, `crates/agentspaces/tests/support`), members that bind workers with the
//! catalogue tests' actions (so the tool names are the Ruby gateway's), and an rmcp client that
//! records the notifications it hears.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentspaces::agent::{Bound, Reply, TakeContext};
use agentspaces::clock::{SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::Peer;
use agentspaces::space::{Fleet, Lease};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces_mcp::{FleetMcpServer, ServerOptions};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientConfig, JsonObject, ProgressNotificationParam,
    ProtocolVersion,
};
use rmcp::service::ClientServiceExt as _;
use rmcp::service::{NotificationContext, RunningService};
use rmcp::{ClientHandler, RoleClient, ServiceExt as _};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::support::{FakeSeed, PATIENCE, config, eventually};

pub const SEED: &str = "127.0.0.1:7931";
pub const FOUNDING: &str = "agentspaces-rust-mcp";
pub const SPACE: &str = "tasks";
pub const SETTLE: Duration = Duration::from_millis(200);

/// The names the Ruby gateway gives the two `research` actions (catalogue tests, `mcp.rb`).
pub const RESEARCH_TASK: &str = "research_854bb186";
pub const RESEARCH_OTHER: &str = "research_9bae3fcd";

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry, schemars::JsonSchema,
)]
#[entry(schema = "com.acme.Task#v1")]
pub struct Task {
    pub topic: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.OtherTask#v1")]
pub struct OtherTask {
    pub topic: String,
}

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry, schemars::JsonSchema,
)]
#[entry(schema = "com.acme.Result#v1")]
pub struct Outcome {
    pub topic: String,
    pub worker: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Summary#v1")]
pub struct Summary {
    pub topic: String,
    pub words: i64,
}

/// A typed task whose `weight` is a double, as a Java `double` field.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry, schemars::JsonSchema,
)]
#[entry(schema = "com.acme.Weigh#v1")]
pub struct Weigh {
    pub topic: String,
    pub weight: f64,
}

pub fn system() -> SharedClock {
    Arc::new(SystemClock)
}

pub fn lease() -> Lease {
    Lease::parse("30s").expect("a lease")
}

/// A relaying seed on a fresh network.
pub struct Net {
    pub network: MemoryNetwork,
    _seed: FakeSeed,
}

impl Net {
    pub fn new() -> Net {
        let network = MemoryNetwork::new();
        let group = ids::group_id_from_founding(FOUNDING.as_bytes());
        let seed = FakeSeed::start_relay(&network, SEED, &group, system());
        Net {
            network,
            _seed: seed,
        }
    }

    pub async fn member(&self) -> Fleet {
        let peer = Peer::start(config(
            &self.network,
            Identity::generate().expect("identity"),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
            &[SEED],
            system(),
        ))
        .await
        .expect("the peer starts");
        Fleet::from_peer(peer)
    }
}

/// Binds `agent` on `fleet` with a `research` take of `Task` answering an `Outcome`.
pub async fn research_task(fleet: &Fleet, agent: &str) -> Bound {
    fleet
        .agent(agent)
        .describe("Researches a topic\u{1b}[31m and\nreports\u{200b} back")
        .settle(SETTLE)
        .take(SPACE, lease(), |task: Task, ctx: TakeContext| async move {
            Ok(Reply::from(Outcome {
                topic: task.topic,
                worker: ctx.agent_id().to_owned(),
            }))
        })
        .action("research")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind")
}

/// Binds `agent` on `fleet` with a `research` take of `OtherTask` answering an `Outcome`.
pub async fn research_other(fleet: &Fleet, agent: &str) -> Bound {
    fleet
        .agent(agent)
        .settle(SETTLE)
        .take(
            SPACE,
            lease(),
            |task: OtherTask, ctx: TakeContext| async move {
                Ok(Reply::from(Outcome {
                    topic: task.topic,
                    worker: ctx.agent_id().to_owned(),
                }))
            },
        )
        .action("research")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind")
}

/// Options for tests: a fast refresh and fast progress.
pub fn options() -> ServerOptions {
    ServerOptions::new()
        .refresh_interval(Duration::from_millis(150))
        .progress_interval(Duration::from_millis(100))
}

/// A client that records what the server tells it.
#[derive(Clone)]
pub struct Recorder {
    pub list_changed: Arc<AtomicUsize>,
    pub progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
    version: ProtocolVersion,
}

impl Recorder {
    /// A client of the `initialize` lifecycle (sessions hear notifications directly).
    pub fn legacy() -> Recorder {
        Recorder::with_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
    }

    /// A client of the newest protocol (2026-07-28: notifications through `subscriptions/listen`).
    pub fn latest() -> Recorder {
        Recorder::with_version(ProtocolVersion::LATEST)
    }

    fn with_version(version: ProtocolVersion) -> Recorder {
        Recorder {
            list_changed: Arc::new(AtomicUsize::new(0)),
            progress: Arc::new(Mutex::new(Vec::new())),
            version,
        }
    }

    pub fn changes(&self) -> usize {
        self.list_changed.load(Ordering::SeqCst)
    }

    pub fn progress_reports(&self) -> usize {
        self.progress.lock().expect("progress").len()
    }
}

impl ClientHandler for Recorder {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default().with_protocol_version(self.version.clone())
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.list_changed.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress.lock().expect("progress").push(params);
    }
}

pub type Client = RunningService<RoleClient, Recorder>;

/// Serves `server` over an in-process duplex pipe (as over standard input and output) and
/// connects `recorder` to it.
pub async fn connect(server: FleetMcpServer, recorder: Recorder) -> Client {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    if recorder.version.has_initialize() {
        recorder
            .serve(client_io)
            .await
            .expect("the client connects")
    } else {
        let lifecycle = rmcp::service::ClientLifecycleMode::Discover {
            preferred_versions: vec![recorder.version.clone()],
        };
        recorder
            .serve_with_lifecycle(client_io, lifecycle)
            .await
            .expect("the client connects")
    }
}

/// The tool names the server lists now.
pub async fn names(client: &Client) -> Vec<String> {
    client
        .peer()
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect()
}

/// Waits until the server lists exactly `expected`.
pub async fn wait_for_tools(client: &Client, expected: &[&str]) {
    eventually(&format!("the tools {expected:?}"), || async {
        names(client).await == expected
    })
    .await;
}

/// Calls `name` with `arguments`.
pub async fn call(client: &Client, name: &str, arguments: Json) -> CallToolResult {
    let arguments: JsonObject = match arguments {
        Json::Object(object) => object,
        other => panic!("arguments are an object, not {other}"),
    };
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments))
        .await
        .expect("tools/call answers")
}

/// Calls `name` with `arguments`, answering the protocol error the server answers instead of a
/// result.
pub async fn call_refused(client: &Client, name: &str, arguments: Json) -> rmcp::model::ErrorData {
    let arguments: JsonObject = match arguments {
        Json::Object(object) => object,
        other => panic!("arguments are an object, not {other}"),
    };
    match client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments))
        .await
    {
        Ok(result) => panic!("a result, not a protocol error: {result:?}"),
        Err(rmcp::ServiceError::McpError(error)) => error,
        Err(other) => panic!("not a protocol error: {other}"),
    }
}

/// The text of a result's first content block.
pub fn text(result: &CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|text| text.text.clone())
        .unwrap_or_default()
}

/// Waits until `check` holds, for at most [`PATIENCE`].
pub async fn until(what: &str, check: impl Fn() -> bool) {
    eventually(what, || {
        let held = check();
        async move { held }
    })
    .await;
}

/// How long a test waits at most.
pub const WAIT: Duration = PATIENCE;
