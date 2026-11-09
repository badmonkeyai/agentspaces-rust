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

//! Example 32's Rust worker: an agent of example 02's research fleet that takes `ResearchTask`
//! entries the Java coordinator writes and completes each with a `Finding`.
//!
//! It joins from the configuration (`ASPACE_SEEDS`, `ASPACE_GROUP=research-fleet-demo-v1`,
//! `ASPACE_KEYSTORE`, or the fleet YAML; [`agentspaces::Config`]), binds the agent `rust-worker`
//! with one `take` action named `research` on its AgentCard, and serves until SIGINT or SIGTERM.
//! The `aspace work` script worker (`research.sh`) declares the same action, so the fleet
//! catalogue folds the two into one offering with two replicas, and `aspace call` reaches
//! whichever takes the task.
//!
//! ```sh
//! ASPACE_SEEDS=tcp://127.0.0.1:7451 ASPACE_GROUP=research-fleet-demo-v1 ASPACE_KEYSTORE=./keys/rust \
//!     cargo run -p rust-fleet --bin rust-worker
//! ```
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use agentspaces::Entry;
use agentspaces::agent::{HandlerError, Reply, TakeContext};
use agentspaces::space::{Fleet, Lease};
use serde::{Deserialize, Serialize};

/// A unit of research work: Java's `record ResearchTask(String topic, int priority)`, whose wire
/// schema is the record's binary class name and version.
#[derive(Debug, Clone, Serialize, Deserialize, Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1")]
#[serde(rename_all = "camelCase")]
struct ResearchTask {
    topic: String,
    priority: i32,
}

/// A completed research result: Java's `record Finding(String topic, String summary, String
/// worker)`. The coordinator tallies findings by `worker`.
#[derive(Debug, Clone, Serialize, Deserialize, Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1")]
#[serde(rename_all = "camelCase")]
struct Finding {
    topic: String,
    summary: String,
    worker: String,
}

/// The worker's name, stamped into its findings and its AgentID (`<peerId>/rust-worker`).
const WORKER: &str = "rust-worker";

/// How long one piece of research takes (so the fleet's workers share the tasks).
const RESEARCH: Duration = Duration::from_millis(400);

/// Researches one task: what the agent's `research` action does.
async fn research(task: ResearchTask, ctx: TakeContext) -> Result<Reply, HandlerError> {
    // keepalive renews the take at half its lease while long work runs; this work is short.
    ctx.keepalive(tokio::time::sleep(RESEARCH)).await;
    println!(
        "{WORKER}: researched '{}' (attempt {})",
        task.topic,
        ctx.attempt()
    );
    Ok(Finding {
        summary: format!("researched in rust: {}", task.topic),
        topic: task.topic,
        worker: WORKER.to_owned(),
    }
    .into())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let fleet = Fleet::join_from_env().await?;
    let bound = fleet
        .agent(WORKER)
        .describe("Researches a topic (example 32's Rust worker)")
        .take::<ResearchTask, _, _>("tasks", Lease::parse("30s")?, research)
        .action("research")
        .produces::<Finding>()
        .bind()
        .await?;
    println!(
        "{WORKER}: serving as {} in group {}",
        bound.agent_id(),
        fleet.peer().group_id()
    );
    bound.stop_on_signals().await?;
    println!(
        "{WORKER}: stopped after {} tasks ({} failed)",
        bound.handled(),
        bound.failures()
    );
    fleet.close().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{WORKER}: {error}");
            ExitCode::FAILURE
        }
    }
}
