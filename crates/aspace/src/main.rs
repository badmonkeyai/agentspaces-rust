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

//! `aspace`: a member of an AgentSpaces fleet for scripts, hooks, and shells.
//!
//! A visitor command joins, waits until linked and the space is pulled, does its one thing, and
//! leaves: `id`, `status`, `write`, `read`, `take`, `complete`, `watch`, `cards`, `call`,
//! `doctor`; when an `aspace daemon` of the same configuration answers on the local socket, the
//! command runs on its peer instead ([`session::through_daemon`]). `work` stays and
//! runs a program per task, and `daemon` stays and serves the visitors. Results are JSON on
//! standard output (one object, or JSON Lines for streams), with wire names and the schema
//! string; diagnostics go to standard error. Exit codes ([`exit`]): 0 success, 1 error, 2
//! refused or not found, 3 timeout, 4 authentication or authorization.
//!
//! `cards` and `call` read the fleet catalogue ([`agentspaces::catalog::FleetCatalog`]); `work`
//! binds an agent of the worker layer ([`agentspaces::agent`]) and publishes its card, so the
//! one finds and invokes what the other offers. `mcp` serves the same catalogue as MCP tools
//! ([`mcp`], over [`agentspaces_mcp`]), on standard input and output or
//! over HTTP.
//!
//! Configuration ([`agentspaces::config::Config`]): the flags, then `ASPACE_*` variables, then
//! the fleet YAML.
//!
//! # Recipes
//!
//! The MCP hosts (Codex CLI, Claude Code, goose, Zed) start `aspace mcp`: their configuration
//! is in `aspace mcp --help` and in the [`agentspaces_mcp`] crate documentation. Elsewhere
//! `aspace` is a command like any other.
//!
//! cron, a report every morning (the visitor goes through a running `aspace daemon`, or joins
//! itself):
//!
//! ```text
//! 0 7 * * * aspace call report.Daily#v1 --json '{"team":"ops"}' --timeout 5m >> ~/reports.jsonl
//! ```
//!
//! GitHub Actions, a step that asks the fleet and fails the job on a refusal or a timeout (the
//! exit code is the contract's):
//!
//! ```yaml
//! - name: Ask the fleet
//!   env:
//!     ASPACE_SEEDS: tls://fleet.example.com:7500
//!     ASPACE_JOIN: ${{ vars.FLEET_GROUP }}
//!     ASPACE_KEYSTORE: ${{ runner.temp }}/keys
//!   run: aspace call review.Request#v1 --json @request.json --timeout 10m > review.json
//! ```
#![forbid(unsafe_code)]

mod cli;
mod commands;
mod daemon;
mod doctor;
mod exit;
mod io;
mod mcp;
mod resident;
mod session;
mod signals;
mod work;

use std::process::ExitCode;
use std::time::Duration;

/// How long the runtime waits, once the command is done, for tasks still running: a read of
/// standard input blocked on a thread (the stdio MCP server's, when its client keeps the pipe
/// open past a signal) cannot be cancelled and must not keep the process alive.
const RUNTIME_SHUTDOWN: Duration = Duration::from_millis(500);

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::exit::Failure;

fn main() -> ExitCode {
    let cli = Cli::parse();
    session::set_quiet(cli.global.quiet);
    init_tracing(cli.global.verbose, cli.global.quiet);
    let outcome = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let outcome = runtime.block_on(run(cli));
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
            outcome
        }
        Err(error) => Err(Failure::error(format!("cannot start the runtime: {error}"))),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if !failure.message.is_empty() {
                // Not eprintln!: a closed standard error must not turn the exit code into a
                // panic's 101.
                session::say(&format!("aspace: {}", failure.message));
            }
            ExitCode::from(failure.code)
        }
    }
}

/// Runs the command.
async fn run(mut cli: Cli) -> Result<(), Failure> {
    let global = &cli.global;
    if let Some(outcome) = session::through_daemon(global, &mut cli.command).await {
        return outcome;
    }
    match cli.command {
        Command::Id => commands::id(global),
        Command::Status { json } => commands::status(global, json).await,
        Command::Write {
            schema,
            json,
            space,
            lease,
            tags,
        } => commands::write(global, &schema, &json, space.as_deref(), lease, &tags).await,
        Command::Read {
            schema,
            clauses,
            tags,
            limit,
            timeout,
            space,
        } => {
            commands::read(
                global,
                &schema,
                &clauses,
                &tags,
                limit,
                timeout,
                space.as_deref(),
            )
            .await
        }
        Command::Take {
            schema,
            clauses,
            lease,
            timeout,
            space,
        } => commands::take(global, &schema, &clauses, lease, timeout, space.as_deref()).await,
        Command::Complete {
            id,
            json,
            produces,
            result_lease,
            tags,
            timeout,
            space,
        } => {
            commands::complete(
                global,
                &id,
                json.as_deref(),
                produces.as_deref(),
                result_lease,
                &tags,
                timeout,
                space.as_deref(),
            )
            .await
        }
        Command::Watch {
            schema,
            kinds,
            count,
            clauses,
            space,
        } => commands::watch(global, &schema, &kinds, count, &clauses, space.as_deref()).await,
        Command::Cards { json, only } => commands::cards(global, json, &only).await,
        Command::Call {
            target,
            json,
            timeout,
        } => commands::call(global, &target, json.as_deref(), timeout).await,
        Command::Work {
            take,
            space,
            produces,
            clauses,
            parallel,
            task_timeout,
            lease,
            grace,
            result_lease,
            name,
            action,
            description,
            env,
            command,
        } => {
            work::work(
                global,
                work::WorkOptions {
                    schema: take,
                    space,
                    produces,
                    clauses,
                    parallel,
                    task_timeout,
                    lease,
                    grace,
                    result_lease,
                    name,
                    action,
                    description,
                    env,
                    command,
                },
            )
            .await
        }
        Command::Daemon => daemon::daemon(global).await,
        Command::Mcp {
            http,
            tokens,
            jwt_issuer,
            jwt_audience,
            jwks,
            origins,
            allowed_hosts,
            allow_unauthenticated,
            only,
            policy,
            refresh,
            call_timeout,
        } => {
            mcp::mcp(
                global,
                mcp::McpOptions {
                    http,
                    tokens,
                    jwt_issuer,
                    jwt_audience,
                    jwks,
                    origins,
                    allowed_hosts,
                    allow_unauthenticated,
                    only,
                    policy,
                    refresh,
                    call_timeout,
                },
            )
            .await
        }
        Command::Doctor {
            json,
            tokens,
            policy,
        } => doctor::doctor(global, json, tokens.as_deref(), policy.as_deref()).await,
        Command::Completions { shell } => commands::completions(shell),
        Command::Man { out_dir } => commands::man(out_dir.as_deref()),
    }
}

/// Diagnostics of the library on standard error: warnings by default, more with `-v`, errors
/// only with `--quiet`. A failed take handler of `work` is said once, by `work` itself: the
/// library's own warning of it ([`HANDLER_LOG_TARGET`]) shows from `-v` on.
///
/// [`HANDLER_LOG_TARGET`]: agentspaces::agent::HANDLER_LOG_TARGET
fn init_tracing(verbose: u8, quiet: bool) {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt as _;

    let level = match (quiet, verbose) {
        (true, _) => tracing::Level::ERROR,
        (false, 0) => tracing::Level::WARN,
        (false, 1) => tracing::Level::INFO,
        (false, 2) => tracing::Level::DEBUG,
        (false, _) => tracing::Level::TRACE,
    };
    let handler = if verbose == 0 {
        LevelFilter::ERROR
    } else {
        LevelFilter::from_level(level)
    };
    let targets = Targets::new()
        .with_default(level)
        .with_target(agentspaces::agent::HANDLER_LOG_TARGET, handler);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .finish()
        .with(targets);
    let _ = tracing::subscriber::set_global_default(subscriber);
}
