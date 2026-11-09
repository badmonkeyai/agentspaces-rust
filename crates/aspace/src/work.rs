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

//! `aspace work`: a program per task taken, with no shell between, run
//! as an agent of the worker layer ([`agentspaces::agent`]).
//!
//! The worker binds one agent with one `take` binding ([`AgentBuilder::take_value`]) and
//! publishes its AgentCard: one declared `take` action, named `--action` (by default the simple
//! name of the `--take` schema), that consumes `--take`, produces `--produces`, in `--space`, so
//! `aspace cards`, `aspace call`, and every catalogue of the fleet find it. The agent is
//! `<peerId>/<--name>` (the action's name by default) under a renewing subordinate identity of the
//! keystore's peer, so its claims, completions, and results are AGENT_ATTESTED, and its card is
//! refreshed every 5 minutes until it stops (then it lapses with its 15-minute TTL).
//!
//! For each task a take loop holds (`--parallel` loops), the program runs in a process group of
//! its own with the entry's payload as JSON on standard input, `ASPACE_ENTRY_ID`,
//! `ASPACE_SCHEMA`, and `ASPACE_SPACE` set, and a minimal environment ([`INHERITED`] and each
//! `--env`). While it runs the take is renewed at half its lease ([`TakeContext::renew`], the Java
//! `TakeContext` keepalive), the first time at half of what the hold has left when that
//! is sooner (the claim was made a settle window before the program started); at
//! `--task-timeout` its group is killed. On exit 0 the first JSON object on standard output is
//! the result: the task completes with it under `--produces` (atomically, in the same space), or
//! without a result (the output is then read and discarded). Anything else (a non-zero exit, a
//! signal, the timeout, output that is not a JSON object, more than [`MAX_STDOUT`] bytes of it
//! under `--produces`, a hold lost while it ran) fails the handler, so nothing completes, the
//! lease lapses, and the task reappears for another worker. A program that exits leaving a child
//! that holds its standard output has its group killed, and what it printed counts. Standard
//! error passes through, each line prefixed with the entry id. A task whose entry id carries a
//! control character is refused without running anything (said once per id).
//!
//! SIGINT, SIGTERM, SIGHUP (a closed terminal or ssh session), or SIGQUIT stops taking
//! ([`Bound::request_stop`]); running programs finish within `--grace`, then each group is sent
//! SIGTERM and, 2 s later, SIGKILL (a second signal ends them so at once), the last completions
//! are confirmed with the seed, and the peer closes. A SIGKILL of the worker itself
//! leaves its programs running. A peer that gives up redialing its seeds stops the worker the
//! same way, with exit 1, so a supervisor can restart it; an agent found revoked stops with
//! exit 4.
//!
//! The worker is a member with its keystore's PeerID, and a seed takes every link of one PeerID
//! for one member: it marks its keystore ([`Resident`]) so a visitor run from the same keystore
//! says why it sees nothing, and how to fix it (a keystore of its own).
//!
//! [`AgentBuilder::take_value`]: agentspaces::agent::AgentBuilder::take_value
//! [`Bound::request_stop`]: agentspaces::agent::Bound::request_stop

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agentspaces::agent::{AgentError, HandlerError, Reply, TakeContext};
use agentspaces::json::{json_to_value, value_to_json};
use agentspaces::space::{EntryView, EventKind, Lease, Space, Template};
use rustix::process::{Pid, Signal, kill_process_group};
use serde_json::{Map as JsonMap, Value as Json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::cli::Global;
use crate::exit::Failure;
use crate::io::{self, printable};
use crate::resident::Resident;
use crate::session::{self, Session, note};
use crate::signals::Stop;

/// The most bytes of standard output a program run with `--produces` may print: 8 MiB, the most
/// a result entry's payload block carries. Past it the program's group is killed and the lease
/// lapses. Without `--produces` the output is read and discarded, however long.
pub const MAX_STDOUT: usize = 8 * 1024 * 1024;

/// The longest line of standard error passed through whole; a longer one is cut there.
const MAX_STDERR_LINE: usize = 64 * 1024;

/// The only variables a program inherits from this process (when set), besides `--env` and the
/// `ASPACE_*` of its task. Any other a program needs (`TZ`,
/// `TMPDIR`, `USER`, ...) is passed by name with `--env`.
pub const INHERITED: [&str; 3] = ["PATH", "HOME", "LANG"];

/// The longest agent or action name `--name` and `--action` take (the catalogue's longest
/// offering name, [`agentspaces::catalog::MAX_NAME`]).
pub const MAX_NAME: usize = agentspaces::catalog::MAX_NAME;

/// How long the pipes of an exited program may stay open (a child it left behind) before its
/// group is killed.
const DRAIN: Duration = Duration::from_millis(500);

/// How long after a completion it is confirmed with the seed when the worker stops.
const RECENT: Duration = Duration::from_secs(15);

/// How long the confirmation at the stop may take.
const FINAL_CONFIRM: Duration = Duration::from_secs(5);

/// How long the take loops have to end once running programs were killed (a waiting take ends
/// within its poll and settle window), before they are abandoned.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// How long a program's group has to end after SIGTERM, when the worker stops it, before it is
/// sent SIGKILL.
const TERM_WAIT: Duration = Duration::from_secs(2);

/// The shortest `--lease` a worker takes with: a claim is made a settle window (600 ms) and a
/// pull (up to 300 ms more) before the program starts, so a shorter hold would lapse, or come
/// close to it, before its first renewal.
pub const MIN_WORK_LEASE: Duration = Duration::from_secs(2);

/// How many entry ids a worker remembers: those it refused for a control character (said once
/// each) and the tasks it ran to completion (whose completions it notes).
const REMEMBERED: usize = 4096;

/// What `aspace work` runs.
#[derive(Debug, Clone)]
pub struct WorkOptions {
    /// The tasks' schema.
    pub schema: String,
    /// The space taken from (and written to).
    pub space: String,
    /// The result's schema.
    pub produces: Option<String>,
    /// Filter clauses on the tasks.
    pub clauses: Vec<String>,
    /// How many programs run at once.
    pub parallel: u16,
    /// How long one program may run.
    pub task_timeout: Duration,
    /// The take lease, renewed at half-life.
    pub lease: Lease,
    /// How long running programs may finish after a stop request.
    pub grace: Duration,
    /// The result lease.
    pub result_lease: Lease,
    /// The agent's local name (`--name`); the action's name when `None`.
    pub name: Option<String>,
    /// The action's name on the card (`--action`); the take schema's simple name when `None`.
    pub action: Option<String>,
    /// The agent's description on the card (`--description`).
    pub description: Option<String>,
    /// `--env` as given.
    pub env: Vec<String>,
    /// The program and its arguments.
    pub command: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// The worker

/// Where the worker is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Taking and running.
    Running,
    /// A stop was asked for: no new takes; running programs finish.
    Draining,
    /// The grace ran out, or a second signal came: running programs are killed.
    Killing,
}

/// What every run of the handler shares: the options, the program, its environment, the stop
/// phase, and the entry ids it remembers.
struct Shared {
    options: WorkOptions,
    program: PathBuf,
    env: Vec<(String, String)>,
    phase: watch::Receiver<Phase>,
    /// The tasks this process ran to an answer, whose completions [`watch_own`] notes.
    ran: Arc<Remembered>,
    /// The entry ids refused for a control character, each said once.
    refused: Remembered,
}

/// A bounded set of entry ids, the oldest forgotten first past [`REMEMBERED`].
#[derive(Debug, Default)]
struct Remembered(Mutex<(std::collections::HashSet<String>, VecDeque<String>)>);

impl Remembered {
    /// Remembers `id`; whether it is new.
    fn insert(&self, id: &str) -> bool {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (ids, order) = &mut *held;
        if ids.contains(id) {
            return false;
        }
        if order.len() >= REMEMBERED
            && let Some(oldest) = order.pop_front()
        {
            ids.remove(&oldest);
        }
        ids.insert(id.to_owned());
        order.push_back(id.to_owned());
        true
    }

    fn contains(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .contains(id)
    }
}

/// The ids of the worker's recent completions and results, confirmed with the seed when it
/// stops (closing a peer drops what it has not sent).
#[derive(Debug, Default)]
struct Recent(Mutex<VecDeque<(Instant, String)>>);

impl Recent {
    fn push(&self, id: String) {
        let mut recent = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        recent.retain(|(at, _)| at.elapsed() < RECENT);
        recent.push_back((Instant::now(), id));
    }

    fn ids(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(at, _)| at.elapsed() < RECENT)
            .map(|(_, id)| id.clone())
            .collect()
    }
}

/// The agent a worker binds, checked before joining.
struct Agent {
    name: String,
    action: String,
    description: String,
    template: Template,
}

/// Why the worker stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stopping {
    /// SIGINT, SIGTERM, SIGHUP, or SIGQUIT.
    Signal,
    /// The peer gave up redialing its seeds.
    GaveUp,
    /// Every take loop ended by itself: the agent was revoked, or the peer closed.
    OnItsOwn,
}

/// `aspace work`: checks the program and the names, joins, binds the agent, and runs until a stop
/// request.
pub async fn work(global: &Global, options: WorkOptions) -> Result<(), Failure> {
    crate::commands::check_schema(&options.schema)?;
    if let Some(produces) = &options.produces {
        crate::commands::check_schema(produces)?;
    }
    let template = crate::commands::template(&options.schema, &options.clauses)?;
    let Some((program, _)) = options.command.split_first() else {
        return Err(Failure::refused("name the program to run after --"));
    };
    let program = resolve_program(program)?;
    let env = program_env(&options.env)?;
    let action = match &options.action {
        Some(action) => checked_name(action, "--action")?,
        None => default_action(&options.schema),
    };
    let name = match &options.name {
        Some(name) => checked_name(name, "--name")?,
        None => action.clone(),
    };
    let description = options
        .description
        .clone()
        .unwrap_or_else(|| default_description(&program, &options.schema));
    let agent = Agent {
        name,
        action,
        description,
        template,
    };
    let session = Session::join(global).await?;
    // Later invocations on this keystore learn that it is this resident's PeerID.
    let resident = session
        .config
        .settings
        .keystore
        .as_deref()
        .and_then(|keystore| Resident::mark(keystore, "aspace work"));
    let outcome = serve(&session, options, program, env, agent).await;
    session.close().await;
    drop(resident);
    outcome
}

/// The bound worker's life, from the pull of its space to the confirmation of its last
/// completions.
async fn serve(
    session: &Session,
    options: WorkOptions,
    program: PathBuf,
    env: Vec<(String, String)>,
    agent: Agent,
) -> Result<(), Failure> {
    let peer = session.peer().clone();
    let space = session.fleet.space(&options.space);
    space.pull().await?;
    let agent_id = format!("{}/{}", peer.peer_id(), agent.name);
    // The agent's own completions and results, watched from before it binds: those of this
    // process only (the pull folds the space's history, earlier runs' completions included).
    let recent = Arc::new(Recent::default());
    let ran = Arc::new(Remembered::default());
    let own = watch_own(
        &space,
        &options,
        &agent_id,
        Arc::clone(&recent),
        Arc::clone(&ran),
    )
    .await?;
    let (phase_tx, phase) = watch::channel(Phase::Running);
    let shared = Arc::new(Shared {
        options: options.clone(),
        program,
        env,
        phase,
        ran,
        refused: Remembered::default(),
    });
    let handler = {
        let shared = Arc::clone(&shared);
        move |entry: EntryView, ctx: TakeContext| {
            let shared = Arc::clone(&shared);
            async move { run(&shared, entry, ctx).await }
        }
    };
    // From here SIGINT, SIGTERM, SIGHUP, and SIGQUIT ask for a stop instead of ending the
    // process (and orphaning the running programs).
    let mut stop = Stop::new()?;
    let bound = session
        .fleet
        .agent(&agent.name)
        .describe(agent.description.clone())
        .grace(options.grace)
        .take_value(
            &options.space,
            &options.schema,
            options.produces.clone(),
            options.lease,
            handler,
        )
        .action(agent.action.clone())
        .template(agent.template.clone())
        .parallel(usize::from(options.parallel))
        .result_lease(options.result_lease)
        .bind()
        .await
        .map_err(agent_failure)?;
    note(format!(
        "working as {} (action {}: {} -> {} in {}, on its card): running {} for each task, {} at \
         once",
        bound.agent_id(),
        agent.action,
        options.schema,
        options.produces.as_deref().unwrap_or("no result"),
        options.space,
        shared.program.display(),
        options.parallel
    ));
    let (gave_up_tx, mut gave_up) = watch::channel(false);
    let link_watch = tokio::spawn(crate::resident::watch_link(peer.subscribe(), gave_up_tx));

    let why = tokio::select! {
        () = bound.wait() => Stopping::OnItsOwn,
        () = stop.requested() => Stopping::Signal,
        _ = gave_up.wait_for(|gave_up| *gave_up) => Stopping::GaveUp,
    };
    let mut failure = None;
    match why {
        Stopping::OnItsOwn => {
            failure = Some(if peer.is_revoked(bound.agent_id()).await {
                Failure::auth(format!(
                    "{} is revoked; the worker stopped and its card lapses",
                    bound.agent_id()
                ))
            } else {
                Failure::error("the worker's take loops ended: the peer closed")
            });
        }
        Stopping::Signal | Stopping::GaveUp => {
            if why == Stopping::GaveUp {
                failure = Some(Failure::error(
                    "the peer gave up redialing the seeds (its reconnect window ran out)",
                ));
            } else {
                note(format!(
                    "stopping: no new tasks; running programs have {} to finish (a second \
                     signal kills them)",
                    session::millis_text(options.grace)
                ));
            }
            bound.request_stop();
            phase_tx.send_if_modified(|phase| advance(phase, Phase::Draining));
            let drained = tokio::select! {
                () = bound.wait() => true,
                () = async {
                    tokio::select! {
                        () = stop.requested() => {}
                        () = tokio::time::sleep(options.grace) => {}
                    }
                } => false,
            };
            if !drained {
                phase_tx.send_if_modified(|phase| advance(phase, Phase::Killing));
                if !bound.stop(KILL_WAIT).await {
                    note("a take loop did not end in time; it was abandoned");
                }
            }
        }
    }
    link_watch.abort();
    own.abort();
    let confirmed = session
        .confirm(&options.space, &recent.ids(), FINAL_CONFIRM)
        .await;
    note(format!(
        "stopped: {} tasks completed, {} failed",
        bound.handled(),
        bound.failures()
    ));
    match failure {
        Some(failure) => Err(failure),
        None => confirmed,
    }
}

/// What a bind refusal means for the exit code.
fn agent_failure(error: AgentError) -> Failure {
    match error {
        AgentError::Peer(error) => error.into(),
        AgentError::Space(error) => error.into(),
        AgentError::Invalid(why) => Failure::refused(why),
        other => Failure::error(other.to_string()),
    }
}

/// Notes the agent's completions (and their results) as the space folds them, for the
/// confirmation when the worker stops; the watches start before the agent binds. Only what this
/// process did counts: a completion of a task it ran (`ran`), and a result issued since it
/// started. The pull at the start folds the space's history, whose earlier completions under the
/// same AgentID (the keystore's) were not this run's.
async fn watch_own(
    space: &Space,
    options: &WorkOptions,
    agent_id: &str,
    recent: Arc<Recent>,
    ran: Arc<Remembered>,
) -> Result<JoinHandle<()>, Failure> {
    let mut tasks = space.watch(&Template::new(options.schema.clone())).await?;
    let mut results = match &options.produces {
        Some(schema) => Some(space.watch(&Template::new(schema.clone())).await?),
        None => None,
    };
    let agent = agent_id.to_owned();
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        });
    Ok(tokio::spawn(async move {
        loop {
            let result = async {
                match results.as_mut() {
                    Some(results) => results.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                event = tasks.next() => match event {
                    Some(event)
                        if event.kind == EventKind::Completed
                            && event.entry.holder() == Some(agent.as_str())
                            && ran.contains(event.entry.entry_id().as_str()) =>
                    {
                        note(format!(
                            "completed {}",
                            printable(event.entry.entry_id().as_str())
                        ));
                        recent.push(event.entry.entry_id().as_str().to_owned());
                    }
                    Some(_) => {}
                    None => return,
                },
                event = result => match event {
                    Some(event)
                        if event.kind == EventKind::Written
                            && event.entry.issuer() == agent
                            && issued_since(event.entry.issued(), started) =>
                    {
                        recent.push(event.entry.entry_id().as_str().to_owned());
                    }
                    Some(_) => {}
                    None => results = None,
                },
            }
        }
    }))
}

/// Whether an entry issued at the HLC stamp `issued` was issued at or after `started` (epoch
/// milliseconds); a stamp that does not parse counts.
fn issued_since(issued: &str, started: i64) -> bool {
    agentspaces::wire::hlc::Stamp::parse(issued).is_none_or(|stamp| stamp.physical >= started)
}

/// Moves the phase forward to `to` (never back); whether it changed.
fn advance(phase: &mut Phase, to: Phase) -> bool {
    let rank = |phase: &Phase| match phase {
        Phase::Running => 0,
        Phase::Draining => 1,
        Phase::Killing => 2,
    };
    if rank(&to) > rank(phase) {
        *phase = to;
        true
    } else {
        false
    }
}

/// How a program's run ended.
enum Ended {
    Exited(ExitStatus),
    TimedOut,
    Lost(String),
    Stopped,
    WaitFailed(std::io::Error),
}

/// Kills a program's process group when dropped: when its run ends, and when a worker that
/// stops abandons the run.
struct GroupGuard(Option<Pid>);

impl Drop for GroupGuard {
    fn drop(&mut self) {
        kill(self.0);
    }
}

/// The take handler: runs the program for one task and answers its result, or fails so the
/// task's lease lapses.
async fn run(shared: &Shared, entry: EntryView, ctx: TakeContext) -> Result<Reply, HandlerError> {
    let reply = run_program(shared, &entry, &ctx).await?;
    // A task this process ran: its completion, when it folds, is this run's to note.
    shared.ran.insert(entry.entry_id().as_str());
    Ok(reply)
}

/// [`run`]'s work: refuses an id it cannot pass on, starts the program, keeps the hold, and
/// reads what the program answered.
async fn run_program(
    shared: &Shared,
    entry: &EntryView,
    ctx: &TakeContext,
) -> Result<Reply, HandlerError> {
    let options = &shared.options;
    let id = entry.entry_id().as_str().to_owned();
    if unpassable(&id) {
        // A writer chooses its entry ids: one with a control character is neither printed nor
        // passed in the program's environment (a NUL could not be). Said once per id.
        let reason = "its entry id carries a control character, so no program runs for it";
        if shared.refused.insert(&id) {
            return Err(fail(&id, reason));
        }
        return Err(HandlerError::msg(reason));
    }
    let tag = short(&printable(&id));
    let mut phase = shared.phase.clone();
    if *phase.borrow() == Phase::Killing {
        return Err(fail(&id, "the worker is stopping, so it was not started"));
    }
    let input = match serde_json::to_vec(&value_to_json(entry.payload())) {
        Ok(mut input) => {
            input.push(b'\n');
            input
        }
        Err(error) => {
            return Err(fail(
                &id,
                &format!("its payload has no JSON form ({error})"),
            ));
        }
    };
    note(format!(
        "took {} ({}, attempt {})",
        printable(&id),
        printable(entry.schema()),
        ctx.attempt()
    ));
    let mut command = tokio::process::Command::new(&shared.program);
    command
        .args(options.command.iter().skip(1))
        .env_clear()
        .envs(INHERITED.iter().filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).to_owned(), value))
        }))
        .envs(shared.env.iter().cloned())
        .env("ASPACE_ENTRY_ID", &id)
        .env("ASPACE_SCHEMA", entry.schema())
        .env("ASPACE_SPACE", &options.space)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Err(fail(
                &id,
                &format!("{} did not start ({error})", shared.program.display()),
            ));
        }
    };
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(Pid::from_raw);
    let _guard = GroupGuard(group);
    if let Some(mut stdin) = child.stdin.take() {
        tokio::spawn(async move {
            // A program that does not read its input closes the pipe; that is its business.
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
    }
    // Without --produces nothing is wanted from standard output: it is read and discarded.
    let keep = options.produces.is_some();
    let stdout = child
        .stdout
        .take()
        .map(|stdout| tokio::spawn(capture(stdout, group, keep)));
    let stderr = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(pass_through(stderr, tag.clone())));

    let deadline = Instant::now() + options.task_timeout;
    let half = (options.lease.duration() / 2).max(Duration::from_millis(50));
    // The claim was made a settle window and a pull before the program started: the first
    // renewal comes at half of what the hold has left when that is sooner than half a lease.
    let left = ctx.hold_left().await;
    let mut renew_at = Instant::now() + (left / 2).min(half);
    let ended = loop {
        tokio::select! {
            status = child.wait() => break match status {
                Ok(status) => Ended::Exited(status),
                Err(error) => Ended::WaitFailed(error),
            },
            () = tokio::time::sleep_until(deadline) => {
                kill(group);
                let _ = child.wait().await;
                break Ended::TimedOut;
            }
            () = tokio::time::sleep_until(renew_at) => match ctx.renew().await {
                Ok(_) => renew_at = Instant::now() + half,
                Err(error) => {
                    kill(group);
                    let _ = child.wait().await;
                    break Ended::Lost(error.to_string());
                }
            },
            () = killing(&mut phase) => {
                end_group(group, &mut child).await;
                break Ended::Stopped;
            }
        }
    };
    // The program is gone. A child it left may still hold its standard output: then its group
    // is killed, which closes the pipe, and what was printed is read to its end.
    let captured = match stdout {
        Some(mut reader) => match tokio::time::timeout(DRAIN, &mut reader).await {
            Ok(Ok(captured)) => Some(captured),
            Ok(Err(_)) => None,
            Err(_) => {
                kill(group);
                match tokio::time::timeout(DRAIN, &mut reader).await {
                    Ok(Ok(captured)) => Some(captured),
                    _ => {
                        reader.abort();
                        None
                    }
                }
            }
        },
        None => None,
    };
    kill(group);
    if let Some(mut reader) = stderr
        && tokio::time::timeout(DRAIN, &mut reader).await.is_err()
    {
        reader.abort();
        tracing::debug!(id, "standard error still open after the program ended");
    }

    let status = match ended {
        Ended::Exited(status) => status,
        Ended::TimedOut => {
            let limit = session::millis_text(options.task_timeout);
            return Err(fail(
                &id,
                &format!("ran past --task-timeout {limit}; its process group was killed"),
            ));
        }
        Ended::Lost(why) => {
            return Err(fail(
                &id,
                &format!("its hold could not be renewed ({why}); it was killed"),
            ));
        }
        Ended::Stopped => {
            return Err(fail(
                &id,
                "the worker stopped before it ended; it was killed (SIGTERM, then SIGKILL \
                 2s later)",
            ));
        }
        Ended::WaitFailed(error) => {
            return Err(fail(&id, &format!("it could not be waited for ({error})")));
        }
    };
    // The cap first: a program killed for it ends with SIGKILL, which would hide why.
    if captured
        .as_ref()
        .is_some_and(|captured| captured.overflowed)
    {
        return Err(fail(
            &id,
            &format!(
                "it printed more than {MAX_STDOUT} bytes on standard output (the most a result \
                 carries); its process group was killed"
            ),
        ));
    }
    if !status.success() {
        return Err(fail(&id, &format!("it ended with {status}")));
    }
    let Some(Captured { bytes, .. }) = captured else {
        return Err(fail(
            &id,
            "its standard output could not be read to its end",
        ));
    };
    match &options.produces {
        None => Ok(Reply::none()),
        Some(schema) => {
            let Some(object) = first_object(&bytes) else {
                return Err(fail(
                    &id,
                    "it exited 0 but printed no JSON object on standard output",
                ));
            };
            let hint = io::widths_hint(ctx.space(), schema).await;
            match json_to_value(&Json::Object(object), hint.as_ref()) {
                Ok(value) => Ok(Reply::value(schema.clone(), value)),
                Err(error) => Err(fail(&id, &format!("its result is refused ({error})"))),
            }
        }
    }
}

/// Whether an entry id cannot be printed or passed to a program (`ASPACE_ENTRY_ID`): it carries
/// a control character (an escape sequence for the terminal, a NUL no environment holds). A
/// writer chooses its entry ids.
fn unpassable(id: &str) -> bool {
    id.chars().any(char::is_control)
}

/// Ends a program's group when the worker stops: SIGTERM, so it can clean up, then SIGKILL past
/// [`TERM_WAIT`].
async fn end_group(group: Option<Pid>, child: &mut tokio::process::Child) {
    signal_group(group, Signal::TERM);
    if tokio::time::timeout(TERM_WAIT, child.wait()).await.is_err() {
        kill(group);
        let _ = child.wait().await;
    }
}

/// The default action name: the simple name of the take schema (`shop.ConvertRequest#v1` is
/// `ConvertRequest`, `a.Outer$Inner#v1` is `Inner`).
pub fn default_action(schema: &str) -> String {
    let class = schema.split_once('#').map_or(schema, |(class, _)| class);
    let simple = class
        .rsplit(['.', '$'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(class);
    simple.chars().take(MAX_NAME).collect()
}

/// The card's default description: the program's file name and the schema it works on (never
/// the program's full path, which the whole fleet would read).
fn default_description(program: &Path, schema: &str) -> String {
    let file = program.file_name().map_or_else(
        || "a program".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    format!(
        "Runs {file} for each {} (aspace work)",
        default_action(schema)
    )
}

/// An agent or action name as given: trimmed, not empty, without `/` (an AgentID's separator)
/// or control characters, at most [`MAX_NAME`] characters; refused (exit 2) before joining.
pub fn checked_name(name: &str, flag: &str) -> Result<String, Failure> {
    let name = name.trim();
    if name.is_empty()
        || name.contains('/')
        || name.chars().any(char::is_control)
        || name.chars().count() > MAX_NAME
    {
        return Err(Failure::refused(format!(
            "{flag} {name:?}: write a name of at most {MAX_NAME} characters, without '/' or \
             control characters"
        )));
    }
    Ok(name.to_owned())
}

/// Resolves when the phase reaches [`Phase::Killing`]; never when the phase can no longer change.
async fn killing(phase: &mut watch::Receiver<Phase>) {
    let reached = phase
        .wait_for(|phase| *phase == Phase::Killing)
        .await
        .is_ok();
    if !reached {
        std::future::pending::<()>().await;
    }
}

/// Says why a task failed and answers the error that lets its lease lapse: the worker layer
/// completes nothing for a handler that fails, so the task reappears for another worker.
fn fail(id: &str, reason: &str) -> HandlerError {
    note(format!(
        "task {} failed: {reason}; its lease lapses and the task reappears",
        printable(id)
    ));
    HandlerError::msg(reason.to_owned())
}

/// SIGKILL to a program's process group; a group already gone is no error.
fn kill(group: Option<Pid>) {
    signal_group(group, Signal::KILL);
}

/// `signal` to a program's process group; a group already gone is no error.
fn signal_group(group: Option<Pid>, signal: Signal) {
    if let Some(group) = group
        && let Err(error) = kill_process_group(group, signal)
        && error != rustix::io::Errno::SRCH
    {
        tracing::debug!(%error, "signal the process group");
    }
}

/// What a program printed on standard output.
struct Captured {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// Reads standard output up to [`MAX_STDOUT`]; past it, kills the group and stops reading.
/// Without `keep` (no result is wanted) every byte is read and discarded, with no cap.
async fn capture(
    mut stdout: tokio::process::ChildStdout,
    group: Option<Pid>,
    keep: bool,
) -> Captured {
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match stdout.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                return Captured {
                    bytes,
                    overflowed: false,
                };
            }
            Ok(_) if !keep => {}
            Ok(read) => {
                if bytes.len() + read > MAX_STDOUT {
                    kill(group);
                    return Captured {
                        bytes,
                        overflowed: true,
                    };
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

/// Copies standard error to this process's, each line prefixed with `[tag] `.
async fn pass_through(stderr: tokio::process::ChildStderr, tag: String) {
    let mut reader = BufReader::new(stderr);
    let mut line = Vec::new();
    loop {
        line.clear();
        let mut limited = (&mut reader).take(MAX_STDERR_LINE as u64);
        match limited.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                // A closed standard error loses the line; the program runs on.
                session::say(&format!("[{tag}] {}", text.trim_end_matches(['\n', '\r'])));
            }
        }
    }
}

/// The first JSON object of a program's output: from the first line that starts with `{` (after
/// spaces), the first JSON value, which must be an object. Lines before it (stray output) are
/// skipped; `None` when no line starts an object or the value there is not one.
pub fn first_object(bytes: &[u8]) -> Option<JsonMap<String, Json>> {
    let mut offset = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if let Some(start) = line.iter().position(|byte| !byte.is_ascii_whitespace())
            && line[start] == b'{'
        {
            let mut values =
                serde_json::Deserializer::from_slice(&bytes[offset + start..]).into_iter::<Json>();
            return match values.next() {
                Some(Ok(Json::Object(object))) => Some(object),
                _ => None,
            };
        }
        offset += line.len();
    }
    None
}

/// The first 8 characters of an entry id, for the prefix of a program's standard error.
fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

/// The program to run: a path with a `/` as given, else the first match on `PATH`; it must be an
/// executable file (checked before joining, so a typo is refused at once, exit 2).
pub fn resolve_program(program: &str) -> Result<PathBuf, Failure> {
    let executable = |path: &Path| -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        let path = PathBuf::from(program);
        return if executable(&path) {
            std::path::absolute(&path)
                .map_err(|error| Failure::refused(format!("cannot resolve {program}: {error}")))
        } else {
            Err(Failure::refused(format!(
                "{program} is not an executable file; write the program's path (a script needs \
                 its #! line and chmod +x)"
            )))
        };
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| executable(candidate))
        .ok_or_else(|| Failure::refused(format!("{program} is not on PATH")))
}

/// `--env NAME` (from this environment; skipped with a note when unset) and `--env NAME=VALUE`.
pub fn program_env(flags: &[String]) -> Result<Vec<(String, String)>, Failure> {
    let mut env = Vec::new();
    for flag in flags {
        let (name, value) = match flag.split_once('=') {
            Some((name, value)) => (name.to_owned(), Some(value.to_owned())),
            None => (flag.clone(), None),
        };
        let well_formed = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.as_bytes()[0].is_ascii_digit();
        if !well_formed {
            return Err(Failure::refused(format!(
                "--env {flag:?}: write NAME or NAME=VALUE, NAME of letters, digits, and _"
            )));
        }
        match value.or_else(|| std::env::var(&name).ok()) {
            Some(value) => env.push((name, value)),
            None => note(format!("--env {name}: not set here, so not passed")),
        }
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_object_starts_the_first_line_that_opens_one() {
        let object =
            |text: &str| first_object(text.as_bytes()).map(|o| Json::Object(o).to_string());
        assert_eq!(object("{\"a\":1}\n"), Some("{\"a\":1}".into()));
        assert_eq!(
            object("log line\n  {\"a\": [1, 2]}\n{\"b\":2}\n"),
            Some("{\"a\":[1,2]}".into())
        );
        assert_eq!(
            object("{\n  \"a\": 1\n}\n"),
            Some("{\"a\":1}".into()),
            "pretty-printed"
        );
        assert_eq!(object("{\"a\":1} trailing words"), Some("{\"a\":1}".into()));
        assert_eq!(object(""), None);
        assert_eq!(object("[1, 2]\n"), None);
        assert_eq!(
            object("{not json}\n{\"a\":1}\n"),
            None,
            "the first object must parse"
        );
        assert_eq!(object("done\n"), None);
    }

    /// An entry id is its writer's text: one with a control character (ESC, NUL)
    /// is refused before any program runs, said once, and every id printed is made printable.
    #[test]
    fn writer_chosen_ids_are_checked_and_printed_safely() {
        for bad in [
            "a\u{1b}]0;title\u{7}",
            "nul\0id",
            "csi\u{9b}2J",
            "line\nbreak",
        ] {
            assert!(unpassable(bad), "{bad:?}");
        }
        assert!(!unpassable("6054f3c0-e8aa-4d98-ba65-c2d6f3884a42"));
        assert!(!unpassable("résumé-ok"));
        let refused = Remembered::default();
        assert!(refused.insert("nul\0id"), "said the first time");
        assert!(!refused.insert("nul\0id"), "not again");
        assert_eq!(short(&printable("\u{1b}[31mred\0x")), " [31mred");
        assert_eq!(printable("\u{1b}]0;owned\u{7}"), " ]0;owned ");
    }

    /// A program inherits PATH, HOME, and LANG, nothing else unless `--env` names it.
    #[test]
    fn the_inherited_environment_is_the_allowlist() {
        assert_eq!(INHERITED, ["PATH", "HOME", "LANG"]);
    }

    /// The ids remembered are bounded, the oldest forgotten first; results count from the
    /// worker's start.
    #[test]
    fn remembered_ids_are_bounded_and_results_count_from_the_start() {
        let ran = Remembered::default();
        for n in 0..=REMEMBERED {
            assert!(ran.insert(&format!("t{n}")));
        }
        assert!(!ran.contains("t0"), "the oldest is forgotten");
        assert!(ran.contains(&format!("t{REMEMBERED}")));
        assert!(issued_since("1700000000500:0:zPeer", 1_700_000_000_000));
        assert!(issued_since("1700000000000:3:zPeer", 1_700_000_000_000));
        assert!(!issued_since("1699999999999:9:zPeer", 1_700_000_000_000));
        assert!(issued_since("not a stamp", 1_700_000_000_000));
    }

    #[test]
    fn the_phase_only_moves_forward() {
        let mut phase = Phase::Running;
        assert!(advance(&mut phase, Phase::Draining));
        assert!(!advance(&mut phase, Phase::Draining));
        assert!(advance(&mut phase, Phase::Killing));
        assert!(!advance(&mut phase, Phase::Draining));
        assert_eq!(phase, Phase::Killing);
    }

    #[test]
    fn env_flags_are_names_or_assignments() {
        let env = program_env(&["A=1".into(), "B_2=x=y".into()]).expect("parses");
        assert_eq!(
            env,
            [("A".into(), "1".into()), ("B_2".into(), "x=y".into())]
        );
        for bad in ["", "=x", "1A=2", "A-B=3"] {
            assert!(program_env(&[bad.to_owned()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn actions_default_to_the_simple_name_of_the_schema() {
        assert_eq!(default_action("shop.ConvertRequest#v1"), "ConvertRequest");
        assert_eq!(
            default_action("ai.badmonkey.agentspaces.interop.Seed$Task#v1"),
            "Task"
        );
        assert_eq!(default_action("Plain#v2"), "Plain");
        assert_eq!(default_action("trailing.#v1"), "trailing.");
        let description = default_description(Path::new("/opt/secret/dir/convert.sh"), "a.B#v1");
        assert_eq!(description, "Runs convert.sh for each B (aspace work)");
        assert!(!description.contains("secret"), "no path reaches the card");
    }

    #[test]
    fn names_are_checked_before_joining() {
        assert_eq!(
            checked_name(" research ", "--action").as_deref(),
            Ok("research")
        );
        for bad in ["", "  ", "a/b", "tab\there", &"x".repeat(MAX_NAME + 1)] {
            let error = checked_name(bad, "--name").expect_err(bad);
            assert_eq!(error.code, crate::exit::REFUSED);
        }
    }

    #[test]
    fn programs_are_resolved_before_joining() {
        assert!(resolve_program("sh").is_ok());
        assert!(resolve_program("/bin/sh").is_ok());
        let error = resolve_program("/no/such/program").expect_err("missing");
        assert_eq!(error.code, crate::exit::REFUSED);
        let error = resolve_program("no-such-program-anywhere-1234").expect_err("not on PATH");
        assert!(error.message.contains("not on PATH"));
    }
}
