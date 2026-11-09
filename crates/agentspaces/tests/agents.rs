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

//! The worker layer ([`agentspaces::agent`]) and remote actions ([`agentspaces::remote`]) over
//! the in-memory network: Rust peers joined through one relaying fake seed
//! (`support::FakeSeed::start_relay`), which forwards every rumor (space states, claims, and the
//! `ads` stream's cards) to the other members and answers their space pulls.
//!
//! Workers: a typed worker's takes completed with results under its agent identity; an error
//! (and a panic) letting the entry reappear for another worker; forks, tagged results, nothing,
//! and a fork inside a fork; value-level takes and deduplicated reactions; `keepalive` holding a
//! long handler's take past its lease and stopping after; a graceful stop that lets a running
//! handler finish and takes nothing new, and one that abandons a handler past its grace; bind-time
//! refusals. Cards: published in Java's shape, seen by another peer and its remote actions,
//! refreshed on a short cadence, and gone (with the agent stopped) after the agent's revocation.
//! Remote actions: an invocation answered by the correlated result past a decoy, typed, and a
//! timeout that leaves the input leased.
//!
//! The last test runs a Rust worker against the Java reference (the interop seed of
//! `interop/java-seed`): Java writes tasks, the bound Rust agent takes and completes them
//! agent-attested, and Java reads the results and the completions. It passes with a note when
//! Java cannot run, unless `ASPACE_INTEROP_REQUIRED=1`.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces::Entry;
use agentspaces::agent::{
    AgentCard, AgentError, HandlerError, NotifyContext, Reply, Tagged, TakeContext,
};
use agentspaces::clock::{Clock, SharedClock, SystemClock};
use agentspaces::group::GroupSpec;
use agentspaces::peer::Peer;
use agentspaces::remote::RemoteActions;
use agentspaces::space::{
    Attestation, EntryView, EventKind, Fleet, Lease, Space, SpaceError, Template, TypedView,
};
use agentspaces::transport::memory::MemoryNetwork;
use agentspaces::wire::bodies::{self, KIND_RUMOR, RUMOR_HOPS};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::cbor_map;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::{ids, revocation, time};
use serde::{Deserialize, Serialize};
use support::{FakeSeed, PATIENCE, config, eventually};
use tokio::sync::mpsc;

const SEED: &str = "127.0.0.1:7900";
const FOUNDING: &str = "agentspaces-rust-agents";
const SPACE: &str = "tasks";
/// The settle window of the takes here (a Java space's 200 ms).
const SETTLE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Task#v1")]
struct Task {
    topic: String,
    priority: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "com.acme.Report#v1")]
struct Report {
    topic: String,
    summary: String,
    worker: String,
}

fn system() -> SharedClock {
    Arc::new(SystemClock)
}

fn group_id() -> String {
    ids::group_id_from_founding(FOUNDING.as_bytes())
}

fn lease(text: &str) -> Lease {
    Lease::parse(text).expect("a lease")
}

fn task(topic: &str) -> Task {
    Task {
        topic: topic.to_owned(),
        priority: 1,
    }
}

fn report(topic: &str, worker: &str) -> Report {
    Report {
        topic: topic.to_owned(),
        summary: format!("did {topic}"),
        worker: worker.to_owned(),
    }
}

/// A relaying seed on a fresh network.
struct Net {
    network: MemoryNetwork,
    seed: FakeSeed,
}

impl Net {
    fn new() -> Net {
        let network = MemoryNetwork::new();
        let seed = FakeSeed::start_relay(&network, SEED, &group_id(), system());
        Net { network, seed }
    }

    /// A member joined through the seed, and its identity.
    async fn member(&self) -> (Fleet, Identity) {
        let identity = Identity::generate().expect("identity");
        let peer = Peer::start(config(
            &self.network,
            identity.clone(),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
            &[SEED],
            system(),
        ))
        .await
        .expect("the peer starts");
        (Fleet::from_peer(peer), identity)
    }

    /// Revokes `agent` with a key-compromise revocation its own peer `issuer` signs, rumored by
    /// the seed to every member.
    async fn revoke_agent(&self, issuer: &Identity, agent: &str) {
        let now = SystemClock.now_ms();
        let ad = revocation::credential_revocation(
            issuer.peer_id(),
            &group_id(),
            &time::instant_iso(now - 1000),
            "PT720H",
            &revocation::agent_target(agent),
            revocation::KEY_COMPROMISE,
            None,
        )
        .expect("a credential revocation");
        let signed = Value::Map(revocation::sign_revocation(&ad, issuer));
        let body = bodies::rumor_body(
            revocation::CREDENTIAL_STREAM,
            &format!("revoke:{agent}"),
            RUMOR_HOPS,
            &cbor::encode(&signed),
        );
        self.seed.broadcast(KIND_RUMOR, &body).await;
    }
}

/// The reports `space` reads (available ones).
async fn reports(space: &Space) -> Vec<TypedView<Report>> {
    space
        .read_all_typed::<Report>(&Template::of::<Report>(), 100)
        .await
        .expect("read reports")
}

/// Waits until `space` reads a report on `topic`, and answers it.
async fn report_on(space: &Space, topic: &str) -> TypedView<Report> {
    let wanted = Template::of::<Report>().where_clause(&format!("topic={topic}"));
    let wanted = wanted.expect("a clause");
    space
        .read_typed::<Report>(&wanted, PATIENCE)
        .await
        .expect("read")
        .unwrap_or_else(|| panic!("no report on {topic} in time"))
}

/// The view of the task `topic` as `space` holds it, whatever its state.
async fn task_view(space: &Space, topic: &str, id: &agentspaces::space::EntryId) -> EntryView {
    space
        .get(id)
        .await
        .expect("get")
        .unwrap_or_else(|| panic!("the task {topic} is held"))
}

// ------------------------------------------------------------------------------- workers

/// A typed worker takes every task, completes each with a report under its own agent identity
/// (AGENT_ATTESTED), and counts what it handled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_typed_worker_serves_takes_and_completes_with_results() {
    let net = Net::new();
    let (worker, worker_identity) = net.member().await;
    let (writer, _) = net.member().await;
    let bound = worker
        .agent("worker")
        .describe("works tasks")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("30s"),
            |task: Task, ctx: TakeContext| async move {
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            },
        )
        .action("work")
        .produces::<Report>()
        .parallel(2)
        .bind()
        .await
        .expect("bind");
    assert_eq!(bound.agent_id(), worker_identity.agent("worker"));
    assert!(bound.is_running());

    let tasks = writer.space(SPACE);
    let mut ids = Vec::new();
    for topic in ["a", "b", "c"] {
        let id = tasks
            .write(&task(topic), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
        ids.push((topic, id));
    }
    eventually("three reports", || async {
        reports(&tasks).await.len() == 3
    })
    .await;
    for report in reports(&tasks).await {
        assert_eq!(report.value().worker, bound.agent_id());
        assert_eq!(report.view().issuer(), bound.agent_id());
        assert_eq!(report.view().attestation(), Attestation::AgentAttested);
    }
    for (topic, id) in &ids {
        let held = &id;
        eventually("the completion", || async {
            task_view(&tasks, topic, held).await.completed()
        })
        .await;
        let view = task_view(&tasks, topic, id).await;
        assert_eq!(view.holder(), Some(bound.agent_id()));
    }
    eventually("three handled", || async { bound.handled() == 3 }).await;
    assert_eq!(bound.failures(), 0);
    assert!(bound.stop(Duration::from_secs(5)).await);
    assert!(!bound.is_running());
}

/// A handler that fails completes nothing: the take's hold lapses and the entry reappears, and
/// another worker takes it as its second attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_error_lets_the_entry_reappear_for_another_worker() {
    let net = Net::new();
    let (a, _) = net.member().await;
    let (b, _) = net.member().await;
    let (writer, _) = net.member().await;
    let (calls_tx, mut calls) = mpsc::unbounded_channel();
    let flaky = a
        .agent("flaky")
        .settle(SETTLE)
        .take(SPACE, lease("1s"), move |_task: Task, ctx: TakeContext| {
            let calls = calls_tx.clone();
            async move {
                let _ = calls.send(ctx.attempt());
                Err::<Reply, _>(HandlerError::msg("not today"))
            }
        })
        .bind()
        .await
        .expect("bind flaky");
    let tasks = writer.space(SPACE);
    let id = tasks
        .write(&task("retry"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let attempt = tokio::time::timeout(PATIENCE, calls.recv())
        .await
        .expect("the flaky handler runs")
        .expect("a call");
    assert_eq!(attempt, 1);
    assert!(flaky.stop(Duration::from_secs(5)).await);
    assert!(flaky.failures() >= 1);
    // Nothing completed it: it is held (until its hold lapses) and not completed.
    assert!(!task_view(&tasks, "retry", &id).await.completed());

    let steady = b
        .agent("steady")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("30s"),
            |task: Task, ctx: TakeContext| async move {
                let mut done = report(&task.topic, ctx.agent_id());
                done.summary = format!("attempt {}", ctx.attempt());
                Ok(Reply::from(done))
            },
        )
        .bind()
        .await
        .expect("bind steady");
    let answered = report_on(&tasks, "retry").await;
    assert_eq!(answered.value().worker, steady.agent_id());
    // A later attempt: the flaky loop's take already in flight when it was stopped may have
    // claimed the lapsed entry once more (and failed again), as Java's loop would.
    let attempt: i64 = answered
        .value()
        .summary
        .trim_start_matches("attempt ")
        .parse()
        .expect("an attempt number");
    assert!(attempt >= 2, "attempt {attempt}");
    eventually("the completion by steady", || async {
        task_view(&tasks, "retry", &id).await.holder() == Some(steady.agent_id())
    })
    .await;
    steady.stop(Duration::from_secs(5)).await;
}

/// A panicking handler is a failure like an error: the loop goes on and takes the next task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_handler_is_a_failure_and_the_loop_goes_on() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (writer, _) = net.member().await;
    let bound = worker
        .agent("brittle")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("1s"),
            |task: Task, ctx: TakeContext| async move {
                assert_ne!(task.topic, "boom", "the handler gives up");
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            },
        )
        .bind()
        .await
        .expect("bind");
    let tasks = writer.space(SPACE);
    tasks
        .write(&task("boom"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write boom");
    eventually("the panic counted", || async { bound.failures() >= 1 }).await;
    tasks
        .write(&task("fine"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write fine");
    report_on(&tasks, "fine").await;
    assert!(bound.is_running());
    bound.stop(Duration::from_secs(5)).await;
}

/// The return conventions: a fork completes once and writes each element (a tagged one with
/// its tags, nothing for none); a tagged result carries its tags; nothing completes without a
/// result; a fork inside a fork is refused where it stands, after the elements before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fork_tagged_and_nothing_replies_follow_the_java_binder() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (writer, _) = net.member().await;
    let bound = worker
        .agent("forker")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("30s"),
            |task: Task, ctx: TakeContext| async move {
                let me = ctx.agent_id().to_owned();
                Ok(match task.topic.as_str() {
                    "fork" => Reply::fork([
                        Reply::from(report("fork-1", &me)),
                        Tagged::new(report("fork-2", &me), [("lane", "b")]).into(),
                        Reply::none(),
                    ]),
                    "tagged" => Tagged::new(report("tagged", &me), [("claimId", "c-1")]).into(),
                    "nested" => Reply::fork([
                        Reply::from(report("nested-1", &me)),
                        Reply::fork([report("nested-x", &me)]),
                        Reply::from(report("nested-2", &me)),
                    ]),
                    _ => Reply::none(),
                })
            },
        )
        .produces::<Report>()
        .bind()
        .await
        .expect("bind");
    let tasks = writer.space(SPACE);
    let mut ids = Vec::new();
    for topic in ["fork", "tagged", "none", "nested"] {
        let id = tasks
            .write(&task(topic), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write");
        ids.push((topic, id));
    }
    for (topic, id) in &ids {
        eventually("every task completed", || async {
            task_view(&tasks, topic, id).await.completed()
        })
        .await;
    }
    let fork_2 = report_on(&tasks, "fork-2").await;
    assert_eq!(fork_2.view().tag("lane"), Some("b"));
    let fork_1 = report_on(&tasks, "fork-1").await;
    assert!(fork_1.view().tags().is_empty());
    let tagged = report_on(&tasks, "tagged").await;
    assert_eq!(tagged.view().tag("claimId"), Some("c-1"));
    report_on(&tasks, "nested-1").await;
    eventually("the nested fork counted", || async {
        bound.failures() == 1
    })
    .await;
    let topics: Vec<String> = reports(&tasks)
        .await
        .into_iter()
        .map(|r| r.into_value().topic)
        .collect();
    assert!(!topics.contains(&"nested-x".to_owned()));
    assert!(!topics.contains(&"nested-2".to_owned()));
    assert_eq!(
        topics.len(),
        4,
        "fork-1, fork-2, tagged, nested-1: {topics:?}"
    );
    assert_eq!(bound.handled(), 3);
    bound.stop(Duration::from_secs(5)).await;
}

/// The value-level twins: a take of raw entries completing with `Reply::payload` in the declared
/// produced schema, and a reaction that runs once per written entry and writes its result into
/// the watched space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn value_level_takes_and_reactions() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (writer, _) = net.member().await;
    let reactions = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&reactions);
    let bound = worker
        .agent("valued")
        .settle(SETTLE)
        .take_value(
            SPACE,
            Task::SCHEMA,
            Some(Report::SCHEMA.to_owned()),
            lease("30s"),
            |entry: EntryView, ctx: TakeContext| async move {
                assert_eq!(ctx.produces(), Some(Report::SCHEMA));
                let topic = entry.payload().get("topic").cloned().unwrap_or(Value::Null);
                Ok(Reply::payload(
                    cbor_map! { "topic" => topic, "summary" => "valued", "worker" => "value" },
                ))
            },
        )
        .notify_value(
            "audit",
            Task::SCHEMA,
            Some(Report::SCHEMA.to_owned()),
            move |entry: EntryView, ctx: NotifyContext| {
                let counted = Arc::clone(&counted);
                async move {
                    assert_eq!(ctx.kind(), EventKind::Written);
                    counted.fetch_add(1, Ordering::SeqCst);
                    let topic = entry.payload().get("topic").cloned().unwrap_or(Value::Null);
                    Ok(Reply::payload(
                        cbor_map! { "topic" => topic, "summary" => "audited", "worker" => "audit" },
                    ))
                }
            },
        )
        .bind()
        .await
        .expect("bind");
    let tasks = writer.space(SPACE);
    tasks
        .write(&task("raw"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(report_on(&tasks, "raw").await.value().summary, "valued");

    let audit = writer.space("audit");
    for topic in ["x", "y"] {
        audit
            .write(&task(topic), Lease::DEFAULT_WRITE, Map::new())
            .await
            .expect("write audit");
    }
    assert_eq!(report_on(&audit, "x").await.value().summary, "audited");
    report_on(&audit, "y").await;
    // Once per entry: the reactions stay at two while the space settles.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(reactions.load(Ordering::SeqCst), 2);
    assert_eq!(reports(&audit).await.len(), 2);
    bound.stop(Duration::from_secs(5)).await;
}

/// The typed reaction: `notify::<T>` passes over entries that do not decode as `T`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_typed_reaction_writes_its_result() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (writer, _) = net.member().await;
    let bound = worker
        .agent("watcher")
        .notify("audit", |task: Task, ctx: NotifyContext| async move {
            Ok(Reply::from(report(&task.topic, ctx.space().name())))
        })
        .produces::<Report>()
        .bind()
        .await
        .expect("bind");
    let audit = writer.space("audit");
    // Of the task's schema but not its shape: passed over.
    audit
        .write_value(
            Task::SCHEMA,
            cbor_map! { "topic" => 7 },
            Lease::DEFAULT_WRITE,
            Map::new(),
        )
        .await
        .expect("write odd");
    audit
        .write(&task("typed"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(report_on(&audit, "typed").await.value().worker, "audit");
    assert_eq!(reports(&audit).await.len(), 1);
    bound.stop(Duration::from_secs(5)).await;
}

/// `keepalive` renews the hold every half lease while the work runs, so another member cannot
/// take the entry past the original lease; once the work ends the renewals stop and the hold
/// lapses (here while the handler still runs, so the other member takes it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_holds_a_long_take_and_stops_when_the_work_ends() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (other, _) = net.member().await;
    let (signals_tx, mut signals) = mpsc::unbounded_channel();
    let bound = worker
        .agent("patient")
        .settle(SETTLE)
        .take(SPACE, lease("1s"), move |_task: Task, ctx: TakeContext| {
            let signals = signals_tx.clone();
            async move {
                let _ = signals.send("started");
                ctx.keepalive(tokio::time::sleep(Duration::from_millis(2500)))
                    .await;
                let _ = signals.send("kept");
                tokio::time::sleep(Duration::from_secs(4)).await;
                Err::<Reply, _>(HandlerError::msg("gave up after the keepalive"))
            }
        })
        .bind()
        .await
        .expect("bind");
    let writer = other.space(SPACE).with_settle(SETTLE);
    let id = writer
        .write(&task("long"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    assert_eq!(next_signal(&mut signals).await, "started");
    // Past the 1 s lease, the take is still held.
    let during = writer
        .take(
            &Template::of::<Task>(),
            lease("30s"),
            Duration::from_millis(1800),
        )
        .await
        .expect("take");
    assert!(during.is_none(), "the keepalive holds the take");
    assert_eq!(
        writer
            .get(&id)
            .await
            .expect("get")
            .and_then(|v| v.holder().map(str::to_owned)),
        Some(bound.agent_id().to_owned())
    );
    assert_eq!(next_signal(&mut signals).await, "kept");
    // The renewals stopped with the work: the hold lapses while the handler sleeps on.
    let after = writer
        .take(
            &Template::of::<Task>(),
            lease("30s"),
            Duration::from_secs(4),
        )
        .await
        .expect("take")
        .expect("the other member takes the lapsed entry");
    assert_eq!(after.entry_id(), &id);
    after
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
    bound.stop(Duration::from_millis(100)).await;
}

/// The next signal a handler sent, within [`PATIENCE`].
async fn next_signal(signals: &mut mpsc::UnboundedReceiver<&'static str>) -> &'static str {
    tokio::time::timeout(PATIENCE, signals.recv())
        .await
        .expect("a signal in time")
        .expect("a signal")
}

/// `stop(grace)` takes nothing new and lets the running handler finish within the grace; a
/// handler past the grace is abandoned and its take lapses for other workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_lets_a_running_handler_finish_and_takes_nothing_new() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (other, _) = net.member().await;
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let bound = worker
        .agent("graceful")
        .settle(SETTLE)
        .take(SPACE, lease("30s"), move |task: Task, ctx: TakeContext| {
            let started = started_tx.clone();
            async move {
                let _ = started.send(task.topic.clone());
                tokio::time::sleep(Duration::from_millis(800)).await;
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            }
        })
        .poll(Duration::from_millis(200))
        .bind()
        .await
        .expect("bind");
    let tasks = other.space(SPACE).with_settle(SETTLE);
    tasks
        .write(&task("first"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let first = tokio::time::timeout(PATIENCE, started.recv())
        .await
        .expect("the handler starts")
        .expect("a topic");
    assert_eq!(first, "first");
    assert!(
        bound.stop(Duration::from_secs(5)).await,
        "finished within the grace"
    );
    assert!(!bound.is_running());
    // The running handler finished: its report is there.
    report_on(&tasks, "first").await;
    // Nothing new is taken.
    let second = tasks
        .write(&task("second"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write second");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let view = tasks.get(&second).await.expect("get").expect("held");
    assert_eq!(view.holder(), None, "the stopped agent took nothing new");
    assert!(started.try_recv().is_err());
    tasks.cancel(&second).await.expect("cancel");

    // Past the grace: the handler is abandoned, its take lapses and reappears.
    let slow = worker
        .agent("slowpoke")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("1s"),
            |_task: Task, ctx: TakeContext| async move {
                ctx.keepalive(tokio::time::sleep(Duration::from_secs(30)))
                    .await;
                Ok(Reply::none())
            },
        )
        .bind()
        .await
        .expect("bind slowpoke");
    let stuck = tasks
        .write(&task("stuck"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write stuck");
    eventually("slowpoke holds the task", || async {
        tasks
            .get(&stuck)
            .await
            .ok()
            .flatten()
            .and_then(|view| view.holder().map(str::to_owned))
            .as_deref()
            == Some(slow.agent_id())
    })
    .await;
    assert!(
        !slow.stop(Duration::from_millis(300)).await,
        "abandoned past the grace"
    );
    let retaken = tasks
        .take(
            &Template::of::<Task>(),
            lease("30s"),
            Duration::from_secs(5),
        )
        .await
        .expect("take")
        .expect("the abandoned take lapses and reappears");
    assert_eq!(retaken.entry_id(), &stuck);
    retaken
        .complete(None, Lease::DEFAULT_RESULT, Map::new())
        .await
        .expect("complete");
}

/// A stop reaches the take loops that are waiting, not only the next one round: with two loops,
/// one running a handler and one waiting in a long poll, an entry written after the stop is
/// never claimed, and the waiting loop ends at once rather than at the end of its poll (Java's
/// `Bound.close` interrupts a waiting take); `interop_agents.rs` checks the same against the
/// Java seed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_ends_waiting_takes_at_once_and_claims_nothing_late() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (other, _) = net.member().await;
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let (release, released) = tokio::sync::watch::channel(false);
    let bound = worker
        .agent("two-loops")
        .settle(SETTLE)
        .take(SPACE, lease("30s"), move |task: Task, ctx: TakeContext| {
            let started = started_tx.clone();
            let mut released = released.clone();
            async move {
                let _ = started.send(task.topic.clone());
                released.wait_for(|go| *go).await?;
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            }
        })
        .parallel(2)
        .poll(Duration::from_secs(10))
        .bind()
        .await
        .expect("bind");
    let tasks = other.space(SPACE).with_settle(SETTLE);
    tasks
        .write(&task("running"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let first = tokio::time::timeout(PATIENCE, started.recv())
        .await
        .expect("the handler starts")
        .expect("a topic");
    assert_eq!(first, "running");

    bound.request_stop();
    let late = tasks
        .write(&task("late"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write late");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let view = tasks.get(&late).await.expect("get").expect("held");
    assert_eq!(view.holder(), None, "the waiting loop claimed nothing late");
    assert!(
        started.try_recv().is_err(),
        "no handler started after the stop"
    );

    // The running handler finishes within the grace; the waiting loop has already ended, long
    // before its 10 s poll would have.
    release.send_replace(true);
    let stopping = tokio::time::Instant::now();
    assert!(
        bound.stop(Duration::from_secs(20)).await,
        "finished in grace"
    );
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "the waiting take ended at the stop, not at its poll: {:?}",
        stopping.elapsed()
    );
    report_on(&tasks, "running").await;
    assert_eq!(bound.handled(), 1);
    tasks.cancel(&late).await.expect("cancel");
}

/// Bind refuses what Java's binder refuses: a modifier with no binding, action names that stay
/// shared, a clause that does not parse, a template of another schema, an identity of another
/// agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_refuses_what_the_java_binder_refuses() {
    let net = Net::new();
    let (fleet, _) = net.member().await;
    let handler = |_t: Task, _c: TakeContext| async { Ok(Reply::none()) };
    let refused = fleet.agent("a").action("x").bind().await;
    assert!(
        matches!(refused, Err(AgentError::Invalid(_))),
        "{refused:?}"
    );
    let refused = fleet
        .agent("b")
        .take(SPACE, lease("30s"), handler)
        .action("same")
        .take(SPACE, lease("30s"), handler)
        .action("same")
        .bind()
        .await;
    assert!(
        matches!(refused, Err(AgentError::Invalid(_))),
        "{refused:?}"
    );
    let refused = fleet
        .agent("c")
        .take(SPACE, lease("30s"), handler)
        .where_clause("not a clause")
        .bind()
        .await;
    assert!(
        matches!(refused, Err(AgentError::Space(SpaceError::Filter(_)))),
        "{refused:?}"
    );
    let refused = fleet
        .agent("d")
        .take(SPACE, lease("30s"), handler)
        .template(Template::new("other#v1"))
        .bind()
        .await;
    assert!(
        matches!(refused, Err(AgentError::Invalid(_))),
        "{refused:?}"
    );
    let other = fleet
        .peer()
        .agent_identity("someone-else", "PT24H")
        .await
        .expect("identity");
    let refused = fleet.agent("e").identity(other).bind().await;
    assert!(
        matches!(refused, Err(AgentError::Invalid(_))),
        "{refused:?}"
    );
    // Two bindings of one name on different schemas are disambiguated, as Java does.
    let report_handler = |_t: Report, _c: TakeContext| async { Ok(Reply::none()) };
    let bound = fleet
        .agent("f")
        .take(SPACE, lease("30s"), handler)
        .action("same")
        .take(SPACE, lease("30s"), report_handler)
        .action("same")
        .bind()
        .await
        .expect("bind f");
    let card = bound.card().expect("a card");
    let names: Vec<String> = card
        .actions()
        .unwrap_or_default()
        .iter()
        .map(|action| action.name.clone())
        .collect();
    assert_eq!(
        names,
        [
            format!("same({})", Report::SCHEMA),
            format!("same({})", Task::SCHEMA)
        ]
    );
    bound.stop(Duration::from_secs(2)).await;
}

// ------------------------------------------------------------------------------- cards

/// The card: published at bind in Java's shape, seen by another member and its remote actions,
/// republished on its cadence with a fresh issue instant, and gone after the agent's revocation,
/// which also stops the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_card_is_published_refreshed_and_gone_after_revocation() {
    let net = Net::new();
    let (worker, worker_identity) = net.member().await;
    let (reader, _) = net.member().await;
    let bound = worker
        .agent("scout")
        .describe("researches topics")
        .goal("answer questions")
        .settle(SETTLE)
        .card_refresh(Duration::from_millis(300))
        .take(
            SPACE,
            lease("30s"),
            |task: Task, ctx: TakeContext| async move {
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            },
        )
        .action("research")
        .action_description("researches one topic")
        .produces::<Report>()
        .notify("audit", |_task: Task, _ctx: NotifyContext| async {
            Ok(Reply::none())
        })
        .action("audit")
        .bind()
        .await
        .expect("bind");
    let published = bound.card().expect("published");

    // The card's shape, as Java's binder builds it.
    let map = bound.card_map().expect("the map");
    assert_eq!(map.get("ttl").and_then(Value::as_str), Some("PT15M"));
    assert_eq!(
        map.get("agentPublicKey").and_then(Value::as_bytes),
        Some(bound.identity().public_raw().as_slice())
    );
    assert!(
        map.get("agentCertificate")
            .and_then(Value::as_map)
            .is_some()
    );
    assert_eq!(published.agent(), worker_identity.agent("scout"));
    assert_eq!(published.issuer(), worker_identity.peer_id());
    assert_eq!(published.description(), "researches topics");
    assert_eq!(published.goals(), ["answer questions"]);
    assert_eq!(published.consumes(), [Task::SCHEMA]);
    assert_eq!(published.produces(), [Report::SCHEMA]);
    assert_eq!(published.space_for(Task::SCHEMA), Some(SPACE));
    let actions = published.actions().expect("declared actions");
    let names: Vec<&str> = actions.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["audit", "research"], "sorted by name");
    let research = &actions[1];
    assert_eq!(research.kind, "take");
    assert_eq!(research.space.as_deref(), Some(SPACE));
    assert_eq!(research.description, "researches one topic");
    assert_eq!(research.consumes, [Task::SCHEMA]);
    assert_eq!(research.produces, [Report::SCHEMA]);
    assert_eq!(actions[0].kind, "notify");
    assert_eq!(actions[0].space.as_deref(), Some("audit"));

    // Seen by the other member, and among its remote actions.
    let agent = bound.agent_id().to_owned();
    let seen = |reader: Fleet, agent: String| async move {
        reader
            .peer()
            .cards()
            .await
            .into_iter()
            .filter_map(AgentCard::parse)
            .find(|card| card.agent() == agent)
    };
    eventually("the reader to hold the card", || {
        let (reader, agent) = (reader.clone(), agent.clone());
        async move { seen(reader, agent).await.is_some() }
    })
    .await;
    let first = seen(reader.clone(), agent.clone()).await.expect("held");
    let remote = RemoteActions::new(&reader);
    let available = remote.available().await;
    let action = available
        .iter()
        .find(|action| action.name() == "research")
        .expect("the research action");
    assert_eq!(action.agent(), agent);
    assert_eq!(action.consumes(), Task::SCHEMA);
    assert_eq!(action.produces(), Report::SCHEMA);
    assert_eq!(action.space(), SPACE);
    assert_eq!(action.result_space(), SPACE);
    assert_eq!(action.description(), "researches one topic");
    assert_eq!(action.planner_name(), "scout_Task");
    // The notify action produces nothing, so it is no remote action; own cards are not listed.
    assert_eq!(available.len(), 1);
    assert!(RemoteActions::new(&worker).available().await.is_empty());
    assert_eq!(
        RemoteActions::new(&worker)
            .include_own(true)
            .available()
            .await
            .len(),
        1
    );

    // Refreshed on its cadence.
    eventually("a refreshed card", || {
        let (reader, agent) = (reader.clone(), agent.clone());
        let before = first.issued_millis();
        async move {
            seen(reader, agent)
                .await
                .is_some_and(|card| card.issued_millis() > before)
        }
    })
    .await;

    // Gone after the agent's revocation, and the agent stops.
    net.revoke_agent(&worker_identity, &agent).await;
    eventually("the card dropped", || {
        let (reader, agent) = (reader.clone(), agent.clone());
        async move { seen(reader, agent).await.is_none() }
    })
    .await;
    assert!(remote.available().await.is_empty());
    tokio::time::timeout(PATIENCE, bound.wait())
        .await
        .expect("the revoked agent stops");
    assert!(!bound.is_running());
}

// ------------------------------------------------------------------------------- remote actions

/// An invocation writes the input where the worker takes and answers the result whose shared
/// fields match it, past a decoy result of another topic the worker writes first; typed too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_invocation_answers_the_correlated_result_past_a_decoy() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (caller, _) = net.member().await;
    let bound = worker
        .agent("researcher")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("30s"),
            |task: Task, ctx: TakeContext| async move {
                // A result for another request lands first.
                ctx.space()
                    .write(
                        &report(&format!("decoy-{}", task.topic), "decoy"),
                        Lease::DEFAULT_RESULT,
                        Map::new(),
                    )
                    .await?;
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            },
        )
        .action("research")
        .produces::<Report>()
        .bind()
        .await
        .expect("bind");
    let remote = RemoteActions::new(&caller);
    eventually("the action", || async {
        !remote.consuming(Task::SCHEMA).await.is_empty()
    })
    .await;
    let action = remote
        .consuming(Task::SCHEMA)
        .await
        .into_iter()
        .next()
        .expect("an action");
    assert_eq!(remote.producing(Report::SCHEMA).await.len(), 1);
    assert!(remote.producing("nothing#v1").await.is_empty());

    let input = cbor_map! { "topic" => "rust", "priority" => 3 };
    let result = remote
        .invoke(&action, input, PATIENCE)
        .await
        .expect("invoke")
        .expect("a result");
    let answered: Report = result.decode().expect("a report");
    assert_eq!(answered.topic, "rust");
    assert_eq!(answered.worker, bound.agent_id());

    let typed = remote
        .invoke_typed::<Task, Report>(&action, &task("typed"), PATIENCE)
        .await
        .expect("invoke typed")
        .expect("a typed result");
    assert_eq!(typed.value().topic, "typed");
    let wrong = remote
        .invoke_typed::<Report, Report>(&action, &report("x", "y"), PATIENCE)
        .await;
    assert!(matches!(wrong, Err(SpaceError::Entry(_))), "{wrong:?}");
    bound.stop(Duration::from_secs(5)).await;
}

/// At the timeout an invocation answers nothing and the input stays written and leased (held by
/// the slow worker, not cancelled).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_invocation_timeout_leaves_the_input_leased() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (caller, _) = net.member().await;
    let bound = worker
        .agent("sluggish")
        .settle(SETTLE)
        .take(
            SPACE,
            lease("2s"),
            |task: Task, ctx: TakeContext| async move {
                ctx.keepalive(tokio::time::sleep(Duration::from_secs(30)))
                    .await;
                Ok(Reply::from(report(&task.topic, ctx.agent_id())))
            },
        )
        .produces::<Report>()
        .bind()
        .await
        .expect("bind");
    let remote = RemoteActions::new(&caller);
    eventually("the action", || async {
        !remote.available().await.is_empty()
    })
    .await;
    let action = remote.available().await.remove(0);
    let invocation = remote
        .invoke_tracked(
            &action,
            cbor_map! { "topic" => "slow", "priority" => 1 },
            Duration::from_millis(1500),
        )
        .await
        .expect("invoke");
    assert!(invocation.result.is_none());
    let input = caller
        .space(SPACE)
        .get(&invocation.input_id)
        .await
        .expect("get")
        .expect("the input is still held");
    assert!(!input.completed());
    assert_eq!(
        input.holder(),
        Some(bound.agent_id()),
        "leased to the worker"
    );
    assert!(input.expires_at_millis() > SystemClock.now_ms() + 60_000);
    bound.stop(Duration::from_millis(100)).await;
}

// ------------------------------------------------------------------------------- edge cases

/// Dropping every handle of a bound agent leaves it running, as the docs say (Java keeps the handle
/// in its binder): a task written after the last `Bound` is gone is still taken and completed with
/// its result. The peer's close ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_bound_leaves_the_agent_running() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (writer, _) = net.member().await;
    let taken = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&taken);
    let agent_id = {
        // The common shape: bind, and keep nothing.
        let bound = worker
            .agent("unheld")
            .settle(SETTLE)
            .take(SPACE, lease("30s"), move |task: Task, ctx: TakeContext| {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(Reply::from(report(&task.topic, ctx.agent_id())))
                }
            })
            .produces::<Report>()
            .bind()
            .await
            .expect("bind");
        bound.agent_id().to_owned()
    };
    let tasks = writer.space(SPACE).with_settle(SETTLE);
    let id = tasks
        .write(&task("after-drop"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let answered = report_on(&tasks, "after-drop").await;
    assert_eq!(answered.value().worker, agent_id);
    eventually("the completion", || async {
        task_view(&tasks, "after-drop", &id).await.completed()
    })
    .await;
    assert_eq!(taken.load(Ordering::SeqCst), 1);
    worker.close().await.expect("close");
}

/// A reaction slower than the entries it reacts to gets every one of them, also past the watch's
/// capacity (1024): the loop reads on into its backlog while every permit is busy (Java runs each
/// delivered event on a thread of its own and loses none).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_reaction_reacts_to_every_entry_past_the_watch_capacity() {
    const NOTES: usize = 1300;
    let net = Net::new();
    let (fleet, _) = net.member().await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let reactions = Arc::new(AtomicUsize::new(0));
    let (gated, counted) = (Arc::clone(&gate), Arc::clone(&reactions));
    let bound = fleet
        .agent("auditor")
        .notify_value(
            SPACE,
            "com.acme.Note#v1",
            None,
            move |_entry: EntryView, _ctx: NotifyContext| {
                let gate = Arc::clone(&gated);
                let counted = Arc::clone(&counted);
                async move {
                    // Every reaction waits for the gate, as slow work would.
                    let _pass = gate.acquire().await;
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(Reply::none())
                }
            },
        )
        .parallel(1)
        .without_card()
        .bind()
        .await
        .expect("bind");
    let space = fleet.space(SPACE);
    for n in 0..NOTES {
        space
            .write_value(
                "com.acme.Note#v1",
                cbor_map! { "n" => i64::try_from(n).expect("small") },
                Lease::DEFAULT_WRITE,
                Map::new(),
            )
            .await
            .expect("write");
    }
    gate.add_permits(NOTES * 2);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while reactions.load(Ordering::SeqCst) < NOTES && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        reactions.load(Ordering::SeqCst),
        NOTES,
        "every written entry gets its reaction"
    );
    eventually("every reaction counted", || async {
        bound.handled() == u64::try_from(NOTES).expect("small")
    })
    .await;
    assert_eq!(bound.failures(), 0);
    bound.stop(Duration::from_secs(2)).await;
}

/// With the default settle window (600 ms) a claim is made well before the handler starts, so a
/// short lease has little left: `keepalive` renews first at half of what is left, and the hold of a
/// 1 s lease survives two seconds of work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_holds_a_short_lease_under_the_default_settle_window() {
    let net = Net::new();
    let (worker, _) = net.member().await;
    let (other, _) = net.member().await;
    let (signals_tx, mut signals) = mpsc::unbounded_channel();
    let bound = worker
        .agent("prompt")
        // No settle: the space's default window, as `aspace work` takes.
        .take(SPACE, lease("1s"), move |_task: Task, ctx: TakeContext| {
            let signals = signals_tx.clone();
            async move {
                let left = ctx.hold_left().await;
                let _ = signals.send(format!("started with {} ms left", left.as_millis()));
                ctx.keepalive(tokio::time::sleep(Duration::from_millis(2200)))
                    .await;
                let renewed = ctx.renew().await;
                let _ = signals.send(format!("renewed after the work: {}", renewed.is_ok()));
                Err::<Reply, _>(HandlerError::msg("done"))
            }
        })
        .bind()
        .await
        .expect("bind");
    let writer = other.space(SPACE).with_settle(SETTLE);
    writer
        .write(&task("short"), Lease::DEFAULT_WRITE, Map::new())
        .await
        .expect("write");
    let started = tokio::time::timeout(PATIENCE, signals.recv())
        .await
        .expect("the handler starts")
        .expect("a signal");
    assert!(started.starts_with("started with"), "{started}");
    let during = writer
        .take(
            &Template::of::<Task>(),
            lease("30s"),
            Duration::from_millis(1800),
        )
        .await
        .expect("take");
    assert!(during.is_none(), "the keepalive holds the take ({started})");
    let renewed = tokio::time::timeout(PATIENCE, signals.recv())
        .await
        .expect("the work ends")
        .expect("a signal");
    assert_eq!(
        renewed, "renewed after the work: true",
        "the hold never lapsed ({started})"
    );
    bound.stop(Duration::from_millis(100)).await;
}

/// A take lease over a day is refused at bind (every take would refuse it, and the agent
/// would advertise work it never does).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_refuses_a_take_lease_no_take_accepts() {
    let net = Net::new();
    let (fleet, _) = net.member().await;
    let handler = |_t: Task, _c: TakeContext| async { Ok(Reply::none()) };
    let refused = fleet
        .agent("forever")
        .take(SPACE, lease("25h"), handler)
        .bind()
        .await;
    match refused {
        Err(AgentError::Invalid(why)) => assert!(why.contains("at most"), "{why}"),
        other => panic!("refused as invalid, not {other:?}"),
    }
    let bound = fleet
        .agent("daily")
        .take(SPACE, Lease::MAX_TAKE, handler)
        .bind()
        .await
        .expect("a day is the most, and allowed");
    bound.stop(Duration::from_secs(2)).await;
}

// ------------------------------------------------------------------------------- Java interop

mod interop {
    //! A bound Rust agent serving the Java reference's tasks.

    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime};

    use agentspaces::agent::{Reply, TakeContext};
    use agentspaces::group::GroupSpec;
    use agentspaces::peer::{Peer, PeerConfig, default_dialers};
    use agentspaces::space::{Fleet, Lease};
    use agentspaces::wire::identity::Identity;
    use agentspaces::wire::seed::Seed;
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    const FOUNDING: &str = "agentspaces-rust-interop-v1";
    const SEED_MAIN: &str = "ai.badmonkey.agentspaces.interop.Seed";
    const SEED_CLASS: &str = "target/classes/ai/badmonkey/agentspaces/interop/Seed.class";
    const SEED_SOURCE: &str = "src/main/java/ai/badmonkey/agentspaces/interop/Seed.java";
    const SEED_CLASSPATH: &str = "target/classpath.txt";
    const DEADLINE: Duration = Duration::from_secs(20);

    /// The seed's `record Task(String topic, int priority)`.
    #[derive(Debug, Clone, Serialize, Deserialize, agentspaces::Entry)]
    #[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
    struct Task {
        topic: String,
        priority: i32,
    }

    /// The seed's `record Result(String topic, String summary, String worker)`.
    #[derive(Debug, Clone, Serialize, Deserialize, agentspaces::Entry)]
    #[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Result#v1")]
    struct Outcome {
        topic: String,
        summary: String,
        worker: String,
    }

    fn required() -> bool {
        std::env::var("ASPACE_INTEROP_REQUIRED").as_deref() == Ok("1")
    }

    fn seed_dir() -> PathBuf {
        std::env::var_os("AGENTSPACES_JAVA_SEED_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../interop/java-seed")
            })
    }

    fn java_bin() -> PathBuf {
        std::env::var_os("JAVA_HOME")
            .map(|home| PathBuf::from(home).join("bin/java"))
            .filter(|java| java.is_file())
            .unwrap_or_else(|| PathBuf::from("java"))
    }

    /// The seed's classpath, or why it cannot run (built with `mvn -q -o` when missing).
    fn classpath() -> Result<String, String> {
        static PREPARED: OnceLock<Result<String, String>> = OnceLock::new();
        PREPARED.get_or_init(prepare).clone()
    }

    fn prepare() -> Result<String, String> {
        let java = java_bin();
        let runs = Command::new(&java)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("`{}` does not run: {error}", java.display()))?;
        if !runs.success() {
            return Err(format!("`{} -version` exited with {runs}", java.display()));
        }
        let dir = seed_dir();
        let listed = dir.join(SEED_CLASSPATH);
        let class = dir.join(SEED_CLASS);
        let modified =
            |path: &Path| -> Option<SystemTime> { std::fs::metadata(path).ok()?.modified().ok() };
        let stale = matches!(
            (modified(&dir.join(SEED_SOURCE)), modified(&class)),
            (Some(source), Some(built)) if source > built
        );
        if !class.is_file() || !listed.is_file() || stale {
            for args in [
                &["-q", "-o", "compile"][..],
                &[
                    "-q",
                    "-o",
                    "dependency:build-classpath",
                    "-Dmdep.outputFile=target/classpath.txt",
                ][..],
            ] {
                let output = Command::new("mvn")
                    .args(args)
                    .current_dir(&dir)
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|error| format!("`mvn` does not run: {error}"))?;
                if !output.status.success() {
                    return Err(format!(
                        "`mvn {}` failed: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
        let jars = std::fs::read_to_string(&listed)
            .map_err(|error| format!("{} unreadable: {error}", listed.display()))?;
        Ok(format!(
            "{}:{}",
            dir.join("target/classes").display(),
            jars.trim()
        ))
    }

    /// A running Java seed, killed when dropped.
    struct JavaSeed {
        child: Child,
        stdin: Option<ChildStdin>,
        lines: mpsc::UnboundedReceiver<String>,
        port: u16,
        peer: String,
    }

    impl JavaSeed {
        async fn start(classpath: &str) -> JavaSeed {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|probe| probe.local_addr())
                .map(|address| address.port())
                .expect("a free port");
            let mut child = Command::new(java_bin())
                .arg("-cp")
                .arg(classpath)
                .arg(SEED_MAIN)
                .arg(port.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("java starts");
            let stdin = child.stdin.take();
            let stdout = child.stdout.take().expect("a stdout pipe");
            let (tx, lines) = mpsc::unbounded_channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            let mut seed = JavaSeed {
                child,
                stdin,
                lines,
                port,
                peer: String::new(),
            };
            let listening = seed
                .next_json(Duration::from_secs(60))
                .await
                .expect("the listening line");
            assert_eq!(listening["event"], "listening");
            seed.peer = listening["peer"].as_str().unwrap_or_default().to_owned();
            seed
        }

        async fn next_json(&mut self, wait: Duration) -> Option<Json> {
            let deadline = Instant::now() + wait;
            loop {
                let line = tokio::time::timeout_at(deadline, self.lines.recv())
                    .await
                    .ok()??;
                if let Ok(json) = serde_json::from_str::<Json>(&line)
                    && json.is_object()
                {
                    return Some(json);
                }
            }
        }

        async fn ask(&mut self, command: &str) -> Json {
            let answer = self.try_ask(command).await;
            assert!(answer.get("error").is_none(), "{command}: {answer}");
            answer
        }

        /// The seed's answer to `command`, an error answer included.
        async fn try_ask(&mut self, command: &str) -> Json {
            let stdin = self.stdin.as_mut().expect("the seed's stdin");
            stdin
                .write_all(format!("{command}\n").as_bytes())
                .and_then(|()| stdin.flush())
                .expect("a command sent");
            self.next_json(DEADLINE).await.expect("an answer")
        }
    }

    impl Drop for JavaSeed {
        fn drop(&mut self) {
            self.stdin = None;
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Java's discovery service admits the bound Rust agent's card (attested, certified, its
    /// declared action); Java writes tasks, and the agent takes and completes them with results
    /// Java reads, its claims and completions folding in Java under the agent's certified key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_bound_rust_agent_serves_java_tasks() {
        let classpath = match classpath() {
            Ok(classpath) => classpath,
            Err(why) => {
                assert!(!required(), "the Java interop seed cannot run: {why}");
                eprintln!("skipping: the Java interop seed cannot run: {why}");
                return;
            }
        };
        let mut seed = JavaSeed::start(&classpath).await;
        let mut config = PeerConfig::new(
            Identity::generate().expect("identity"),
            GroupSpec::FoundingText(FOUNDING.to_owned()),
        );
        config.seeds = vec![Seed::new("127.0.0.1", seed.port, "tcp")];
        config.dialers = default_dialers();
        config.dial_timeout = Duration::from_secs(3);
        config.reconnect_interval = Duration::from_millis(500);
        let peer = Peer::start(config).await.expect("the Rust peer joins");
        let deadline = Instant::now() + DEADLINE;
        loop {
            let members = seed.ask("members").await;
            let listed = members["members"]
                .as_array()
                .is_some_and(|all| all.iter().any(|m| m.as_str() == Some(peer.peer_id())));
            if listed {
                break;
            }
            assert!(Instant::now() < deadline, "the seed lists the Rust peer");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let fleet = Fleet::from_peer(peer.clone());
        let bound = fleet
            .agent("rust-worker")
            .settle(Duration::from_millis(200))
            .take(
                "tasks",
                Lease::parse("30s").expect("a lease"),
                |task: Task, ctx: TakeContext| async move {
                    Ok(Reply::from(Outcome {
                        topic: task.topic.clone(),
                        summary: format!("researched in rust: {}", task.topic),
                        worker: ctx.agent_id().to_owned(),
                    }))
                },
            )
            .action("research")
            .produces::<Outcome>()
            .bind()
            .await
            .expect("bind");
        // Java's DiscoveryService admits the card (`AdCache.accept`): attested, certified, and
        // declaring the action.
        let deadline = Instant::now() + DEADLINE;
        loop {
            let cards = seed.try_ask("cards").await;
            if cards.get("error").is_some() {
                eprintln!(
                    "note: this seed has no `cards` command; the card check is skipped: {cards}"
                );
                break;
            }
            let ours = cards["cards"].as_array().and_then(|all| {
                all.iter()
                    .find(|card| card["agent"].as_str() == Some(bound.agent_id()))
                    .cloned()
            });
            if let Some(card) = ours {
                assert_eq!(card["issuer"].as_str(), Some(peer.peer_id()));
                assert_eq!(card["attested"], Json::Bool(true));
                assert_eq!(card["certified"], Json::Bool(true));
                let action = &card["actions"][0];
                assert_eq!(action["name"], "research");
                assert_eq!(action["kind"], "take");
                assert_eq!(action["space"], "tasks");
                assert_eq!(
                    action["consumes"][0].as_str(),
                    Some(<Task as agentspaces::Entry>::SCHEMA)
                );
                assert_eq!(
                    action["produces"][0].as_str(),
                    Some(<Outcome as agentspaces::Entry>::SCHEMA)
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Java admits the Rust card: {cards}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for topic in ["j1", "j2"] {
            seed.ask(&format!("write-task {topic} 2")).await;
        }
        let deadline = Instant::now() + DEADLINE;
        loop {
            let results = seed.ask("results").await;
            let ours: Vec<&Json> = results["results"]
                .as_array()
                .map(|all| {
                    all.iter()
                        .filter(|r| r["worker"].as_str() == Some(bound.agent_id()))
                        .collect()
                })
                .unwrap_or_default();
            if ours.len() == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Java reads both results: {results}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for topic in ["j1", "j2"] {
            let deadline = Instant::now() + DEADLINE;
            loop {
                let state = seed.ask(&format!("task-state {topic}")).await;
                if state["state"] == "completed" {
                    assert_eq!(state["holder"].as_str(), Some(bound.agent_id()));
                    let events = state["events"].to_string();
                    assert!(
                        events.contains(&format!("COMPLETED by {}", bound.agent_id())),
                        "{state}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "Java folds the completion: {state}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        assert!(bound.stop(Duration::from_secs(5)).await);
        fleet.close().await.expect("close");
        let _ = seed.ask("quit").await;
    }
}
