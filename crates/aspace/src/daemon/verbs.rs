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

//! The serving side every platform shares: the state of the resident peer, the connection
//! exchange ([`connection`]: the hello, one request, its frames, the exit frame), and the verbs,
//! each what its visitor command does after its join, with the same output and the same
//! failures, answered as frames ([`Reply`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use agentspaces::catalog::{CatalogError, FleetCatalog, Offering, Principal};
use agentspaces::peer::{DEFAULT_AGENT_NAME, PeerEvent};
use agentspaces::space::{EntryId, EventKind, Lease, Space};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, OnceCell, broadcast, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::protocol::{
    CallArgs, CardsArgs, CompleteArgs, Envelope, Frame, Hello, LineError, MAX_REQUEST, PROTOCOL,
    ReadArgs, StatusArgs, TakeArgs, VERBS, WatchArgs, WriteArgs, read_json, write_json,
};
use super::{REQUEST_WAIT, STOP_GRACE};
use crate::commands::{self, catalogue, offering_json, offering_line, template};
use crate::exit::{Failure, SUCCESS};
use crate::io::{self, entry_json, event_json, printable, tags_map};
use crate::session::{self, Session};

/// The most spaces the daemon keeps open (each pulled and settled once). Past it, the space
/// used least recently is closed to make room ([`agentspaces::peer::Peer::close_space`]),
/// unless it is configured, in use by a request (a watch among them), or holds a take made
/// through the daemon; the peer's own bound (1024) leaves room for the spaces the catalogue's
/// calls open.
pub const MAX_SPACES: usize = 960;

/// How long the connections still running after the grace have to send their last frame.
const ABANDON_FLUSH: Duration = Duration::from_millis(500);

/// What the daemon serves with: its joined session, its hello, the spaces it has settled, and
/// the stop signals.
pub struct State {
    /// The joined peer and the daemon's configuration.
    pub session: Session,
    /// The hello every connection is greeted with.
    pub hello: Hello,
    /// When it started serving.
    pub started: Instant,
    spaces: Mutex<HashMap<String, Cached>>,
    configured: HashSet<String>,
    stopping: watch::Receiver<bool>,
    /// Turned true at the end of the stop's grace: each request still running answers its
    /// visitor what may have happened, then the connection is dropped.
    abandoning: watch::Sender<bool>,
}

/// A space handle and whether its first pull has settled.
#[derive(Clone)]
struct Opened {
    space: Space,
    settled: Arc<OnceCell<()>>,
}

/// A space the daemon keeps: its handle, when a request last used it, and until when a take
/// made through the daemon holds an entry of it.
struct Cached {
    opened: Opened,
    used: Instant,
    held_until: Option<Instant>,
}

impl Cached {
    /// Whether a request holds the space now ([`InUse`]).
    fn in_use(&self) -> bool {
        Arc::strong_count(&self.opened.settled) > 1
    }
}

/// A space a request uses: while it lives, the daemon does not close the space.
pub struct InUse {
    opened: Opened,
}

impl std::ops::Deref for InUse {
    type Target = Space;

    fn deref(&self) -> &Space {
        &self.opened.space
    }
}

impl State {
    /// The state of a joined `session` greeting with `hello`; `stopping` turns true when the
    /// daemon stops.
    pub fn new(session: Session, hello: Hello, stopping: watch::Receiver<bool>) -> State {
        let configured = session.config.settings.spaces.iter().cloned().collect();
        let (abandoning, _) = watch::channel(false);
        State {
            session,
            hello,
            started: Instant::now(),
            spaces: Mutex::new(HashMap::new()),
            configured,
            stopping,
            abandoning,
        }
    }

    /// Marks `name` as pulled and settled, answering its handle to pull (the configured spaces,
    /// pulled and settled together at the start).
    pub async fn settled(&self, name: &str) -> Result<Space, Failure> {
        let opened = self.opened(name).await?;
        let _ = opened.opened.settled.set(());
        Ok(opened.opened.space.clone())
    }

    /// The space `name`, kept (and marked in use) for the request; at the bound, the space used
    /// least recently is closed to make room, or the request is refused naming the bound.
    async fn opened(&self, name: &str) -> Result<InUse, Failure> {
        let mut spaces = self.spaces.lock().await;
        if let Some(cached) = spaces.get_mut(name) {
            cached.used = Instant::now();
            return Ok(InUse {
                opened: cached.opened.clone(),
            });
        }
        let peer = self.session.peer();
        if spaces.len() >= MAX_SPACES || peer.open_spaces().await >= MAX_SPACES {
            let now = Instant::now();
            let mut idle: Vec<(Instant, String)> = spaces
                .iter()
                .filter(|(name, cached)| {
                    !self.configured.contains(*name)
                        && !cached.in_use()
                        && cached.held_until.is_none_or(|until| until <= now)
                })
                .map(|(name, cached)| (cached.used, name.clone()))
                .collect();
            idle.sort_unstable();
            let mut closed = false;
            for (_, victim) in idle {
                // A space a watch follows is not closed by the peer: the next one is tried.
                if peer.close_space(&victim).await.unwrap_or_default() {
                    spaces.remove(&victim);
                    tracing::debug!(space = %victim, "closed the space used least recently");
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(too_many_spaces());
            }
        }
        let opened = Opened {
            space: self.session.fleet.space(name),
            settled: Arc::new(OnceCell::new()),
        };
        spaces.insert(
            name.to_owned(),
            Cached {
                opened: opened.clone(),
                used: Instant::now(),
                held_until: None,
            },
        );
        Ok(InUse { opened })
    }

    /// Notes that a take made through the daemon holds an entry of `name` for `lease`: the
    /// space is not closed before the hold lapses.
    async fn holds(&self, name: &str, lease: Duration) {
        if let Some(cached) = self.spaces.lock().await.get_mut(name) {
            let until = Instant::now() + lease;
            cached.held_until = Some(cached.held_until.map_or(until, |held| held.max(until)));
        }
    }

    /// The space `name`, pulled and settled on its first use (within the join timeout); after
    /// that the resident peer folds its rumors as they come.
    async fn space(&self, name: &str) -> Result<InUse, Failure> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Failure::refused("the request names no space"));
        }
        let opened = self.opened(name).await?;
        let deadline = Instant::now() + self.session.config.join_timeout;
        let peer = self.session.peer();
        opened
            .opened
            .settled
            .get_or_try_init(|| session::pull_and_settle(peer, &opened.opened.space, deadline))
            .await
            .map_err(|failure| {
                if failure.message.contains("cannot open space") {
                    too_many_spaces()
                } else {
                    failure
                }
            })?;
        Ok(opened)
    }

    /// The fleet catalogue as a visitor of `spaces` reads it ([`catalogue`]).
    fn catalogue(&self, spaces: &[String]) -> FleetCatalog {
        let mut config = self.session.config.clone();
        config.settings.spaces = spaces.to_vec();
        catalogue(&self.session.fleet, &config)
    }

    /// Whether the daemon is stopping.
    fn is_stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    /// Tells the requests still running that the daemon abandons them: each answers its visitor
    /// what may have happened ([`abandoned`]) before its connection is dropped.
    pub fn abandon(&self) {
        self.abandoning.send_replace(true);
    }
}

/// The refusal of a space past [`MAX_SPACES`] when none can be closed.
fn too_many_spaces() -> Failure {
    Failure::refused(format!(
        "the daemon keeps at most {MAX_SPACES} spaces open, and every one is configured, in use, \
         or holds a take made through it; try again when a request ends, or restart the daemon"
    ))
}

/// Lets the requests in flight finish for [`STOP_GRACE`]; past it, each one still running is
/// told to answer what may have happened ([`State::abandon`]) and given a moment to, then
/// dropped. Answers whether every request finished within the grace.
pub async fn drain(connections: &mut JoinSet<()>, state: &State) -> bool {
    let drained = tokio::time::timeout(STOP_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !drained {
        state.abandon();
        let _ = tokio::time::timeout(ABANDON_FLUSH, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        connections.shutdown().await;
    }
    drained
}

/// Resolves once `halt` reads true; never when its sender is gone without saying so.
async fn halted(halt: &mut watch::Receiver<bool>) {
    if halt.wait_for(|halt| *halt).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Why a request ended early: the daemon stopped (exit 3, `what` says what did not happen), or
/// its visitor went away (nobody reads the answer).
fn interrupted(state: &State, what: &str) -> Failure {
    if state.is_stopping() {
        Failure::timeout(format!("the daemon stopped; {what}"))
    } else {
        Failure::error("the visitor went away")
    }
}

/// The last word of a request still running at the end of the stop's grace, by verb: whether
/// it may have taken effect, and whether running it again is safe.
pub fn abandoned(verb: &str) -> Failure {
    match verb {
        "write" => Failure::timeout(
            "the daemon stopped before the seed confirmed the write; it may have taken effect: \
             read before writing it again",
        ),
        "complete" => Failure::timeout(
            "the daemon stopped before the seed confirmed the completion; it may have taken \
             effect: read the entry before completing it again",
        ),
        "call" => Failure::timeout(
            "the daemon stopped before the result came; the input may stay leased for a worker, \
             which may still answer it: do not call again blindly",
        ),
        "take" => Failure::timeout(
            "the daemon stopped while the take settled; the entry may be held by the daemon's \
             identity until its lease lapses",
        ),
        _ => Failure::error("the daemon stopped before it answered; run the command again"),
    }
}

/// Where a request's frames go: the connection's writing half.
pub struct Reply<W> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> Reply<W> {
    /// Frames written to `writer`.
    pub fn new(writer: W) -> Reply<W> {
        Reply { writer }
    }

    /// Sends one frame; a visitor that went away ends the request (exit 0, nothing to say).
    pub async fn send(&mut self, frame: &Frame) -> Result<(), Failure> {
        write_json(&mut self.writer, &frame.to_json())
            .await
            .map_err(|_| Failure {
                code: SUCCESS,
                message: String::new(),
            })
    }

    /// A line for the visitor's standard output.
    pub async fn out(&mut self, value: Json) -> Result<(), Failure> {
        self.send(&Frame::Out(value)).await
    }

    /// A text line for the visitor's standard output.
    pub async fn text(&mut self, line: String) -> Result<(), Failure> {
        self.send(&Frame::Text(line)).await
    }

    /// A diagnostic for the visitor's standard error; one that cannot be sent is dropped.
    pub async fn note(&mut self, line: String) {
        let _ = self.send(&Frame::Note(line)).await;
    }

    /// Sends the last frame, the exit code of `outcome`, and closes the writing half.
    pub async fn finish(mut self, outcome: Result<(), Failure>) {
        let frame = match outcome {
            Ok(()) => Frame::Exit {
                code: SUCCESS,
                error: None,
            },
            Err(failure) => Frame::Exit {
                code: failure.code,
                error: (!failure.message.is_empty()).then_some(failure.message),
            },
        };
        let _ = self.send(&frame).await;
        let _ = self.writer.shutdown().await;
    }
}

/// Runs one request: its protocol and verb checked, its arguments parsed, its verb run. `halt`
/// turns true when the visitor closes its side of the connection or the daemon stops: a verb
/// still waiting (a take, a read or a completion with a timeout, a call looking for its
/// offering, a watch) ends then, having changed nothing.
pub async fn serve<W: AsyncWrite + Unpin>(
    state: &State,
    envelope: Envelope,
    reply: &mut Reply<W>,
    halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    if envelope.protocol != PROTOCOL {
        return Err(Failure::refused(format!(
            "the request speaks protocol {}, and this daemon {PROTOCOL}; run the same aspace \
             version as the daemon, or pass --no-daemon",
            envelope.protocol
        )));
    }
    tracing::debug!(verb = envelope.verb, "request");
    fn args<T: serde::de::DeserializeOwned>(envelope: &Envelope) -> Result<T, Failure> {
        envelope.args().map_err(Failure::refused)
    }
    match envelope.verb.as_str() {
        "status" => status(state, args(&envelope)?, reply).await,
        "write" => write(state, args(&envelope)?, reply).await,
        "read" => read(state, args(&envelope)?, reply, halt).await,
        "take" => take(state, args(&envelope)?, reply, halt).await,
        "complete" => complete(state, args(&envelope)?, reply, halt).await,
        "watch" => watch(state, args(&envelope)?, reply, halt).await,
        "cards" => cards(state, args(&envelope)?, reply).await,
        "call" => call(state, args(&envelope)?, reply, halt).await,
        other => Err(Failure::refused(format!(
            "{:?} is not a verb this daemon serves ({})",
            printable(other),
            VERBS.join(", ")
        ))),
    }
}

/// A lease from milliseconds.
fn lease(millis: i64) -> Result<Lease, Failure> {
    Ok(Lease::from_millis(millis)?)
}

/// `status`: the report of [`commands::status`] from the resident peer, with the daemon's
/// socket and pid.
async fn status<W: AsyncWrite + Unpin>(
    state: &State,
    args: StatusArgs,
    reply: &mut Reply<W>,
) -> Result<(), Failure> {
    let session = &state.session;
    let peer = session.peer();
    let members = peer.members().await;
    let reachable = peer.reachable().await;
    let counters = peer.counters().await;
    let link = peer.link();
    let offerings = catalogue(&session.fleet, &session.config).current().await;
    let report = json!({
        "peerId": peer.peer_id(),
        "group": peer.group_id(),
        "groupName": session.config.group_name,
        "link": link.as_ref().map(|link| json!({
            "scheme": link.scheme,
            "remote": link.remote,
            "attested": link.attested,
        })),
        "seed": peer.seed_peer().await,
        "members": members,
        "reachable": reachable,
        "spaces": session.config.settings.spaces,
        "cards": peer.cards().await.len(),
        "counters": commands::counters_json(&counters),
        "catalogue": offerings.iter().map(offering_json).collect::<Vec<_>>(),
        "daemon": {
            "socket": state.hello.socket,
            "pid": state.hello.pid,
            "used": true,
            "upMillis": u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        "mcp": args.mcp,
    });
    if args.json {
        return reply.out(report).await;
    }
    let text = |key: &str| report[key].as_str().unwrap_or("-").to_owned();
    let mut lines = vec![
        format!("peer     {}", text("peerId")),
        format!(
            "group    {}{}",
            text("group"),
            report["groupName"]
                .as_str()
                .map(|name| format!(" ({name})"))
                .unwrap_or_default()
        ),
        match &link {
            Some(link) => format!(
                "link     {}://{}{}",
                link.scheme,
                link.remote,
                link.attested
                    .as_deref()
                    .map(|peer| format!(" attested {peer}"))
                    .unwrap_or_default()
            ),
            None => "link     none".to_owned(),
        },
        commands::daemon_line(&report["daemon"]),
        format!("members  {} ({} reachable)", members.len(), reachable.len()),
    ];
    lines.extend(members.iter().map(|member| format!("  {member}")));
    lines.push(format!("cards    {}", report["cards"]));
    lines.push(format!("offers   {}", offerings.len()));
    lines.extend(
        offerings
            .iter()
            .map(|offering| format!("  {}", offering_line(offering))),
    );
    lines.push(format!(
        "frames   malformed={} ignored={} stale={} ahead={} replayed={} reconnects={}",
        counters.malformed,
        counters.ignored_total(),
        counters.filter.stale,
        counters.filter.ahead,
        counters.filter.replayed,
        counters.reconnects
    ));
    lines.push(crate::mcp::settings_line(&report["mcp"]));
    for line in lines {
        reply.text(line).await?;
    }
    Ok(())
}

/// `write`: one entry, confirmed held by the seed before the visitor is answered.
async fn write<W: AsyncWrite + Unpin>(
    state: &State,
    args: WriteArgs,
    reply: &mut Reply<W>,
) -> Result<(), Failure> {
    commands::check_schema(&args.schema)?;
    let lease = lease(args.lease_millis)?;
    let space = state.space(&args.space).await?;
    let payload = io::payload(&space, &args.schema, args.entry).await?;
    let id = space
        .write_value(&args.schema, payload, lease, tags_map(&args.tags))
        .await?;
    let confirmed = session::confirm(
        state.session.peer(),
        space.name(),
        &[id.as_str().to_owned()],
        session::CONFIRM,
    )
    .await;
    reply
        .out(json!({"id": id.as_str(), "schema": args.schema, "space": space.name()}))
        .await?;
    confirmed
}

/// `read`: the available entries of a schema, one `out` frame each.
async fn read<W: AsyncWrite + Unpin>(
    state: &State,
    args: ReadArgs,
    reply: &mut Reply<W>,
    mut halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let mut template = template(&args.schema, &args.clauses)?;
    for (key, value) in &args.tags {
        template = template.tag_eq(key.as_str(), value.as_str());
    }
    let space = state.space(&args.space).await?;
    let name = space.name().to_owned();
    let pending = session::await_payloads(state.session.peer(), &space, &template).await?;
    if pending > 0 {
        reply
            .note(session::payloads_note(pending, &template, &name))
            .await;
    }
    if let Some(timeout) = args.timeout_millis.map(Duration::from_millis) {
        // A read claims nothing: ending its wait early leaves nothing behind.
        let found = tokio::select! {
            found = space.read(&template, timeout) => found?,
            () = halted(&mut halt) => return Err(interrupted(state, "nothing was read")),
        };
        if found.is_none() {
            return Err(Failure::timeout(format!(
                "no {} entry matched in {name} within {}",
                args.schema,
                session::millis_text(timeout)
            )));
        }
    }
    let found = space.read_all(&template, args.limit).await?;
    if found.is_empty() {
        return Err(Failure::refused(format!(
            "no {} entry matches in {name}",
            args.schema
        )));
    }
    for view in &found {
        reply.out(entry_json(view, &name)).await?;
    }
    Ok(())
}

/// `take`: one entry, held by the daemon's identity for the lease. The wait heeds `halt`
/// ([`Space::halting_on`]): once the visitor goes away or the daemon stops, it makes no further
/// claim, so a take nobody waits for never takes the next entry; a claim already out settles as
/// a take of the visitor's own would.
async fn take<W: AsyncWrite + Unpin>(
    state: &State,
    args: TakeArgs,
    reply: &mut Reply<W>,
    halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let template = template(&args.schema, &args.clauses)?;
    let lease = lease(args.lease_millis)?;
    let space = state.space(&args.space).await?;
    let name = space.name().to_owned();
    let pending = session::await_payloads(state.session.peer(), &space, &template).await?;
    if pending > 0 {
        reply
            .note(session::payloads_note(pending, &template, &name))
            .await;
    }
    let timeout = args.timeout_millis.map(Duration::from_millis);
    let wait = timeout.unwrap_or(Duration::ZERO);
    let heeding = space.halting_on(halt.clone());
    let Some(taken) = heeding.take(&template, lease, wait).await? else {
        if *halt.borrow() {
            return Err(interrupted(state, "nothing was taken"));
        }
        return Err(match timeout {
            Some(timeout) if !timeout.is_zero() => Failure::timeout(format!(
                "no {} entry could be taken in {name} within {}",
                args.schema,
                session::millis_text(timeout)
            )),
            _ => Failure::refused(format!("no {} entry is available in {name}", args.schema)),
        });
    };
    let entry = taken.entry();
    let line = json!({
        "id": entry.entry_id().as_str(),
        "schema": entry.schema(),
        "space": name,
        "entry": agentspaces::json::value_to_json(entry.payload()),
        "tags": io::tags_json(entry.tags()),
        "holder": taken.holder(),
        "epoch": taken.epoch(),
        "expiresAt": taken.expires_at_millis(),
    });
    // The hold stays with the daemon's identity until it is completed or lapses; the space
    // stays open until then.
    state
        .holds(
            &name,
            Duration::from_millis(u64::try_from(lease.millis()).unwrap_or_default()),
        )
        .await;
    taken.release();
    reply.out(line).await
}

/// `complete`: completes a take the daemon's identity holds, by id.
async fn complete<W: AsyncWrite + Unpin>(
    state: &State,
    args: CompleteArgs,
    reply: &mut Reply<W>,
    mut halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let result_object = match (args.produces.as_deref(), args.result) {
        (Some(schema), Some(object)) => {
            commands::check_schema(schema)?;
            Some((schema, object))
        }
        _ => None,
    };
    let result_lease = lease(args.result_lease_millis)?;
    let space = state.space(&args.space).await?;
    let name = space.name().to_owned();
    let id = args.id.trim();
    let entry_id = EntryId::new(id);
    let peer = state.session.peer();
    let me = format!("{}/{}", peer.peer_id(), DEFAULT_AGENT_NAME);
    if let Some(view) = space.get(&entry_id).await? {
        if view.completed() {
            return Err(Failure::refused(format!(
                "{id} in {name} is already completed"
            )));
        }
        if let Some(holder) = view.holder().filter(|holder| *holder != me) {
            return Err(Failure::refused(format!(
                "{id} in {name} is held by {holder}, not by {me}"
            )));
        }
    }
    let timeout = Duration::from_millis(args.timeout_millis);
    // Finding the hold changes nothing: the wait ends with the visitor or the daemon.
    let held = tokio::select! {
        held = space.held(&entry_id, timeout) => held?,
        () = halted(&mut halt) => return Err(interrupted(state, "nothing was completed")),
    };
    let Some(taken) = held else {
        return Err(Failure::refused(format!(
            "{id} is not held by {} in {name}: it was never taken through this daemon or with \
             its keystore, its take lapsed, or it is completed",
            peer.peer_id()
        )));
    };
    let result = match result_object {
        Some((schema, object)) => Some((schema, io::payload(&space, schema, object).await?)),
        None => None,
    };
    let result_id = taken
        .complete(result, result_lease, tags_map(&args.tags))
        .await?;
    let mut confirm = vec![entry_id.as_str().to_owned()];
    confirm.extend(result_id.iter().map(|id| id.as_str().to_owned()));
    let confirmed = session::confirm(peer, &name, &confirm, session::CONFIRM).await;
    reply
        .out(json!({
            "id": entry_id.as_str(),
            "space": name,
            "completed": true,
            "result": result_id.as_ref().map(EntryId::as_str),
            "schema": args.produces,
        }))
        .await?;
    confirmed
}

/// `watch`: transitions as `out` frames until `count`, the visitor's going away, or the
/// daemon's stop.
async fn watch<W: AsyncWrite + Unpin>(
    state: &State,
    args: WatchArgs,
    reply: &mut Reply<W>,
    mut halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let template = template(&args.schema, &args.clauses)?;
    let kinds = args
        .kinds
        .iter()
        .map(|kind| crate::cli::parse_kind(kind))
        .collect::<Result<Vec<EventKind>, String>>()
        .map_err(Failure::refused)?;
    let space = state.space(&args.space).await?;
    let name = space.name().to_owned();
    let mut events = space.watch(&template).await?;
    reply
        .note(format!("watching {} in {name}", args.schema))
        .await;
    if args.count == Some(0) {
        return Ok(());
    }
    let mut printed = 0u64;
    loop {
        tokio::select! {
            event = events.next() => {
                let Some(event) = event else {
                    return Err(Failure::error(format!(
                        "the watch of {name} ended: {:?}",
                        events.close_reason()
                    )));
                };
                if !kinds.is_empty() && !kinds.contains(&event.kind) {
                    continue;
                }
                reply.out(event_json(&event, &name)).await?;
                printed += 1;
                if args.count.is_some_and(|count| printed >= count) {
                    return Ok(());
                }
            }
            () = halted(&mut halt) => {
                if !state.is_stopping() {
                    return Ok(()); // the visitor was interrupted
                }
                return Err(Failure::error(format!(
                    "the daemon stopped; the watch of {name} ended"
                )));
            }
        }
    }
}

/// `cards`: the catalogue's offerings, from the cards the resident peer holds.
async fn cards<W: AsyncWrite + Unpin>(
    state: &State,
    args: CardsArgs,
    reply: &mut Reply<W>,
) -> Result<(), Failure> {
    let offerings = state
        .catalogue(&args.spaces)
        .only(args.only.iter().cloned())
        .current()
        .await;
    if offerings.is_empty() {
        reply
            .note(
                "the fleet offers nothing: no live card declares an invocable take action"
                    .to_owned(),
            )
            .await;
    }
    for offering in &offerings {
        if args.json {
            reply.out(offering_json(offering)).await?;
        } else {
            reply.text(offering_line(offering)).await?;
            let description = printable(&offering.description());
            if !description.trim().is_empty() {
                reply.text(format!("    {description}")).await?;
            }
        }
    }
    Ok(())
}

/// `call`: finds the offering (waiting up to the visitor's join timeout for its card), writes
/// the input, and answers the correlated result.
async fn call<W: AsyncWrite + Unpin>(
    state: &State,
    args: CallArgs,
    reply: &mut Reply<W>,
    mut halt: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let target = args.target.trim();
    if target.is_empty() {
        return Err(Failure::refused(
            "name the offering to call, or the schema it consumes (aspace cards lists them)",
        ));
    }
    let catalog = state.catalogue(&args.spaces);
    let deadline = Instant::now() + Duration::from_millis(args.wait_millis);
    // Nothing is written until the offering is found: the wait ends with the visitor or the
    // daemon.
    let offering = tokio::select! {
        found = find_offering(state, &catalog, target, deadline) => found?,
        () = halted(&mut halt) => return Err(interrupted(state, "nothing was written")),
    };
    let space = state.space(offering.space()).await?;
    let input = io::payload(&space, offering.consumes(), args.input).await?;
    let timeout = Duration::from_millis(args.timeout_millis);
    let local = Principal::local();
    let call = catalog.call_offering(&offering, input, &local, timeout);
    tokio::pin!(call);
    // Once written, the input stays for a worker: a visitor gone ends the wait (the result is
    // read, never taken, so nothing is held); a stopping daemon keeps waiting for its grace.
    let called = tokio::select! {
        called = &mut call => called?,
        () = halted(&mut halt) => {
            if !state.is_stopping() {
                return Err(interrupted(state, "the input stays leased for a worker"));
            }
            call.await?
        }
    };
    let Some(result) = &called.result else {
        // The input stays leased for a late worker: make sure the seed holds it.
        if let Err(failure) = session::confirm(
            state.session.peer(),
            offering.space(),
            &[called.input_id.as_str().to_owned()],
            session::CONFIRM,
        )
        .await
        {
            reply
                .note(format!(
                    "the input may not have reached the seed: {failure}"
                ))
                .await;
        }
        return Err(Failure::timeout(format!(
            "no {} result answered {} within {}; the input {} stays leased in {} for a late \
             worker",
            printable(offering.produces()),
            printable(offering.name()),
            session::millis_text(timeout),
            called.input_id,
            printable(offering.space())
        )));
    };
    let mut line = JsonMap::new();
    line.insert("offering".to_owned(), Json::from(called.offering.clone()));
    line.insert("input".to_owned(), Json::from(called.input_id.as_str()));
    line.insert("inputSpace".to_owned(), Json::from(offering.space()));
    if let Json::Object(mut entry) = entry_json(result, offering.action().result_space()) {
        line.append(&mut entry);
    }
    reply.out(Json::Object(line)).await
}

/// The offering `target` names, from the cards the peer holds; each card that arrives before
/// `deadline` is another chance.
async fn find_offering(
    state: &State,
    catalog: &FleetCatalog,
    target: &str,
    deadline: Instant,
) -> Result<Offering, Failure> {
    let mut events = state.session.peer().subscribe();
    loop {
        match catalog.find(target).await {
            Ok(offering) => return Ok(offering),
            Err(CatalogError::NotFound(_)) if Instant::now() < deadline => {
                let card = loop {
                    match tokio::time::timeout_at(deadline, events.recv()).await {
                        Ok(Ok(PeerEvent::AdAccepted { .. }))
                        | Ok(Err(broadcast::error::RecvError::Lagged(_))) => break true,
                        Ok(Ok(_)) => {}
                        Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break false,
                    }
                };
                if !card {
                    return catalog.find(target).await.map_err(Failure::from);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// The hello of a joined session serving `socket`.
pub fn hello(session: &Session, socket: &str) -> Hello {
    let peer = session.peer();
    Hello {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        group: peer.group_id().to_owned(),
        group_name: session.config.group_name.clone(),
        peer_id: peer.peer_id().to_owned(),
        keystore: super::keystore_text(&session.config),
        profile: super::profile_name(session.config.settings.profile).to_owned(),
        pid: std::process::id(),
        socket: socket.to_owned(),
        verbs: VERBS.iter().map(ToString::to_string).collect(),
    }
}

/// Pulls the advertisements and the configured spaces and waits until they settle (within the
/// join timeout), before the first visitor: the spaces are then marked settled.
pub async fn warm_up(state: &State) -> Result<(), Failure> {
    let session = &state.session;
    let peer = session.peer();
    let mut events = peer.subscribe();
    peer.pull_ads().await?;
    for space in &session.config.settings.spaces {
        // A failed pull is pulled again after the next reconnect.
        if let Ok(space) = state.settled(space).await {
            let _ = space.pull().await;
        }
    }
    let deadline = Instant::now() + session.config.join_timeout;
    session::settle_on(&mut events, deadline, |event| {
        matches!(
            event,
            PeerEvent::AdAccepted { .. }
                | PeerEvent::StateFolded { .. }
                | PeerEvent::ClaimFolded { .. }
        )
    })
    .await;
    Ok(())
}

/// One connection, once its peer is authorized: the hello, one request, its frames, the exit
/// frame.
pub async fn connection<S>(stream: S, state: &State)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read, write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut reply = Reply::new(write);
    if reply
        .send(&Frame::Hello(state.hello.clone()))
        .await
        .is_err()
    {
        return;
    }
    let request = tokio::time::timeout(REQUEST_WAIT, read_json(&mut reader, MAX_REQUEST)).await;
    let envelope = match request {
        Ok(Ok(json)) => match serde_json::from_value::<Envelope>(json) {
            Ok(envelope) => envelope,
            Err(error) => {
                reply
                    .finish(Err(Failure::refused(format!(
                        "a request that does not parse: {error}"
                    ))))
                    .await;
                return;
            }
        },
        // The visitor read the hello and joins itself.
        Ok(Err(LineError::Closed)) => return,
        Ok(Err(error)) => {
            reply
                .finish(Err(Failure::refused(format!(
                    "a request the daemon cannot read: {error}"
                ))))
                .await;
            return;
        }
        Err(_) => {
            reply
                .finish(Err(Failure::timeout(format!(
                    "no request came within {} of the hello",
                    session::millis_text(REQUEST_WAIT)
                ))))
                .await;
            return;
        }
    };
    // The visitor keeps its side open until it has the exit frame: its end is its going away.
    // Either that or the daemon's stop halts a request still waiting.
    let (halt_tx, halt) = watch::channel(false);
    let mut stopping = state.stopping.clone();
    let drain = tokio::spawn(async move {
        let mut sink = [0u8; 512];
        loop {
            tokio::select! {
                read = reader.read(&mut sink) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                },
                () = halted(&mut stopping) => break,
            }
        }
        halt_tx.send_replace(true);
    });
    let verb = envelope.verb.clone();
    let mut abandoning = state.abandoning.subscribe();
    let outcome = tokio::select! {
        outcome = serve(state, envelope, &mut reply, halt) => outcome,
        () = halted(&mut abandoning) => Err(abandoned(&verb)),
    };
    reply.finish(outcome).await;
    drain.abort();
}
