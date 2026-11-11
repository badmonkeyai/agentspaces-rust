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

//! The visitor commands: `id`, `status`, `write`, `read`, `take`, `complete`, `watch`, the
//! catalogue's `cards` and `call` (over [`FleetCatalog`]), `completions`, and `man`.

use std::path::Path;
use std::time::Duration;

use agentspaces::catalog::{CatalogError, FleetCatalog, Offering, Principal};
use agentspaces::config::Config;
use agentspaces::keystore;
use agentspaces::peer::{DEFAULT_AGENT_NAME, PeerCounters, PeerEvent};
use agentspaces::remote::RemoteActions;
use agentspaces::space::{EntryId, EventKind, Fleet, Lease, Template};
use clap::CommandFactory;
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::cli::{Cli, Global};
use crate::exit::Failure;
use crate::io::{self, entry_json, event_json, print_line, printable, tags_map};
use crate::session::{self, Session, note};

/// `aspace id`: the PeerID of the keystore, minted there when it holds none.
pub fn id(global: &Global) -> Result<(), Failure> {
    let (dir, origin) = session::keystore_with_origin(global)?;
    let created = !dir.join(keystore::PRIVATE_FILE).exists();
    let identity = session::identity(Some(&dir), global.allow_readable_key)?;
    if created {
        note(format!(
            "minted a new identity in {} ({origin})",
            dir.display()
        ));
    }
    print_line(&json!({
        "peerId": identity.peer_id(),
        "keystore": dir.display().to_string(),
        "created": created,
    }))
}

/// `aspace status`: join, wait for the group's members and cards, report, leave. The report
/// also says whether a daemon answers on the socket ([`daemon_json`]; this visitor did not go
/// through one) and the MCP settings ([`crate::mcp::settings_json`]).
pub async fn status(global: &Global, as_json: bool) -> Result<(), Failure> {
    let session = Session::join(global).await?;
    let daemon = daemon_json(&session.config, crate::session::skips_daemon(global)).await;
    let peer = session.peer().clone();
    let mut events = peer.subscribe();
    peer.pull_ads().await?;
    for space in &session.config.settings.spaces {
        peer.pull_space(space).await?;
    }
    session::settle_on(&mut events, session.deadline, |event| {
        matches!(
            event,
            PeerEvent::AdAccepted { .. } | PeerEvent::StateFolded { .. }
        )
    })
    .await;
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
        "counters": counters_json(&counters),
        "catalogue": offerings.iter().map(offering_json).collect::<Vec<_>>(),
        "daemon": daemon,
        "mcp": crate::mcp::settings_json(),
    });
    session.close().await;
    if as_json {
        return print_line(&report);
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
        daemon_line(&report["daemon"]),
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
        print_text(&line)?;
    }
    Ok(())
}

/// The daemon as a visitor that joined itself sees it: `null` when none answers on the socket,
/// else its socket and pid, `"used": false`, and why it was not used (`--no-daemon`, or what
/// it serves).
pub async fn daemon_json(config: &Config, skipped: bool) -> Json {
    use crate::daemon::client;
    let Ok(socket) = client::socket_of(config) else {
        return Json::Null;
    };
    #[cfg(unix)]
    let uid = crate::daemon::paths::own_uid();
    #[cfg(windows)]
    let uid = 0;
    let Ok(connection) = client::connect(&socket, uid).await else {
        return Json::Null;
    };
    let why = if skipped {
        "--no-daemon or ASPACE_NO_DAEMON".to_owned()
    } else {
        match connection.serves(config) {
            Ok(()) => "it answered only now".to_owned(),
            Err(why) => format!("it {why}"),
        }
    };
    json!({
        "socket": socket.display().to_string(),
        "pid": connection.hello().pid,
        "used": false,
        "why": why,
    })
}

/// The `status` text line of a daemon report ([`daemon_json`], or the daemon's own).
pub fn daemon_line(daemon: &Json) -> String {
    match daemon["socket"].as_str() {
        None => "daemon   none".to_owned(),
        Some(socket) if daemon["used"] == true => {
            format!("daemon   {socket} (pid {}, used)", daemon["pid"])
        }
        Some(socket) => format!(
            "daemon   {socket} (pid {}, not used: {})",
            daemon["pid"],
            printable(daemon["why"].as_str().unwrap_or_default())
        ),
    }
}

/// The counters as one JSON object.
pub fn counters_json(counters: &PeerCounters) -> Json {
    json!({
        "malformed": counters.malformed,
        "ignoredKinds": counters.ignored_kinds,
        "filter": {
            "stale": counters.filter.stale,
            "ahead": counters.filter.ahead,
            "replayed": counters.filter.replayed,
        },
        "attestedFrames": counters.attested_frames,
        "sessionFrames": counters.session_frames,
        "reconnects": counters.reconnects,
        "sendOverflows": counters.send_overflows,
        "sendRefused": counters.send_refused,
        "sendDropped": counters.send_dropped,
        "repliesSkipped": counters.replies_skipped,
        "blocksServed": counters.blocks_served,
        "revokedFrames": counters.revoked_frames,
        "unopenedSpaceItems": counters.unopened_space_items,
        "pingsRelayed": counters.pings_relayed,
        "relayedOut": counters.relayed_out,
        "relayedIn": counters.relayed_in,
        "outboxDropped": counters.outbox_dropped,
        "spaceRefusedInserts": counters.space_refused_inserts,
        "spaceCollected": counters.space_collected,
    })
}

/// One line of text on standard output (a closed pipe ends quietly).
pub fn print_text(line: &str) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Err(Failure {
            code: crate::exit::SUCCESS,
            message: String::new(),
        }),
        Err(error) => Err(Failure::error(format!(
            "cannot write standard output: {error}"
        ))),
    }
}

/// `aspace write`: one entry, confirmed held by the seed before the visitor leaves.
pub async fn write(
    global: &Global,
    schema: &str,
    json: &str,
    space: Option<&str>,
    lease: Lease,
    tags: &[(String, String)],
) -> Result<(), Failure> {
    check_schema(schema)?;
    let object = io::read_object(json, "--json")?;
    let config = session::resolve(global)?;
    let name = session::space_name(&config, space)?;
    let session = Session::join_with(global, config).await?;
    let outcome = async {
        let space = session.fleet.space(&name);
        if io::has_numbers(&object) {
            // The widths of the schema's entries the space holds decide the numbers' encoding.
            session.pull_and_settle(&space).await?;
        } else {
            space.pull().await?;
        }
        let payload = io::payload(&space, schema, object).await?;
        let id = space
            .write_value(schema, payload, lease, tags_map(tags))
            .await?;
        let confirmed = session
            .confirm(&name, &[id.as_str().to_owned()], session::CONFIRM)
            .await;
        print_line(&json!({"id": id.as_str(), "schema": schema, "space": name}))?;
        confirmed
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace read`: the available entries of a schema, JSON Lines.
pub async fn read(
    global: &Global,
    schema: &str,
    clauses: &[String],
    tags: &[(String, String)],
    limit: usize,
    timeout: Option<Duration>,
    space: Option<&str>,
) -> Result<(), Failure> {
    let mut template = template(schema, clauses)?;
    for (key, value) in tags {
        template = template.tag_eq(key.as_str(), value.as_str());
    }
    let config = session::resolve(global)?;
    let name = session::space_name(&config, space)?;
    let session = Session::join_with(global, config).await?;
    let outcome = async {
        let space = session.fleet.space(&name);
        session.pull_and_settle(&space).await?;
        session.await_payloads(&space, &template).await?;
        if let Some(timeout) = timeout
            && space.read(&template, timeout).await?.is_none()
        {
            return Err(Failure::timeout(format!(
                "no {schema} entry matched in {name} within {}",
                session::millis_text(timeout)
            )));
        }
        let found = space.read_all(&template, limit).await?;
        if found.is_empty() {
            return Err(Failure::refused(format!(
                "no {schema} entry matches in {name}"
            )));
        }
        for view in &found {
            print_line(&entry_json(view, &name))?;
        }
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace take`: one entry, held for the lease, printed with its id.
pub async fn take(
    global: &Global,
    schema: &str,
    clauses: &[String],
    lease: Lease,
    timeout: Option<Duration>,
    space: Option<&str>,
) -> Result<(), Failure> {
    let template = template(schema, clauses)?;
    let config = session::resolve(global)?;
    let name = session::space_name(&config, space)?;
    let session = Session::join_with(global, config).await?;
    let outcome = async {
        let space = session.fleet.space(&name);
        session.pull_and_settle(&space).await?;
        session.await_payloads(&space, &template).await?;
        let wait = timeout.unwrap_or(Duration::ZERO);
        let Some(taken) = space.take(&template, lease, wait).await? else {
            return Err(match timeout {
                Some(timeout) if !timeout.is_zero() => Failure::timeout(format!(
                    "no {schema} entry could be taken in {name} within {}",
                    session::millis_text(timeout)
                )),
                _ => Failure::refused(format!("no {schema} entry is available in {name}")),
            });
        };
        let entry = taken.entry();
        print_line(&json!({
            "id": entry.entry_id().as_str(),
            "schema": entry.schema(),
            "space": name,
            "entry": agentspaces::json::value_to_json(entry.payload()),
            "tags": io::tags_json(entry.tags()),
            "holder": taken.holder(),
            "epoch": taken.epoch(),
            "expiresAt": taken.expires_at_millis(),
        }))?;
        // The claim went out before the settle window; the hold stays when this peer leaves.
        taken.release();
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace complete`: completes a take this keystore's identity holds, by id.
#[allow(clippy::too_many_arguments)]
pub async fn complete(
    global: &Global,
    id: &str,
    json: Option<&str>,
    produces: Option<&str>,
    result_lease: Lease,
    tags: &[(String, String)],
    timeout: Duration,
    space: Option<&str>,
) -> Result<(), Failure> {
    let result_object = match (json, produces) {
        (Some(json), Some(schema)) => {
            check_schema(schema)?;
            Some((schema, io::read_object(json, "--json")?))
        }
        _ => None,
    };
    let config = session::resolve(global)?;
    let name = session::space_name(&config, space)?;
    let session = Session::join_with(global, config).await?;
    let outcome = async {
        let space = session.fleet.space(&name);
        let entry_id = EntryId::new(id.trim());
        session.pull_and_settle(&space).await?;
        let me = format!("{}/{}", session.peer().peer_id(), DEFAULT_AGENT_NAME);
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
        let Some(taken) = space.held(&entry_id, timeout).await? else {
            return Err(Failure::refused(format!(
                "{id} is not held by {} in {name}: it was never taken with this keystore, its \
                 take lapsed, or it is completed",
                session.peer().peer_id()
            )));
        };
        let result = match result_object {
            Some((schema, object)) => Some((schema, io::payload(&space, schema, object).await?)),
            None => None,
        };
        let result_id = taken.complete(result, result_lease, tags_map(tags)).await?;
        let mut confirm = vec![entry_id.as_str().to_owned()];
        confirm.extend(result_id.iter().map(|id| id.as_str().to_owned()));
        let confirmed = session.confirm(&name, &confirm, session::CONFIRM).await;
        print_line(&json!({
            "id": entry_id.as_str(),
            "space": name,
            "completed": true,
            "result": result_id.as_ref().map(EntryId::as_str),
            "schema": produces,
        }))?;
        confirmed
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace watch`: transitions as JSON Lines, until interrupted or `count` lines.
pub async fn watch(
    global: &Global,
    schema: &str,
    kinds: &[EventKind],
    count: Option<u64>,
    clauses: &[String],
    space: Option<&str>,
) -> Result<(), Failure> {
    let template = template(schema, clauses)?;
    let config = session::resolve(global)?;
    let name = session::space_name(&config, space)?;
    let session = Session::join_with(global, config).await?;
    let outcome = async {
        let space = session.fleet.space(&name);
        session.pull_and_settle(&space).await?;
        let mut events = space.watch(&template).await?;
        note(format!("watching {schema} in {name}"));
        let mut printed = 0u64;
        if count == Some(0) {
            return Ok(());
        }
        let mut stop = crate::signals::Stop::new()?;
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
                    print_line(&event_json(&event, &name))?;
                    printed += 1;
                    if count.is_some_and(|count| printed >= count) {
                        return Ok(());
                    }
                }
                () = stop.requested() => return Ok(()),
            }
        }
    }
    .await;
    session.close().await;
    outcome
}

/// The fleet catalogue a visitor reads: every live, verified, unrevoked card's offerings,
/// those of this keystore's peer included (a visitor publishes no card, so a card of its PeerID
/// is another process's: an `aspace work` with the same keystore).
///
/// The space an offering's input goes to is foreign data, written by whoever published the
/// card: when the configuration names the group's spaces (`ASPACE_SPACES`, or the `spaces` of
/// the fleet file's group), only those are followed, as Java follows only the spaces registered
/// with it; with none named, any space a card names is.
pub fn catalogue(fleet: &Fleet, config: &Config) -> FleetCatalog {
    let remote = RemoteActions::new(fleet).include_own(true);
    let remote = if config.settings.spaces.is_empty() {
        remote
    } else {
        remote.spaces(config.settings.spaces.iter().cloned())
    };
    FleetCatalog::with_actions(remote)
}

/// An offering as `cards --json` prints it (and `status --json` lists it).
pub fn offering_json(offering: &Offering) -> Json {
    let action = offering.action();
    json!({
        "name": offering.name(),
        "consumes": offering.consumes(),
        "produces": offering.produces(),
        "space": offering.space(),
        "kind": action.kind(),
        "agent": action.agent(),
        "issuer": action.issuer(),
        "replicas": offering.replicas(),
        "description": offering.description(),
    })
}

/// An offering as one line of text: every field a card's publisher wrote is made printable.
pub fn offering_line(offering: &Offering) -> String {
    let replicas = if offering.replicas() > 1 {
        format!(", {} replicas", offering.replicas())
    } else {
        String::new()
    };
    format!(
        "{}  {} -> {} in {}  (agent {}{replicas})",
        printable(offering.name()),
        printable(offering.consumes()),
        printable(offering.produces()),
        printable(offering.space()),
        printable(offering.action().agent()),
    )
}

/// Pulls the group's advertisements and waits until the cards stop arriving: the first within
/// 1.5 s, then until they pause for 300 ms, all within the join deadline.
async fn settle_cards(
    session: &Session,
    events: &mut broadcast::Receiver<PeerEvent>,
) -> Result<(), Failure> {
    session.peer().pull_ads().await?;
    session::settle_on(events, session.deadline, |event| {
        matches!(event, PeerEvent::AdAccepted { .. })
    })
    .await;
    // No cards from a seed that never spoke says nothing of the fleet's offerings.
    session::heard_from_seed(session.peer(), session.deadline).await
}

/// `aspace cards`: join, wait for the fleet's cards, print the catalogue's offerings, leave.
pub async fn cards(global: &Global, as_json: bool, only: &[String]) -> Result<(), Failure> {
    let session = Session::join(global).await?;
    let outcome = async {
        let mut events = session.peer().subscribe();
        settle_cards(&session, &mut events).await?;
        let offerings = catalogue(&session.fleet, &session.config)
            .only(only.iter().cloned())
            .current()
            .await;
        if offerings.is_empty() {
            note("the fleet offers nothing: no live card declares an invocable take action");
        }
        for offering in &offerings {
            if as_json {
                print_line(&offering_json(offering))?;
            } else {
                print_text(&offering_line(offering))?;
                let description = printable(&offering.description());
                if !description.trim().is_empty() {
                    print_text(&format!("    {description}"))?;
                }
            }
        }
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace call`: find the offering (waiting within the join deadline for its card), write the
/// input where its agent takes, and print the correlated result; exit 2 without an offering, 3
/// without a result within `timeout` (the input stays leased for a late worker).
pub async fn call(
    global: &Global,
    target: &str,
    json: Option<&str>,
    timeout: Duration,
) -> Result<(), Failure> {
    let target = target.trim();
    if target.is_empty() {
        return Err(Failure::refused(
            "name the offering to call, or the schema it consumes (aspace cards lists them)",
        ));
    }
    let object = match json {
        Some(json) => io::read_object(json, "--json")?,
        None => JsonMap::new(),
    };
    let session = Session::join(global).await?;
    let outcome = async {
        let catalog = catalogue(&session.fleet, &session.config);
        let offering = find_offering(&session, &catalog, target).await?;
        let space = session.fleet.space(offering.space());
        if io::has_numbers(&object) {
            // The widths of the consumed schema's entries the space holds decide the numbers.
            session.pull_and_settle(&space).await?;
        }
        let input = io::payload(&space, offering.consumes(), object).await?;
        let called = catalog
            .call_offering(&offering, input, &Principal::local(), timeout)
            .await?;
        let Some(result) = &called.result else {
            // The input stays leased for a late worker: make sure the seed holds it.
            if let Err(failure) = session
                .confirm(
                    offering.space(),
                    &[called.input_id.as_str().to_owned()],
                    session::CONFIRM,
                )
                .await
            {
                note(format!(
                    "the input may not have reached the seed: {failure}"
                ));
            }
            // The schema and the space are a card's text: printable, as `cards` prints them.
            return Err(Failure::timeout(format!(
                "no {} result answered {} within {}; the input {} stays leased in {} for a \
                 late worker",
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
        // Where the input went: a card names it, so the caller sees where it was routed.
        line.insert("inputSpace".to_owned(), Json::from(offering.space()));
        if let Json::Object(mut entry) = entry_json(result, offering.action().result_space()) {
            line.append(&mut entry);
        }
        print_line(&Json::Object(line))
    }
    .await;
    session.close().await;
    outcome
}

/// The offering `target` names (or the one consuming it), from the fleet's cards: they are
/// pulled and settled, then each card that arrives before the join deadline is another chance.
async fn find_offering(
    session: &Session,
    catalog: &FleetCatalog,
    target: &str,
) -> Result<Offering, Failure> {
    let mut events = session.peer().subscribe();
    settle_cards(session, &mut events).await?;
    loop {
        match catalog.find(target).await {
            Ok(offering) => return Ok(offering),
            Err(CatalogError::NotFound(_)) if Instant::now() < session.deadline => {
                let card = loop {
                    match tokio::time::timeout_at(session.deadline, events.recv()).await {
                        // A card arrived, or events were dropped and one may have: look again.
                        Ok(Ok(PeerEvent::AdAccepted { .. }))
                        | Ok(Err(broadcast::error::RecvError::Lagged(_))) => break true,
                        Ok(Ok(_)) => {}
                        Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break false,
                    }
                };
                if !card {
                    // The join window ended: one last look, with the fleet as it is now.
                    return catalog.find(target).await.map_err(Failure::from);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// `aspace completions <shell>`.
pub fn completions(shell: clap_complete::Shell) -> Result<(), Failure> {
    let mut command = Cli::command();
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut command, "aspace", &mut out);
    write_stdout(&out)
}

/// `aspace man`: the page of `aspace` on standard output, or one page per command in `dir`.
pub fn man(out_dir: Option<&Path>) -> Result<(), Failure> {
    let command = Cli::command();
    let render = |command: clap::Command| -> Result<Vec<u8>, Failure> {
        let mut page = Vec::new();
        clap_mangen::Man::new(command)
            .render(&mut page)
            .map_err(|error| Failure::error(format!("cannot render the manual: {error}")))?;
        Ok(page)
    };
    let Some(dir) = out_dir else {
        return write_stdout(&render(command)?);
    };
    std::fs::create_dir_all(dir)
        .map_err(|error| Failure::error(format!("cannot create {}: {error}", dir.display())))?;
    let mut written = Vec::new();
    for sub in command.get_subcommands() {
        let name = format!("aspace-{}", sub.get_name());
        let page = render(sub.clone().name(name.clone()))?;
        let path = dir.join(format!("{name}.1"));
        std::fs::write(&path, page)
            .map_err(|error| Failure::error(format!("cannot write {}: {error}", path.display())))?;
        written.push(path.display().to_string());
    }
    let path = dir.join("aspace.1");
    std::fs::write(&path, render(command)?)
        .map_err(|error| Failure::error(format!("cannot write {}: {error}", path.display())))?;
    written.insert(0, path.display().to_string());
    print_line(&json!({"written": written}))
}

/// Writes `bytes` to standard output; a reader that went away (a closed pipe) ends the command
/// quietly with exit 0, as [`print_line`] does.
fn write_stdout(bytes: &[u8]) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Err(Failure {
            code: crate::exit::SUCCESS,
            message: String::new(),
        }),
        Err(error) => Err(Failure::error(format!(
            "cannot write standard output: {error}"
        ))),
    }
}

/// A template of `schema` and the filter clauses.
pub fn template(schema: &str, clauses: &[String]) -> Result<Template, Failure> {
    check_schema(schema)?;
    let mut template = Template::new(schema);
    for clause in clauses {
        template = template
            .where_clause(clause)
            .map_err(|error| Failure::refused(format!("--where {clause:?}: {error}")))?;
    }
    Ok(template)
}

/// A schema is `<Type>#v<version>`; anything else is refused before joining.
pub fn check_schema(schema: &str) -> Result<(), Failure> {
    let well_formed = schema.rsplit_once("#v").is_some_and(|(name, version)| {
        !name.trim().is_empty()
            && !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_digit())
    });
    if well_formed {
        Ok(())
    } else {
        Err(Failure::refused(format!(
            "{schema:?} is not a schema; write <Type>#v<version>, such as \
             'shop.Order#v1' (quote it: # starts a shell comment)"
        )))
    }
}

/// What the configuration says, for `doctor`.
pub fn config_origin(config: &Config, name: &str) -> String {
    config
        .origin(name)
        .map_or_else(|| "the default".to_owned(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_must_carry_a_version() {
        assert!(check_schema("shop.Order#v1").is_ok());
        assert!(check_schema("a.B$C#v12").is_ok());
        for bad in ["shop.Order", "#v1", "shop.Order#v", "shop.Order#vx", ""] {
            let error = check_schema(bad).expect_err(bad);
            assert_eq!(error.code, crate::exit::REFUSED);
        }
    }
}
