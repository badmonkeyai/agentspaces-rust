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

//! The visitor side: connect to the daemon, judge its hello against the visitor's
//! configuration, send the command as a request, and relay the frames to standard output and
//! standard error ([`visit`]). [`Connection`] is the same exchange for any other face of
//! `aspace` that wants the daemon's peer (an MCP gateway).

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentspaces::config::Config;
use agentspaces::group::{GroupSpec, Profile};
use serde_json::{Map as JsonMap, Value as Json};
use tokio::io::{BufReader, ReadHalf, WriteHalf};

use super::protocol::{
    CallArgs, CardsArgs, CompleteArgs, Envelope, Frame, Hello, MAX_FRAME, MAX_HELLO, PROTOCOL,
    ReadArgs, StatusArgs, TakeArgs, WatchArgs, WriteArgs, read_json, write_json,
};
use super::{CONNECT_WAIT, HELLO_WAIT};
use crate::cli::{Command, Global};
use crate::commands::{check_schema, print_text, template};
use crate::exit::{Failure, SUCCESS};
use crate::io::{print_line, read_object};
use crate::session::{self, note};

/// The stream a visitor holds.
#[cfg(unix)]
type Stream = tokio::net::UnixStream;
/// The stream a visitor holds.
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Why no daemon serves a visitor.
#[derive(Debug)]
pub enum NoDaemon {
    /// Nothing is at the socket, or nothing accepts its connections (a stale socket).
    Absent(PathBuf),
    /// Something accepted but sent no hello in time, or not one this visitor reads.
    NoAnswer(PathBuf, String),
    /// The socket, its directory, or the process serving it is not this user's (or not safe).
    Unsafe(Failure),
    /// The daemon refused this visitor (its exit frame instead of a hello).
    Refused(PathBuf, String),
    /// The daemon speaks another protocol version.
    Version(PathBuf, u32),
    /// The daemon serves another group, keystore, or a weaker profile.
    Mismatch(PathBuf, String),
}

impl std::fmt::Display for NoDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoDaemon::Absent(socket) => write!(f, "no daemon answered at {}", socket.display()),
            NoDaemon::NoAnswer(socket, why) => {
                write!(
                    f,
                    "the daemon at {} did not answer: {why}",
                    socket.display()
                )
            }
            NoDaemon::Unsafe(failure) => write!(f, "the daemon socket is refused: {failure}"),
            NoDaemon::Refused(socket, why) => {
                write!(f, "the daemon at {} refused: {why}", socket.display())
            }
            NoDaemon::Version(socket, version) => write!(
                f,
                "the daemon at {} speaks protocol {version}, this aspace {PROTOCOL}",
                socket.display()
            ),
            NoDaemon::Mismatch(socket, why) => {
                write!(f, "the daemon at {} {why}", socket.display())
            }
        }
    }
}

/// A connection to a daemon whose hello was read.
pub struct Connection {
    reader: BufReader<ReadHalf<Stream>>,
    writer: WriteHalf<Stream>,
    hello: Hello,
    socket: PathBuf,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("socket", &self.socket)
            .field("hello", &self.hello)
            .finish_non_exhaustive()
    }
}

/// Connects to the daemon at `socket` as user `uid`: the socket and its directory must be this
/// user's (and the directory not writable by others), the process accepting must run as `uid`,
/// and its first frame must be a hello of this protocol, all within [`CONNECT_WAIT`] and
/// [`HELLO_WAIT`].
#[cfg(unix)]
pub async fn connect(socket: &Path, uid: u32) -> Result<Connection, NoDaemon> {
    use super::paths::{self, AtPath};
    let absent = || NoDaemon::Absent(socket.to_path_buf());
    if !paths::check_dir(socket, uid).map_err(NoDaemon::Unsafe)? {
        return Err(absent());
    }
    if paths::check_socket_file(socket, uid).map_err(NoDaemon::Unsafe)? == AtPath::Nothing {
        return Err(absent());
    }
    let stream = match tokio::time::timeout(CONNECT_WAIT, Stream::connect(socket)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err(absent()),
        Err(_) => {
            return Err(NoDaemon::NoAnswer(
                socket.to_path_buf(),
                format!(
                    "the connection was not accepted within {}",
                    session::millis_text(CONNECT_WAIT)
                ),
            ));
        }
    };
    let serving = stream.peer_cred().ok().map(|credentials| credentials.uid());
    if serving != Some(uid) {
        return Err(NoDaemon::Unsafe(Failure::auth(format!(
            "the process serving {} runs as {}, not as this user (uid {uid})",
            socket.display(),
            serving.map_or_else(|| "an unknown user".to_owned(), |uid| format!("uid {uid}"))
        ))));
    }
    greet(stream, socket).await
}

/// Connects to the daemon's named pipe `socket` ([`super::windows`]).
#[cfg(windows)]
pub async fn connect(socket: &Path, _uid: u32) -> Result<Connection, NoDaemon> {
    let stream = super::windows::connect(socket)
        .await
        .map_err(|_| NoDaemon::Absent(socket.to_path_buf()))?;
    greet(stream, socket).await
}

/// Reads the hello of a connected daemon.
async fn greet(stream: Stream, socket: &Path) -> Result<Connection, NoDaemon> {
    let (read, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let no_answer = |why: String| NoDaemon::NoAnswer(socket.to_path_buf(), why);
    let first = match tokio::time::timeout(HELLO_WAIT, read_json(&mut reader, MAX_HELLO)).await {
        Ok(Ok(json)) => json,
        Ok(Err(error)) => return Err(no_answer(error.to_string())),
        Err(_) => {
            return Err(no_answer(format!(
                "no hello within {}",
                session::millis_text(HELLO_WAIT)
            )));
        }
    };
    let hello = match first
        .get("hello")
        .and_then(|hello| hello.get("protocol"))
        .and_then(Json::as_u64)
    {
        Some(version) if version != u64::from(PROTOCOL) => {
            return Err(NoDaemon::Version(
                socket.to_path_buf(),
                u32::try_from(version).unwrap_or(u32::MAX),
            ));
        }
        _ => match Frame::from_json(first).map_err(no_answer)? {
            Frame::Hello(hello) => hello,
            Frame::Exit { error, .. } => {
                return Err(NoDaemon::Refused(
                    socket.to_path_buf(),
                    error.unwrap_or_else(|| "no reason given".to_owned()),
                ));
            }
            _ => return Err(no_answer("its first frame is not a hello".to_owned())),
        },
    };
    Ok(Connection {
        reader,
        writer,
        hello,
        socket: socket.to_path_buf(),
    })
}

impl Connection {
    /// The daemon's hello.
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Whether the daemon serves `config`: the same GroupID, the same keystore (or neither has
    /// one), and a profile at least as strict (`mtls` serves a `dev-local` visitor, not the
    /// other way round); why not otherwise.
    pub fn serves(&self, config: &Config) -> Result<(), String> {
        let hello = &self.hello;
        let Some(group) = group_id(config) else {
            return Err(
                "cannot be matched: the configuration's founding document does not verify"
                    .to_owned(),
            );
        };
        if hello.group != group {
            return Err(format!(
                "serves group {}{}, not {}",
                hello.group,
                hello
                    .group_name
                    .as_deref()
                    .map(|name| format!(" ({name})"))
                    .unwrap_or_default(),
                session::describe_group(config)
            ));
        }
        let keystore = super::keystore_text(config);
        if hello.keystore != keystore {
            let named = |keystore: Option<&str>| {
                keystore.map_or_else(
                    || "no keystore (a fresh identity)".to_owned(),
                    |dir| format!("the keystore {dir}"),
                )
            };
            return Err(format!(
                "runs with {}, not {} (a take through it would be held by another identity)",
                named(hello.keystore.as_deref()),
                named(keystore.as_deref())
            ));
        }
        let strict = |profile: &str| match Profile::parse(profile) {
            Some(Profile::Mtls) => 1,
            Some(Profile::DevLocal) => 0,
            None => -1,
        };
        let wanted = super::profile_name(config.settings.profile);
        if strict(&hello.profile) < strict(wanted) {
            return Err(format!(
                "runs the {} profile, weaker than this configuration's {wanted}",
                hello.profile
            ));
        }
        Ok(())
    }

    /// Sends one request, answering its frames as they come ([`Replies`]).
    pub async fn request(mut self, envelope: &Envelope) -> Result<Replies, Failure> {
        let json = serde_json::to_value(envelope)
            .map_err(|error| Failure::error(format!("the request does not serialize: {error}")))?;
        write_json(&mut self.writer, &json).await.map_err(|error| {
            Failure::error(format!(
                "the daemon at {} closed the connection before the request: {error}",
                self.socket.display()
            ))
        })?;
        Ok(Replies {
            connection: self,
            verb: envelope.verb.clone(),
        })
    }
}

/// The frames answering a request, up to its exit frame.
#[derive(Debug)]
pub struct Replies {
    connection: Connection,
    verb: String,
}

/// Whether a request of `verb` may have changed the fleet before its answer was lost (a write,
/// a take, a completion, a call): running it again blindly could do it twice.
fn may_have_taken_effect(verb: &str) -> bool {
    matches!(verb, "write" | "take" | "complete" | "call")
}

impl Replies {
    /// The next frame; an error when the daemon closed the connection without an exit frame
    /// (it stopped, or died), or sent what is not a frame. What the error advises depends on the
    /// verb: a read may simply run again, a write, take, completion, or call may have taken
    /// effect.
    pub async fn next(&mut self) -> Result<Frame, Failure> {
        let socket = self.connection.socket.display().to_string();
        let verb = &self.verb;
        let json = read_json(&mut self.connection.reader, MAX_FRAME)
            .await
            .map_err(|error| {
                if may_have_taken_effect(verb) {
                    Failure::error(format!(
                        "the daemon at {socket} ended the request without an answer ({error}); \
                         it may have stopped, and the {verb} may have taken effect: check (read, \
                         or aspace status) before running it again"
                    ))
                } else {
                    Failure::error(format!(
                        "the daemon at {socket} ended the request without an answer ({error}); \
                         it may have stopped: run the command again"
                    ))
                }
            })?;
        Frame::from_json(json)
            .map_err(|why| Failure::error(format!("the daemon at {socket} sent {why}")))
    }

    /// Prints each frame as the command would have, until the exit frame, and answers its
    /// outcome. With `stop`, a SIGINT, SIGTERM, SIGHUP, or SIGQUIT ends it with exit 0 (an
    /// interrupted `watch`), closing the connection, which ends the request on the daemon.
    pub async fn relay(mut self, mut stop: Option<crate::signals::Stop>) -> Result<(), Failure> {
        loop {
            let frame = match stop.as_mut() {
                Some(stop) => tokio::select! {
                    frame = self.next() => frame?,
                    () = stop.requested() => return Ok(()),
                },
                None => self.next().await?,
            };
            match frame {
                Frame::Out(value) => print_line(&value)?,
                Frame::Text(line) => print_text(&line)?,
                Frame::Note(line) => note(line),
                Frame::Exit { code, error } => {
                    return if code == SUCCESS {
                        Ok(())
                    } else {
                        Err(Failure {
                            code,
                            message: error.unwrap_or_default(),
                        })
                    };
                }
                Frame::Hello(_) => {
                    return Err(Failure::error(format!(
                        "the daemon at {} sent a second hello",
                        self.connection.socket.display()
                    )));
                }
            }
        }
    }
}

/// The GroupID a configuration joins: from its founding text or join URI, or from its founding
/// document once that verifies; `None` when it does not.
pub fn group_id(config: &Config) -> Option<String> {
    match &config.settings.group {
        GroupSpec::FoundingDocument(bytes) => {
            let signed = agentspaces::wire::cbor::decode(bytes).ok()?;
            agentspaces::wire::founding::verify_signed_group_ad(&signed)
        }
        other => other.group_id(),
    }
}

/// The socket a configuration names, or the default for this user.
pub fn socket_of(config: &Config) -> Result<PathBuf, Failure> {
    #[cfg(unix)]
    {
        super::paths::socket_path(
            config.socket.as_deref(),
            session::env,
            super::paths::own_uid(),
        )
    }
    #[cfg(windows)]
    {
        Ok(super::windows::pipe_name(config.socket.as_deref()))
    }
}

/// The user this process runs as (0 where there is none).
fn own_uid() -> u32 {
    #[cfg(unix)]
    {
        super::paths::own_uid()
    }
    #[cfg(windows)]
    {
        0
    }
}

/// [`session::through_daemon`]: the command checked as it checks itself before joining, then
/// run through a daemon that serves `global`'s configuration; `None` when the command never uses
/// one or none serves it (said on standard error, in one line), and the command then joins
/// itself.
///
/// The JSON of `--json -` or `--json @file` is read first, before any connection, so a slow
/// producer holds no connection of the daemon's (whose wait for a request is bounded); for a
/// join of its own the command then carries what was read as its literal `--json`, so standard
/// input is read once whichever path runs.
///
/// A join of its own is refused when it would share a running daemon's PeerID in the same group
/// (the seed would take the two links for one member, and the join would see nothing): the
/// daemon answered with this keystore and group but a weaker profile (exit 2), or a daemon whose
/// keystore marker names this group did not answer, was busy, or spoke another protocol (exit 1),
/// or listens on another socket (exit 2).
pub async fn visit(global: &Global, command: &mut Command) -> Option<Result<(), Failure>> {
    match Plan::of(command)? {
        Ok(_) => {}
        Err(failure) => return Some(Err(failure)),
    }
    if let Err(failure) = read_ahead(command) {
        return Some(Err(failure));
    }
    let command: &Command = command;
    let plan = match Plan::of(command)? {
        Ok(plan) => plan,
        Err(failure) => return Some(Err(failure)),
    };
    let config = match session::resolve(global) {
        Ok(config) => config,
        Err(failure) => return Some(Err(failure)),
    };
    if let Err(failure) = plan.check(&config) {
        return Some(Err(failure));
    }
    let socket = match socket_of(&config) {
        Ok(socket) => socket,
        Err(failure) => {
            note(format!(
                "no daemon socket ({failure}); joining the group itself"
            ));
            return None;
        }
    };
    let connection = match connect(&socket, own_uid()).await {
        Ok(connection) => connection,
        Err(why) => {
            if let Some(failure) = unanswered_resident(&config, &socket, &why) {
                return Some(Err(failure));
            }
            note(format!("{why}; joining the group itself"));
            return None;
        }
    };
    if let Err(why) = connection.serves(&config) {
        if let Some(failure) = same_member(&connection, &config, &why) {
            return Some(Err(failure));
        }
        note(format!(
            "{}; joining the group itself",
            NoDaemon::Mismatch(socket, why)
        ));
        return None;
    }
    tracing::debug!(socket = %socket.display(), pid = connection.hello().pid, "through the daemon");
    // From here the command is the daemon's: its JSON goes in the request, and every failure is
    // the command's.
    let envelope = match plan.envelope(&config) {
        Ok(envelope) => envelope,
        Err(failure) => return Some(Err(failure)),
    };
    let stop = if plan.streams() {
        match crate::signals::Stop::new() {
            Ok(stop) => Some(stop),
            Err(failure) => return Some(Err(failure)),
        }
    } else {
        None
    };
    Some(match connection.request(&envelope).await {
        Ok(replies) => replies.relay(stop).await,
        Err(failure) => Err(failure),
    })
}

/// Reads the JSON a command takes from `-` or `@file` now, and gives the command the object
/// read as its literal `--json`: whichever path runs it then, standard input has been read once.
fn read_ahead(command: &mut Command) -> Result<(), Failure> {
    let json = match command {
        Command::Write { json, .. } => Some(json),
        Command::Complete {
            json: Some(json),
            produces: Some(_),
            ..
        } => Some(json),
        Command::Call {
            json: Some(json), ..
        } => Some(json),
        _ => None,
    };
    if let Some(json) = json
        && (json.as_str() == "-" || json.starts_with('@'))
    {
        let object = read_object(json, "--json")?;
        *json = Json::Object(object).to_string();
    }
    Ok(())
}

/// The refusal of a join of its own while a daemon on the visitor's keystore serves its group
/// but did not answer at `socket` (or could not be used): that join would share the daemon's
/// PeerID and see nothing. `None` when no live daemon marks the keystore for this group.
fn unanswered_resident(config: &Config, socket: &Path, why: &NoDaemon) -> Option<Failure> {
    let keystore = config.settings.keystore.as_deref()?;
    let group = group_id(config)?;
    let daemon = crate::resident::daemons_on(keystore)
        .into_iter()
        .find(|mark| mark.group.as_deref().is_none_or(|marked| marked == group))?;
    let pid = daemon.pid;
    let listens = daemon
        .socket
        .as_deref()
        .map(crate::io::printable)
        .filter(|marked| *marked != socket.display().to_string());
    let shared = format!(
        "a join of its own would share the PeerID of the running aspace daemon (pid {pid}) on \
         the keystore {}, and see nothing",
        keystore.display()
    );
    Some(match (why, listens) {
        (NoDaemon::Unsafe(failure), _) => failure.clone(),
        (NoDaemon::Absent(_), Some(listens)) => Failure::refused(format!(
            "{why}; {shared}: the daemon listens on {listens}, so pass --socket {listens} (or \
             set ASPACE_SOCKET), or give this command another keystore (--keystore DIR)"
        )),
        (NoDaemon::Absent(_), None) => Failure::refused(format!(
            "{why}; {shared}: pass the daemon's --socket, or give this command another keystore \
             (--keystore DIR)"
        )),
        _ => Failure::error(format!(
            "{why}; {shared}: try again in a moment, or stop the daemon (pid {pid}), or give this \
             command another keystore (--keystore DIR)"
        )),
    })
}

/// The refusal of a join of its own when the daemon that answered serves this group with this
/// keystore, only not as this configuration wants (a weaker profile): that join would share its
/// PeerID and see nothing. `None` for a daemon of another group or keystore.
fn same_member(connection: &Connection, config: &Config, why: &str) -> Option<Failure> {
    let hello = connection.hello();
    let group = group_id(config)?;
    if hello.group != group || hello.keystore != super::keystore_text(config) {
        return None;
    }
    let wanted = super::profile_name(config.settings.profile);
    Some(Failure::refused(format!(
        "the daemon at {} {why}; a join of its own would share the daemon's PeerID (its keystore \
         is this command's) and see nothing: pass --profile {} to use the daemon, restart the \
         daemon with --profile {wanted}, or give this command another keystore (--keystore DIR)",
        connection.socket.display(),
        crate::io::printable(&hello.profile),
    )))
}

/// A visitor command as the daemon runs it.
struct Plan<'a> {
    command: &'a Command,
}

impl<'a> Plan<'a> {
    /// The plan of `command`, or `None` for a command that never uses the daemon. The checks a
    /// command makes before reading its configuration are made here (`Some(Err)`), in its
    /// order: a literal `--json` is parsed, while one from `-` or `@file` is read by
    /// [`read_ahead`] once these checks pass.
    fn of(command: &'a Command) -> Option<Result<Plan<'a>, Failure>> {
        let checked = match command {
            Command::Status { .. } | Command::Cards { .. } => Ok(()),
            Command::Write { schema, json, .. } => {
                check_schema(schema).and_then(|()| literal(json).map(drop))
            }
            Command::Read {
                schema, clauses, ..
            }
            | Command::Take {
                schema, clauses, ..
            }
            | Command::Watch {
                schema, clauses, ..
            } => template(schema, clauses).map(drop),
            Command::Complete { json, produces, .. } => match (json, produces) {
                (Some(json), Some(schema)) => {
                    check_schema(schema).and_then(|()| literal(json).map(drop))
                }
                _ => Ok(()),
            },
            Command::Call { target, json, .. } => {
                if target.trim().is_empty() {
                    Err(Failure::refused(
                        "name the offering to call, or the schema it consumes (aspace cards \
                         lists them)",
                    ))
                } else {
                    json.as_deref()
                        .map_or(Ok(()), |json| literal(json).map(drop))
                }
            }
            _ => return None,
        };
        Some(checked.map(|()| Plan { command }))
    }

    /// The check of the resolved configuration a command makes before joining: the space it
    /// names.
    fn check(&self, config: &Config) -> Result<(), Failure> {
        match self.command {
            Command::Write { space, .. }
            | Command::Read { space, .. }
            | Command::Take { space, .. }
            | Command::Complete { space, .. }
            | Command::Watch { space, .. } => {
                session::space_name(config, space.as_deref()).map(drop)
            }
            _ => Ok(()),
        }
    }

    /// Whether the command streams until interrupted.
    fn streams(&self) -> bool {
        matches!(self.command, Command::Watch { .. })
    }

    /// The request, with its JSON ([`read_ahead`] has made it literal).
    fn envelope(&self, config: &Config) -> Result<Envelope, Failure> {
        let space = |flag: &Option<String>| session::space_name(config, flag.as_deref());
        let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let built = match self.command {
            Command::Status { json } => Envelope::new(
                "status",
                &StatusArgs {
                    json: *json,
                    mcp: crate::mcp::settings_json(),
                },
            ),
            Command::Write {
                schema,
                json,
                space: flag,
                lease,
                tags,
            } => Envelope::new(
                "write",
                &WriteArgs {
                    schema: schema.clone(),
                    entry: read_object(json, "--json")?,
                    space: space(flag)?,
                    lease_millis: lease.millis(),
                    tags: tags.clone(),
                },
            ),
            Command::Read {
                schema,
                clauses,
                tags,
                limit,
                timeout,
                space: flag,
            } => Envelope::new(
                "read",
                &ReadArgs {
                    schema: schema.clone(),
                    clauses: clauses.clone(),
                    tags: tags.clone(),
                    limit: *limit,
                    timeout_millis: timeout.map(millis),
                    space: space(flag)?,
                },
            ),
            Command::Take {
                schema,
                clauses,
                lease,
                timeout,
                space: flag,
            } => Envelope::new(
                "take",
                &TakeArgs {
                    schema: schema.clone(),
                    clauses: clauses.clone(),
                    lease_millis: lease.millis(),
                    timeout_millis: timeout.map(millis),
                    space: space(flag)?,
                },
            ),
            Command::Complete {
                id,
                json,
                produces,
                result_lease,
                tags,
                timeout,
                space: flag,
            } => {
                let result = match (json, produces) {
                    (Some(json), Some(_)) => Some(read_object(json, "--json")?),
                    _ => None,
                };
                Envelope::new(
                    "complete",
                    &CompleteArgs {
                        id: id.clone(),
                        produces: result.as_ref().and(produces.clone()),
                        result,
                        result_lease_millis: result_lease.millis(),
                        tags: tags.clone(),
                        timeout_millis: millis(*timeout),
                        space: space(flag)?,
                    },
                )
            }
            Command::Watch {
                schema,
                kinds,
                count,
                clauses,
                space: flag,
            } => Envelope::new(
                "watch",
                &WatchArgs {
                    schema: schema.clone(),
                    kinds: kinds.iter().map(|kind| kind.as_str().to_owned()).collect(),
                    count: *count,
                    clauses: clauses.clone(),
                    space: space(flag)?,
                },
            ),
            Command::Cards { json, only } => Envelope::new(
                "cards",
                &CardsArgs {
                    json: *json,
                    only: only.clone(),
                    spaces: config.settings.spaces.clone(),
                },
            ),
            Command::Call {
                target,
                json,
                timeout,
            } => Envelope::new(
                "call",
                &CallArgs {
                    target: target.trim().to_owned(),
                    input: match json {
                        Some(json) => read_object(json, "--json")?,
                        None => JsonMap::new(),
                    },
                    timeout_millis: millis(*timeout),
                    wait_millis: millis(config.join_timeout),
                    spaces: config.settings.spaces.clone(),
                },
            ),
            _ => Err("the command is not one the daemon serves".to_owned()),
        };
        built.map_err(Failure::error)
    }
}

/// A literal `--json` parsed now (`Some`); `None` for `-` and `@file`, read later.
fn literal(argument: &str) -> Result<Option<JsonMap<String, Json>>, Failure> {
    if argument == "-" || argument.starts_with('@') {
        Ok(None)
    } else {
        read_object(argument, "--json").map(Some)
    }
}
