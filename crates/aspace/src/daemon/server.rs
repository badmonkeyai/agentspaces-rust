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

//! The resident side on Unix: the lock, the stale socket, the join, the listener, the uid check
//! of every connection, and the stop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::client::{self, NoDaemon};
use super::paths::{self, AtPath, Lock, LockError};
use super::verbs::{self, Reply, State};
use super::{MAX_CONNECTIONS, STOP_GRACE};
use crate::cli::Global;
use crate::exit::Failure;
use crate::io::print_line;
use crate::resident::Resident;
use crate::session::{self, Session, note};
use crate::signals::Stop;

/// Whether a connecting process may use the daemon: only a process of the daemon's own user,
/// `own`. `peer` is the connecting process's uid as the socket reports it, `None` when it could
/// not be read (refused too).
pub fn authorize(peer: Option<u32>, own: u32) -> Result<(), String> {
    match peer {
        Some(uid) if uid == own => Ok(()),
        Some(uid) => Err(format!(
            "a process of uid {uid} may not use the daemon of uid {own}"
        )),
        None => Err("the connecting process's credentials could not be read".to_owned()),
    }
}

/// `aspace daemon` on Unix.
pub async fn run(global: &Global) -> Result<(), Failure> {
    let config = session::resolve(global)?;
    let uid = paths::own_uid();
    let socket = paths::socket_path(config.socket.as_deref(), session::env, uid)?;
    paths::check_length(&socket)?;
    paths::ensure_dir(&socket, uid)?;
    // One daemon per socket: the lock first, so two starting daemons never both join (with one
    // keystore, the seed would take them for one member).
    let lock = match Lock::take(&socket) {
        Ok(lock) => lock,
        Err(LockError::Held(pid)) => return Err(already_running(&socket, pid, uid).await),
        Err(LockError::Failed(why)) => return Err(Failure::error(why)),
    };
    clear_stale(&socket, uid).await?;
    let session = Session::join_with(global, config).await?;
    let outcome = serve(session, &socket, uid).await;
    drop(lock);
    outcome
}

/// The refusal of a second daemon: who runs on `socket`, as its hello (or its lock) says.
async fn already_running(socket: &Path, pid: Option<u32>, uid: u32) -> Failure {
    match client::connect(socket, uid).await {
        Ok(connection) => {
            let hello = connection.hello();
            Failure::refused(format!(
                "a daemon is already running on {} (pid {}, group {}{}); stop it first, or pass \
                 another --socket",
                socket.display(),
                hello.pid,
                hello.group,
                hello
                    .group_name
                    .as_deref()
                    .map(|name| format!(" {name}"))
                    .unwrap_or_default()
            ))
        }
        Err(_) => Failure::refused(format!(
            "another daemon{} holds {} and is starting or stopping; wait for it, or pass another \
             --socket",
            pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default(),
            paths::lock_path(socket).display()
        )),
    }
}

/// Removes a socket left by a daemon that is gone (nothing answers it); refuses when one answers
/// (a daemon that does not hold the lock: its lock file was removed under it).
async fn clear_stale(socket: &Path, uid: u32) -> Result<(), Failure> {
    if paths::check_socket_file(socket, uid)? == AtPath::Nothing {
        return Ok(());
    }
    match client::connect(socket, uid).await {
        Ok(connection) => {
            let hello = connection.hello();
            Err(Failure::refused(format!(
                "a daemon is already running on {} (pid {}, group {})",
                socket.display(),
                hello.pid,
                hello.group
            )))
        }
        Err(NoDaemon::Unsafe(failure)) => Err(failure),
        Err(NoDaemon::Absent(_)) => {
            std::fs::remove_file(socket).map_err(|error| {
                Failure::error(format!(
                    "cannot remove the stale socket {}: {error}",
                    socket.display()
                ))
            })?;
            note(format!(
                "removed the stale socket {} (no daemon answered it)",
                socket.display()
            ));
            Ok(())
        }
        // Something accepts on the socket: it is not stale, whatever it is.
        Err(other) => Err(Failure::refused(format!(
            "{other}, but a process listens on it; stop that process, or pass another --socket"
        ))),
    }
}

/// The bound socket, removed when dropped if it is still the file this daemon bound.
struct Bound {
    path: PathBuf,
    id: Option<(u64, u64)>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        if self.id.is_some() && paths::file_id(&self.path) == self.id {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Why the daemon stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stopping {
    Signal,
    GaveUp,
}

/// The joined daemon's life: settle, bind, greet, serve, stop, leave.
async fn serve(session: Session, socket: &Path, uid: u32) -> Result<(), Failure> {
    let hello = verbs::hello(&session, &socket.display().to_string());
    // The marker names the group and the socket: a visitor that cannot use this daemon then
    // knows not to join the group with its PeerID.
    let resident = session
        .config
        .settings
        .keystore
        .as_deref()
        .and_then(|keystore| {
            Resident::mark_with(
                keystore,
                "aspace daemon",
                &[("group", &hello.group), ("socket", &hello.socket)],
            )
        });
    let (stopping_tx, stopping) = watch::channel(false);
    let state = Arc::new(State::new(session, hello, stopping));
    let outcome = listen(&state, socket, uid, &stopping_tx).await;
    // The connections still running hold the state; the peer is closed through the fleet,
    // which every clone shares.
    if let Err(error) = state.session.fleet.close().await {
        tracing::debug!(%error, "close");
    }
    drop(resident);
    outcome
}

/// Pulls the advertisements and the configured spaces, binds the socket, greets, and serves
/// until a stop.
async fn listen(
    state: &Arc<State>,
    socket: &Path,
    uid: u32,
    stopping: &watch::Sender<bool>,
) -> Result<(), Failure> {
    let session = &state.session;
    let peer = session.peer().clone();
    // From here SIGINT, SIGTERM, SIGHUP, and SIGQUIT ask for a stop.
    let mut stop = Stop::new()?;
    let (gave_up_tx, mut gave_up) = watch::channel(false);
    let link_watch = tokio::spawn(crate::resident::watch_link(peer.subscribe(), gave_up_tx));
    verbs::warm_up(state).await?;

    let listener = UnixListener::bind(socket).map_err(|error| {
        Failure::error(format!("cannot listen on {}: {error}", socket.display()))
    })?;
    let bound = Bound {
        path: socket.to_path_buf(),
        id: paths::file_id(socket),
    };
    paths::restrict_socket(socket)?;
    // The hello on standard output tells a script or a supervisor the daemon serves; a closed
    // standard output does not stop it.
    let hello = serde_json::to_value(&state.hello).unwrap_or_default();
    let _ = print_line(&hello);
    note(format!(
        "serving {} as {} on {} (stop with SIGINT or SIGTERM)",
        session::describe_group(&session.config),
        peer.peer_id(),
        socket.display()
    ));

    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    let why = loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let credentials = stream.peer_cred().map(|credentials| credentials.uid());
                    // Why the credentials could not be read (a visitor that gave up waiting and
                    // left before it was accepted, mostly), said with the refusal.
                    let unread = credentials
                        .as_ref()
                        .err()
                        .map(|error| format!(" ({error})"))
                        .unwrap_or_default();
                    if let Err(why) = authorize(credentials.ok(), uid) {
                        tracing::warn!("refused a connection: {why}{unread}");
                        connections.spawn(refuse(stream, crate::exit::AUTH, "this daemon serves only its own user".to_owned()));
                        continue;
                    }
                    match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => {
                            let state = Arc::clone(state);
                            connections.spawn(async move {
                                verbs::connection(stream, &state).await;
                                drop(permit);
                            });
                        }
                        Err(_) => {
                            connections.spawn(refuse(
                                stream,
                                crate::exit::ERROR,
                                format!("the daemon is serving {MAX_CONNECTIONS} visitors; try again in a moment"),
                            ));
                        }
                    }
                }
                Err(error) => {
                    // Out of descriptors, or an aborted connection: keep serving.
                    tracing::warn!(%error, "accept");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            },
            // Reap the finished connections as they end.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            () = stop.requested() => break Stopping::Signal,
            _ = gave_up.wait_for(|gave_up| *gave_up) => break Stopping::GaveUp,
        }
    };
    // No new visitor: the socket goes first, then the requests in flight have their grace.
    drop(listener);
    drop(bound);
    stopping.send_replace(true);
    note(format!(
        "stopping: the socket is removed; requests in flight have {}",
        session::millis_text(STOP_GRACE)
    ));
    if !verbs::drain(&mut connections, state).await {
        note(
            "requests still running at the end of the grace were abandoned, each told what may \
             have happened",
        );
    }
    link_watch.abort();
    note("stopped");
    match why {
        Stopping::Signal => Ok(()),
        Stopping::GaveUp => Err(Failure::error(
            "the peer gave up redialing the seeds (its reconnect window ran out)",
        )),
    }
}

/// Answers a connection that is not served with its exit code and why, and closes it.
async fn refuse(stream: UnixStream, code: u8, why: String) {
    let (_, write) = tokio::io::split(stream);
    Reply::new(write)
        .finish(Err(Failure { code, message: why }))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_daemons_own_user_is_served() {
        assert_eq!(authorize(Some(501), 501), Ok(()));
        let other = authorize(Some(502), 501).expect_err("another user");
        assert!(other.contains("uid 502"), "{other}");
        assert!(authorize(Some(0), 501).is_err(), "not even root's");
        assert!(authorize(None, 501).is_err(), "unknown credentials");
    }
}
