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

//! The daemon on Windows: a named pipe instead of a Unix socket. Compiled on Windows
//! only, and not yet run there: the rest of `aspace` (its signals, `work`'s process groups) is
//! Unix-only today.
//!
//! The pipe is `--socket`/`ASPACE_SOCKET` when it names one (`\\.\pipe\<name>`), else
//! `\\.\pipe\aspace-daemon-<USERNAME>`. A pipe's default security descriptor grants its creator
//! (and the administrators and the system) full control and everyone else read access only, so
//! no other user can write a request; remote clients are rejected. The first instance is created
//! with `first_pipe_instance`, so a second daemon on the same name fails to create it and exits
//! 2. Ctrl-C stops the daemon.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::MAX_CONNECTIONS;
use super::verbs::{self, State};
use crate::cli::Global;
use crate::exit::Failure;
use crate::io::print_line;
use crate::session::{self, Session, note};

/// The pipe a configuration names, or this user's default.
pub fn pipe_name(configured: Option<&Path>) -> PathBuf {
    if let Some(path) = configured {
        return path.to_path_buf();
    }
    let user: String = std::env::var("USERNAME")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let user = if user.is_empty() {
        "user".to_owned()
    } else {
        user
    };
    PathBuf::from(format!(r"\\.\pipe\aspace-daemon-{user}"))
}

/// Opens the daemon's pipe.
pub async fn connect(pipe: &Path) -> std::io::Result<NamedPipeClient> {
    ClientOptions::new().open(pipe)
}

/// `aspace daemon` on Windows.
pub async fn run(global: &Global) -> Result<(), Failure> {
    let config = session::resolve(global)?;
    let pipe = pipe_name(config.socket.as_deref());
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&pipe)
        .map_err(|error| {
            Failure::refused(format!(
                "cannot create the pipe {} (a daemon may already be running on it): {error}",
                pipe.display()
            ))
        })?;
    let session = Session::join_with(global, config).await?;
    let hello = verbs::hello(&session, &pipe.display().to_string());
    let (stopping_tx, stopping) = watch::channel(false);
    let state = Arc::new(State::new(session, hello, stopping));
    let (gave_up_tx, mut gave_up) = watch::channel(false);
    let link_watch = tokio::spawn(crate::resident::watch_link(
        state.session.peer().subscribe(),
        gave_up_tx,
    ));
    verbs::warm_up(&state).await?;
    let _ = print_line(&serde_json::to_value(&state.hello).unwrap_or_default());
    note(format!(
        "serving {} on {} (stop with Ctrl-C)",
        session::describe_group(&state.session.config),
        pipe.display()
    ));
    let mut connections = JoinSet::new();
    let gave_up_first = loop {
        tokio::select! {
            connected = server.connect() => {
                if let Err(error) = connected {
                    tracing::warn!(%error, "connect");
                    continue;
                }
                let next = ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&pipe)
                    .map_err(|error| Failure::error(format!("cannot serve {}: {error}", pipe.display())))?;
                let client = std::mem::replace(&mut server, next);
                if connections.len() >= MAX_CONNECTIONS {
                    continue;
                }
                let state = Arc::clone(&state);
                connections.spawn(async move { verbs::connection(client, &state).await });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = tokio::signal::ctrl_c() => break false,
            _ = gave_up.wait_for(|gave_up| *gave_up) => break true,
        }
    };
    drop(server);
    stopping_tx.send_replace(true);
    verbs::drain(&mut connections, &state).await;
    link_watch.abort();
    let _ = state.session.fleet.close().await;
    note("stopped");
    if gave_up_first {
        Err(Failure::error(
            "the peer gave up redialing the seeds (its reconnect window ran out)",
        ))
    } else {
        Ok(())
    }
}
