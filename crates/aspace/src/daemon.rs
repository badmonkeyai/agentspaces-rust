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

//! `aspace daemon`: a resident peer that serves other `aspace` invocations
//! over a local socket, so a visitor command answers in milliseconds instead of joining.
//!
//! # The resident
//!
//! The daemon resolves its configuration as every command does (flags, `ASPACE_*`, the fleet
//! file), takes its lock, joins, pulls the advertisements and the configured spaces, and then
//! listens on its socket ([`paths`]): a Unix domain socket of mode 0600 in a directory of mode
//! 0700 (`$XDG_RUNTIME_DIR/aspace/daemon.sock`, else `${TMPDIR:-/tmp}/aspace-<uid>/daemon.sock`,
//! or `--socket`/`ASPACE_SOCKET`); on Windows a named pipe (the `windows` module, compiled there only).
//! It serves only processes of its own user: the connecting process's uid
//! ([`tokio::net::UnixStream::peer_cred`]) must be the daemon's ([`server::authorize`]), and a
//! visitor checks the daemon's the same way. One daemon runs per socket: its lock file
//! (`<socket>.lock`, `flock`ed, holding its pid) keeps a second one from racing it, and a second
//! one exits 2 ("already running"). A socket left by a daemon that died is found answering
//! nothing and removed. SIGINT, SIGTERM, SIGHUP, or SIGQUIT stops it: it stops accepting,
//! removes its socket, and ends at once every request still waiting with nothing done (a take,
//! a read or a completion with a timeout, a call looking for its offering: exit 3, "the daemon
//! stopped; nothing was taken"; a `watch` ends too). The requests in flight then have up to 5 s
//! to finish; one still running after that (a write or a completion waiting for the seed's
//! confirmation, a call waiting for its result) answers its visitor that it may have taken
//! effect (exit 3) before it is dropped, and the daemon leaves the group. A peer that gives up
//! redialing its seeds stops it the same way, with exit 1, so a service manager restarts it.
//!
//! The daemon's peer is shared by every visitor: a take made through it is held by the daemon's
//! identity (`<peerId>/rust`), so `aspace complete <id>` through the daemon completes it
//! ([`Space::held`](agentspaces::space::Space::held)), and so does a `--no-daemon` complete run
//! with the daemon's keystore once the daemon has stopped. Each space is pulled and settled
//! once, on its first use (the configured spaces at the start); the resident peer then folds
//! every rumor as it comes, so a request answers from what it holds without waiting a settle
//! window. Writes and completions are still confirmed with the seed before the visitor is
//! answered, as a visitor of its own confirms them. The daemon keeps at most
//! [`verbs::MAX_SPACES`] spaces open; past it, the space used least recently is closed to make
//! room (never a configured one, one a request uses, or one holding a take made through it).
//!
//! # The protocol
//!
//! Newline-delimited JSON, versioned ([`protocol::PROTOCOL`], now 1), **one request per
//! connection**: a connection is cheap on a local socket, and a stream (`watch`) then needs no
//! multiplexing ids.
//!
//! 1. The visitor connects; the daemon checks its uid and sends its hello,
//!    `{"hello": {"protocol": 1, "version", "group", "groupName", "peerId", "keystore",
//!    "profile", "pid", "socket", "verbs"}}`. A refused visitor gets `{"exit": 4, "error"}`
//!    instead.
//! 2. The visitor uses the daemon only when the hello's protocol is its own and the daemon
//!    serves the GroupID of its configuration, with its keystore and a profile at least as strict
//!    (`mtls` over `dev-local`); otherwise it closes the connection and joins itself.
//! 3. It sends one request of at most 9 MiB ([`protocol::MAX_REQUEST`]):
//!    `{"protocol": 1, "verb": "write", "args": {...}}`, the verb one of `status`, `write`,
//!    `read`, `take`, `complete`, `watch`, `cards`, `call`, with the arguments the visitor
//!    resolved (the space named, the JSON read from `-` or `@file`, durations in milliseconds).
//! 4. The daemon answers with `{"out": <json>}` (a line the visitor prints on standard output,
//!    exactly as it would have printed it), `{"text": "..."}` (a text line, for `status` and
//!    `cards` without `--json`), and `{"note": "..."}` (a diagnostic for standard error), then
//!    `{"exit": <code>, "error": "..."}`, the exit code of the command and why.
//!    A `watch` streams `out` frames until its `--count`, or until the visitor closes the
//!    connection (an interrupted `aspace watch`).
//!
//! A request of another protocol version, an unknown verb, or arguments that do not parse are
//! answered with exit 2; a request line over the cap, or one not sent within 5 minutes of the
//! hello, ends the connection. A visitor that goes away mid-request ends what still waits: a take
//! makes no further claim (one already out settles, as a take of the visitor's own would), a read
//! or a completion stops waiting, a call stops waiting for its result (the input stays leased for
//! a worker), a watch ends. A write already sent finishes on the daemon.
//!
//! A visitor that cannot use the daemon joins the group itself, unless that join would share a
//! running daemon's PeerID in its group: then it refuses ([`client::visit`]), since the seed
//! would take the two links for one member and the join would see nothing.

pub mod client;
#[cfg(unix)]
pub mod paths;
pub mod protocol;
#[cfg(unix)]
pub mod server;
mod verbs;
#[cfg(windows)]
pub mod windows;

use std::time::Duration;

use agentspaces::config::Config;
use agentspaces::group::Profile;

pub use client::visit;

use crate::cli::Global;
use crate::exit::Failure;

/// How long a visitor waits for the daemon to accept its connection.
pub const CONNECT_WAIT: Duration = Duration::from_millis(500);

/// How long a visitor waits for the daemon's hello once connected.
pub const HELLO_WAIT: Duration = Duration::from_secs(2);

/// How long the daemon waits for a visitor's request after its hello (a visitor reading
/// `--json -` from a slow producer sends it late).
pub const REQUEST_WAIT: Duration = Duration::from_secs(300);

/// How long the requests in flight may finish once the daemon is stopping.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// The most connections the daemon serves at once; one more is answered with exit 1.
pub const MAX_CONNECTIONS: usize = 256;

/// `aspace daemon`: join, serve visitors over the local socket until interrupted, leave.
pub async fn daemon(global: &Global) -> Result<(), Failure> {
    #[cfg(unix)]
    {
        server::run(global).await
    }
    #[cfg(windows)]
    {
        windows::run(global).await
    }
}

/// The keystore of a configuration as a hello names it: absolute, links resolved when it exists;
/// `None` for a configuration with none (a fresh identity).
pub fn keystore_text(config: &Config) -> Option<String> {
    config.settings.keystore.as_deref().map(|dir| {
        std::fs::canonicalize(dir)
            .or_else(|_| std::path::absolute(dir))
            .unwrap_or_else(|_| dir.to_path_buf())
            .display()
            .to_string()
    })
}

/// A profile's name, as a hello carries it and the configuration spells it.
pub fn profile_name(profile: Profile) -> &'static str {
    match profile {
        Profile::DevLocal => "dev-local",
        Profile::Mtls => "mtls",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_named_as_the_configuration_names_them() {
        assert_eq!(profile_name(Profile::Mtls), "mtls");
        assert_eq!(profile_name(Profile::DevLocal), "dev-local");
        for profile in [Profile::Mtls, Profile::DevLocal] {
            assert_eq!(Profile::parse(profile_name(profile)), Some(profile));
        }
    }
}
