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

//! `aspace mcp`: the fleet catalogue as MCP tools,
//! served by [`agentspaces_mcp::FleetMcpServer`] over standard input and output (the default),
//! or over Streamable HTTP with `--http`.
//!
//! # Its life
//!
//! 1. Everything that needs no fleet is checked first, so a misconfigured gateway fails at once
//!    and joins nothing: the policy file (`--policy`, `ASPACE_MCP_POLICY`), and under `--http`
//!    the token verifier (`--tokens` or `ASPACE_MCP_TOKENS`, or the JWT flags) and the HTTP
//!    options ([`HttpOptions::check`]). An HTTP gateway without a verifier is refused (exit 2)
//!    unless `--allow-unauthenticated`; a token file its group or others may read, or a policy
//!    file they may write, exits 4.
//! 2. It joins as every command does ([`Session::join`]), and stays: a resident with
//!    its keystore's PeerID, which it marks ([`Resident`]). It never goes through `aspace
//!    daemon`: the daemon's protocol carries one visitor command per connection, while the
//!    gateway holds the catalogue, its refresh, and calls that wait on the fleet, so it shares no
//!    peer with the daemon. A seed takes every link of one PeerID for one member, so the gateway
//!    wants a keystore of its own when a daemon or a worker runs (the resident warning says so).
//! 3. It pulls the group's advertisements and the configured spaces, settles, lists the
//!    catalogue once, and serves: [`serve_stdio_until`] or [`serve_http`]. The catalogue is
//!    [`commands::catalogue`]'s, the one `aspace cards` lists, so a tool has the name `aspace
//!    cards` prints and `--only` filters as `aspace cards --only` does (plus `space:<glob>`).
//! 4. SIGINT, SIGTERM, SIGHUP, or SIGQUIT stops it with exit 0, as does a stdio client closing
//!    standard input; a peer that gives up redialing its seeds stops it with exit 1, so a
//!    supervisor restarts it. At a stop every call still waiting on the fleet first answers a
//!    tool error saying the gateway stopped ([`FleetMcpServer::end_calls`]; its input stays
//!    leased for a late worker), so a client is not left to its own request timeout.
//!
//! # Standard output
//!
//! Over standard input and output, standard output carries the MCP stream and nothing else:
//! notes ([`note`]) and the library's `tracing` go to standard error, and nothing here prints.
//! With `--http`, the one line `{"mcp": <url>, ...}` on standard output says the gateway serves.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentspaces::peer::PeerEvent;
use agentspaces_mcp::{
    FleetMcpServer, HttpOptions, JwksSource, JwtOptions, JwtVerifier, Policy, ServerOptions,
    StaticTokens, TokenVerifier, serve_http, serve_stdio_until,
};
use serde_json::{Value as Json, json};
use tokio::sync::watch;

use crate::cli::Global;
use crate::commands;
use crate::exit::Failure;
use crate::io::print_line;
use crate::resident::{self, Resident};
use crate::session::{self, Session, note};
use crate::signals::Stop;

/// The variable naming the token file, as `--tokens` does.
pub const ENV_MCP_TOKENS: &str = "ASPACE_MCP_TOKENS";

/// The variable naming the policy file, as `--policy` does.
pub const ENV_MCP_POLICY: &str = "ASPACE_MCP_POLICY";

/// The options of `aspace mcp` (see `aspace mcp --help`).
#[derive(Debug, Clone)]
pub struct McpOptions {
    /// Serve Streamable HTTP here instead of standard input and output.
    pub http: Option<SocketAddr>,
    /// The bearer token file.
    pub tokens: Option<PathBuf>,
    /// The JWT issuer.
    pub jwt_issuer: Option<String>,
    /// The JWT audience.
    pub jwt_audience: Option<String>,
    /// The JWT key set: a URL or a file.
    pub jwks: Option<String>,
    /// More browser origins allowed.
    pub origins: Vec<String>,
    /// The `Host` header values accepted.
    pub allowed_hosts: Vec<String>,
    /// Serve HTTP without a verifier.
    pub allow_unauthenticated: bool,
    /// The `only` patterns.
    pub only: Vec<String>,
    /// The policy file.
    pub policy: Option<PathBuf>,
    /// How often the catalogue is refreshed.
    pub refresh: Duration,
    /// How long a call waits by default.
    pub call_timeout: Duration,
}

/// A file named by a flag, else by `variable` (set and not blank): its path, and where it was
/// named.
pub fn named_file(
    flag: Option<&Path>,
    flag_name: &str,
    variable: &str,
) -> Option<(PathBuf, String)> {
    match flag {
        Some(path) => Some((path.to_path_buf(), flag_name.to_owned())),
        None => session::env(variable)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| (PathBuf::from(value), variable.to_owned())),
    }
}

/// What the gateway serves, checked before it joins.
struct Plan {
    server: ServerOptions,
    http: Option<HttpOptions>,
}

/// Checks everything that needs no fleet: the policy, and under `--http` the verifier and the
/// HTTP options.
fn plan(options: &McpOptions) -> Result<Plan, Failure> {
    let mut server = ServerOptions::new()
        .name("aspace")
        .version(env!("CARGO_PKG_VERSION"))
        .only(options.only.iter().cloned())
        .refresh_interval(options.refresh)
        .call_timeout(options.call_timeout);
    if let Some((path, _)) = named_file(options.policy.as_deref(), "--policy", ENV_MCP_POLICY) {
        server = server.policy(Policy::load(&path)?);
    }
    let Some(bind) = options.http else {
        return Ok(Plan { server, http: None });
    };
    let mut http = HttpOptions::new()
        .bind(bind)
        .allow_unauthenticated(options.allow_unauthenticated);
    if let Some(verifier) = verifier(options)? {
        http = http.shared_verifier(verifier);
    }
    for origin in &options.origins {
        http = http.allow_origin(origin.clone());
    }
    if !options.allowed_hosts.is_empty() {
        http = http.allowed_hosts(options.allowed_hosts.iter().cloned());
    }
    http.check()?;
    Ok(Plan {
        server,
        http: Some(http),
    })
}

/// The HTTP gateway's token verifier: the JWT flags', else the token file's (`--tokens`, else
/// `ASPACE_MCP_TOKENS`); `None` when neither is named.
fn verifier(options: &McpOptions) -> Result<Option<Arc<dyn TokenVerifier>>, Failure> {
    if let Some(issuer) = &options.jwt_issuer {
        let jwks = options.jwks.as_deref().map(str::trim).unwrap_or_default();
        let source = if jwks.starts_with("https://") || jwks.starts_with("http://") {
            JwksSource::Url(jwks.to_owned())
        } else {
            JwksSource::File(PathBuf::from(jwks))
        };
        let audience = options.jwt_audience.clone().unwrap_or_default();
        let verifier = JwtVerifier::new(JwtOptions::new(issuer.clone(), audience, source))?;
        return Ok(Some(Arc::new(verifier)));
    }
    match named_file(options.tokens.as_deref(), "--tokens", ENV_MCP_TOKENS) {
        Some((path, _)) => Ok(Some(Arc::new(StaticTokens::load(&path)?))),
        None => Ok(None),
    }
}

/// `aspace mcp`: check, join, serve until stopped, leave.
pub async fn mcp(global: &Global, options: McpOptions) -> Result<(), Failure> {
    let plan = plan(&options)?;
    let session = Session::join(global).await?;
    let outcome = serve(&session, plan).await;
    session.close().await;
    outcome
}

/// The joined gateway's life: mark, settle, list, serve, stop.
async fn serve(session: &Session, plan: Plan) -> Result<(), Failure> {
    let _resident = session
        .config
        .settings
        .keystore
        .as_deref()
        .and_then(|keystore| Resident::mark(keystore, "aspace mcp"));
    let peer = session.peer().clone();
    // From here SIGINT, SIGTERM, SIGHUP, and SIGQUIT ask for a stop.
    let mut stop = Stop::new()?;
    let (gave_up_tx, mut gave_up) = watch::channel(false);
    let link_watch = tokio::spawn(resident::watch_link(peer.subscribe(), gave_up_tx));
    warm_up(session).await?;

    let server = FleetMcpServer::with_catalog(
        commands::catalogue(&session.fleet, &session.config),
        plan.server,
    );
    server.refresh().await;
    let tools = server.tool_names();
    let offered = format!(
        "{} tool{} of {} as {}",
        tools.len(),
        if tools.len() == 1 { "" } else { "s" },
        session::describe_group(&session.config),
        peer.peer_id()
    );
    // The stop borrows the signals and the link watch until serving ends.
    let served = {
        let stopped = async {
            tokio::select! {
                () = stop.requested() => {}
                _ = gave_up.wait_for(|gave_up| *gave_up) => {}
            }
        };
        serve_on(&server, plan.http, session, &tools, &offered, stopped).await
    };
    server.close();
    link_watch.abort();
    served?;
    if *gave_up.borrow() {
        return Err(Failure::error(
            "the peer gave up redialing the seeds (its reconnect window ran out)",
        ));
    }
    note("stopped");
    Ok(())
}

/// Serves `server` over standard input and output, or over HTTP with `http`, until `stopped`.
async fn serve_on(
    server: &FleetMcpServer,
    http: Option<HttpOptions>,
    session: &Session,
    tools: &[String],
    offered: &str,
    stopped: impl std::future::Future<Output = ()>,
) -> Result<(), Failure> {
    let peer = session.peer();
    let served = match http {
        None => {
            note(format!(
                "serving {offered} over standard input and output (stop with SIGINT or SIGTERM, \
                 or close standard input)"
            ));
            serve_stdio_until(server.clone(), stopped).await
        }
        Some(http) => match serve_http(server.clone(), http).await {
            Ok(running) => {
                let hello = json!({
                    "mcp": running.url(),
                    "peerId": peer.peer_id(),
                    "group": peer.group_id(),
                    "groupName": session.config.group_name,
                    "pid": std::process::id(),
                    "tools": tools,
                });
                // A closed standard output does not stop the gateway.
                let _ = print_line(&hello);
                note(format!(
                    "serving {offered} at {} (stop with SIGINT or SIGTERM)",
                    running.url()
                ));
                running.run_until(stopped).await
            }
            Err(error) => Err(error),
        },
    };
    served.map_err(Failure::from)
}

/// Pulls the group's advertisements and the configured spaces (whose entries decide the number
/// widths of a call's input), and waits until they settle, within the join deadline.
async fn warm_up(session: &Session) -> Result<(), Failure> {
    let peer = session.peer();
    let mut events = peer.subscribe();
    peer.pull_ads().await?;
    for space in &session.config.settings.spaces {
        // A failed pull is pulled again after the next reconnect.
        let _ = session.fleet.space(space).pull().await;
    }
    session::settle_on(&mut events, session.deadline, |event| {
        matches!(
            event,
            PeerEvent::AdAccepted { .. } | PeerEvent::StateFolded { .. }
        )
    })
    .await;
    Ok(())
}

/// The permission bits of `path`, when it can be read.
pub fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o7777)
}

/// The MCP settings of this environment, as `status` reports them: the token file and the
/// policy file `aspace mcp` would read (`ASPACE_MCP_TOKENS`, `ASPACE_MCP_POLICY`), each with
/// its mode and whether the mode is safe (a token file owner-only, a policy file writable by no
/// one else), or `null`. `aspace doctor` reads them through.
pub fn settings_json() -> Json {
    let file = |variable: &str, unsafe_bits: u32| {
        named_file(None, "", variable).map_or(Json::Null, |(path, _)| {
            let mode = file_mode(&path);
            json!({
                "path": path.display().to_string(),
                "mode": mode.map(|mode| format!("{mode:04o}")),
                "safe": mode.is_some_and(|mode| mode & unsafe_bits == 0),
            })
        })
    };
    json!({
        "tokens": file(ENV_MCP_TOKENS, 0o077),
        "policy": file(ENV_MCP_POLICY, 0o022),
    })
}

/// The `status` text line of [`settings_json`].
pub fn settings_line(settings: &Json) -> String {
    let file = |key: &str| {
        let file = &settings[key];
        file["path"].as_str().map(|path| {
            format!(
                "{key} {path} ({}{})",
                file["mode"].as_str().unwrap_or("missing"),
                if file["safe"] == true { "" } else { ", unsafe" }
            )
        })
    };
    let named: Vec<String> = ["tokens", "policy"].into_iter().filter_map(file).collect();
    if named.is_empty() {
        format!("mcp      no token or policy file named ({ENV_MCP_TOKENS}, {ENV_MCP_POLICY})")
    } else {
        format!("mcp      {}", named.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_line_names_the_files_and_their_modes() {
        let none = json!({"tokens": null, "policy": null});
        assert!(settings_line(&none).contains("no token or policy file named"));
        let both = json!({
            "tokens": {"path": "/t.yaml", "mode": "0600", "safe": true},
            "policy": {"path": "/p.yaml", "mode": "0666", "safe": false},
        });
        assert_eq!(
            settings_line(&both),
            "mcp      tokens /t.yaml (0600), policy /p.yaml (0666, unsafe)"
        );
        let missing = json!({"tokens": {"path": "/gone", "mode": null, "safe": false}});
        assert_eq!(
            settings_line(&missing),
            "mcp      tokens /gone (missing, unsafe)"
        );
    }
}
