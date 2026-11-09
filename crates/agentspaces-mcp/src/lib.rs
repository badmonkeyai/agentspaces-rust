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

//! The fleet's catalogue as Model Context Protocol tools, over [`rmcp`], the official
//! Rust MCP SDK.
//!
//! [`FleetMcpServer`] is an rmcp [`ServerHandler`](rmcp::ServerHandler): one tool per offering of
//! the fleet catalogue ([`agentspaces::catalog::FleetCatalog`]), named as every AgentSpaces
//! gateway names them (replicas collapse into one tool; different actions sharing a name get the
//! Ruby gateway's `name_<8 hex>` suffix). A call writes the tool's input entry where the
//! advertising agent takes, waits for the correlated result, and answers it as
//! `structuredContent` plus the same JSON as text. A background refresh (every 5 s by default)
//! sends `notifications/tools/list_changed` to every connected session when the offering names
//! change.
//!
//! ```no_run
//! # async fn run(fleet: agentspaces::space::Fleet) -> Result<(), agentspaces_mcp::ServeError> {
//! use agentspaces_mcp::{FleetMcpServer, ServerOptions, serve_stdio};
//!
//! let server = FleetMcpServer::new(&fleet, ServerOptions::new().only(["shop.*"]));
//! serve_stdio(server).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Transports
//!
//! - [`serve_stdio`] serves one client on standard input and output, the way Codex, goose, Zed,
//!   and Claude Code start a local server. The caller is the local user ([`Principal::local`]).
//!   [`serve_stdio_until`] also ends at a stop the host chooses (a signal).
//! - [`serve_http`] serves Streamable HTTP (rmcp's server over axum) and needs a token verifier
//!   ([`StaticTokens`] or [`JwtVerifier`]); see [`http`] for the posture: loopback by default,
//!   Origin checked, 401 with `WWW-Authenticate` without a valid bearer token, 403 for a call
//!   outside the token's scopes, bounded bodies and sessions.
//! - Any other rmcp transport: [`FleetMcpServer`] is a `ServerHandler`, so
//!   `server.serve(transport)` ([`rmcp::ServiceExt`]) works, and a host's own rmcp server can
//!   embed it ([`FleetMcpServer::tools`], [`FleetMcpServer::call`],
//!   [`FleetMcpServer::changes`]).
//!
//! # Who may call what
//!
//! A [`Policy`] maps token scopes to the offerings a caller may invoke (globs over offering
//! names) and is judged at every call: over HTTP before the request reaches the
//! session (an HTTP 403 with `error="insufficient_scope"`, as the MCP authorization
//! specification asks), and again inside the call, against the offering the call resolves to
//! (a tool error). The fleet's own authorizer still judges every entry the peer writes: a gateway
//! authenticates its caller and never widens what its peer may do.
//!
//! # Card text
//!
//! Tool titles, descriptions, and the schema names in input schemas come from AgentCards,
//! written by whichever peer published them. They reach a model's context, so every piece is
//! stripped of control and invisible format characters, capped in length, and the description
//! framed as fleet-provided data ([`text`]). Tool names are unique: a card cannot take another
//! offering's name ([`agentspaces::catalog`]).
//!
//! # Recipes
//!
//! Every host below starts the stdio gateway, `aspace mcp`, which reads the fleet
//! file and `ASPACE_*` variables like every `aspace` command. Codex CLI, in
//! `~/.codex/config.toml`:
//!
//! ```toml
//! [mcp_servers.fleet]
//! command = "aspace"
//! args = ["mcp"]
//! ```
//!
//! Claude Code, in a project's `.mcp.json`:
//!
//! ```json
//! {"mcpServers": {"fleet": {"command": "aspace", "args": ["mcp"]}}}
//! ```
//!
//! goose, as an extension in its `config.yaml`:
//!
//! ```yaml
//! extensions:
//!   fleet:
//!     type: stdio
//!     cmd: aspace
//!     args: [mcp]
//!     enabled: true
//! ```
//!
//! Zed, as a context server in its `settings.json`:
//!
//! ```json
//! {"context_servers": {"fleet": {"command": "aspace", "args": ["mcp"]}}}
//! ```
//!
//! The HTTP gateway for a team, its token file owner-only (`chmod 600`;
//! [`StaticTokens`]), and a client of it:
//!
//! ```sh
//! aspace mcp --http 127.0.0.1:8740 --tokens /etc/agentspaces/mcp-tokens.yaml --only 'shop.*'
//! ```
//!
//! ```json
//! {"mcpServers": {"fleet": {"type": "http", "url": "http://127.0.0.1:8740/mcp",
//!   "headers": {"Authorization": "Bearer ${FLEET_MCP_TOKEN}"}}}}
//! ```
//!
//! A Rust host with its own rmcp server lists [`FleetMcpServer::tools`] beside its own tools,
//! routes their calls to [`FleetMcpServer::call`] with the caller it authenticated, and forwards
//! [`FleetMcpServer::changes`] as its own `list_changed`; or it serves the `FleetMcpServer`
//! itself on any rmcp transport.
//!
//! # Features
//!
//! - `schemars` (default): [`SchemaRegistry::register`] derives a tool's input and output JSON
//!   Schema (2020-12) from a registered Rust type that implements both
//!   [`Entry`](agentspaces::Entry) and `schemars::JsonSchema`. Without the feature,
//!   [`SchemaRegistry::insert`] takes a schema written by hand.
#![forbid(unsafe_code)]

pub mod auth;
pub mod http;
pub mod jwt;
pub mod policy;
pub mod schema;
pub mod server;
pub mod text;
pub mod validate;

pub use agentspaces::catalog::Principal;
pub use auth::{AuthError, StaticTokens, TokenFileError, TokenVerifier};
pub use http::{HttpOptions, HttpServer, ProtectedResource, serve_http};
pub use jwt::{JwksSource, JwtOptions, JwtVerifier};
pub use policy::{Policy, PolicyFileError};
pub use schema::{SchemaProvider, SchemaRegistry};
pub use server::{Caller, FleetMcpServer, STOPPED_WHILE_WAITING, STOPPING, ServerOptions};

use rmcp::ServiceExt as _;

/// Why a server could not start or ended with an error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// HTTP without a token verifier: refused unless
    /// [`HttpOptions::allow_unauthenticated`] says otherwise.
    #[error(
        "an HTTP MCP endpoint at {bind} would invoke fleet actions for whoever reaches it: give \
         it a token verifier (StaticTokens or JwtVerifier), or allow_unauthenticated behind an \
         authenticating proxy"
    )]
    NoVerifier {
        /// The address asked for.
        bind: std::net::SocketAddr,
    },
    /// The options cannot be served (a path that does not start with `/`, a malformed allowed
    /// origin).
    #[error("invalid HTTP options: {0}")]
    Options(String),
    /// The address could not be bound.
    #[error("cannot bind {bind}: {source}")]
    Bind {
        /// The address asked for.
        bind: std::net::SocketAddr,
        /// Why.
        source: std::io::Error,
    },
    /// Serving failed.
    #[error("the MCP server failed: {0}")]
    Io(#[from] std::io::Error),
    /// The MCP session could not start or ended abnormally.
    #[error("the MCP session failed: {0}")]
    Mcp(String),
}

/// Serves `server` to one client on standard input and output until the client leaves.
/// The caller is the local user: [`Principal::local`], judged by [`Policy`]'s local rule.
///
/// # Errors
///
/// [`ServeError::Mcp`] when the session cannot start (the client's first message is not an MCP
/// handshake) or its task fails.
pub async fn serve_stdio(server: FleetMcpServer) -> Result<(), ServeError> {
    serve_stdio_until(server, std::future::pending()).await
}

/// How long [`serve_stdio_until`] waits for the session to wind down once `stop` resolved.
pub const STDIO_CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// [`serve_stdio`] until the client leaves or `stop` resolves (a signal, a peer that gave up),
/// whichever comes first. At `stop` the calls end first ([`FleetMcpServer::end_calls`], within
/// [`STDIO_CLOSE_WAIT`]): a call still waiting on the fleet answers a tool error saying the
/// gateway stopped (its input stays in the fleet, leased for a late worker), so a client that
/// still reads hears it; then the session is cancelled and given [`STDIO_CLOSE_WAIT`] to end.
/// Standard output carries only the MCP stream: every diagnostic of this crate goes to
/// `tracing`, which a stdio host must send to standard error.
///
/// # Errors
///
/// [`ServeError::Mcp`] when the session cannot start (the client's first message is not an MCP
/// handshake, or standard input closed before one) or its task fails.
pub async fn serve_stdio_until(
    server: FleetMcpServer,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), ServeError> {
    let mut stop = std::pin::pin!(stop);
    let ending = server.clone();
    let running = tokio::select! {
        started = server.serve(rmcp::transport::stdio()) => {
            started.map_err(|error| ServeError::Mcp(error.to_string()))?
        }
        () = &mut stop => {
            tracing::debug!("stopped before the stdio MCP session began");
            return Ok(());
        }
    };
    let cancel = running.cancellation_token();
    let mut waiting = std::pin::pin!(running.waiting());
    let reason = tokio::select! {
        ended = &mut waiting => ended.map_err(|error| ServeError::Mcp(error.to_string()))?,
        () = &mut stop => {
            ending.end_calls(STDIO_CLOSE_WAIT).await;
            cancel.cancel();
            match tokio::time::timeout(STDIO_CLOSE_WAIT, waiting).await {
                Ok(ended) => ended.map_err(|error| ServeError::Mcp(error.to_string()))?,
                Err(_) => {
                    tracing::debug!("the stdio MCP session did not end within the close wait");
                    return Ok(());
                }
            }
        }
    };
    tracing::debug!(?reason, "the stdio MCP session ended");
    Ok(())
}
