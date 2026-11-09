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

//! The Streamable HTTP gateway: [`serve_http`] serves a [`FleetMcpServer`] with rmcp's
//! Streamable HTTP server over axum, behind a guard that every request passes first.
//!
//! ```no_run
//! # async fn run(server: agentspaces_mcp::FleetMcpServer) -> Result<(), Box<dyn std::error::Error>> {
//! use agentspaces_mcp::{HttpOptions, StaticTokens, serve_http};
//!
//! let tokens = StaticTokens::load("/etc/agentspaces/mcp-tokens.yaml")?;
//! let http = serve_http(server, HttpOptions::new().verifier(tokens)).await?;
//! println!("serving {}", http.url());
//! http.wait().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # The posture
//!
//! - **Loopback by default.** The default address is `127.0.0.1:8740`.
//! - **A token verifier is required.** Without one ([`HttpOptions::verifier`]) the gateway
//!   refuses to start ([`ServeError::NoVerifier`]) unless
//!   [`HttpOptions::allow_unauthenticated`] is set, for a gateway behind an authenticating
//!   proxy; on a routable address that is logged as a warning at every start.
//! - **Origin.** A request whose `Origin` header is not allowed is refused with 403 before
//!   anything else, the DNS-rebinding protection the MCP transport specification asks for. The
//!   loopback origins (`http` and `https` on `localhost`, `127.0.0.1`, and `[::1]`, any port)
//!   are allowed by default; [`HttpOptions::allow_origin`] adds others. A request without an
//!   `Origin` (not from a browser) passes. The `Host` header is checked too (rmcp's allowlist:
//!   the loopback names, the bound address, or [`HttpOptions::allowed_hosts`]).
//! - **401.** A request without a bearer token, or with one the verifier refuses, is answered
//!   401 with `WWW-Authenticate: Bearer realm="agentspaces"` (with `error="invalid_token"` and a
//!   reason for a refused token, and `resource_metadata` when [`ProtectedResource`] metadata is
//!   served), and reaches neither the session nor the fleet. The `Authorization` header is
//!   removed before the request goes on, and no token is ever logged.
//! - **403.** A `tools/call` the token's scopes do not allow ([`Policy`](crate::Policy)) is
//!   answered 403 with `WWW-Authenticate: Bearer error="insufficient_scope"` and the scopes that
//!   would allow it, as the MCP authorization specification asks; the call never starts. Inside
//!   the session the call is judged again against the offering it resolves to (a tool error).
//! - **Sessions.** A session belongs to the principal that opened it: another principal using
//!   its id is answered 404, as for an unknown session. At most [`HttpOptions::max_sessions`]
//!   sessions are open at once (a further `initialize` is answered 503); an idle one closes after
//!   [`HttpOptions::session_idle`]. A session whose client holds its standalone stream (the
//!   `GET` that carries `notifications/tools/list_changed`) open is connected, not idle: the
//!   gateway sends it a `ping` every half of `session_idle` while the stream is open, so a host
//!   left alone (an IDE whose user is away) still hears every change. A session without one
//!   closes after `session_idle`. A request naming an unknown, closed, or another principal's
//!   session is answered 404 with the JSON-RPC error a client re-initializes on, as the
//!   TypeScript SDK's own server answers it: `{"jsonrpc": "2.0", "error": {"code": -32001,
//!   "message": "Session not found"}, "id": null}`.
//! - **Bodies.** A request body larger than [`HttpOptions::max_body_bytes`] (4 MiB) is answered
//!   413.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use agentspaces::catalog::Principal;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json as AxumJson, Router};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value as Json, json};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ServeError;
use crate::auth::{MAX_TOKEN_BYTES, TokenVerifier};
use crate::jwt::is_loopback_host;
use crate::server::{Caller, FleetMcpServer};

/// The default address: loopback, port 8740.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8740);

/// The default path of the MCP endpoint.
pub const DEFAULT_PATH: &str = "/mcp";

/// The default largest request body: 4 MiB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The default most sessions open at once.
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// The default idle time after which a session closes.
pub const DEFAULT_SESSION_IDLE: Duration = Duration::from_secs(300);

/// The principal of an HTTP caller when the gateway runs without a verifier
/// ([`HttpOptions::allow_unauthenticated`]): a token principal with no scopes.
pub const ANONYMOUS: &str = "anonymous";

/// The path protected resource metadata is served at (RFC 9728), before the endpoint's path.
pub const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// How long [`HttpServer::run_until`] lets the requests in flight finish once stopped.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How long a stopping server waits for its waiting calls to answer
/// ([`FleetMcpServer::end_calls`]) before it closes the sessions.
pub const CALLS_END_GRACE: Duration = Duration::from_secs(2);

/// How long the answers of the calls ended at a stop have to reach their streams before the
/// sessions close.
const ANSWERS_FLUSH: Duration = Duration::from_millis(200);

/// The header naming a Streamable HTTP session.
const SESSION_HEADER: &str = "mcp-session-id";

/// The JSON-RPC code of an unknown session's 404 (the TypeScript SDK server's), on which clients
/// re-initialize.
pub const SESSION_NOT_FOUND_CODE: i64 = -32001;

/// The body rmcp answers an unknown session's request with.
const RMCP_SESSION_NOT_FOUND: &[u8] = b"Not Found: Session not found";

/// The shortest keepalive period, whatever `session_idle` is.
const MIN_KEEPALIVE: Duration = Duration::from_millis(100);

/// The loopback origins allowed by default.
const LOOPBACK_ORIGINS: [&str; 6] = [
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
    "https://localhost:*",
    "https://127.0.0.1:*",
    "https://[::1]:*",
];

/// The loopback host names the `Host` header may carry by default.
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// OAuth protected resource metadata (RFC 9728) for clients that discover the authorization
/// server from the gateway, as the MCP authorization specification describes: served at
/// [`RESOURCE_METADATA_PATH`] and named in every 401 challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResource {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

impl ProtectedResource {
    /// The metadata of the gateway reachable at `resource` (its public URL, the MCP endpoint's
    /// own: `https://mcp.example.com/mcp`), whose tokens `authorization_server` issues.
    pub fn new(resource: impl Into<String>, authorization_server: impl Into<String>) -> Self {
        ProtectedResource {
            resource: resource.into(),
            authorization_servers: vec![authorization_server.into()],
            scopes_supported: Vec::new(),
        }
    }

    /// Names the scopes a client may ask for.
    #[must_use]
    pub fn scopes<S: Into<String>>(mut self, scopes: impl IntoIterator<Item = S>) -> Self {
        self.scopes_supported = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The document served.
    pub fn document(&self) -> Json {
        let mut document = json!({
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
            "bearer_methods_supported": ["header"],
        });
        if !self.scopes_supported.is_empty()
            && let Json::Object(object) = &mut document
        {
            object.insert(
                "scopes_supported".to_owned(),
                Json::from(self.scopes_supported.clone()),
            );
        }
        document
    }

    /// Where the document is served, as a URL: the resource's origin, then
    /// [`RESOURCE_METADATA_PATH`], then the resource's path.
    pub fn metadata_url(&self) -> Option<String> {
        let uri: http::Uri = self.resource.parse().ok()?;
        let scheme = uri.scheme_str()?;
        let authority = uri.authority()?;
        let path = uri.path().trim_end_matches('/');
        Some(format!(
            "{scheme}://{authority}{RESOURCE_METADATA_PATH}{path}"
        ))
    }
}

/// How [`serve_http`] serves; built with the methods below.
#[derive(Clone)]
pub struct HttpOptions {
    bind: SocketAddr,
    path: String,
    verifier: Option<Arc<dyn TokenVerifier>>,
    allow_unauthenticated: bool,
    origins: Vec<String>,
    hosts: Option<Vec<String>>,
    max_body_bytes: usize,
    max_sessions: usize,
    session_idle: Duration,
    resource: Option<ProtectedResource>,
    realm: String,
}

impl std::fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOptions")
            .field("bind", &self.bind)
            .field("path", &self.path)
            .field("verifier", &self.verifier.is_some())
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("origins", &self.origins)
            .field("hosts", &self.hosts)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_sessions", &self.max_sessions)
            .field("session_idle", &self.session_idle)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            bind: DEFAULT_BIND,
            path: DEFAULT_PATH.to_owned(),
            verifier: None,
            allow_unauthenticated: false,
            origins: LOOPBACK_ORIGINS
                .iter()
                .map(|origin| (*origin).to_owned())
                .collect(),
            hosts: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_sessions: DEFAULT_MAX_SESSIONS,
            session_idle: DEFAULT_SESSION_IDLE,
            resource: None,
            realm: "agentspaces".to_owned(),
        }
    }
}

impl HttpOptions {
    /// The defaults: `127.0.0.1:8740`, path `/mcp`, no verifier yet (one must be given), the
    /// loopback origins, 4 MiB bodies, 64 sessions idle for at most 5 minutes.
    pub fn new() -> HttpOptions {
        HttpOptions::default()
    }

    /// The address to listen at; port 0 picks a free one ([`HttpServer::local_addr`]).
    #[must_use]
    pub fn bind(mut self, address: SocketAddr) -> HttpOptions {
        self.bind = address;
        self
    }

    /// The path of the MCP endpoint (`/mcp`).
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> HttpOptions {
        self.path = path.into();
        self
    }

    /// Verifies every request's bearer token with `verifier`.
    #[must_use]
    pub fn verifier(mut self, verifier: impl TokenVerifier) -> HttpOptions {
        self.verifier = Some(Arc::new(verifier));
        self
    }

    /// [`HttpOptions::verifier`] with a shared verifier.
    #[must_use]
    pub fn shared_verifier(mut self, verifier: Arc<dyn TokenVerifier>) -> HttpOptions {
        self.verifier = Some(verifier);
        self
    }

    /// Serves without a verifier: every caller is [`ANONYMOUS`]. Only behind a proxy that
    /// authenticates; logged as a warning at every start.
    #[must_use]
    pub fn allow_unauthenticated(mut self, allow: bool) -> HttpOptions {
        self.allow_unauthenticated = allow;
        self
    }

    /// Allows browser requests from `origin` too: `scheme://host`, `scheme://host:port`,
    /// `scheme://host:*` for any port, or `null`. Without a port only the scheme's default
    /// port matches.
    #[must_use]
    pub fn allow_origin(mut self, origin: impl Into<String>) -> HttpOptions {
        self.origins.push(origin.into());
        self
    }

    /// The `Host` header values accepted (`mcp.example.com`, `mcp.example.com:443`), instead of
    /// the loopback names and the bound address. Needed behind a reverse proxy, and on an
    /// unspecified address (`0.0.0.0`), where without it the `Host` header is not checked.
    #[must_use]
    pub fn allowed_hosts<S: Into<String>>(mut self, hosts: impl IntoIterator<Item = S>) -> Self {
        self.hosts = Some(hosts.into_iter().map(Into::into).collect());
        self
    }

    /// The largest request body accepted (413 above it).
    #[must_use]
    pub fn max_body_bytes(mut self, bytes: usize) -> HttpOptions {
        self.max_body_bytes = bytes;
        self
    }

    /// The most sessions open at once (503 for a further `initialize`).
    #[must_use]
    pub fn max_sessions(mut self, sessions: usize) -> HttpOptions {
        self.max_sessions = sessions;
        self
    }

    /// How long a session may stay idle before it is closed (5 minutes). A session whose client
    /// holds its standalone stream open is pinged every half of it, so it is never idle.
    #[must_use]
    pub fn session_idle(mut self, idle: Duration) -> HttpOptions {
        self.session_idle = idle;
        self
    }

    /// Serves `resource` metadata and names it in 401 challenges.
    #[must_use]
    pub fn protected_resource(mut self, resource: ProtectedResource) -> HttpOptions {
        self.resource = Some(resource);
        self
    }

    /// The realm 401 and 403 challenges name (`agentspaces`).
    #[must_use]
    pub fn realm(mut self, realm: impl Into<String>) -> HttpOptions {
        self.realm = realm.into();
        self
    }

    /// The address asked for.
    pub fn bind_address(&self) -> SocketAddr {
        self.bind
    }

    /// Whether [`serve_http`] would serve these options, judged without binding anything: a
    /// host checks them before it joins its fleet, so a misconfigured gateway fails at once.
    ///
    /// # Errors
    ///
    /// [`ServeError::NoVerifier`] without a verifier and without
    /// [`HttpOptions::allow_unauthenticated`]; [`ServeError::Options`] for a path that does not
    /// start with `/`, or an allowed origin that is not `scheme://host[:port|:*]` or `null`.
    pub fn check(&self) -> Result<(), ServeError> {
        if self.verifier.is_none() && !self.allow_unauthenticated {
            return Err(ServeError::NoVerifier { bind: self.bind });
        }
        if !self.path.starts_with('/') {
            return Err(ServeError::Options(format!(
                "the endpoint path {:?} does not start with /",
                self.path
            )));
        }
        for origin in &self.origins {
            parse_rule(origin).map_err(ServeError::Options)?;
        }
        Ok(())
    }
}

/// A running HTTP gateway.
#[derive(Debug)]
pub struct HttpServer {
    address: SocketAddr,
    path: String,
    server: FleetMcpServer,
    shutdown: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

impl HttpServer {
    /// The address it listens at.
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// The endpoint's URL (`http://127.0.0.1:8740/mcp`).
    pub fn url(&self) -> String {
        format!("http://{}{}", self.address, self.path)
    }

    /// Ends the calls ([`FleetMcpServer::end_calls`], within [`CALLS_END_GRACE`]: a call still
    /// waiting on the fleet answers on its stream that the gateway stopped, its input left
    /// leased for a late worker), then stops accepting, closes the sessions and their streams,
    /// and waits for the server to end.
    ///
    /// # Errors
    ///
    /// [`ServeError::Io`] when serving had failed.
    pub async fn shutdown(self) -> Result<(), ServeError> {
        end_calls(&self.server).await;
        self.shutdown.cancel();
        self.wait().await
    }

    /// Serves until `stop` resolves (a signal), then shuts down as [`HttpServer::shutdown`]
    /// does: the calls still waiting on the fleet answer that the gateway stopped (their inputs
    /// stay leased for a late worker), and the requests in flight get [`SHUTDOWN_GRACE`]; ends
    /// earlier when serving fails.
    ///
    /// # Errors
    ///
    /// [`ServeError::Io`] when serving failed.
    pub async fn run_until(
        self,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<(), ServeError> {
        let HttpServer {
            shutdown,
            task,
            server,
            ..
        } = self;
        let mut task = task;
        tokio::select! {
            ended = &mut task => return joined(ended),
            () = stop => {
                end_calls(&server).await;
                shutdown.cancel();
            }
        }
        match tokio::time::timeout(SHUTDOWN_GRACE, &mut task).await {
            Ok(ended) => joined(ended),
            Err(_) => {
                tracing::debug!("requests still running at the end of the grace were abandoned");
                task.abort();
                Ok(())
            }
        }
    }

    /// Waits until the server ends (after [`HttpServer::shutdown`], or a failure).
    ///
    /// # Errors
    ///
    /// [`ServeError::Io`] when serving failed.
    pub async fn wait(self) -> Result<(), ServeError> {
        joined(self.task.await)
    }
}

/// Ends `server`'s calls before its sessions close, and gives their answers a moment to reach
/// their streams.
async fn end_calls(server: &FleetMcpServer) {
    if server.end_calls(CALLS_END_GRACE).await > 0 {
        tokio::time::sleep(ANSWERS_FLUSH).await;
    }
}

/// The outcome of the server's task.
fn joined(ended: Result<std::io::Result<()>, tokio::task::JoinError>) -> Result<(), ServeError> {
    match ended {
        Ok(result) => result.map_err(ServeError::Io),
        Err(error) => Err(ServeError::Mcp(format!(
            "the HTTP server task failed: {error}"
        ))),
    }
}

/// One allowed origin.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginRule {
    Null,
    Tuple {
        scheme: String,
        host: String,
        /// `None`: any port.
        port: Option<u16>,
    },
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// An allowed origin as [`HttpOptions::allow_origin`] takes it.
fn parse_rule(text: &str) -> Result<OriginRule, String> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("null") {
        return Ok(OriginRule::Null);
    }
    let invalid = || format!("{text:?} is not an origin (scheme://host[:port|:*], or null)");
    let (head, any_port) = match text.strip_suffix(":*") {
        Some(head) => (head, true),
        None => (text, false),
    };
    let uri: http::Uri = head.parse().map_err(|_| invalid())?;
    let scheme = uri.scheme_str().ok_or_else(invalid)?.to_ascii_lowercase();
    let authority = uri.authority().ok_or_else(invalid)?;
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/" && !path.as_str().is_empty())
    {
        return Err(invalid());
    }
    let port = if any_port {
        None
    } else {
        Some(
            authority
                .port_u16()
                .or_else(|| default_port(&scheme))
                .ok_or_else(invalid)?,
        )
    };
    Ok(OriginRule::Tuple {
        scheme,
        host: normalize_host(authority.host()),
        port,
    })
}

/// Whether an `Origin` header's value is allowed by `rules`.
fn origin_allowed(value: &HeaderValue, rules: &[OriginRule]) -> bool {
    let Ok(text) = value.to_str() else {
        return false;
    };
    let text = text.trim();
    if text.eq_ignore_ascii_case("null") {
        return rules.contains(&OriginRule::Null);
    }
    let Ok(uri) = text.parse::<http::Uri>() else {
        return false;
    };
    let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    let Some(port) = authority.port_u16().or_else(|| default_port(&scheme)) else {
        return false;
    };
    let host = normalize_host(authority.host());
    rules.iter().any(|rule| match rule {
        OriginRule::Null => false,
        OriginRule::Tuple {
            scheme: allowed_scheme,
            host: allowed_host,
            port: allowed_port,
        } => {
            *allowed_scheme == scheme
                && *allowed_host == host
                && allowed_port.is_none_or(|allowed| allowed == port)
        }
    })
}

/// What the guard knows.
struct Gate {
    server: FleetMcpServer,
    verifier: Option<Arc<dyn TokenVerifier>>,
    origins: Vec<OriginRule>,
    max_body_bytes: usize,
    max_sessions: usize,
    sessions: Arc<LocalSessionManager>,
    /// The subject of the principal that opened each session.
    owners: Mutex<HashMap<String, Option<String>>>,
    /// How many standalone (`GET`) streams each session's client holds open.
    streams: Arc<Mutex<HashMap<String, usize>>>,
    realm: String,
    metadata_url: Option<String>,
}

/// The 404 of a request naming a session that is not (or no longer, or not the caller's) open:
/// the JSON-RPC error clients re-initialize on.
fn session_not_found() -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "error": {"code": SESSION_NOT_FOUND_CODE, "message": "Session not found"},
        "id": null,
    });
    (StatusCode::NOT_FOUND, AxumJson(body)).into_response()
}

/// One open standalone stream of a session, counted in [`Gate::streams`] while it lives.
struct OpenStream {
    streams: Arc<Mutex<HashMap<String, usize>>>,
    id: String,
}

impl OpenStream {
    fn new(streams: &Arc<Mutex<HashMap<String, usize>>>, id: &str) -> OpenStream {
        *streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id.to_owned())
            .or_default() += 1;
        OpenStream {
            streams: Arc::clone(streams),
            id: id.to_owned(),
        }
    }
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = streams.get_mut(&self.id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                streams.remove(&self.id);
            }
        }
    }
}

/// A standalone stream's body, counted open until the connection drops it.
struct Tracked {
    inner: Body,
    _open: OpenStream,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        http_body::Body::is_end_stream(&self.inner)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::Body::size_hint(&self.inner)
    }
}

/// A challenge parameter's value: printable ASCII without quotes or backslashes.
fn quoted(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '"' | '\\' => '\'',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => ' ',
        })
        .collect()
}

impl Gate {
    /// A `WWW-Authenticate` value: `Bearer realm=...` with the parameters given.
    fn challenge(&self, parameters: &[(&str, &str)]) -> HeaderValue {
        let mut value = format!("Bearer realm=\"{}\"", quoted(&self.realm));
        for (name, text) in parameters {
            value.push_str(&format!(", {name}=\"{}\"", quoted(text)));
        }
        if let Some(url) = &self.metadata_url {
            value.push_str(&format!(", resource_metadata=\"{}\"", quoted(url)));
        }
        HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
    }

    fn unauthorized(&self, reason: Option<&str>) -> Response {
        let challenge = match reason {
            None => self.challenge(&[]),
            Some(reason) => {
                self.challenge(&[("error", "invalid_token"), ("error_description", reason)])
            }
        };
        let body = match reason {
            None => "Unauthorized: this MCP endpoint needs a bearer token".to_owned(),
            Some(reason) => format!("Unauthorized: {reason}"),
        };
        let mut response = (StatusCode::UNAUTHORIZED, body).into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
        response
    }

    /// The caller of a request, or the 401 answering it.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, Box<Response>> {
        let Some(verifier) = &self.verifier else {
            return Ok(Principal::token(ANONYMOUS, Vec::<String>::new()));
        };
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(Box::new(if headers.contains_key(header::AUTHORIZATION) {
                self.unauthorized(Some("send one Authorization header"))
            } else {
                self.unauthorized(None)
            }));
        };
        let token = value
            .to_str()
            .ok()
            .and_then(|text| {
                let (scheme, token) = text.trim().split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
            })
            .filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN_BYTES);
        let Some(token) = token else {
            return Err(Box::new(self.unauthorized(Some(
                "the Authorization header is not a bearer token",
            ))));
        };
        match verifier.verify(token).await {
            Ok(principal) => Ok(principal),
            Err(error) => {
                tracing::info!(
                    reason = error.reason(),
                    "an HTTP request's token was refused"
                );
                Err(Box::new(self.unauthorized(Some(error.reason()))))
            }
        }
    }

    /// Whether `principal` may use the session `id` (the one that opened it, or a session this
    /// gate did not see open).
    fn may_use(&self, id: &str, principal: &Principal) -> bool {
        self.owners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .is_none_or(|owner| *owner == principal.subject)
    }

    /// Notes that `principal` opened the session `id`, forgetting closed sessions now and then.
    async fn opened(&self, id: &str, principal: &Principal) {
        let crowded = {
            let mut owners = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
            owners.insert(id.to_owned(), principal.subject.clone());
            owners.len() > self.max_sessions.saturating_mul(2).max(16)
        };
        if crowded {
            let live: Vec<String> = self
                .sessions
                .sessions
                .read()
                .await
                .keys()
                .map(|id| id.to_string())
                .collect();
            self.owners
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|id, _| live.contains(id));
        }
    }

    /// Looks into a POST's JSON-RPC messages: a refusal for an `initialize` past the session
    /// limit (503) or a `tools/call` outside the caller's scopes (403).
    async fn inspect(
        &self,
        body: &[u8],
        principal: &Principal,
        new_session: bool,
    ) -> Option<Response> {
        let Ok(message) = serde_json::from_slice::<Json>(body) else {
            return None; // rmcp answers the parse error
        };
        let messages: Vec<&Json> = match &message {
            Json::Array(items) => items.iter().collect(),
            single => vec![single],
        };
        for message in messages {
            match message.get("method").and_then(Json::as_str) {
                Some("initialize") if new_session => {
                    let open = self.sessions.sessions.read().await.len();
                    if open >= self.max_sessions {
                        tracing::warn!(open, "an MCP session was refused: too many open");
                        let mut response = (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Service Unavailable: too many MCP sessions are open",
                        )
                            .into_response();
                        response
                            .headers_mut()
                            .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
                        return Some(response);
                    }
                }
                Some("tools/call") => {
                    let name = message
                        .get("params")
                        .and_then(|params| params.get("name"))
                        .and_then(Json::as_str)
                        .unwrap_or_default();
                    if !self.server.policy().allows(principal, name) {
                        return Some(self.insufficient_scope(name, message.get("id"), principal));
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn insufficient_scope(&self, name: &str, id: Option<&Json>, principal: &Principal) -> Response {
        let shown = crate::text::clean(name, agentspaces::catalog::MAX_NAME);
        tracing::warn!(
            tool = %shown,
            caller = principal.subject.as_deref().unwrap_or(ANONYMOUS),
            "an HTTP tools/call was refused: insufficient scope"
        );
        let scopes = self.server.policy().scopes_for(name).join(" ");
        let message = format!("the token's scopes do not allow invoking {shown}");
        let mut parameters = vec![
            ("error", "insufficient_scope"),
            ("error_description", message.as_str()),
        ];
        if !scopes.is_empty() {
            parameters.push(("scope", scopes.as_str()));
        }
        let challenge = self.challenge(&parameters);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id.cloned().unwrap_or(Json::Null),
            "error": {"code": -32001, "message": format!("forbidden: {message}")},
        });
        let mut response = (StatusCode::FORBIDDEN, AxumJson(body)).into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
        response
    }
}

/// The guard every request to the MCP endpoint passes; see the [module docs](self).
async fn guard(State(gate): State<Arc<Gate>>, request: Request, next: Next) -> Response {
    if let Some(origin) = request.headers().get(header::ORIGIN)
        && !origin_allowed(origin, &gate.origins)
    {
        tracing::warn!("an HTTP request was refused: its Origin is not allowed");
        return (StatusCode::FORBIDDEN, "Forbidden: Origin not allowed").into_response();
    }
    let principal = match gate.authenticate(request.headers()).await {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let (mut parts, body) = request.into_parts();
    // The token stays here: nothing downstream sees it, logs it, or keeps it.
    parts.headers.remove(header::AUTHORIZATION);
    let session = parts
        .headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if let Some(id) = &session
        && !gate.may_use(id, &principal)
    {
        tracing::warn!("an HTTP request named another principal's session");
        return session_not_found();
    }
    let standalone = parts.method == Method::GET;
    let body = if parts.method == Method::POST {
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.parse::<u64>().ok());
        if declared.is_some_and(|length| length > gate.max_body_bytes as u64) {
            return too_large(gate.max_body_bytes);
        }
        let Ok(bytes) = to_bytes(body, gate.max_body_bytes).await else {
            return too_large(gate.max_body_bytes);
        };
        if let Some(response) = gate.inspect(&bytes, &principal, session.is_none()).await {
            return response;
        }
        Body::from(bytes)
    } else {
        body
    };
    parts.extensions.insert(Caller(principal.clone()));
    let response = next.run(Request::from_parts(parts, body)).await;
    if session.is_none()
        && let Some(id) = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
    {
        gate.opened(id, &principal).await;
    }
    match &session {
        Some(_) if response.status() == StatusCode::NOT_FOUND => unknown_session(response).await,
        Some(id) if standalone && response.status() == StatusCode::OK => {
            // The client's standalone stream: counted open until the connection drops it.
            let (parts, body) = response.into_parts();
            let tracked = Tracked {
                inner: body,
                _open: OpenStream::new(&gate.streams, id),
            };
            Response::from_parts(parts, Body::new(tracked))
        }
        _ => response,
    }
}

/// rmcp's 404 for an unknown session, answered as [`session_not_found`]; any other 404 (a
/// JSON-RPC error of its own) as it was.
async fn unknown_session(response: Response) -> Response {
    let (parts, body) = response.into_parts();
    match to_bytes(body, 4096).await {
        Ok(bytes) if bytes.as_ref() == RMCP_SESSION_NOT_FOUND => session_not_found(),
        Ok(bytes) => Response::from_parts(parts, Body::from(bytes)),
        Err(_) => session_not_found(),
    }
}

/// Pings, every `every`, the sessions whose client holds a standalone stream open, until
/// `stop`: a session's ping and its answer are activity, so a connected client is never closed
/// as idle ([`HttpOptions::session_idle`]).
async fn keep_sessions_alive(
    server: FleetMcpServer,
    streams: Arc<Mutex<HashMap<String, usize>>>,
    every: Duration,
    stop: CancellationToken,
) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let open: Vec<String> = streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        if !open.is_empty() {
            let pinged = server.ping_sessions(&open, every);
            tracing::trace!(pinged, "kept the connected sessions alive");
        }
    }
}

fn too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("Payload Too Large: at most {limit} bytes"),
    )
        .into_response()
}

/// Serves `server` over Streamable HTTP under `options`; see the [module docs](self). Answers
/// once the address is bound; the server runs until [`HttpServer::shutdown`].
///
/// # Errors
///
/// [`ServeError::NoVerifier`] without a token verifier (unless
/// [`HttpOptions::allow_unauthenticated`]), [`ServeError::Options`] for a path or an allowed
/// origin that cannot be served, and [`ServeError::Bind`] when the address cannot be bound.
pub async fn serve_http(
    server: FleetMcpServer,
    options: HttpOptions,
) -> Result<HttpServer, ServeError> {
    options.check()?;
    let bind = options.bind;
    let routable = !bind.ip().is_loopback();
    if options.verifier.is_none() {
        if routable {
            tracing::warn!(
                %bind,
                "SERVING MCP OVER HTTP WITHOUT AUTHENTICATION ON A ROUTABLE ADDRESS: anyone who \
                 reaches {bind} can invoke the fleet's actions; only do this behind a proxy that \
                 authenticates every request"
            );
        } else {
            tracing::warn!(
                %bind,
                "serving MCP over HTTP without authentication: every local user and process can \
                 invoke the fleet's actions"
            );
        }
    }
    let origins = options
        .origins
        .iter()
        .map(|origin| parse_rule(origin))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ServeError::Options)?;
    let mut config = StreamableHttpServerConfig::default()
        .with_allowed_origins(options.origins.clone())
        .enforce_origin_validation()
        .with_max_request_body_bytes(options.max_body_bytes);
    config = match &options.hosts {
        Some(hosts) => config.with_allowed_hosts(hosts.clone()),
        None if bind.ip().is_unspecified() => {
            tracing::warn!(
                %bind,
                "the Host header is not checked on an unspecified address; name the hosts the \
                 gateway is reached by (allowed_hosts)"
            );
            config.disable_allowed_hosts()
        }
        None => {
            let mut hosts: Vec<String> = LOOPBACK_HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect();
            if !is_loopback_host(&bind.ip().to_string()) {
                hosts.push(bind.ip().to_string());
            }
            config.with_allowed_hosts(hosts)
        }
    };
    let shutdown = CancellationToken::new();
    config = config.with_cancellation_token(shutdown.child_token());
    let mut sessions = LocalSessionManager::default();
    sessions.session_config.keep_alive = Some(options.session_idle);
    let sessions = Arc::new(sessions);
    let factory_server = server.clone();
    let service = StreamableHttpService::new(
        move || Ok(factory_server.clone()),
        Arc::clone(&sessions),
        config,
    );
    let metadata_url = options
        .resource
        .as_ref()
        .and_then(ProtectedResource::metadata_url);
    let streams: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
    let gate = Arc::new(Gate {
        server: server.clone(),
        verifier: options.verifier.clone(),
        origins,
        max_body_bytes: options.max_body_bytes,
        max_sessions: options.max_sessions,
        sessions,
        owners: Mutex::new(HashMap::new()),
        streams: Arc::clone(&streams),
        realm: options.realm.clone(),
        metadata_url,
    });
    let mut router = Router::new()
        .route_service(&options.path, service)
        .layer(from_fn_with_state(gate, guard));
    if let Some(resource) = &options.resource {
        let document = resource.document();
        let suffix = options.path.trim_end_matches('/');
        let serve_document = move || {
            let document = document.clone();
            async move { AxumJson(document) }
        };
        router = router
            .route(RESOURCE_METADATA_PATH, get(serve_document.clone()))
            .route(
                &format!("{RESOURCE_METADATA_PATH}{suffix}"),
                get(serve_document),
            );
    }
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|source| ServeError::Bind { bind, source })?;
    let address = listener
        .local_addr()
        .map_err(|source| ServeError::Bind { bind, source })?;
    server.ensure_refresher();
    tokio::spawn(keep_sessions_alive(
        server.clone(),
        streams,
        (options.session_idle / 2).max(MIN_KEEPALIVE),
        shutdown.child_token(),
    ));
    tracing::info!(%address, path = %options.path, "serving the fleet's tools over MCP Streamable HTTP");
    let stop = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { stop.cancelled().await })
            .await
    });
    Ok(HttpServer {
        address,
        path: options.path,
        server,
        shutdown,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(texts: &[&str]) -> Vec<OriginRule> {
        texts
            .iter()
            .map(|text| parse_rule(text).expect("a rule"))
            .collect()
    }

    #[test]
    fn origins_match_scheme_host_and_port() {
        let loopback = rules(&LOOPBACK_ORIGINS);
        let allowed = |origin: &'static str, rules: &[OriginRule]| {
            origin_allowed(&HeaderValue::from_static(origin), rules)
        };
        assert!(allowed("http://localhost:3000", &loopback));
        assert!(allowed("http://127.0.0.1", &loopback));
        assert!(allowed("https://[::1]:8443", &loopback));
        assert!(!allowed("http://evil.example", &loopback));
        assert!(!allowed("http://localhost.evil.example", &loopback));
        assert!(!allowed("null", &loopback));
        assert!(!allowed("ftp://localhost", &loopback));
        let app = rules(&["https://app.example.com", "null"]);
        assert!(allowed("https://app.example.com", &app));
        assert!(allowed("https://app.example.com:443", &app));
        assert!(!allowed("https://app.example.com:8443", &app));
        assert!(!allowed("http://app.example.com", &app));
        assert!(allowed("null", &app));
        assert!(parse_rule("app.example.com").is_err());
        assert!(parse_rule("https://app.example.com/path").is_err());
    }

    #[test]
    fn metadata_urls_put_the_well_known_path_first() {
        let resource =
            ProtectedResource::new("https://mcp.example.com/mcp", "https://auth.example.com");
        assert_eq!(
            resource.metadata_url().as_deref(),
            Some("https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(
            resource.document()["authorization_servers"][0],
            "https://auth.example.com"
        );
    }

    #[test]
    fn challenge_values_cannot_break_their_quotes() {
        assert_eq!(quoted("a \"b\" \\c\n"), "a 'b' 'c ");
    }
}
