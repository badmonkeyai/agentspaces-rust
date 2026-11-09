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

//! The Streamable HTTP gateway over real loopback sockets: authentication (401 without a token,
//! 401 with a bad one, 403 for a call outside the token's scopes, 200 in scope), sessions bound
//! to their principal, the start refused without a verifier (on loopback, and on a routable
//! address), the Origin check, the session and body bounds, protected resource metadata, JWT
//! tokens against a test key set (expiry, audience, issuer, signature, key rotation with a
//! rate-limited reload), and token files refused when group or others may read them.

#[path = "../../agentspaces/tests/support/mod.rs"]
mod support;

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces::agent::{Bound, Reply, TakeContext};
use agentspaces::space::Fleet;
use agentspaces::wire::identity::Identity;
use agentspaces_mcp::{
    FleetMcpServer, HttpOptions, HttpServer, JwksSource, JwtOptions, JwtVerifier, Policy,
    ProtectedResource, ServeError, StaticTokens, TokenFileError, serve_http,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value as Json, json};
use support::eventually;

const ANA: &str = "ana-research-token-0123456789";
const BOB: &str = "bob-summaries-token-0123456789";
const PROTOCOL: &str = "2025-11-25";

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// A scratch directory of this test process, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "asrs-mcp-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn write(&self, name: &str, text: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fleet with a `research` and a `summarize` worker, and a gateway member.
struct Fixture {
    net: Net,
    gateway: Fleet,
    workers: Vec<Bound>,
}

impl Fixture {
    async fn new() -> Fixture {
        let net = Net::new();
        let worker = net.member().await;
        let gateway = net.member().await;
        let research = research_task(&worker, "researcher").await;
        let summarize = worker
            .agent("summarizer")
            .settle(SETTLE)
            .take(
                "summaries",
                lease(),
                |task: Task, _ctx: TakeContext| async move {
                    Ok(Reply::from(Summary {
                        words: i64::try_from(task.topic.len()).unwrap_or_default(),
                        topic: task.topic,
                    }))
                },
            )
            .action("summarize")
            .produces::<Summary>()
            .bind()
            .await
            .expect("bind");
        Fixture {
            net,
            gateway,
            workers: vec![research, summarize],
        }
    }

    /// The scoped policy: `research` lets a token call research, `summaries` summarize.
    fn server(&self) -> FleetMcpServer {
        FleetMcpServer::new(
            &self.gateway,
            options().policy(
                Policy::scoped()
                    .allow("research", ["research*"])
                    .allow("summaries", ["summarize"]),
            ),
        )
    }

    async fn stop(self) {
        for worker in self.workers {
            worker.stop(Duration::from_secs(5)).await;
        }
    }
}

/// The token file the gateway loads: ana by token, bob by the token's SHA-256.
fn token_file(scratch: &Scratch) -> PathBuf {
    let bob_digest = hex::encode(agentspaces::wire::crypto::port().sha256(BOB.as_bytes()));
    scratch.write(
        "tokens.yaml",
        &format!(
            "tokens:\n  - token: \"{ANA}\"\n    principal: ana\n    scopes: [research]\n  - sha256: \
             \"{bob_digest}\"\n    principal: bob\n    scopes: [summaries, research]\n"
        ),
        0o600,
    )
}

/// Raw HTTP to the gateway.
struct Raw {
    client: reqwest::Client,
    url: String,
}

/// What one POST answered.
struct Answer {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    /// The JSON-RPC response the body carries (JSON, or an SSE stream's `data:` lines).
    fn rpc(&self) -> Json {
        if let Ok(json) = serde_json::from_str::<Json>(&self.body) {
            return json;
        }
        self.body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Json>(data.trim()).ok())
            .find(|message| message.get("result").is_some() || message.get("error").is_some())
            .unwrap_or(Json::Null)
    }
}

impl Raw {
    fn new(http: &HttpServer) -> Raw {
        Raw {
            client: reqwest::Client::new(),
            url: http.url(),
        }
    }

    async fn post(
        &self,
        token: Option<&str>,
        session: Option<&str>,
        headers: &[(&str, &str)],
        body: &Json,
    ) -> Answer {
        let mut request = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body.to_string());
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", PROTOCOL);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("the request is answered");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();
        Answer {
            status,
            headers,
            body,
        }
    }

    /// Opens a session for `token`: initialize, then initialized.
    async fn open(&self, token: Option<&str>) -> String {
        let answer = self.post(token, None, &[], &initialize(1)).await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        let session = answer.header("mcp-session-id");
        assert!(!session.is_empty(), "a session id");
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let answer = self.post(token, Some(&session), &[], &initialized).await;
        assert_eq!(answer.status, 202, "{}", answer.body);
        session
    }

    async fn call(&self, token: &str, session: &str, id: i64, name: &str, topic: &str) -> Answer {
        let call = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": {"input": {"topic": topic}, "timeout": "20s"}},
        });
        self.post(Some(token), Some(session), &[], &call).await
    }

    async fn tool_names(&self, token: &str, session: &str) -> Vec<String> {
        let list = json!({"jsonrpc": "2.0", "id": 99, "method": "tools/list"});
        let answer = self.post(Some(token), Some(session), &[], &list).await;
        answer.rpc()["result"]["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn initialize(id: i64) -> Json {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "http-test", "version": "1"},
        },
    })
}

/// Every request is authenticated, every call judged against the
/// caller's scopes: 401 without a token or with a bad one, 403 for a call outside the scopes,
/// 200 in scope; a session answers only the principal that opened it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_http_auth_test() {
    let fixture = Fixture::new().await;
    let scratch = Scratch::new("auth");
    let tokens = StaticTokens::load(token_file(&scratch)).expect("the token file");
    assert_eq!(tokens.principals(), ["ana", "bob"]);
    let http = serve_http(
        fixture.server(),
        HttpOptions::new().bind(loopback()).verifier(tokens),
    )
    .await
    .expect("serving");
    let raw = Raw::new(&http);

    // 401 without a token: a bare challenge, and nothing reaches the session.
    let answer = raw.post(None, None, &[], &initialize(1)).await;
    assert_eq!(answer.status, 401);
    assert_eq!(
        answer.header("www-authenticate"),
        "Bearer realm=\"agentspaces\""
    );
    assert!(answer.header("mcp-session-id").is_empty());
    let get = raw.client.get(&raw.url).send().await.expect("answered");
    assert_eq!(get.status(), 401, "every request is authenticated");
    // 401 with a bad token, or with no bearer token at all.
    let answer = raw
        .post(Some("not-a-known-token"), None, &[], &initialize(1))
        .await;
    assert_eq!(answer.status, 401);
    let challenge = answer.header("www-authenticate");
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(!challenge.contains("not-a-known-token"), "{challenge}");
    let answer = raw
        .post(
            None,
            None,
            &[("authorization", "Basic YW5hOnB3")],
            &initialize(1),
        )
        .await;
    assert_eq!(answer.status, 401);

    // 200 in scope.
    let session = raw.open(Some(ANA)).await;
    eventually("both tools over HTTP", || async {
        raw.tool_names(ANA, &session).await == ["research", "summarize"]
    })
    .await;
    let answer = raw.call(ANA, &session, 2, "research", "http").await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let result = &answer.rpc()["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["topic"], "http");

    // 403 out of scope, with the scopes that would allow it, and the call never starts.
    let answer = raw.call(ANA, &session, 3, "summarize", "nope").await;
    assert_eq!(answer.status, 403, "{}", answer.body);
    let challenge = answer.header("www-authenticate");
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(challenge.contains("scope=\"summaries\""), "{challenge}");
    let error = answer.rpc();
    assert_eq!(error["id"], 3);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("summarize")
    );

    // Another principal may not use ana's session.
    let answer = raw.call(BOB, &session, 4, "summarize", "x").await;
    assert_eq!(answer.status, 404);

    // The rmcp client, with bob's token: the whole round trip.
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(raw.url.clone()).auth_header(BOB),
    );
    let client = Recorder::legacy()
        .serve(transport)
        .await
        .expect("bob connects");
    let summary = client
        .call_tool(
            CallToolRequestParams::new("summarize").with_arguments(
                json!({"input": {"topic": "four"}})
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await
        .expect("a result");
    assert_eq!(summary.is_error, Some(false), "{}", text(&summary));
    assert_eq!(summary.structured_content.expect("structured")["words"], 4);
    let _ = client.cancel().await;

    http.shutdown().await.expect("shut down");
    fixture.stop().await;
}

/// The gateway refuses to start without a token verifier, on loopback and on a routable
/// address, unless told to; told to, it serves every caller as the scopeless anonymous
/// principal, which a scoped policy refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gateway_needs_a_verifier() {
    let fixture = Fixture::new().await;
    let routable = serve_http(
        fixture.server(),
        HttpOptions::new().bind(SocketAddr::from(([0, 0, 0, 0], 0))),
    )
    .await;
    assert!(
        matches!(routable, Err(ServeError::NoVerifier { .. })),
        "{routable:?}"
    );
    let local = serve_http(fixture.server(), HttpOptions::new().bind(loopback())).await;
    assert!(
        matches!(local, Err(ServeError::NoVerifier { .. })),
        "{local:?}"
    );
    let bad_path = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .path("mcp")
            .verifier(StaticTokens::new()),
    )
    .await;
    assert!(
        matches!(bad_path, Err(ServeError::Options(_))),
        "{bad_path:?}"
    );

    let open = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .allow_unauthenticated(true),
    )
    .await
    .expect("serving without authentication when told to");
    let raw = Raw::new(&open);
    let session = raw.open(None).await;
    eventually("the tools", || async {
        raw.tool_names("", &session).await.len() == 2
    })
    .await;
    let answer = raw.call("", &session, 2, "research", "x").await;
    assert_eq!(answer.status, 403, "the anonymous caller has no scope");
    open.shutdown().await.expect("shut down");
    fixture.stop().await;
}

/// A request whose Origin is not allowed is refused before anything else (DNS-rebinding
/// protection); loopback origins and those added are allowed; a request without one passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origins_are_checked_first() {
    let fixture = Fixture::new().await;
    let tokens = StaticTokens::new()
        .token(ANA, "ana", ["research"])
        .expect("a token");
    let http = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .verifier(tokens)
            .allow_origin("https://app.example.com"),
    )
    .await
    .expect("serving");
    let raw = Raw::new(&http);
    let evil = [("origin", "http://evil.example")];
    let answer = raw.post(None, None, &evil, &initialize(1)).await;
    assert_eq!(answer.status, 403, "refused before authentication");
    assert!(answer.header("www-authenticate").is_empty());
    let answer = raw.post(Some(ANA), None, &evil, &initialize(1)).await;
    assert_eq!(answer.status, 403);
    let answer = raw
        .post(
            Some(ANA),
            None,
            &[("origin", "http://localhost.evil.example")],
            &initialize(1),
        )
        .await;
    assert_eq!(answer.status, 403);
    let answer = raw
        .post(
            Some(ANA),
            None,
            &[("origin", "http://localhost:5173")],
            &initialize(1),
        )
        .await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let answer = raw
        .post(
            Some(ANA),
            None,
            &[("origin", "https://app.example.com")],
            &initialize(1),
        )
        .await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let answer = raw
        .post(
            Some(ANA),
            None,
            &[("origin", "https://app.example.com:8443")],
            &initialize(1),
        )
        .await;
    assert_eq!(answer.status, 403);
    http.shutdown().await.expect("shut down");
    fixture.stop().await;
}

/// At most `max_sessions` sessions are open (503 past it), bodies over the cap are 413, and
/// protected resource metadata is served and named in the challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_bodies_and_metadata() {
    let fixture = Fixture::new().await;
    let tokens = StaticTokens::new()
        .token(ANA, "ana", ["research"])
        .expect("a token");
    let resource = ProtectedResource::new("http://127.0.0.1/mcp", "https://auth.example.com")
        .scopes(["research", "summaries"]);
    let http = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .verifier(tokens)
            .max_sessions(1)
            .max_body_bytes(2048)
            .protected_resource(resource),
    )
    .await
    .expect("serving");
    let raw = Raw::new(&http);
    let _session = raw.open(Some(ANA)).await;
    let answer = raw.post(Some(ANA), None, &[], &initialize(2)).await;
    assert_eq!(answer.status, 503, "{}", answer.body);
    assert_eq!(answer.header("retry-after"), "30");

    let big = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {"pad": "x".repeat(4096)}});
    let answer = raw.post(Some(ANA), None, &[], &big).await;
    assert_eq!(answer.status, 413);

    let answer = raw.post(None, None, &[], &initialize(1)).await;
    let challenge = answer.header("www-authenticate");
    assert!(
        challenge.contains(
            "resource_metadata=\"http://127.0.0.1/.well-known/oauth-protected-resource/mcp\""
        ),
        "{challenge}"
    );
    let metadata: Json = raw
        .client
        .get(format!(
            "http://{}/.well-known/oauth-protected-resource/mcp",
            http.local_addr()
        ))
        .send()
        .await
        .expect("answered")
        .json()
        .await
        .expect("JSON");
    assert_eq!(
        metadata["authorization_servers"],
        json!(["https://auth.example.com"])
    );
    assert_eq!(
        metadata["scopes_supported"],
        json!(["research", "summaries"])
    );
    http.shutdown().await.expect("shut down");
    fixture.stop().await;
}

/// A key set served over loopback HTTP, counting its fetches; its keys can be rotated.
struct Issuer {
    keys: Arc<std::sync::Mutex<Vec<Json>>>,
    fetches: Arc<AtomicUsize>,
    /// How long each fetch is answered after, milliseconds (a slow or degraded issuer).
    delay: Arc<std::sync::atomic::AtomicU64>,
    url: String,
    stop: tokio::sync::oneshot::Sender<()>,
}

impl Issuer {
    async fn start() -> Issuer {
        let keys: Arc<std::sync::Mutex<Vec<Json>>> = Arc::default();
        let fetches = Arc::new(AtomicUsize::new(0));
        let delay = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (served, counted, slow) = (Arc::clone(&keys), Arc::clone(&fetches), Arc::clone(&delay));
        let router = axum::Router::new().route(
            "/jwks.json",
            axum::routing::get(move || {
                let (served, counted, slow) =
                    (Arc::clone(&served), Arc::clone(&counted), Arc::clone(&slow));
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let wait = slow.load(Ordering::SeqCst);
                    if wait > 0 {
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                    }
                    let keys = served.lock().expect("keys").clone();
                    axum::Json(json!({ "keys": keys }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(loopback())
            .await
            .expect("bind");
        let url = format!(
            "http://{}/jwks.json",
            listener.local_addr().expect("address")
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await;
        });
        Issuer {
            keys,
            fetches,
            delay,
            url,
            stop,
        }
    }

    fn publish(&self, kid: &str, identity: &Identity) {
        self.keys.lock().expect("keys").push(json!({
            "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(identity.public_raw()),
        }));
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

const ISSUER: &str = "https://auth.example.com/";
const AUDIENCE: &str = "https://mcp.example.com/mcp";

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("seconds")
}

/// A JWT signed by `identity` under `kid` with `claims`.
fn jwt(identity: &Identity, kid: &str, claims: &Json) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    let key = jsonwebtoken::EncodingKey::from_ed_der(&identity.pkcs8());
    jsonwebtoken::encode(&header, claims, &key).expect("a token")
}

fn claims(scope: &str, audience: &str, issuer: &str, expires_in: i64) -> Json {
    json!({
        "iss": issuer, "aud": audience, "sub": "ana", "scope": scope,
        "iat": now(), "exp": now() + expires_in,
    })
}

/// JWT bearer tokens against a test key set: a valid token in scope is served, expired, wrong
/// audience, wrong issuer, and forged ones are 401; an unknown key id reloads the set at most
/// once per cooldown, and a rotated key is accepted after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jwt_tokens_against_a_test_key_set() {
    let fixture = Fixture::new().await;
    let issuer = Issuer::start().await;
    let signer = Identity::generate().expect("a key");
    issuer.publish("k1", &signer);
    let verifier = Arc::new(
        JwtVerifier::new(
            JwtOptions::new(ISSUER, AUDIENCE, JwksSource::Url(issuer.url.clone()))
                .algorithms(["EdDSA"])
                .expect("algorithms")
                .refresh_cooldown(Duration::from_millis(500))
                .leeway(Duration::from_secs(5)),
        )
        .expect("a verifier"),
    );
    let http = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .shared_verifier(Arc::clone(&verifier) as Arc<dyn agentspaces_mcp::TokenVerifier>),
    )
    .await
    .expect("serving");
    let raw = Raw::new(&http);

    let good = jwt(&signer, "k1", &claims("research", AUDIENCE, ISSUER, 300));
    let session = raw.open(Some(&good)).await;
    assert_eq!(
        issuer.fetches(),
        1,
        "the key set is fetched at the first token"
    );
    eventually("the tools", || async {
        raw.tool_names(&good, &session).await.len() == 2
    })
    .await;
    let answer = raw.call(&good, &session, 2, "research", "jwt").await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.rpc()["result"]["structuredContent"]["topic"], "jwt");
    let answer = raw.call(&good, &session, 3, "summarize", "jwt").await;
    assert_eq!(answer.status, 403, "the token's scope is research only");

    let refused = |token: String, reason: &'static str| {
        let raw = &raw;
        async move {
            let answer = raw.post(Some(&token), None, &[], &initialize(1)).await;
            assert_eq!(answer.status, 401, "{reason}");
            let challenge = answer.header("www-authenticate");
            assert!(challenge.contains("invalid_token"), "{reason}: {challenge}");
            assert!(challenge.contains(reason), "{reason}: {challenge}");
        }
    };
    refused(
        jwt(&signer, "k1", &claims("research", AUDIENCE, ISSUER, -60)),
        "expired",
    )
    .await;
    refused(
        jwt(
            &signer,
            "k1",
            &claims("research", "https://other.example.com", ISSUER, 300),
        ),
        "not for this server",
    )
    .await;
    refused(
        jwt(
            &signer,
            "k1",
            &claims("research", AUDIENCE, "https://evil.example.com/", 300),
        ),
        "accepted issuer",
    )
    .await;
    let forger = Identity::generate().expect("a key");
    refused(
        jwt(&forger, "k1", &claims("research", AUDIENCE, ISSUER, 300)),
        "signature",
    )
    .await;
    assert_eq!(issuer.fetches(), 1, "known key ids need no fetch");

    // An unknown key id reloads the set once; another right after is refused without a fetch.
    tokio::time::sleep(Duration::from_millis(600)).await;
    refused(
        jwt(&forger, "k9", &claims("research", AUDIENCE, ISSUER, 300)),
        "not in the issuer's key set",
    )
    .await;
    assert_eq!(issuer.fetches(), 2);
    refused(
        jwt(&forger, "k8", &claims("research", AUDIENCE, ISSUER, 300)),
        "not in the issuer's key set",
    )
    .await;
    assert_eq!(issuer.fetches(), 2, "the reload is rate limited");

    // A rotated key is accepted once the cooldown has passed.
    let rotated = Identity::generate().expect("a key");
    issuer.publish("k2", &rotated);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let fresh = jwt(
        &rotated,
        "k2",
        &claims("research summaries", AUDIENCE, ISSUER, 300),
    );
    let answer = raw.post(Some(&fresh), None, &[], &initialize(1)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(issuer.fetches(), 3);
    assert_eq!(verifier.jwks_loads(), 3);

    // The same keys from a file.
    let scratch = Scratch::new("jwks");
    let set = json!({"keys": issuer.keys.lock().expect("keys").clone()});
    let file = scratch.write("jwks.json", &set.to_string(), 0o644);
    let from_file = JwtVerifier::new(JwtOptions::new(ISSUER, AUDIENCE, JwksSource::File(file)))
        .expect("a verifier");
    let principal = from_file.verify_token(&fresh).await.expect("verified");
    assert_eq!(principal.subject.as_deref(), Some("ana"));
    assert_eq!(principal.scopes, ["research", "summaries"]);
    assert!(
        JwtVerifier::new(JwtOptions::new(
            ISSUER,
            AUDIENCE,
            JwksSource::Url("http://auth.example.com/jwks.json".into())
        ))
        .is_err(),
        "a key set over plain HTTP to another host is refused"
    );

    http.shutdown().await.expect("shut down");
    let _ = issuer.stop.send(());
    fixture.stop().await;
}

/// A session whose client holds its standalone stream open is connected, not idle:
/// past `session_idle` with no request, it still hears `notifications/tools/list_changed` and
/// its next request is served (the client never re-initializes). A session without a stream
/// still closes after `session_idle`, and a request naming it, an unknown session, or another
/// principal's session is answered 404 with the JSON-RPC error `-32001` clients re-initialize
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_session_is_never_closed_as_idle() {
    let fixture = Fixture::new().await;
    let tokens = StaticTokens::new()
        .token(ANA, "ana", ["research"])
        .expect("a token")
        .token(BOB, "bob", ["summaries"])
        .expect("a token");
    let http = serve_http(
        fixture.server(),
        HttpOptions::new()
            .bind(loopback())
            .verifier(tokens)
            .session_idle(Duration::from_secs(2)),
    )
    .await
    .expect("serving");
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(http.url())
            .auth_header(ANA)
            .reinit_on_expired_session(false),
    );
    let recorder = Recorder::legacy();
    let client = recorder
        .clone()
        .serve(transport)
        .await
        .expect("ana connects");
    let names = || async {
        client
            .peer()
            .list_all_tools()
            .await
            .map(|tools| {
                tools
                    .into_iter()
                    .map(|tool| tool.name.into_owned())
                    .collect()
            })
            .unwrap_or_else(|_| Vec::<String>::new())
    };
    eventually("the tools", || async { names().await.len() == 2 }).await;

    // Idle well past the session window, the client's standalone stream open.
    tokio::time::sleep(Duration::from_millis(4500)).await;
    let before = recorder.changes();
    let extra = fixture.net.member().await;
    let librarian = research_other(&extra, "librarian").await;
    until("list_changed after the idle window", || {
        recorder.changes() > before
    })
    .await;
    let listed = client
        .peer()
        .list_all_tools()
        .await
        .expect("the session is still served");
    assert_eq!(listed.len(), 3, "{listed:?}");

    // A session without a stream closes after session_idle; then, like an unknown session or
    // another principal's, it is a JSON-RPC -32001 404.
    let raw = Raw::new(&http);
    let quiet = raw.open(Some(ANA)).await;
    let list = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let mine = raw.open(Some(ANA)).await;
    for (token, session, why) in [
        (ANA, quiet.as_str(), "idle, with no stream"),
        (ANA, "no-such-session", "unknown"),
        (BOB, mine.as_str(), "another principal's"),
    ] {
        let answer = raw.post(Some(token), Some(session), &[], &list).await;
        assert_eq!(answer.status, 404, "{why}: {}", answer.body);
        assert!(
            answer
                .header("content-type")
                .starts_with("application/json"),
            "{why}: {}",
            answer.header("content-type")
        );
        assert!(
            answer.body.contains("\"code\":-32001"),
            "{why}: {}",
            answer.body
        );
        assert_eq!(
            answer.rpc()["error"]["message"],
            "Session not found",
            "{why}"
        );
    }
    let _ = client.cancel().await;
    librarian.stop(Duration::from_secs(5)).await;
    http.shutdown().await.expect("shut down");
    fixture.stop().await;
}

/// A token naming a made-up key id makes the verifier reload the key set from a
/// slow issuer, and while that fetch runs a valid token whose key is cached is judged at once,
/// not after the fetch; the forged token is still refused once the reload ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_reload_never_holds_up_a_cached_key() {
    let issuer = Issuer::start().await;
    let signer = Identity::generate().expect("a key");
    issuer.publish("k1", &signer);
    let verifier = Arc::new(
        JwtVerifier::new(
            JwtOptions::new(ISSUER, AUDIENCE, JwksSource::Url(issuer.url.clone()))
                .algorithms(["EdDSA"])
                .expect("algorithms")
                .refresh_cooldown(Duration::from_millis(100)),
        )
        .expect("a verifier"),
    );
    let good = jwt(&signer, "k1", &claims("research", AUDIENCE, ISSUER, 300));
    verifier.verify_token(&good).await.expect("the first token");
    assert_eq!(issuer.fetches(), 1);

    // The issuer turns slow; a forged key id (no secret needed) starts a reload.
    issuer.delay.store(3000, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let forger = Identity::generate().expect("a key");
    let forged = jwt(&forger, "k9", &claims("research", AUDIENCE, ISSUER, 300));
    let reloading = {
        let verifier = Arc::clone(&verifier);
        tokio::spawn(async move { verifier.verify_token(&forged).await })
    };
    eventually("the reload to start", || async { issuer.fetches() == 2 }).await;
    let started = std::time::Instant::now();
    let principal = verifier.verify_token(&good).await.expect("the cached key");
    let took = started.elapsed();
    assert_eq!(principal.subject.as_deref(), Some("ana"));
    assert!(
        took < Duration::from_millis(1000),
        "a cached key waited {took:?} for a reload it did not need"
    );
    let refused = reloading.await.expect("joined");
    assert!(
        refused.is_err(),
        "the forged key id is refused: {refused:?}"
    );
    assert_eq!(issuer.fetches(), 2, "one reload");
    let _ = issuer.stop.send(());
}

/// A token file group or others may read is refused; owner-only, it loads, as
/// YAML or JSON; a bad record names its index and field, never a value.
#[tokio::test]
async fn token_files_readable_by_others_are_refused() {
    let scratch = Scratch::new("tokens");
    let yaml = "- token: \"s3cret-token\"\n  principal: ana\n  scopes: [a]\n";
    for mode in [0o644, 0o640, 0o604, 0o660] {
        let path = scratch.write("open.yaml", yaml, mode);
        match StaticTokens::load(&path) {
            Err(TokenFileError::Readable { mode: found, .. }) => assert_eq!(found, mode),
            other => panic!("mode {mode:o}: expected a refusal, got {other:?}"),
        }
    }
    let path = scratch.write("owner.yaml", yaml, 0o600);
    let tokens = StaticTokens::load(&path).expect("owner-only loads");
    assert!(tokens.lookup("s3cret-token").is_some());
    let path = scratch.write(
        "tokens.json",
        r#"{"tokens": [{"token": "json-token", "principal": "bob", "scopes": ["b"]}]}"#,
        0o400,
    );
    let tokens = StaticTokens::load(&path).expect("JSON loads");
    assert_eq!(tokens.principals(), ["bob"]);
    let path = scratch.write(
        "bad.yaml",
        "tokens:\n  - token: \"fine-token\"\n    principal: a\n  - token: \"leaky-secret\"\n    principal: b\n    scops: [x]\n",
        0o600,
    );
    let error = StaticTokens::load(&path)
        .expect_err("a bad record")
        .to_string();
    assert!(
        error.contains("record 1: unknown field \"scops\""),
        "{error}"
    );
    assert!(
        !error.contains("leaky-secret") && !error.contains("fine-token"),
        "{error}"
    );
    let path = scratch.write(
        "broken.yaml",
        "tokens: [\n  token: \"leaky-secret\"\n",
        0o600,
    );
    let error = StaticTokens::load(&path).expect_err("not YAML").to_string();
    assert!(!error.contains("leaky-secret"), "{error}");
    let path = scratch.write("empty.yaml", "tokens: []\n", 0o600);
    assert!(StaticTokens::load(&path).is_err(), "no token");
}

/// A client of the newest protocol (2026-07-28: no session, a `subscriptions/listen` stream for
/// notifications) lists, calls, and hears `list_changed` over HTTP with its token; a call
/// outside its scopes is still 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_newest_protocol_works_over_http() {
    use rmcp::model::{ServerNotification, SubscriptionFilter};
    use rmcp::service::{ClientLifecycleMode, ClientServiceExt as _};

    let fixture = Fixture::new().await;
    let tokens = StaticTokens::new()
        .token(ANA, "ana", ["research"])
        .expect("a token");
    let server = fixture.server();
    let http = serve_http(
        server.clone(),
        HttpOptions::new().bind(loopback()).verifier(tokens),
    )
    .await
    .expect("serving");
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(http.url()).auth_header(ANA),
    );
    let client = Recorder::latest()
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![rmcp::model::ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("ana connects");
    eventually("the tools", || async {
        client
            .peer()
            .list_all_tools()
            .await
            .map(|tools| tools.len())
            .unwrap_or_default()
            == 2
    })
    .await;
    let result = client
        .call_tool(
            CallToolRequestParams::new("research").with_arguments(
                json!({"input": {"topic": "stateless"}})
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await
        .expect("a result");
    assert_eq!(result.is_error, Some(false), "{}", text(&result));
    assert_eq!(
        result.structured_content.expect("structured")["topic"],
        "stateless"
    );
    let refused = client
        .call_tool(
            CallToolRequestParams::new("summarize").with_arguments(
                json!({"input": {"topic": "x"}})
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await;
    assert!(refused.is_err(), "403 out of scope: {refused:?}");

    let mut subscription = client
        .peer()
        .listen(SubscriptionFilter::builder().tools_list_changed().build())
        .await
        .expect("subscriptions/listen");
    let worker = fixture.net.member().await;
    let audit = worker
        .agent("auditor")
        .settle(SETTLE)
        .take(
            SPACE,
            lease(),
            |task: OtherTask, ctx: TakeContext| async move {
                Ok(Reply::from(Outcome {
                    topic: task.topic,
                    worker: ctx.agent_id().to_owned(),
                }))
            },
        )
        .action("audit")
        .produces::<Outcome>()
        .bind()
        .await
        .expect("bind");
    let heard = tokio::time::timeout(WAIT, subscription.next())
        .await
        .expect("a notification in time")
        .expect("the subscription is open")
        .expect("a notification");
    assert!(
        matches!(heard, ServerNotification::ToolListChangedNotification(_)),
        "{heard:?}"
    );
    assert!(server.tool_names().contains(&"audit".to_owned()));
    let _ = subscription.cancel().await;
    let _ = client.cancel().await;
    audit.stop(Duration::from_secs(5)).await;
    http.shutdown().await.expect("shut down");
    fixture.stop().await;
}
