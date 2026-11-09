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

//! `aspace mcp` against MCP clients that share no code with rmcp or `aspace`, and against the
//! Java reference: the official
//! TypeScript SDK (`@modelcontextprotocol/sdk`, under Node) and the Ruby SDK (the `mcp` gem),
//! each driven by a script in `interop/mcp-clients` that reads operations on standard input and
//! answers JSON lines.
//!
//! Against the scripted Java seed (`interop/java-seed`), a Java agent it binds, and a Rust worker
//! (`aspace work`):
//!
//! 1. the TypeScript SDK over standard input and output: `initialize`, `tools/list` with the
//!    Java agent's action and the Rust worker's, `tools/call` reaching each (Java and the worker
//!    answering), and a Java agent bound later (a new action) heard as
//!    `notifications/tools/list_changed` and listed, and called, next; the SDK closing with a
//!    call in flight stops the gateway with exit 0 (its SIGTERM, before its SIGKILL), the call
//!    answered first with a tool error saying the gateway stopped, and the worker still
//!    completes the call's input;
//! 2. the Ruby SDK the same way, with the gateway started exactly as the Codex CLI recipe of the
//!    `agentspaces_mcp` documentation starts it (`command = "aspace"`, `args = ["mcp"]`),
//!    configured only by the fleet file in `$XDG_CONFIG_HOME/agentspaces/fleet.yaml`, and the
//!    modern lifecycle (`server/discover`, protocol 2026-07-28) too;
//! 3. the TypeScript SDK over Streamable HTTP, started as the team gateway (`--http`,
//!    `--tokens`, `--only`) with a policy: 401 without a token and with an unknown one, 403 for a
//!    browser Origin not allowed, 200 and a Java result in scope, 403 `insufficient_scope` out of
//!    scope (the input never written); then a JWT-protected gateway whose key set the client
//!    generated (RS256): 401 for an expired token, another audience, and another key, 200 in
//!    scope, 403 out of it, `list_changed` heard on the session's SSE stream, and SIGTERM with
//!    calls in flight answering them (the gateway stopped) before the streams close;
//! 4. standard output under load (requests pipelined, cards changing as Rust workers join, a call
//!    timing out, progress reported, `-vv` diagnostics): every line on standard output is one
//!    JSON-RPC message, every request is answered exactly once, and standard error carries every
//!    diagnostic and no frame;
//! 5. over attested TLS (the seed run with `--tls --require-attestation --channel-auth
//!    ATTESTED`): the Ruby SDK's call path of 2, with a Java action and a Rust action that share
//!    the name `research` (each named `research_<8 hex>`, the hex computed here by Ruby's
//!    `JSON.generate` and `Digest::SHA256`, as the Ruby gateway names them), the gateway's link
//!    to the seed attested.
//!
//! Each test passes with a note when `java`, the seed's build, or its client is unavailable,
//! unless `ASPACE_INTEROP_REQUIRED=1` (then each is a failure). Every process a test starts (the
//! seed, workers, gateways, drivers and the servers they spawn) is killed when the test ends,
//! also when it fails; every `aspace` runs with `HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, and
//! `TMPDIR` in a scratch directory.

#[macro_use]
mod support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};
use support::*;

/// The seed's schemas.
const TASK: &str = "ai.badmonkey.agentspaces.interop.Seed$Task#v1";
const RESULT: &str = "ai.badmonkey.agentspaces.interop.Seed$Result#v1";
/// The schemas of the Rust workers' actions.
const SHOUT: &str = "rust.Shout#v1";
const SHOUTED: &str = "rust.Shouted#v1";
/// The tokens of the token file.
const ANA: &str = "ana-research-token-0123456789";
const BOB: &str = "bob-other-token-0123456789";
/// The list-changed notification.
const LIST_CHANGED: &str = "notifications/tools/list_changed";

/// What a Rust worker runs per task: answers the topic shouted, after 4 s for a topic that
/// starts with `slow`.
const SHOUT_SCRIPT: &str = r#"read -r line
topic=$(printf '%s' "$line" | sed -n 's/.*"topic":"\([^"]*\)".*/\1/p')
case "$topic" in slow*) sleep 4;; esac
upper=$(printf '%s' "$topic" | tr '[:lower:]' '[:upper:]')
printf '{"topic":"%s","shouted":"%s","worker":"rust"}\n' "$topic" "$upper"
"#;

/// An `aspace work` worker of the seed's group, with a keystore of its own in `scratch`:
/// action `action`, taking `take`, producing [`SHOUTED`], answering with [`SHOUT_SCRIPT`].
fn rust_worker(
    scratch: &Scratch,
    seed: &JavaSeed,
    profile: &[&str],
    action: &str,
    take: &str,
) -> Running {
    let script = scratch.write(&format!("{action}.sh"), SHOUT_SCRIPT, 0o755);
    let mut command = with(aspace(scratch, &seed.seed(), FOUNDING), profile);
    command
        .args([
            "work",
            "--take",
            take,
            "--space",
            "tasks",
            "--produces",
            SHOUTED,
        ])
        .args(["--action", action, "--name", &format!("rust-{action}")])
        .args(["--description", "Shouts a topic in Rust", "--"])
        .arg("/bin/sh")
        .arg(&script);
    let mut worker = Running::spawn(command);
    worker.wait_err("working as");
    worker
}

/// Stops a worker with SIGTERM: exit 0. Answers its standard error.
fn stop(mut process: Running, what: &str) -> Vec<String> {
    process.signal("-TERM");
    let (code, _) = process.finish();
    assert_eq!(code, Some(0), "{what}: {:?}", process.seen_err);
    process.seen_err.clone()
}

/// The scratch directory's `aspace mcp` of the seed's group under `dev-local`.
fn gateway(scratch: &Scratch, seed: &JavaSeed, args: &[&str]) -> std::process::Command {
    let mut command = with(
        aspace(scratch, &seed.seed(), FOUNDING),
        &["--profile", "dev-local", "mcp"],
    );
    command.args(args);
    command
}

/// Connects, and checks the server is `aspace` with tools that change.
fn connect(driver: &mut Driver, op: Json) -> Json {
    let connected = driver.ok(op);
    let name = &connected["serverInfo"]["name"];
    assert_eq!(name, "aspace", "{}: {connected}", driver.name);
    assert_eq!(
        connected["capabilities"]["tools"]["listChanged"], true,
        "{}: {connected}",
        driver.name
    );
    connected
}

/// The structured result of a call result.
fn structured(result: &Json) -> &Json {
    &result["structuredContent"]
}

/// The common path of scenario 1: both actions listed and called, a Java agent bound later
/// heard and called. `follow` waits for `list_changed`.
fn list_call_and_follow(driver: &mut Driver, seed: &mut JavaSeed, tag: &str) {
    driver.wait_for_tools(&["research", "shout"]);
    let java_topic = format!("{tag}-java");
    let result = driver.call("research", json!({"topic": java_topic, "priority": 3}));
    let answer = structured(&result);
    assert_eq!(
        answer["summary"],
        format!("researched in java: {java_topic}")
    );
    assert_eq!(answer["worker"], format!("{}/researcher", seed.peer()));
    assert_eq!(
        result["_meta"]["ai.badmonkey.agentspaces/schema"], RESULT,
        "{result}"
    );
    let rust_topic = format!("{tag}-rust");
    let result = driver.call("shout", json!({"topic": rust_topic}));
    let answer = structured(&result);
    assert_eq!(answer["shouted"], rust_topic.to_uppercase(), "{result}");
    assert_eq!(answer["worker"], "rust");
    assert_eq!(
        result["_meta"]["ai.badmonkey.agentspaces/offering"],
        "shout"
    );
    // Java confirms the call it answered: its task was taken and completed by its agent.
    seed.wait_for("Java folds the research call's completion", |seed| {
        seed.ask(&format!("task-state {java_topic}"))["state"] == "completed"
    });

    // A Java agent with a new action binds: the client hears list_changed, then lists and calls
    // it.
    let heard_before = count_heard(driver);
    seed.ask("bind-reviewer reviewer");
    let heard = driver.ok(json!({
        "op": "await", "method": LIST_CHANGED, "after": heard_before, "timeoutMs": 30000,
    }));
    assert!(heard["timedOut"].is_null(), "{}: {heard}", driver.name);
    driver.wait_for_tools(&["research", "review", "shout"]);
    let topic = format!("{tag}-review");
    let result = driver.call("review", json!({"topic": topic, "priority": 1}));
    let answer = structured(&result);
    assert_eq!(answer["verdict"], format!("reviewed in java: {topic}"));
    assert_eq!(answer["reviewer"], format!("{}/reviewer", seed.peer()));
}

/// How many `list_changed` the client heard so far, every frame the server wrote before now
/// read first (the Ruby SDK reads the server's output only while a request waits: two pings
/// apart read what a refresh sent around the last answer).
fn count_heard(driver: &mut Driver) -> u64 {
    driver.ok(json!({"op": "ping"}));
    std::thread::sleep(Duration::from_millis(300));
    driver.ok(json!({"op": "ping"}));
    let answer = driver.ok(json!({
        "op": "await", "method": LIST_CHANGED, "after": 1_000_000, "timeoutMs": 0,
    }));
    answer["count"].as_u64().unwrap_or(0)
}

/// The stdio server's standard error: the gateway's notes, and no MCP frame.
fn assert_diagnostics_only(lines: &[String], what: &str) {
    assert!(
        lines.iter().any(|line| line.contains("serving")),
        "{what}: no serving note on standard error: {lines:?}"
    );
    for line in lines {
        let frame = serde_json::from_str::<Json>(line)
            .ok()
            .filter(|json| json.get("jsonrpc").is_some());
        assert!(
            frame.is_none(),
            "{what}: an MCP frame on standard error: {line}"
        );
    }
}

// ------------------------------------------------------------------------------ 1: TypeScript

#[test]
fn the_typescript_sdk_lists_calls_and_follows_the_fleet_over_stdio() {
    let classpath = classpath_or_skip!();
    let client = client_or_skip!(typescript_sdk());
    eprintln!("independent client: {}", client.name);
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    let workers = Scratch::new("ts-worker");
    let worker = rust_worker(&workers, &seed, &["--profile", "dev-local"], "shout", SHOUT);
    let scratch = Scratch::new("ts-stdio");
    let server = gateway(&scratch, &seed, &["--refresh", "500ms"]);
    let mut driver = Driver::stdio(&client, &server, &scratch);

    let connected = connect(&mut driver, json!({"op": "connect"}));
    let pid = connected["pid"].as_u64().expect("the server's pid");
    list_call_and_follow(&mut driver, &mut seed, "ts");

    // Every message the SDK read was JSON-RPC: its transport reported no error.
    let frames = driver.ok(json!({"op": "frames"}));
    assert_eq!(frames["errors"], json!([]), "{frames}");
    assert!(frames["delivered"].as_u64().unwrap_or(0) >= 6, "{frames}");
    let err = driver.server_stderr();
    assert_diagnostics_only(&err, &client.name);

    // The SDK closes with a call in flight (a 4 s task): standard input ends, the SDK's SIGTERM
    // (at 2 s) stops the gateway with exit 0 before its SIGKILL (at 4 s); the call answers
    // nothing, and its input stays in the fleet, where the worker completes it.
    driver.ok(json!({"op": "call", "name": "shout", "background": true,
        "arguments": {"input": {"topic": "slow-closing"}, "timeout": "30s"}}));
    std::thread::sleep(Duration::from_millis(800));
    let closed = driver.ok(json!({"op": "close"}));
    assert_eq!(closed["exit"], 0, "{closed}");
    assert!(closed["signal"].is_null(), "{closed}");
    assert!(
        closed["closeMs"].as_u64().unwrap_or(u64::MAX) < 4000,
        "{closed}"
    );
    // The call in flight was answered before the gateway went: a tool error saying so.
    let outcome = driver.ok(json!({"op": "outcome"}));
    let answer = &outcome["outcomes"][0];
    assert_eq!(answer["ok"], true, "{outcome}");
    assert_eq!(answer["result"]["isError"], true, "{outcome}");
    assert!(
        answer["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("the gateway stopped before the fleet answered")),
        "{outcome}"
    );
    assert!(
        !alive(u32::try_from(pid).unwrap_or(0)),
        "the gateway outlived its client"
    );
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());
    let err = stop(worker, "the Rust worker");
    assert!(
        err.iter()
            .any(|line| line.contains("stopped: 2 tasks completed, 0 failed")),
        "the worker completes the call it took and the one left in flight: {err:?}"
    );
}

// ------------------------------------------------------------------------------ 2: Ruby, Codex recipe

#[test]
fn the_ruby_sdk_runs_the_codex_recipe_and_follows_the_fleet() {
    let classpath = classpath_or_skip!();
    let client = client_or_skip!(ruby_sdk());
    eprintln!("independent client: {}", client.name);
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    let workers = Scratch::new("rb-worker");
    let worker = rust_worker(&workers, &seed, &["--profile", "dev-local"], "shout", SHOUT);

    // The fleet file in the default place, and the recipe's command line exactly:
    // `aspace` with `mcp`, nothing in the environment but HOME and the XDG directories.
    let scratch = Scratch::new("rb-codex");
    let config = scratch.path().join("xdg/agentspaces");
    std::fs::create_dir_all(&config).expect("the config directory");
    std::fs::write(
        config.join("fleet.yaml"),
        format!(
            "agentspaces:\n  keystore: ~/.config/agentspaces/keys\n  security:\n    profile: \
             dev-local\n  groups:\n    - name: interop-fleet\n      founding: {FOUNDING}\n      \
             seeds: [ \"{}\" ]\n      spaces: [ {{ name: tasks }} ]\n",
            seed.seed()
        ),
    )
    .expect("the fleet file");
    let server = with(bare_aspace(&scratch), &["mcp"]);
    let mut driver = Driver::stdio(&client, &server, &scratch);
    connect(&mut driver, json!({"op": "connect"}));
    list_call_and_follow(&mut driver, &mut seed, "rb");
    let frames = driver.ok(json!({"op": "frames"}));
    assert_eq!(frames["notJsonRpc"], json!([]), "{frames}");
    assert!(
        frames["notifications"]
            .as_array()
            .is_some_and(|all| all.iter().any(|method| method == LIST_CHANGED)),
        "{frames}"
    );
    // The gem closes (standard input, then SIGTERM after 2 s): the idle gateway is gone before.
    let closed = driver.ok(json!({"op": "close"}));
    assert_eq!(closed["exit"], 0, "{closed}");
    assert!(
        closed["closeMs"].as_u64().unwrap_or(u64::MAX) < 2000,
        "{closed}"
    );
    assert_diagnostics_only(&driver.server_stderr(), &client.name);
    assert!(
        driver
            .server_stderr()
            .iter()
            .any(|line| line.contains("stopped")),
        "{:?}",
        driver.server_stderr()
    );
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());

    // The recipe's keystore was made where the fleet file says, owner-only.
    let keys = scratch.path().join("home/.config/agentspaces/keys");
    assert_eq!(mode(&keys), 0o700, "the keystore directory");
    assert_eq!(mode(&keys.join("peer.key")), 0o600, "the private key");

    // The modern lifecycle (2026-07-28: `server/discover`, no `initialize`) through the same
    // recipe: the tools listed and a call answered.
    let mut driver = Driver::stdio(&client, &server, &scratch);
    let discovered = driver.ok(json!({"op": "connect", "mode": "auto"}));
    assert_eq!(discovered["protocolVersion"], "2026-07-28", "{discovered}");
    assert_eq!(discovered["serverInfo"]["name"], "aspace", "{discovered}");
    driver.wait_for_tools(&["research", "review", "shout"]);
    let result = driver.call("shout", json!({"topic": "modern"}));
    assert_eq!(structured(&result)["shouted"], "MODERN", "{result}");
    assert_eq!(driver.ok(json!({"op": "close"}))["exit"], 0);
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());
    stop(worker, "the Rust worker");
}

/// The permission bits of `path`.
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

// ------------------------------------------------------------------------------ 3: HTTP

/// Seconds since the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// Starts an HTTP gateway and answers it with its hello.
fn http_gateway(scratch: &Scratch, seed: &JavaSeed, args: &[&str]) -> (Running, Json) {
    let mut running = Running::spawn(gateway(scratch, seed, args));
    let hello = running
        .next_out(DEADLINE)
        .unwrap_or_else(|| panic!("no hello: {:?}", running.seen_err));
    (running, hello)
}

/// A refused connect or call: its HTTP status, and the challenge.
fn refused(answer: &Json, status: u64, what: &str) -> String {
    assert_eq!(answer["ok"], false, "{what}: {answer}");
    assert_eq!(answer["status"], status, "{what}: {answer}");
    answer["challenge"].as_str().unwrap_or_default().to_owned()
}

/// Stops an HTTP gateway with `signal`: exit 0, its port closed, the hello the only line on
/// standard output.
fn stop_http(mut gateway: Running, signal: &str, address: SocketAddr) {
    gateway.signal(signal);
    let (code, took) = gateway.finish();
    assert_eq!(code, Some(0), "{:?}", gateway.seen_err);
    assert!(took < Duration::from_secs(8), "took {took:?} to stop");
    assert_eq!(gateway.seen_out.len(), 1, "{:?}", gateway.seen_out);
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
        "the port is still open"
    );
}

#[test]
fn the_typescript_sdk_over_http_meets_tokens_scopes_origins_and_jwt() {
    let classpath = classpath_or_skip!();
    let client = client_or_skip!(typescript_sdk());
    eprintln!("independent client: {}", client.name);
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    let workers = Scratch::new("http-worker");
    let worker = rust_worker(&workers, &seed, &["--profile", "dev-local"], "shout", SHOUT);
    let scratch = Scratch::new("http-ts");
    let tokens = scratch.write(
        "tokens.yaml",
        &format!(
            "tokens:\n  - token: {ANA}\n    principal: ana\n    scopes: [research]\n  \
             - token: {BOB}\n    principal: bob\n    scopes: [other]\n"
        ),
        0o600,
    );
    let policy = scratch.write(
        "policy.yaml",
        "scopes:\n  research: [research, review]\n  other: [nothing]\n",
        0o644,
    );
    let path = |path: &std::path::Path| path.display().to_string();

    // The team gateway: --http, --tokens, --only (and a policy).
    let bind = format!("127.0.0.1:{}", free_port());
    let address: SocketAddr = bind.parse().expect("an address");
    let (gateway, hello) = http_gateway(
        &scratch,
        &seed,
        &[
            "--http",
            &bind,
            "--tokens",
            &path(&tokens),
            "--only",
            "research",
            "--only",
            "shout",
            "--policy",
            &path(&policy),
        ],
    );
    let url = format!("http://{bind}/mcp");
    assert_eq!(hello["mcp"], url.as_str(), "{hello}");
    let mut driver = Driver::http(&client, &url, &scratch);

    // 401 without a token, and with one the file does not hold (never echoed); 403 for a browser
    // Origin not allowed, even with a good token.
    let challenge = refused(&driver.op(json!({"op": "connect"})), 401, "no token");
    assert_eq!(challenge, "Bearer realm=\"agentspaces\"");
    let answer = driver
        .op(json!({"op": "connect", "headers": {"Authorization": "Bearer not-a-known-token"}}));
    let challenge = refused(&answer, 401, "an unknown token");
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(
        !answer.to_string().contains("not-a-known-token"),
        "{answer}"
    );
    let answer = driver.op(json!({"op": "connect", "headers": {
        "Authorization": format!("Bearer {ANA}"), "Origin": "https://evil.example"}}));
    refused(&answer, 403, "a foreign Origin");

    // 200 in scope: Java answers.
    connect(
        &mut driver,
        json!({"op": "connect", "headers": {"Authorization": format!("Bearer {ANA}")}}),
    );
    driver.wait_for_tools(&["research", "shout"]);
    let result = driver.call("research", json!({"topic": "http-ts", "priority": 2}));
    assert_eq!(
        structured(&result)["summary"],
        "researched in java: http-ts"
    );

    // 403 out of scope: no scope of ana's allows shout, and none names it in the challenge.
    let answer = driver.op(json!({"op": "call", "name": "shout",
        "arguments": {"input": {"topic": "http-forbidden"}}}));
    let challenge = refused(&answer, 403, "shout for ana");
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    // bob's scope does not allow research: 403 naming the scope that would, the input never
    // written (Java never sees the task).
    driver.ok(json!({"op": "terminate"}));
    connect(
        &mut driver,
        json!({"op": "connect", "headers": {"Authorization": format!("Bearer {BOB}")}}),
    );
    let answer = driver.op(json!({"op": "call", "name": "research",
        "arguments": {"input": {"topic": "bob-forbidden", "priority": 1}}}));
    let challenge = refused(&answer, 403, "research for bob");
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(challenge.contains("scope=\"research\""), "{challenge}");
    let states = seed.ask("task-states");
    assert!(!states.to_string().contains("bob-forbidden"), "{states}");
    driver.ok(json!({"op": "terminate"}));
    stop_http(gateway, "-INT", address);

    // A JWT-protected gateway: the client made the key pair and signs the tokens (RS256).
    let jwks = scratch.path().join("jwks.json");
    driver.ok(json!({"op": "jwks", "path": path(&jwks)}));
    let token = |driver: &mut Driver, claims: Json| -> String {
        driver.ok(json!({"op": "jwt", "claims": claims}))["token"]
            .as_str()
            .expect("a token")
            .to_owned()
    };
    let issued = |subject: &str, scope: &str, audience: &str, expires: i64| {
        json!({"iss": "https://auth.test/", "aud": audience, "sub": subject, "scope": scope,
               "iat": now(), "exp": expires})
    };
    let carol = token(
        &mut driver,
        issued("carol", "research", "fleet", now() + 600),
    );
    let dave = token(&mut driver, issued("dave", "other", "fleet", now() + 600));
    let expired = token(
        &mut driver,
        issued("carol", "research", "fleet", now() - 3600),
    );
    let elsewhere = token(
        &mut driver,
        issued("carol", "research", "another", now() + 600),
    );
    // A token of another key pair under the same key id: its signature fails.
    driver.ok(json!({"op": "jwks", "path": path(&scratch.path().join("other-jwks.json"))}));
    let forged = token(
        &mut driver,
        issued("carol", "research", "fleet", now() + 600),
    );
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());
    let bind = format!("127.0.0.1:{}", free_port());
    let address: SocketAddr = bind.parse().expect("an address");
    let (gateway, hello) = http_gateway(
        &scratch,
        &seed,
        &[
            "--http",
            &bind,
            "--jwt-issuer",
            "https://auth.test/",
            "--jwt-audience",
            "fleet",
            "--jwks",
            &path(&jwks),
            "--policy",
            &path(&policy),
            "--refresh",
            "500ms",
        ],
    );
    let url = format!("http://{bind}/mcp");
    assert_eq!(hello["mcp"], url.as_str(), "{hello}");
    let mut driver = Driver::http(&client, &url, &scratch);
    let bearer = |token: &str| json!({"op": "connect", "headers": {"Authorization": format!("Bearer {token}")}});
    for (token, why, what) in [
        (&expired, "expired", "an expired token"),
        (&elsewhere, "not for this server", "another audience"),
        (&forged, "invalid_token", "another key"),
    ] {
        let challenge = refused(&driver.op(bearer(token)), 401, what);
        assert!(challenge.contains(why), "{what}: {challenge}");
    }
    connect(&mut driver, bearer(&carol));
    driver.wait_for_tools(&["research", "shout"]);
    let result = driver.call("research", json!({"topic": "jwt-ts", "priority": 2}));
    assert_eq!(structured(&result)["summary"], "researched in java: jwt-ts");
    let answer = driver.op(json!({"op": "call", "name": "shout",
        "arguments": {"input": {"topic": "jwt-forbidden"}}}));
    refused(&answer, 403, "shout for carol");

    // list_changed on the session's SSE stream: a Java agent with a new action binds (one that
    // takes 1.5 s per draft).
    let before = count_heard(&mut driver);
    seed.ask("bind-reviewer reviewer 1500");
    let heard = driver
        .ok(json!({"op": "await", "method": LIST_CHANGED, "after": before, "timeoutMs": 30000}));
    assert!(heard["timedOut"].is_null(), "{heard}");
    assert_eq!(driver.tool_names(), ["research", "review", "shout"]);
    let result = driver.call("review", json!({"topic": "jwt-review", "priority": 1}));
    assert_eq!(
        structured(&result)["verdict"],
        "reviewed in java: jwt-review"
    );

    // dave's scope allows nothing.
    connect(&mut driver, bearer(&dave));
    let answer = driver.op(json!({"op": "call", "name": "research",
        "arguments": {"input": {"topic": "dave-forbidden", "priority": 1}}}));
    let challenge = refused(&answer, 403, "research for dave");
    assert!(challenge.contains("scope=\"research\""), "{challenge}");

    // SIGTERM with two calls in flight (the reviewer takes 1.5 s each): each is answered on its
    // stream that the gateway stopped, rather than left to the client's own request timeout.
    connect(&mut driver, bearer(&carol));
    for i in 0..2 {
        driver.ok(json!({"op": "call", "name": "review", "background": true,
            "arguments": {"input": {"topic": format!("jwt-in-flight-{i}"), "priority": 1}, "timeout": "60s"}}));
    }
    std::thread::sleep(Duration::from_millis(500));
    stop_http(gateway, "-TERM", address);
    let outcome = driver.ok(json!({"op": "outcome"}));
    let outcomes = outcome["outcomes"].as_array().cloned().unwrap_or_default();
    assert_eq!(outcomes.len(), 2, "{outcome}");
    for answer in &outcomes {
        assert_eq!(answer["ok"], true, "every call is answered: {outcome}");
        assert_eq!(answer["result"]["isError"], true, "{outcome}");
        assert!(
            answer["result"]["content"][0]["text"].as_str().is_some_and(
                |text| text.starts_with("the gateway stopped before the fleet answered")
            ),
            "{outcome}"
        );
        assert!(
            answer["callMs"].as_u64().unwrap_or(u64::MAX) < 10_000,
            "{outcome}"
        );
    }
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());
    stop(worker, "the Rust worker");
}

// ------------------------------------------------------------------------------ 4: stdout under load

/// A JSON-RPC request line.
fn request(id: u64, method: &str, params: Json) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// A tools/call request line, reporting progress under `token` when given.
fn tool_call(id: u64, name: &str, input: Json, timeout: &str, token: Option<&str>) -> String {
    let mut params = json!({"name": name, "arguments": {"input": input, "timeout": timeout}});
    if let Some(token) = token {
        params["_meta"] = json!({"progressToken": token});
    }
    request(id, "tools/call", params)
}

/// Sends `line`, a request with `id`, which must be answered.
fn send(gateway: &mut Running, line: String, id: u64, expected: &mut Vec<u64>) {
    gateway.send(&line);
    expected.push(id);
}

/// What a stdio gateway wrote on standard output, read as it comes: the answers by id (each
/// counted), and the notifications by method.
#[derive(Default)]
struct Seen {
    answers: BTreeMap<u64, Json>,
    repeats: Vec<u64>,
    notifications: BTreeMap<String, usize>,
}

impl Seen {
    /// Reads standard output until `done` holds, within `wait`; every line must be one JSON-RPC
    /// 2.0 message.
    fn read_until(
        &mut self,
        gateway: &mut Running,
        wait: Duration,
        what: &str,
        done: impl Fn(&Seen) -> bool,
    ) {
        let deadline = Instant::now() + wait;
        while !done(self) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                gateway.drain_err();
                panic!(
                    "{what}: not within {wait:?}; answers {:?}, notifications {:?}\nstderr tail: {:?}",
                    self.answers.keys().collect::<Vec<_>>(),
                    self.notifications,
                    gateway.seen_err.iter().rev().take(20).collect::<Vec<_>>()
                );
            };
            let Some(message) = gateway.next_out(left) else {
                continue;
            };
            assert_eq!(
                message["jsonrpc"], "2.0",
                "not JSON-RPC 2.0 on stdout: {message}"
            );
            match (message.get("id"), message.get("method")) {
                (Some(id), None) => {
                    assert!(
                        message.get("result").is_some() != message.get("error").is_some(),
                        "a response with neither or both of result and error: {message}"
                    );
                    let id = id
                        .as_u64()
                        .unwrap_or_else(|| panic!("an id that is not ours: {message}"));
                    if self.answers.insert(id, message).is_some() {
                        self.repeats.push(id);
                    }
                }
                (None, Some(method)) => {
                    let method = method.as_str().unwrap_or_default().to_owned();
                    *self.notifications.entry(method).or_default() += 1;
                }
                _ => panic!("neither a response nor a notification on stdout: {message}"),
            }
        }
    }

    fn heard(&self, method: &str) -> usize {
        self.notifications.get(method).copied().unwrap_or(0)
    }
}

/// How many research calls the loaded gateway waits on at once.
const RESEARCH_CALLS: u64 = 12;

#[test]
fn standard_output_carries_only_mcp_frames_under_load() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    seed.ask("bind-reviewer slow-reviewer 4000");
    let scratch = Scratch::new("load");
    let mut gateway = Running::spawn(with(
        aspace(&scratch, &seed.seed(), FOUNDING),
        &["--profile", "dev-local", "-vv", "mcp", "--refresh", "200ms"],
    ));
    gateway.wait_err("serving");
    let mut seen = Seen::default();
    gateway.send(&request(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "aspace-load-test", "version": "1"}}),
    ));
    seen.read_until(&mut gateway, DEADLINE, "the initialize answer", |seen| {
        seen.answers.contains_key(&1)
    });
    gateway.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());

    // Pipelined: twelve research calls reporting progress, a review call that times out (1 s
    // against a 4 s reviewer), a review call that waits it out reporting progress, pings, and
    // lists; nothing waits for an answer before the next is sent.
    let mut expected: Vec<u64> = Vec::new();
    let mut next = 10_u64;
    for i in 0..RESEARCH_CALLS {
        let id = next;
        next += 1;
        let input = json!({"topic": format!("load-{i}"), "priority": i});
        send(
            &mut gateway,
            tool_call(id, "research", input, "20s", Some(&format!("p{id}"))),
            id,
            &mut expected,
        );
    }
    let timing_out = next;
    next += 1;
    send(
        &mut gateway,
        tool_call(
            timing_out,
            "review",
            json!({"topic": "slow-timeout", "priority": 1}),
            "1s",
            None,
        ),
        timing_out,
        &mut expected,
    );
    let waiting = next;
    next += 1;
    send(
        &mut gateway,
        tool_call(
            waiting,
            "review",
            json!({"topic": "slow-waited", "priority": 1}),
            "30s",
            Some("slow"),
        ),
        waiting,
        &mut expected,
    );
    for _ in 0..100 {
        let id = next;
        next += 1;
        send(
            &mut gateway,
            request(id, "ping", json!({})),
            id,
            &mut expected,
        );
    }
    for _ in 0..20 {
        let id = next;
        next += 1;
        send(
            &mut gateway,
            request(id, "tools/list", json!({})),
            id,
            &mut expected,
        );
    }

    // Cards change while the calls wait: two Rust workers with new actions join.
    let workers = Scratch::new("load-workers");
    let shout = rust_worker(&workers, &seed, &["--profile", "dev-local"], "shout", SHOUT);
    let echoes = Scratch::new("load-echo");
    let echo = rust_worker(
        &echoes,
        &seed,
        &["--profile", "dev-local"],
        "echo",
        "rust.Echo#v1",
    );
    seen.read_until(
        &mut gateway,
        Duration::from_secs(45),
        "the pipelined answers and the list changes",
        |seen| {
            expected.iter().all(|id| seen.answers.contains_key(id))
                && seen.heard("notifications/tools/list_changed") >= 1
        },
    );
    // The new tools are listed and called, with more pings between.
    let deadline = Instant::now() + DEADLINE;
    loop {
        let id = next;
        next += 1;
        gateway.send(&request(id, "tools/list", json!({})));
        seen.read_until(&mut gateway, DEADLINE, "a tools/list answer", |seen| {
            seen.answers.contains_key(&id)
        });
        let names: Vec<&str> = seen.answers[&id]["result"]["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["name"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        if names == ["echo", "research", "review", "shout"] {
            break;
        }
        assert!(Instant::now() < deadline, "the tools are {names:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut late = Vec::new();
    for (name, schema_topic) in [("shout", "load-shout"), ("echo", "load-echo")] {
        let id = next;
        next += 1;
        gateway.send(&tool_call(
            id,
            name,
            json!({"topic": schema_topic}),
            "20s",
            None,
        ));
        gateway.send(&request(next, "ping", json!({})));
        late.push(id);
        late.push(next);
        next += 1;
    }
    seen.read_until(
        &mut gateway,
        DEADLINE,
        "the calls of the new tools",
        |seen| late.iter().all(|id| seen.answers.contains_key(id)),
    );

    // Every request answered exactly once, as it should be.
    assert!(
        seen.repeats.is_empty(),
        "answered twice: {:?}",
        seen.repeats
    );
    for i in 0..RESEARCH_CALLS {
        let answer = &seen.answers[&(10 + i)]["result"];
        assert_eq!(answer["isError"], false, "{answer}");
        assert_eq!(
            answer["structuredContent"]["summary"],
            format!("researched in java: load-{i}")
        );
    }
    let timed_out = &seen.answers[&timing_out]["result"];
    assert_eq!(timed_out["isError"], true, "{timed_out}");
    assert!(timed_out.to_string().contains("within 1s"), "{timed_out}");
    let waited = &seen.answers[&waiting]["result"];
    assert_eq!(waited["isError"], false, "{waited}");
    assert_eq!(
        waited["structuredContent"]["verdict"],
        "reviewed in java: slow-waited"
    );
    assert!(
        seen.heard("notifications/progress") >= 1,
        "{:?}",
        seen.notifications
    );
    for (id, field, value) in [
        (late[0], "shouted", "LOAD-SHOUT"),
        (late[2], "shouted", "LOAD-ECHO"),
    ] {
        let answer = &seen.answers[&id]["result"];
        assert_eq!(answer["structuredContent"][field], value, "{answer}");
    }
    assert_eq!(
        seen.notifications
            .keys()
            .filter(|method| !matches!(
                method.as_str(),
                "notifications/progress" | "notifications/tools/list_changed"
            ))
            .count(),
        0,
        "{:?}",
        seen.notifications
    );

    // The client leaves: exit 0. Standard error held the diagnostics (debug lines from -vv) and
    // no MCP frame.
    gateway.close_stdin();
    let (code, _) = gateway.finish();
    assert_eq!(code, Some(0), "{:?}", gateway.seen_err);
    for line in &gateway.seen_out {
        let message: Json =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON on stdout: {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "{line}");
    }
    assert!(
        gateway.seen_err.iter().any(|line| line.contains("DEBUG")),
        "no debug diagnostics on standard error"
    );
    assert_diagnostics_only(&gateway.seen_err, "the loaded gateway");
    eprintln!(
        "under load: {} lines on stdout ({} answers, notifications {:?}), {} lines on stderr",
        gateway.seen_out.len(),
        seen.answers.len(),
        seen.notifications,
        gateway.seen_err.len()
    );
    stop(shout, "the shout worker");
    stop(echo, "the echo worker");
}

// ------------------------------------------------------------------------------ 5: attested TLS

#[test]
fn attested_tls_carries_the_ruby_sdk_call_path() {
    let classpath = classpath_or_skip!();
    let client = client_or_skip!(ruby_sdk());
    eprintln!("independent client: {}", client.name);
    let mut seed = JavaSeed::start_with(
        &classpath,
        &[
            "--tls",
            "--require-attestation",
            "--channel-auth",
            "ATTESTED",
        ],
    );
    assert!(seed.seed().starts_with("tls://"), "{}", seed.seed());
    seed.ask("bind-agent researcher");
    // A Rust action that shares the Java action's name (default profile: mtls).
    let workers = Scratch::new("tls-worker");
    let worker = rust_worker(&workers, &seed, &[], "research", "rust.Research#v1");

    // The names the Ruby gateway gives the two: name_<8 hex of SHA-256 of the JSON array>.
    let named = |consumes: &str, produces: &str| -> String {
        let code = format!(
            "require 'json'; require 'digest'; \
             print 'research_' + Digest::SHA256.hexdigest(JSON.generate(\
             ['research', '{consumes}', '{produces}', 'tasks']))[0, 8]"
        );
        client.eval(&code)
    };
    let java = named(TASK, RESULT);
    let rust = named("rust.Research#v1", SHOUTED);
    let mut expected = [java.clone(), rust.clone()];
    expected.sort();

    let scratch = Scratch::new("tls-rb");
    let id = visit(with(aspace(&scratch, &seed.seed(), FOUNDING), &["id"]));
    let me: Json = serde_json::from_slice(&id.stdout).expect("the id");
    let me = me["peerId"].as_str().expect("a PeerID").to_owned();
    let server = with(
        aspace(&scratch, &seed.seed(), FOUNDING),
        &["mcp", "--refresh", "500ms"],
    );
    let mut driver = Driver::stdio(&client, &server, &scratch);
    connect(&mut driver, json!({"op": "connect"}));
    let names: Vec<&str> = expected.iter().map(String::as_str).collect();
    driver.wait_for_tools(&names);

    let result = driver.call(&java, json!({"topic": "tls-java", "priority": 2}));
    assert_eq!(
        structured(&result)["summary"],
        "researched in java: tls-java"
    );
    assert_eq!(
        structured(&result)["worker"],
        format!("{}/researcher", seed.peer())
    );
    let result = driver.call(&rust, json!({"topic": "tls-rust"}));
    assert_eq!(structured(&result)["shouted"], "TLS-RUST", "{result}");

    // The gateway's link to the seed is TLS, its channel attested.
    let links = seed.ask("links");
    let link = links["links"]
        .as_array()
        .and_then(|links| {
            links
                .iter()
                .find(|link| link["peer"] == me.as_str())
                .cloned()
        })
        .unwrap_or_else(|| panic!("no link of the gateway {me}: {links}"));
    assert_eq!(link["scheme"], "tls", "{link}");
    assert_eq!(link["mode"], "attested", "{link}");

    // A Java agent with a new action binds over the same channel.
    let before = count_heard(&mut driver);
    seed.ask("bind-reviewer reviewer");
    let heard = driver
        .ok(json!({"op": "await", "method": LIST_CHANGED, "after": before, "timeoutMs": 30000}));
    assert!(heard["timedOut"].is_null(), "{heard}");
    let mut with_review = [java.clone(), rust.clone(), "review".to_owned()];
    with_review.sort();
    assert_eq!(driver.tool_names(), with_review);
    let result = driver.call("review", json!({"topic": "tls-review", "priority": 1}));
    assert_eq!(
        structured(&result)["verdict"],
        "reviewed in java: tls-review"
    );
    let frames = driver.ok(json!({"op": "frames"}));
    assert_eq!(frames["notJsonRpc"], json!([]), "{frames}");
    assert_eq!(driver.ok(json!({"op": "close"}))["exit"], 0);
    assert_diagnostics_only(&driver.server_stderr(), &client.name);
    assert_eq!(driver.finish(), Some(0), "{}", driver.driver_err());
    stop(worker, "the Rust worker");
}
