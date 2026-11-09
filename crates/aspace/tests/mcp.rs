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

//! `aspace mcp`, and what `status`
//! and `doctor` say of the daemon socket and the gateway's files.
//!
//! Without a fleet (always run):
//!
//! 1. `aspace mcp --help` carries examples and the recipes of the MCP hosts;
//! 2. what the gateway cannot serve is refused before it joins, with the contract's exit codes:
//!    HTTP without a token verifier (2), a token file others may read (4, also through
//!    `ASPACE_MCP_TOKENS`), a policy file others may write (4), a token or policy file that is
//!    not one (2, never echoing a token), an origin that is not one (2), a JWT key set it cannot
//!    use (2), and HTTP options without `--http` (2); a gateway that passes its checks and then
//!    cannot join prints nothing on standard output;
//! 3. `aspace doctor` reports the daemon socket's directory (failing one others may write) and
//!    the token and policy files (failing unsafe modes), naming principals and scopes but never
//!    a token.
//!
//! Against the scripted Java seed (`interop/java-seed`; each test passes with a note when `java`
//! or the build is unavailable, unless `ASPACE_INTEROP_REQUIRED=1`):
//!
//! 4. over standard input and output the gateway answers `initialize`, lists no tool, tells the
//!    client `notifications/tools/list_changed` once a Java agent binds, lists it, calls it (Java
//!    answering), refuses an unknown tool with the protocol error -32602, marks its keystore as
//!    `aspace mcp`, writes nothing but JSON-RPC on standard output, and exits 0 when the client
//!    closes standard input;
//! 5. `--only` limits what it offers, and SIGTERM stops it with exit 0;
//! 6. over HTTP with a token file and a policy file, through `aspace`: the
//!    hello on standard output, 401 without a token and with a bad one, 200 and a Java result in
//!    scope, 403 `insufficient_scope` outside it, 403 for a foreign Origin; SIGINT stops it with
//!    exit 0 and closes the port;
//! 7. `aspace status` reports the daemon (none; one used; one not used, and why) and the MCP
//!    settings of the visitor's environment, in JSON and in text.
//!
//! Every process a test starts is killed when the test ends, also when it fails.

#[macro_use]
mod support;

use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value as Json, json};
use support::*;

/// The MCP protocol version the tests speak.
const PROTOCOL: &str = "2025-06-18";
/// The tokens of the token files.
const ANA: &str = "ana-research-token-0123456789";
const BOB: &str = "bob-other-token-0123456789";

/// A token file of ana (scope `research`) and bob (scope `other`).
fn token_file(scratch: &Scratch, mode: u32) -> std::path::PathBuf {
    scratch.write(
        "tokens.yaml",
        &format!(
            "tokens:\n  - token: {ANA}\n    principal: ana\n    scopes: [research]\n  \
             - token: {BOB}\n    principal: bob\n    scopes: [other]\n"
        ),
        mode,
    )
}

/// A policy letting `research` invoke the research tools, and `other` only `nothing`.
fn policy_file(scratch: &Scratch, mode: u32) -> std::path::PathBuf {
    scratch.write(
        "policy.yaml",
        "scopes:\n  research: [\"research*\"]\n  other: [nothing]\n",
        mode,
    )
}

fn initialize(id: i64) -> Json {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "aspace-mcp-test", "version": "1"},
        },
    })
}

/// Sends a request to a stdio gateway and answers its response.
fn request(gateway: &mut Running, id: i64, method: &str, params: Json) -> Json {
    gateway
        .send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
    gateway.out_until(&format!("the answer to {method} ({id})"), |message| {
        message["id"] == id
    })
}

/// The tool names of a `tools/list` answer.
fn names(listed: &Json) -> Vec<String> {
    listed["result"]["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Every line a stdio gateway wrote on standard output is a JSON-RPC 2.0 message.
fn assert_only_json_rpc(lines: &[String]) {
    for line in lines {
        let message: Json =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON on stdout: {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "not JSON-RPC on stdout: {line}");
    }
}

// ------------------------------------------------------------------------------ without a fleet

#[test]
fn mcp_help_carries_examples_and_host_recipes() {
    let scratch = Scratch::new("help");
    let output = visit(with(bare_aspace(&scratch), &["mcp", "--help"]));
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    for part in [
        "Examples:",
        "aspace mcp --http 127.0.0.1:8740 --tokens",
        "[mcp_servers.fleet]",
        "\"mcpServers\"",
        "context_servers",
        "type: stdio, cmd: aspace",
        "--allow-unauthenticated",
        "--policy",
        "--only",
        "standard output carries only the MCP stream",
    ] {
        assert!(
            help.contains(part),
            "{part:?} missing from mcp --help:\n{help}"
        );
    }
}

#[test]
fn the_gateway_refuses_what_it_cannot_serve_before_joining() {
    let scratch = Scratch::new("refusals");
    let closed = format!("tcp://127.0.0.1:{}", free_port());
    let good_tokens = token_file(&scratch, 0o600);
    let readable_tokens = scratch.write(
        "readable.yaml",
        &format!("- token: {ANA}\n  principal: ana\n"),
        0o644,
    );
    let broken_tokens = scratch.write(
        "broken.yaml",
        "tokens:\n  - tokn: s3cr3t-value-0123456789\n    principal: ana\n",
        0o600,
    );
    let good_policy = policy_file(&scratch, 0o644);
    let writable_policy = scratch.write("writable.yaml", "scopes: {a: [x]}\n", 0o666);
    let broken_policy = scratch.write("not-a-policy.yaml", "scope: {a: [x]}\n", 0o600);
    let path = |path: &std::path::Path| path.display().to_string();
    let gateway = || {
        with(
            aspace(&scratch, &closed, FOUNDING),
            &["--profile", "dev-local", "--join-timeout", "1s", "mcp"],
        )
    };
    let refused = |mut command: Command, args: &[&str], code: i32, mentions: &[&str]| {
        command.args(args);
        let started = Instant::now();
        let output = visit(command);
        let err = stderr(&output);
        assert_eq!(output.status.code(), Some(code), "{args:?}: {err}");
        for part in mentions {
            assert!(err.contains(part), "{args:?}: {part:?} missing from: {err}");
        }
        assert!(
            !err.contains("join") && !err.contains("seed"),
            "{args:?}: refused only after trying to join: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{args:?}: refused slowly"
        );
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(!err.contains("s3cr3t"), "a token value in an error: {err}");
    };
    refused(
        gateway(),
        &["--http", "127.0.0.1:0"],
        2,
        &["token verifier", "--tokens", "--allow-unauthenticated"],
    );
    refused(
        gateway(),
        &["--http", "127.0.0.1:0", "--tokens", &path(&readable_tokens)],
        4,
        &["readable by group or others", "chmod 600"],
    );
    let mut through_variable = gateway();
    through_variable.env("ASPACE_MCP_TOKENS", &readable_tokens);
    refused(
        through_variable,
        &["--http", "127.0.0.1:0"],
        4,
        &["chmod 600"],
    );
    refused(
        gateway(),
        &["--http", "127.0.0.1:0", "--tokens", &path(&broken_tokens)],
        2,
        &["record 0", "unknown field \"tokn\""],
    );
    refused(
        gateway(),
        &["--policy", &path(&writable_policy)],
        4,
        &["writable by group or others", "chmod go-w"],
    );
    let mut policy_variable = gateway();
    policy_variable.env("ASPACE_MCP_POLICY", &broken_policy);
    refused(
        policy_variable,
        &[],
        2,
        &["policy file", "unknown key \"scope\""],
    );
    refused(
        gateway(),
        &[
            "--http",
            "127.0.0.1:0",
            "--tokens",
            &path(&good_tokens),
            "--origin",
            "not an origin",
        ],
        2,
        &["is not an origin"],
    );
    refused(
        gateway(),
        &[
            "--http",
            "127.0.0.1:0",
            "--jwt-issuer",
            "https://auth.example.com/",
            "--jwt-audience",
            "fleet",
            "--jwks",
            "/nonexistent/asm-jwks.json",
        ],
        2,
        &["JWT verifier"],
    );
    // A key set file others may write decides who may sign tokens: refused as a
    // policy file they may write is (exit 4).
    let writable_jwks = scratch.write(
        "jwks.json",
        r#"{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k", "alg": "EdDSA"}]}"#,
        0o666,
    );
    refused(
        gateway(),
        &[
            "--http",
            "127.0.0.1:0",
            "--jwt-issuer",
            "https://auth.example.com/",
            "--jwt-audience",
            "fleet",
            "--jwks",
            &path(&writable_jwks),
        ],
        4,
        &["writable by group or others", "chmod go-w"],
    );
    refused(
        gateway(),
        &[
            "--http",
            "127.0.0.1:0",
            "--jwt-issuer",
            "https://auth.example.com/",
            "--jwt-audience",
            "fleet",
            "--jwks",
            "http://auth.example.com/jwks.json",
        ],
        2,
        &["JWT verifier"],
    );
    refused(
        gateway(),
        &["--tokens", &path(&good_tokens)],
        2,
        &["--http"],
    );

    // Checks passed: the join is what fails, and standard output stays empty (a stdio client
    // reads it), under stdio and HTTP alike.
    for args in [
        vec!["--policy".to_owned(), path(&good_policy)],
        vec![
            "--http".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--tokens".to_owned(),
            path(&good_tokens),
            "--policy".to_owned(),
            path(&good_policy),
        ],
    ] {
        let mut command = gateway();
        command.args(&args);
        let output = visit(command);
        let err = stderr(&output);
        assert!(
            matches!(output.status.code(), Some(1 | 3)),
            "{args:?}: {output:?}"
        );
        assert!(
            err.contains("seed") || err.contains("join"),
            "{args:?}: {err}"
        );
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn doctor_checks_the_daemon_socket_and_the_gateways_files() {
    let scratch = Scratch::new("doctor");
    let closed = format!("tcp://127.0.0.1:{}", free_port());
    let tokens = token_file(&scratch, 0o600);
    let policy = policy_file(&scratch, 0o644);
    let doctor = |extra: &[&str], variables: &[(&str, &std::path::Path)]| -> Json {
        let mut command = with(
            aspace(&scratch, &closed, FOUNDING),
            &["--profile", "dev-local", "doctor", "--json"],
        );
        command.args(extra);
        for (name, value) in variables {
            command.env(name, value);
        }
        let output = visit(command);
        assert_eq!(
            output.status.code(),
            Some(1),
            "the closed seed fails: {output:?}"
        );
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            !text.contains(ANA) && !text.contains(BOB),
            "a token in: {text}"
        );
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("not JSON: {text}"))
    };
    let check = |report: &Json, name: &str| -> (Json, String) {
        let found = report["checks"]
            .as_array()
            .and_then(|checks| checks.iter().find(|check| check["check"] == name))
            .unwrap_or_else(|| panic!("no {name} check: {report}"));
        (
            found["ok"].clone(),
            found["detail"].as_str().unwrap_or_default().to_owned(),
        )
    };

    // Nothing named, no daemon: skipped and passed.
    let report = doctor(&[], &[]);
    let (ok, detail) = check(&report, "daemon");
    assert_eq!(ok, true, "{detail}");
    assert!(detail.contains("no daemon"), "{detail}");
    assert!(
        detail.contains(
            &scratch
                .path()
                .join("run/aspace/daemon.sock")
                .display()
                .to_string()
        ),
        "{detail}"
    );
    assert_eq!(check(&report, "mcp.tokens").0, Json::Null);
    assert_eq!(check(&report, "mcp.policy").0, Json::Null);

    // The files, by flag and by variable: principals and scopes, never a token.
    let report = doctor(
        &["--tokens", &tokens.display().to_string()],
        &[("ASPACE_MCP_POLICY", &policy)],
    );
    let (ok, detail) = check(&report, "mcp.tokens");
    assert_eq!(ok, true, "{detail}");
    for part in ["--tokens", "mode 0600", "2 tokens for ana, bob"] {
        assert!(detail.contains(part), "{part:?} missing from: {detail}");
    }
    let (ok, detail) = check(&report, "mcp.policy");
    assert_eq!(ok, true, "{detail}");
    for part in [
        "ASPACE_MCP_POLICY",
        "mode 0644",
        "2 scopes (research, other)",
    ] {
        assert!(detail.contains(part), "{part:?} missing from: {detail}");
    }

    // Unsafe modes fail, and so does a socket directory others may write.
    chmod(&tokens, 0o640);
    chmod(&policy, 0o620);
    let socket_dir = scratch.path().join("run/aspace");
    std::fs::create_dir_all(&socket_dir).expect("socket directory");
    chmod(&socket_dir, 0o777);
    let report = doctor(
        &[
            "--tokens",
            &tokens.display().to_string(),
            "--policy",
            &policy.display().to_string(),
        ],
        &[],
    );
    let (ok, detail) = check(&report, "mcp.tokens");
    assert_eq!(ok, false, "{detail}");
    assert!(detail.contains("chmod 600"), "{detail}");
    let (ok, detail) = check(&report, "mcp.policy");
    assert_eq!(ok, false, "{detail}");
    assert!(detail.contains("chmod go-w"), "{detail}");
    let (ok, detail) = check(&report, "daemon");
    assert_eq!(ok, false, "{detail}");
    assert!(detail.contains("chmod 700"), "{detail}");
}

// ------------------------------------------------------------------------------ against Java

/// A stdio gateway of the seed's group, started.
fn stdio_gateway(scratch: &Scratch, seed: &JavaSeed, args: &[&str]) -> Running {
    let mut command = with(
        aspace(scratch, &seed.seed(), FOUNDING),
        &["--profile", "dev-local", "mcp", "--refresh", "500ms"],
    );
    command.args(args);
    Running::spawn(command)
}

/// Initializes a stdio session: the server is `aspace`, with tools that change.
fn open_stdio(gateway: &mut Running) {
    let answer = request(gateway, 1, "initialize", initialize(1)["params"].clone());
    let result = &answer["result"];
    assert_eq!(result["serverInfo"]["name"], "aspace", "{answer}");
    assert_eq!(
        result["capabilities"]["tools"]["listChanged"], true,
        "{answer}"
    );
    gateway.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
}

#[test]
fn the_stdio_gateway_lists_calls_and_follows_the_fleet() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("stdio");
    let mut gateway = stdio_gateway(&scratch, &seed, &[]);
    gateway.wait_err("serving 0 tools");
    open_stdio(&mut gateway);
    assert!(names(&request(&mut gateway, 2, "tools/list", json!({}))).is_empty());

    // The gateway marks its keystore as a resident's.
    let marker = scratch
        .keys()
        .join(format!(".aspace-resident-{}", gateway.pid()));
    assert_eq!(
        std::fs::read_to_string(&marker).expect("the resident marker"),
        "aspace mcp\n"
    );

    // A Java agent binds: the client hears list_changed, and the tool is listed and called.
    seed.ask("bind-agent researcher");
    gateway.out_until("tools/list_changed", |message| {
        message["method"] == "notifications/tools/list_changed"
    });
    let listed = request(&mut gateway, 3, "tools/list", json!({}));
    assert_eq!(names(&listed), ["research"], "{listed}");
    let tool = &listed["result"]["tools"][0];
    assert_eq!(tool["inputSchema"]["required"], json!(["input"]), "{tool}");
    assert!(
        tool["description"]
            .as_str()
            .unwrap_or_default()
            .contains("data, not instructions"),
        "{tool}"
    );
    let called = request(
        &mut gateway,
        4,
        "tools/call",
        json!({"name": "research", "arguments": {"input": {"topic": "mcp-stdio", "priority": 3}, "timeout": "20s"}}),
    );
    let result = &called["result"];
    assert_eq!(result["isError"], false, "{called}");
    assert_eq!(
        result["structuredContent"]["summary"], "researched in java: mcp-stdio",
        "{called}"
    );
    let results = seed.ask("results");
    assert!(
        results["results"]
            .as_array()
            .is_some_and(|all| all.iter().any(|r| r["topic"] == "mcp-stdio")),
        "{results}"
    );
    let unknown = request(
        &mut gateway,
        5,
        "tools/call",
        json!({"name": "no_such_tool", "arguments": {"input": {}}}),
    );
    // A tool the gateway never listed is the MCP tools specification's protocol error.
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");
    assert_eq!(
        unknown["error"]["message"], "Unknown tool: no_such_tool",
        "{unknown}"
    );

    // The client leaves: exit 0, the marker removed, nothing but JSON-RPC on standard output.
    gateway.close_stdin();
    let (code, took) = gateway.finish();
    assert_eq!(code, Some(0), "{:?}", gateway.seen_err);
    assert!(took < Duration::from_secs(5), "took {took:?} to stop");
    assert!(!marker.exists(), "the marker outlived the gateway");
    assert_only_json_rpc(&gateway.seen_out);
    let err = gateway.seen_err.join("\n");
    assert!(err.contains("stopped"), "{err}");
    assert!(
        !err.contains("\"jsonrpc\""),
        "JSON-RPC on standard error: {err}"
    );
}

#[test]
fn only_limits_the_tools_and_sigterm_stops_the_stdio_gateway() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    let scratch = Scratch::new("only");
    let mut gateway = stdio_gateway(&scratch, &seed, &["--only", "space:elsewhere"]);
    gateway.wait_err("serving 0 tools");
    open_stdio(&mut gateway);
    let listed = request(&mut gateway, 2, "tools/list", json!({}));
    assert!(names(&listed).is_empty(), "{listed}");
    let refused = request(
        &mut gateway,
        3,
        "tools/call",
        json!({"name": "research", "arguments": {"input": {"topic": "x"}}}),
    );
    // A tool --only leaves out is not offered: the MCP tools specification's unknown tool.
    assert_eq!(refused["error"]["code"], -32602, "{refused}");
    assert_eq!(
        refused["error"]["message"], "Unknown tool: research",
        "{refused}"
    );

    gateway.signal("-TERM");
    let (code, took) = gateway.finish();
    assert_eq!(code, Some(0), "{:?}", gateway.seen_err);
    assert!(took < Duration::from_secs(5), "took {took:?} to stop");
    assert_only_json_rpc(&gateway.seen_out);

    // The same tool, offered under a pattern that names it.
    let other = Scratch::new("only-research");
    let mut gateway = stdio_gateway(&other, &seed, &["--only", "research"]);
    gateway.wait_err("serving 1 tool");
    open_stdio(&mut gateway);
    assert_eq!(
        names(&request(&mut gateway, 2, "tools/list", json!({}))),
        ["research"]
    );
    gateway.signal("-INT");
    assert_eq!(gateway.finish().0, Some(0), "{:?}", gateway.seen_err);
}

#[test]
fn the_http_gateway_authenticates_and_judges_every_call() {
    let classpath = classpath_or_skip!();
    let mut seed = JavaSeed::start(&classpath);
    seed.ask("bind-agent researcher");
    let scratch = Scratch::new("http");
    let tokens = token_file(&scratch, 0o600);
    let policy = policy_file(&scratch, 0o644);
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let mut gateway = Running::spawn(with(
        aspace(&scratch, &seed.seed(), FOUNDING),
        &[
            "--profile",
            "dev-local",
            "mcp",
            "--http",
            &bind,
            "--tokens",
            &tokens.display().to_string(),
            "--policy",
            &policy.display().to_string(),
        ],
    ));
    let hello = gateway
        .next_out(DEADLINE)
        .unwrap_or_else(|| panic!("no hello: {:?}", gateway.seen_err));
    assert_eq!(hello["mcp"], format!("http://{bind}/mcp"), "{hello}");
    assert_eq!(hello["pid"], gateway.pid(), "{hello}");
    let address: SocketAddr = bind.parse().expect("an address");
    let post = |token: Option<&str>, session: Option<&str>, extra: &[(&str, &str)], body: &Json| {
        let bearer = token.map(|token| format!("Bearer {token}"));
        let mut headers: Vec<(&str, &str)> = extra.to_vec();
        if let Some(bearer) = bearer.as_deref() {
            headers.push(("Authorization", bearer));
        }
        if let Some(session) = session {
            headers.push(("Mcp-Session-Id", session));
            headers.push(("Mcp-Protocol-Version", PROTOCOL));
        }
        http_post(address, "/mcp", &headers, &body.to_string())
    };
    let open = |token: &str| -> String {
        let answer = post(Some(token), None, &[], &initialize(1));
        assert_eq!(answer.status, 200, "{answer:?}");
        let session = answer.header("mcp-session-id");
        assert!(!session.is_empty(), "{answer:?}");
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert_eq!(
            post(Some(token), Some(&session), &[], &initialized).status,
            202
        );
        session
    };
    let call = |id: i64, topic: &str| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": "research", "arguments": {"input": {"topic": topic, "priority": 1}, "timeout": "20s"}}})
    };

    // 401 without a token, and with one the file does not hold (never echoed).
    let answer = post(None, None, &[], &initialize(1));
    assert_eq!(answer.status, 401, "{answer:?}");
    assert_eq!(
        answer.header("www-authenticate"),
        "Bearer realm=\"agentspaces\""
    );
    let answer = post(Some("not-a-known-token"), None, &[], &initialize(1));
    assert_eq!(answer.status, 401, "{answer:?}");
    let challenge = answer.header("www-authenticate");
    assert!(challenge.contains("invalid_token"), "{challenge}");
    assert!(!challenge.contains("not-a-known-token"), "{challenge}");

    // 200 in scope, Java answering.
    let ana = open(ANA);
    let deadline = Instant::now() + DEADLINE;
    loop {
        let listed = post(
            Some(ANA),
            Some(&ana),
            &[],
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        );
        if names(&listed.rpc()) == ["research"] {
            break;
        }
        assert!(Instant::now() < deadline, "no research tool: {listed:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let answer = post(Some(ANA), Some(&ana), &[], &call(3, "mcp-http"));
    assert_eq!(answer.status, 200, "{answer:?}");
    let result = answer.rpc();
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(
        result["result"]["structuredContent"]["summary"],
        "researched in java: mcp-http"
    );

    // 403 outside the token's scopes: the policy's scope is named, and the call never starts.
    let bob = open(BOB);
    let answer = post(Some(BOB), Some(&bob), &[], &call(4, "mcp-forbidden"));
    assert_eq!(answer.status, 403, "{answer:?}");
    let challenge = answer.header("www-authenticate");
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(challenge.contains("scope=\"research\""), "{challenge}");
    let tasks = seed.ask("task-states");
    assert!(
        !tasks.to_string().contains("mcp-forbidden"),
        "the forbidden call wrote its input: {tasks}"
    );

    // 403 for a browser origin not allowed, before anything else.
    let answer = post(
        Some(ANA),
        None,
        &[("Origin", "https://evil.example")],
        &initialize(1),
    );
    assert_eq!(answer.status, 403, "{answer:?}");

    // SIGINT: exit 0, the port closed, the hello the only line on standard output.
    gateway.signal("-INT");
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
fn status_reports_the_daemon_and_the_mcp_settings() {
    let classpath = classpath_or_skip!();
    let seed = JavaSeed::start(&classpath);
    let scratch = Scratch::new("status");
    let tokens = token_file(&scratch, 0o600);
    let policy = policy_file(&scratch, 0o666);
    let visitor = |extra: &[&str]| {
        let mut command = with(
            aspace(&scratch, &seed.seed(), FOUNDING),
            &["--profile", "dev-local"],
        );
        command
            .env("ASPACE_MCP_TOKENS", &tokens)
            .env("ASPACE_MCP_POLICY", &policy)
            .args(extra);
        command
    };
    let json_of = |output: &std::process::Output| -> Json {
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("not JSON: {output:?}"))
    };
    let expected_mcp = json!({
        "tokens": {"path": tokens.display().to_string(), "mode": "0600", "safe": true},
        "policy": {"path": policy.display().to_string(), "mode": "0666", "safe": false},
    });

    // No daemon.
    let status = json_of(&visit(visitor(&["status", "--json"])));
    assert_eq!(status["daemon"], Json::Null, "{status}");
    assert_eq!(status["mcp"], expected_mcp, "{status}");
    let text = String::from_utf8_lossy(&visit(visitor(&["status"])).stdout).into_owned();
    assert!(text.contains("daemon   none"), "{text}");
    assert!(
        text.contains(&format!(
            "mcp      tokens {} (0600), policy {} (0666, unsafe)",
            tokens.display(),
            policy.display()
        )),
        "{text}"
    );

    // A daemon of the same configuration is used, and reports the visitor's MCP settings.
    let mut daemon = Running::spawn(with(
        aspace(&scratch, &seed.seed(), FOUNDING),
        &["--profile", "dev-local", "daemon"],
    ));
    let hello = daemon
        .next_out(DEADLINE)
        .unwrap_or_else(|| panic!("no daemon hello: {:?}", daemon.seen_err));
    let status = json_of(&visit(visitor(&["status", "--json"])));
    assert_eq!(status["daemon"]["used"], true, "{status}");
    assert_eq!(status["daemon"]["pid"], hello["pid"], "{status}");
    assert_eq!(status["mcp"], expected_mcp, "{status}");
    let text = String::from_utf8_lossy(&visit(visitor(&["status"])).stdout).into_owned();
    assert!(text.contains("(pid "), "{text}");
    assert!(text.contains(", used)"), "{text}");
    assert!(text.contains("mcp      tokens "), "{text}");

    // A visitor with another keystore joins itself, and says why the daemon was not used.
    let other_keys = scratch.path().join("other-keys");
    let other = other_keys.display().to_string();
    let output = visit(visitor(&["--keystore", &other, "status", "--json"]));
    let status = json_of(&output);
    assert_eq!(status["daemon"]["used"], false, "{status}");
    assert_eq!(status["daemon"]["pid"], hello["pid"], "{status}");
    assert!(
        status["daemon"]["why"]
            .as_str()
            .is_some_and(|why| why.contains("keystore")),
        "{status}"
    );
    assert!(
        stderr(&output).contains("joining the group itself"),
        "{output:?}"
    );

    daemon.signal("-TERM");
    assert_eq!(daemon.finish().0, Some(0), "{:?}", daemon.seen_err);
}
