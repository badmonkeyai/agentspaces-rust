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

//! The `aspace` contract without a fleet: every command's `--help` carries examples, the
//! completions and manual pages render, refusals exit 2 and name the flag, variable, or key they
//! read, a readable key exits 4, a join that never completes exits 3, `doctor` exits 1 on a
//! failed check, and the catalogue commands and the worker's names refuse what they cannot use
//! before joining (`cli_java.rs` runs them against a fleet).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use agentspaces::wire::ids;

const CONFIG_VARIABLES: [&str; 13] = [
    "ASPACE_SEEDS",
    "ASPACE_INVITE",
    "ASPACE_LISTEN",
    "ASPACE_ADVERTISE",
    "ASPACE_GROUP",
    "ASPACE_JOIN",
    "ASPACE_KEYSTORE",
    "ASPACE_PROFILE",
    "ASPACE_SPACES",
    "ASPACE_CONFIG",
    "ASPACE_SOCKET",
    "XDG_CONFIG_HOME",
    "HOME",
];

/// A scratch HOME under Cargo's per-target space, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "cli-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `aspace args` with nothing configured but HOME, run to its end (killed after 30 s).
fn run(scratch: &Scratch, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aspace"));
    for variable in CONFIG_VARIABLES {
        command.env_remove(variable);
    }
    let mut child = command
        .env("HOME", scratch.path())
        // The daemon socket a visitor probes is the scratch directory's, never the user's.
        .env("XDG_RUNTIME_DIR", scratch.path().join("run"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aspace starts");
    // Both pipes are drained while the command runs: an output larger than a pipe's buffer (a
    // completion script) would otherwise block it until the deadline.
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = std::io::Read::read_to_end(&mut pipe, &mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let (status, finished) = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break (status, true);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait().expect("wait"), false);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    };
    assert!(finished, "aspace {args:?} did not finish: {output:?}");
    output
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_exit(output: &Output, code: i32, mentions: &[&str]) {
    let err = stderr(output);
    assert_eq!(output.status.code(), Some(code), "{err}");
    for part in mentions {
        assert!(err.contains(part), "{part:?} missing from: {err}");
    }
}

#[test]
fn every_command_help_carries_examples() {
    let scratch = Scratch::new("help");
    for command in [
        "id",
        "status",
        "write",
        "read",
        "take",
        "complete",
        "watch",
        "cards",
        "call",
        "work",
        "daemon",
        "mcp",
        "doctor",
        "completions",
        "man",
    ] {
        let output = run(&scratch, &[command, "--help"]);
        assert!(output.status.success(), "{command}: {output:?}");
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("Examples:"), "{command} --help: {help}");
        assert!(help.contains("aspace "), "{command} --help: {help}");
    }
    let output = run(&scratch, &["--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    for part in ["Exit codes", "ASPACE_CONFIG", "Examples:"] {
        assert!(help.contains(part), "{part:?} missing from --help");
    }
    let version = run(&scratch, &["--version"]);
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("aspace 0.5.0"));
}

#[test]
fn completions_and_manual_pages_render() {
    let scratch = Scratch::new("completions");
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = run(&scratch, &["completions", shell]);
        assert!(output.status.success(), "{shell}: {output:?}");
        let script = String::from_utf8_lossy(&output.stdout);
        assert!(
            script.contains("aspace") && script.contains("work"),
            "{shell}"
        );
    }
    let output = run(&scratch, &["man"]);
    assert!(output.status.success(), "{output:?}");
    let page = String::from_utf8_lossy(&output.stdout);
    assert!(
        page.starts_with(".ie") || page.contains(".TH aspace"),
        "{page}"
    );
    assert!(page.contains("work"));

    let dir = scratch.path().join("man1");
    let dir_text = dir.display().to_string();
    let output = run(&scratch, &["man", "--out-dir", &dir_text]);
    assert!(output.status.success(), "{output:?}");
    for page in [
        "aspace.1",
        "aspace-work.1",
        "aspace-write.1",
        "aspace-doctor.1",
    ] {
        let text = std::fs::read_to_string(dir.join(page)).expect(page);
        assert!(text.contains(".TH"), "{page}");
    }
}

#[test]
fn refusals_exit_2_and_name_what_they_read() {
    let scratch = Scratch::new("refusals");
    let file = scratch.path().join("fleet.yaml");
    std::fs::write(
        &file,
        "agentspaces:\n  groups:\n    - name: g\n      seeds: [ 'not a seed' ]\n",
    )
    .expect("write");
    let file_text = file.display().to_string();
    let output = run(
        &scratch,
        &["--config", &file_text, "read", "x.T#v1", "--space", "s"],
    );
    assert_exit(
        &output,
        2,
        &[
            "agentspaces.groups[0].seeds[0] in",
            "fleet.yaml",
            "not a seed",
        ],
    );

    let output = run(
        &scratch,
        &["--config", "/no/such/fleet.yaml", "read", "x.T#v1"],
    );
    assert_exit(
        &output,
        2,
        &["--config names the fleet file /no/such/fleet.yaml"],
    );

    let output = run(
        &scratch,
        &[
            "--seeds",
            "tcp://10.0.0.7:7500",
            "--group",
            "g",
            "write",
            "x.T#v1",
            "--json",
            "{}",
            "--space",
            "s",
        ],
    );
    assert_exit(
        &output,
        2,
        &[
            "--seeds holds tcp://10.0.0.7:7500",
            "not loopback",
            "dev-local",
        ],
    );

    let output = run(&scratch, &["read", "x.T#v1", "--space", "s"]);
    assert_exit(&output, 2, &["no group to join", "--join", "ASPACE_GROUP"]);

    let output = run(
        &scratch,
        &["--seeds", "127.0.0.1:1", "--group", "g", "read", "x.T#v1"],
    );
    assert_exit(&output, 2, &["no space named", "--space"]);

    // Refused before any join: a schema without a version, JSON that is not an object, a
    // program that is not there, and a usage error.
    let output = run(&scratch, &["write", "shop.Order", "--json", "{}"]);
    assert_exit(&output, 2, &["not a schema", "#v"]);
    let output = run(&scratch, &["write", "shop.Order#v1", "--json", "[1,2]"]);
    assert_exit(&output, 2, &["--json is an array, not a JSON object"]);
    let output = run(
        &scratch,
        &[
            "work",
            "--take",
            "x.T#v1",
            "--space",
            "s",
            "--",
            "/no/such/program",
        ],
    );
    assert_exit(&output, 2, &["/no/such/program is not an executable file"]);
    let output = run(&scratch, &["read", "x.T#v1", "--no-such-flag"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let output = run(
        &scratch,
        &["read", "x.T#v1", "--where", "nope", "--space", "s"],
    );
    assert_exit(&output, 2, &["--where"]);
}

#[test]
fn a_readable_private_key_exits_4_unless_allowed() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("readable");
    let keys = scratch.path().join("keys");
    let keys_text = keys.display().to_string();
    let output = run(&scratch, &["id", "--keystore", &keys_text]);
    assert!(output.status.success(), "{output:?}");
    std::fs::set_permissions(
        keys.join("peer.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");
    let output = run(&scratch, &["id", "--keystore", &keys_text]);
    assert_exit(&output, 4, &["readable by group or others", "chmod 600"]);
    let output = run(
        &scratch,
        &["id", "--keystore", &keys_text, "--allow-readable-key"],
    );
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_join_that_never_completes_exits_3() {
    let scratch = Scratch::new("join-timeout");
    // A seed that accepts the connection and never says a word: a join by id waits for the
    // founding advertisement until --join-timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().expect("address").port();
    let holder = std::thread::spawn(move || {
        let mut held = Vec::new();
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let until = Instant::now() + Duration::from_secs(20);
        while Instant::now() < until {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
            if held.len() >= 2 {
                std::thread::sleep(Duration::from_secs(3));
                break;
            }
        }
    });
    let join = format!("aspace://{}", ids::group_id_from_founding(b"never-founded"));
    let seed = format!("127.0.0.1:{port}");
    let started = Instant::now();
    let output = run(
        &scratch,
        &[
            "--seeds",
            &seed,
            "--join",
            &join,
            "--join-timeout",
            "1s",
            "read",
            "x.T#v1",
            "--space",
            "s",
        ],
    );
    assert_exit(&output, 3, &["within 1s"]);
    assert!(started.elapsed() < Duration::from_secs(10));
    drop(holder);
}

/// A seed that accepts the connection and never speaks (one that closes it at once,
/// as a load balancer with a dead backend; one that never answers, as a hung process) is a
/// timeout (exit 3) for `take`, `read`, and `cards`, never the authoritative "nothing matched"
/// (exit 2) a script would believe.
#[test]
fn a_seed_that_never_speaks_is_a_timeout_not_a_miss() {
    let scratch = Scratch::new("silent-seed");
    // Accepts every connection and closes it at once.
    let closing = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let closing_port = closing.local_addr().expect("address").port();
    std::thread::spawn(move || {
        for stream in closing.incoming() {
            drop(stream);
        }
    });
    // Listens and never accepts: the kernel completes the handshake, nothing ever answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let silent_port = silent.local_addr().expect("address").port();
    for port in [closing_port, silent_port] {
        let seed = format!("127.0.0.1:{port}");
        for verb in [
            &["take", "x.T#v1", "--space", "s"][..],
            &["read", "x.T#v1", "--space", "s"][..],
            &["cards"][..],
        ] {
            let mut args = vec![
                "--no-daemon",
                "--profile",
                "dev-local",
                "--seeds",
                &seed,
                "--group",
                "a-silent-seed",
                "--join-timeout",
                "2s",
            ];
            args.extend_from_slice(verb);
            let started = Instant::now();
            let output = run(&scratch, &args);
            assert_exit(&output, 3, &["sent nothing"]);
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "{verb:?} took {:?}",
                started.elapsed()
            );
        }
    }
    drop(silent);
}

#[test]
fn doctor_exits_1_when_a_check_fails() {
    let scratch = Scratch::new("doctor");
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .map(|address| address.port())
        .expect("a free port");
    let seed = format!("127.0.0.1:{closed}");
    let output = run(
        &scratch,
        &["--seeds", &seed, "--group", "g", "doctor", "--json"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("a report");
    assert_eq!(report["ok"], false);
    let checks = report["checks"].as_array().expect("checks");
    let failed: Vec<&str> = checks
        .iter()
        .filter(|check| check["ok"] == false)
        .filter_map(|check| check["check"].as_str())
        .collect();
    assert!(
        failed.iter().any(|name| name.starts_with("seed ")),
        "{report}"
    );
    assert!(failed.contains(&"keystore"), "no identity yet: {report}");
    let golden = checks
        .iter()
        .find(|check| check["check"] == "golden")
        .expect("the golden check");
    assert_eq!(golden["ok"], true);
    let group = checks
        .iter()
        .find(|check| check["check"] == "config.group")
        .expect("the group");
    assert!(
        group["detail"]
            .as_str()
            .is_some_and(|d| d.contains("redacted") && d.contains("--group")),
        "{group}"
    );
}

#[test]
fn the_catalogue_commands_and_worker_names_refuse_before_joining() {
    let scratch = Scratch::new("catalogue");
    // No group configured: refused (exit 2) without dialing anything.
    let output = run(&scratch, &["cards"]);
    assert_exit(&output, 2, &["no group to join"]);
    let output = run(&scratch, &["call", "x.T#v1", "--json", "{}"]);
    assert_exit(&output, 2, &["no group to join"]);
    // Input that is not one JSON object, and an empty target, are refused first.
    let output = run(&scratch, &["call", "x.T#v1", "--json", "[1]"]);
    assert_exit(&output, 2, &["--json is an array, not a JSON object"]);
    let output = run(&scratch, &["call", " ", "--json", "{}"]);
    assert_exit(&output, 2, &["name the offering to call"]);
    // The worker's agent and action names are checked before its program runs or it joins.
    for (flag, name) in [
        ("--name", "a/b"),
        ("--action", " "),
        ("--name", "tab\there"),
    ] {
        let output = run(
            &scratch,
            &[
                "--seeds",
                "127.0.0.1:1",
                "--group",
                "g",
                "work",
                "--take",
                "x.T#v1",
                "--space",
                "s",
                flag,
                name,
                "--",
                "/bin/sh",
            ],
        );
        assert_exit(&output, 2, &[flag, "without '/' or control characters"]);
    }
}

/// `aspace args` as [`run`] runs it, with standard error (or standard output) on a pipe whose
/// reader has already gone: every write to it fails with EPIPE.
fn run_closed(scratch: &Scratch, args: &[&str], close_stdout: bool) -> Output {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut command = Command::new(env!("CARGO_BIN_EXE_aspace"));
    for variable in CONFIG_VARIABLES {
        command.env_remove(variable);
    }
    command
        .env("HOME", scratch.path())
        // The daemon socket a visitor probes is the scratch directory's, never the user's.
        .env("XDG_RUNTIME_DIR", scratch.path().join("run"))
        .args(args)
        .stdin(Stdio::null());
    if close_stdout {
        command.stdout(Stdio::from(writer)).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::piped()).stderr(Stdio::from(writer));
    }
    let mut child = command.spawn().expect("aspace starts");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("output");
            panic!("aspace {args:?} did not finish: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A reader that went away never turns an exit into a panic's 101: a note or a failure on
/// a closed standard error, and a report or a script on a closed standard output, end with the
/// contract's codes.
#[test]
fn a_closed_pipe_keeps_the_contract_exit_codes() {
    let scratch = Scratch::new("closed-pipe");
    // Standard error closed: a refusal is still exit 2, a note (a minted identity) is no panic.
    let output = run_closed(&scratch, &["read", "x.T#v1", "--space", "s"], false);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let output = run_closed(&scratch, &["write", "shop.Order", "--json", "{}"], false);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let keys = scratch.path().join("fresh-keys");
    let keys_text = keys.display().to_string();
    let output = run_closed(&scratch, &["id", "--keystore", &keys_text], false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // Standard output closed: the report still says a check failed (exit 1), and a script
    // whose reader went away ends quietly.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .map(|address| address.port())
        .expect("a free port");
    let seed = format!("127.0.0.1:{closed}");
    let output = run_closed(
        &scratch,
        &["--seeds", &seed, "--group", "g", "doctor"],
        true,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let output = run_closed(
        &scratch,
        &["--seeds", &seed, "--group", "g", "doctor", "--json"],
        true,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let output = run_closed(&scratch, &["completions", "bash"], true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

/// A worker's take lease is refused before joining (exit 2) when it is shorter than
/// a claim's settle window and pull allow before the first renewal, or longer than any take may
/// hold (the worker would advertise work it never takes).
#[test]
fn a_workers_lease_outside_two_seconds_to_a_day_is_refused_before_joining() {
    let scratch = Scratch::new("work-lease");
    for (lease, mentions) in [("1s", "at least 2s"), ("25h", "at most")] {
        let output = run(
            &scratch,
            &[
                "--seeds",
                "127.0.0.1:1",
                "--group",
                "g",
                "work",
                "--take",
                "x.T#v1",
                "--space",
                "s",
                "--lease",
                lease,
                "--",
                "/bin/sh",
            ],
        );
        assert_exit(&output, 2, &["--lease", mentions]);
    }
}

/// A fleet that cannot be reached exits as the contract says whatever the number of seeds:
/// seeds whose TLS handshake never answers are a timeout (3) with one seed as with two, and a
/// TLS seed whose channel certificate attests nobody is an authentication failure (4).
#[test]
fn unreachable_and_unattested_seeds_exit_3_and_4() {
    use agentspaces::channel_cert::ChannelCertificate;
    use agentspaces::transport::tls::TlsListener;
    use agentspaces::wire::identity::Identity;

    let scratch = Scratch::new("dial-exits");
    // Two seeds that accept the connection and never answer the handshake.
    let mut ports = Vec::new();
    let mut holders = Vec::new();
    for _ in 0..2 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        ports.push(listener.local_addr().expect("address").port());
        holders.push(std::thread::spawn(move || {
            let mut held = Vec::new();
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let until = Instant::now() + Duration::from_secs(25);
            while Instant::now() < until {
                if let Ok((stream, _)) = listener.accept() {
                    held.push(stream);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }));
    }
    let silent: Vec<String> = ports
        .iter()
        .map(|port| format!("tls://127.0.0.1:{port}"))
        .collect();
    for seeds in [silent[0].clone(), silent.join(",")] {
        for _ in 0..2 {
            let output = run(
                &scratch,
                &[
                    "--seeds",
                    &seeds,
                    "--group",
                    "g",
                    "--join-timeout",
                    "2s",
                    "status",
                ],
            );
            assert_exit(&output, 3, &[]);
        }
    }

    // A TLS seed presenting a certificate that attests nobody.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    let victim = Identity::generate().expect("identity");
    let forger = Identity::generate().expect("identity");
    let forged = ChannelCertificate::build(victim.public_raw(), &forger, 1_700_000_000_000)
        .expect("a certificate");
    let listener = runtime
        .block_on(TlsListener::bind_presenting("127.0.0.1:0", &forged))
        .expect("bind");
    let address = agentspaces::transport::Listener::local_address(&listener);
    let seeds = format!("tls://{address}");
    let output = run(
        &scratch,
        &[
            "--seeds",
            &seeds,
            "--group",
            "g",
            "--join-timeout",
            "5s",
            "status",
        ],
    );
    assert_exit(&output, 4, &["endorsed channel certificate"]);
    drop(listener);
    drop(runtime);
    drop(holders);
}
