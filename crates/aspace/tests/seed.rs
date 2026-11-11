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

//! `aspace seed` and `aspace invite`, with nothing but this build's `aspace` (SPEC §5.1 to
//! §5.4): a seed founds a group, prints its listening line, serves visitors, keeps its GroupID
//! across restarts, and stops with exit 0 on SIGTERM; an `INVITE` group admits a visitor holding
//! an invite key (`--invite`, `ASPACE_INVITE`) and refuses one without (exit 4); a second seed
//! joins the first by id, skipping its own address among its seeds, and entries cross both; the
//! listeners come from flags, variables, or the fleet file's `bind` and `advertise`, and every
//! refusal names its flag, variable, or key.

mod support;

use serde_json::Value as Json;
use support::*;

/// A seed of `scratch` run with `args` before and after `seed`.
fn start_seed(scratch: &Scratch, global: &[&str], args: &[&str]) -> (Running, Json) {
    let mut command = bare_aspace(scratch);
    command.args(global).arg("seed").args(args);
    let mut seed = Running::spawn(command);
    let line = seed.out_until("the listening line", |json| json["event"] == "listening");
    (seed, line)
}

/// The first listener of a listening line, as a seed to dial.
fn address(line: &Json) -> String {
    line["listen"][0].as_str().expect("a listener").to_owned()
}

/// A visitor of `scratch` with keystore `name`, joined through `seeds`, running `args`.
fn visitor(scratch: &Scratch, name: &str, seeds: &str, args: &[&str]) -> std::process::Output {
    let keys = scratch.path().join(name).display().to_string();
    let mut command = bare_aspace(scratch);
    command
        .args(["--no-daemon", "--keystore", &keys, "--seeds", seeds])
        .args(args);
    visit(command)
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Stops `seed` with SIGTERM: exit 0, having said it stopped.
fn stop(mut seed: Running) -> Vec<String> {
    seed.signal("-TERM");
    let (code, _) = seed.finish();
    assert_eq!(code, Some(0), "the seed's exit: {:?}", seed.seen_err);
    assert!(
        seed.seen_err.iter().any(|line| line == "aspace: stopped"),
        "{:?}",
        seed.seen_err
    );
    seed.seen_err.clone()
}

#[test]
fn a_seed_founds_a_group_serves_visitors_and_keeps_its_id() {
    let scratch = Scratch::new("seed-found");
    let keys = scratch.path().join("seed").display().to_string();
    let global = ["--profile", "dev-local", "--keystore", &keys];
    let (seed, line) = start_seed(
        &scratch,
        &global,
        &["--found", "demo", "--listen", "tcp://127.0.0.1:0"],
    );
    let group = line["group"].as_str().expect("a group").to_owned();
    assert_eq!(line["join"], format!("aspace://{group}"));
    assert_eq!(line["membership"], "OPEN");
    let seeds = address(&line);
    assert!(
        seeds.starts_with("tcp://127.0.0.1:") && !seeds.ends_with(":0"),
        "the real port: {seeds}"
    );
    assert!(
        scratch.path().join("seed/founding-demo.cbor").is_file(),
        "the founding is kept beside the keystore"
    );
    let join = line["join"].as_str().expect("join").to_owned();
    let dev = ["--profile", "dev-local", "--join", join.as_str()];

    // A writer writes and leaves; a reader that never met it reads the entry from the seed.
    let write = visitor(
        &scratch,
        "writer",
        &seeds,
        &[
            &dev[..],
            &[
                "write",
                "demo.Note#v1",
                "--space",
                "notes",
                "--json",
                r#"{"text":"kept by the seed"}"#,
            ],
        ]
        .concat(),
    );
    assert!(write.status.success(), "{}", stderr(&write));
    let read = visitor(
        &scratch,
        "reader",
        &seeds,
        &[&dev[..], &["read", "demo.Note#v1", "--space", "notes"]].concat(),
    );
    assert!(read.status.success(), "{}", stderr(&read));
    assert!(
        stdout(&read).contains(r#""entry":{"text":"kept by the seed"}"#),
        "{}",
        stdout(&read)
    );
    // `aspace status` against the seed lists its members: the seed and the writer.
    let status = visitor(
        &scratch,
        "reader",
        &seeds,
        &[&dev[..], &["status", "--json"]].concat(),
    );
    assert!(status.status.success(), "{}", stderr(&status));
    let report: Json = serde_json::from_slice(&status.stdout).expect("status JSON");
    let members: Vec<&str> = report["members"]
        .as_array()
        .expect("members")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert!(
        members.contains(&line["peer"].as_str().expect("peer")),
        "{members:?}"
    );
    assert!(members.len() >= 2, "the writer too: {members:?}");
    let said = stop(seed);
    assert!(
        said.iter()
            .filter(|line| line.starts_with("aspace: admitted z"))
            .count()
            >= 2,
        "{said:?}"
    );

    // A restart keeps the GroupID; a group founded from a text has no id to join by.
    let (again, line) = start_seed(
        &scratch,
        &global,
        &["--found", "demo", "--listen", "tcp://127.0.0.1:0"],
    );
    assert_eq!(
        line["group"],
        group.as_str(),
        "the restart keeps the GroupID"
    );
    stop(again);
    let (text, line) = start_seed(
        &scratch,
        &global,
        &["--group", "shop-v1", "--listen", "tcp://127.0.0.1:0"],
    );
    assert_eq!(line["join"], Json::Null);
    let group_id = agentspaces::wire::ids::group_id_from_founding(b"shop-v1");
    assert_eq!(line["group"], group_id.as_str());
    stop(text);
}

#[test]
fn an_invite_group_admits_only_invited_peers() {
    let scratch = Scratch::new("seed-invite");
    let keys = scratch.path().join("seed").display().to_string();
    let (seed, line) = start_seed(
        &scratch,
        &["--keystore", &keys],
        &[
            "--found",
            "crew",
            "--membership",
            "invite",
            "--listen",
            "tls://127.0.0.1:0",
            "--require-attestation",
        ],
    );
    assert_eq!(line["membership"], "INVITE");
    let seeds = address(&line);
    assert!(seeds.starts_with("tls://"), "{seeds}");
    let join = line["join"].as_str().expect("join").to_owned();

    let invite = visit(with(
        bare_aspace(&scratch),
        &[
            "--keystore",
            &keys,
            "invite",
            "--found",
            "crew",
            "--label",
            "tests",
        ],
    ));
    assert!(invite.status.success(), "{}", stderr(&invite));
    let invite: Json = serde_json::from_slice(&invite.stdout).expect("invite JSON");
    let key = invite["invite"].as_str().expect("a key").to_owned();
    assert!(key.starts_with("aspace-inv1-"), "{key}");
    assert_eq!(invite["join"], join.as_str());
    assert_eq!(invite["label"], "tests");

    // No invite: refused before anything is written (exit 4), saying how to get one.
    let refused = visitor(
        &scratch,
        "stranger",
        &seeds,
        &[
            "--join",
            &join,
            "write",
            "crew.Note#v1",
            "--space",
            "notes",
            "--json",
            "{}",
        ],
    );
    assert_eq!(refused.status.code(), Some(4), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("--invite"),
        "{}",
        stderr(&refused)
    );
    // With the invite, and no group named: the invite names it.
    let write = visitor(
        &scratch,
        "guest",
        &seeds,
        &[
            "--invite",
            &key,
            "write",
            "crew.Note#v1",
            "--space",
            "notes",
            "--json",
            r#"{"text":"invited"}"#,
        ],
    );
    assert!(write.status.success(), "{}", stderr(&write));
    let mut command = bare_aspace(&scratch);
    command.env("ASPACE_INVITE", &key).args([
        "--no-daemon",
        "--keystore",
        &scratch.path().join("other").display().to_string(),
        "--seeds",
        &seeds,
        "read",
        "crew.Note#v1",
        "--space",
        "notes",
    ]);
    let read = visit(command);
    assert!(read.status.success(), "{}", stderr(&read));
    assert!(stdout(&read).contains(r#""entry":{"text":"invited"}"#));
    // An invite of another group beside a group named: refused, naming both.
    let other = agentspaces::wire::ids::group_id_from_founding(b"another");
    let clash = visitor(
        &scratch,
        "guest",
        &seeds,
        &[
            "--invite",
            &key,
            "--join",
            &format!("aspace://{other}"),
            "status",
        ],
    );
    assert_eq!(clash.status.code(), Some(2), "{}", stderr(&clash));
    assert!(
        stderr(&clash).contains("--invite") && stderr(&clash).contains("--join"),
        "{}",
        stderr(&clash)
    );
    assert!(
        !stderr(&clash).contains(&key[20..]),
        "a refusal never shows the key's secret"
    );
    stop(seed);

    // The founding never changes: asking for an open group on the invite founding is refused.
    let mut command = bare_aspace(&scratch);
    command.args([
        "--keystore",
        &keys,
        "seed",
        "--found",
        "crew",
        "--membership",
        "open",
    ]);
    let changed = visit(command);
    assert_eq!(changed.status.code(), Some(2), "{}", stderr(&changed));
    assert!(stderr(&changed).contains("--membership"));
    // Invites only for an invite group this keystore founded.
    for (args, why) in [
        (
            vec!["--keystore", &keys, "invite", "--found", "nothing"],
            "no founding",
        ),
        (
            vec![
                "--keystore",
                &scratch.path().join("empty").display().to_string(),
                "invite",
                "--found",
                "crew",
            ],
            "holds no identity",
        ),
    ] {
        let output = visit(with(bare_aspace(&scratch), &args));
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stderr(&output).contains(why), "{}", stderr(&output));
    }
    let (open, _) = start_seed(
        &scratch,
        &["--profile", "dev-local", "--keystore", &keys],
        &["--found", "lobby", "--listen", "tcp://127.0.0.1:0"],
    );
    stop(open);
    let output = visit(with(
        bare_aspace(&scratch),
        &["--keystore", &keys, "invite", "--found", "lobby"],
    ));
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("is open"), "{}", stderr(&output));
    let bad = visitor(
        &scratch,
        "guest",
        &seeds,
        &["--invite", "aspace-inv1-NOTAKEY", "status"],
    );
    assert_eq!(bad.status.code(), Some(2), "{}", stderr(&bad));
}

#[test]
fn a_second_seed_joins_the_first_and_entries_cross_both() {
    let scratch = Scratch::new("seed-two");
    let first_keys = scratch.path().join("seed1").display().to_string();
    let (first, line) = start_seed(
        &scratch,
        &["--profile", "dev-local", "--keystore", &first_keys],
        &["--found", "pair", "--listen", "tcp://127.0.0.1:0"],
    );
    let first_seed = address(&line);
    let join = line["join"].as_str().expect("join").to_owned();
    // The second seed's own address is among its seeds, as in a fleet file every seed shares:
    // it is skipped.
    let port = free_port();
    let own = format!("tcp://127.0.0.1:{port}");
    let second_keys = scratch.path().join("seed2").display().to_string();
    let seeds = format!("{own},{first_seed}");
    let (mut second, line) = start_seed(
        &scratch,
        &[
            "--profile",
            "dev-local",
            "--keystore",
            &second_keys,
            "--seeds",
            &seeds,
            "--join",
            &join,
        ],
        &["--listen", &own, "--replicate", "notes"],
    );
    assert_eq!(line["join"], join.as_str(), "the same group");
    second.wait_err(&format!("linked to the seed {first_seed}"));
    let dev = ["--profile", "dev-local", "--join", join.as_str()];
    let write = visitor(
        &scratch,
        "writer",
        &own,
        &[
            &dev[..],
            &[
                "write",
                "pair.Note#v1",
                "--space",
                "notes",
                "--json",
                r#"{"text":"through the second seed"}"#,
            ],
        ]
        .concat(),
    );
    assert!(write.status.success(), "{}", stderr(&write));
    let read = visitor(
        &scratch,
        "reader",
        &first_seed,
        &[
            &dev[..],
            &[
                "read",
                "pair.Note#v1",
                "--space",
                "notes",
                "--timeout",
                "15s",
            ],
        ]
        .concat(),
    );
    assert!(read.status.success(), "{}", stderr(&read));
    assert!(stdout(&read).contains("through the second seed"));
    stop(second);
    stop(first);
}

#[test]
fn listeners_come_from_flags_variables_or_the_file_and_refusals_name_them() {
    let scratch = Scratch::new("seed-config");
    let keys = scratch.path().join("seed").display().to_string();
    let refused = |global: &[&str], args: &[&str], env: &[(&str, &str)], names: &[&str]| {
        let mut command = bare_aspace(&scratch);
        for (name, value) in env {
            command.env(name, value);
        }
        command.args(global).arg("seed").args(args);
        let output = visit(command);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{global:?} {args:?}: {}",
            stderr(&output)
        );
        for name in names {
            assert!(
                stderr(&output).contains(name),
                "{name}: {}",
                stderr(&output)
            );
        }
    };
    let mtls = ["--keystore", keys.as_str()];
    let dev = ["--profile", "dev-local", "--keystore", keys.as_str()];
    // A plaintext listener outside loopback needs dev-local.
    refused(
        &mtls,
        &["--group", "g", "--listen", "tcp://0.0.0.0:7700"],
        &[],
        &["--listen", "dev-local"],
    );
    refused(
        &mtls,
        &["--group", "g"],
        &[("ASPACE_LISTEN", "ws://127.0.0.1:7700")],
        &["ASPACE_LISTEN", "tcp and tls"],
    );
    // Two listeners need the scheme in each advertisement.
    refused(
        &dev,
        &[
            "--group",
            "g",
            "--listen",
            "tcp://127.0.0.1:0",
            "--listen",
            "tls://127.0.0.1:0",
            "--advertise",
            "seed.example.com:7700",
        ],
        &[],
        &["--advertise", "scheme"],
    );
    refused(
        &dev,
        &["--group", "g", "--advertise", "tls://seed.example.com:7700"],
        &[],
        &["--advertise", "no listener serves it"],
    );
    // One group: the one founded, or the one named.
    refused(
        &dev,
        &["--found", "x", "--group", "g"],
        &[],
        &["--found", "--group"],
    );
    // Required attestation needs tls listeners.
    refused(
        &dev,
        &["--group", "g", "--require-attestation"],
        &[],
        &["--require-attestation", "tcp://127.0.0.1:7700"],
    );
    // An invite membership on a group founded from a text, from the fleet file.
    let file = scratch.write(
        "fleet.yaml",
        "agentspaces:\n  bind: 127.0.0.1:0\n  security:\n    profile: dev-local\n  groups:\n    \
         - name: shop\n      founding: shop-v1\n      membership: invite\n      spaces: [orders]\n",
        0o644,
    );
    let config = file.display().to_string();
    refused(
        &["--config", &config, "--keystore", &keys],
        &[],
        &[],
        &["agentspaces.groups[0].membership", "aspace seed --found"],
    );

    // The file's bind and advertise, and its group's spaces, make the seed.
    let file = scratch.write(
        "fleet2.yaml",
        "agentspaces:\n  bind: 127.0.0.1:0\n  advertise: localhost:7999\n  security:\n    \
         profile: dev-local\n  groups:\n    - name: shop\n      founding: shop-v1\n      \
         seeds: [ \"tcp://127.0.0.1:7999\" ]\n      spaces: [orders]\n",
        0o644,
    );
    let config = file.display().to_string();
    let (seed, line) = start_seed(&scratch, &["--config", &config, "--keystore", &keys], &[]);
    assert!(address(&line).starts_with("tcp://127.0.0.1:"), "{line}");
    assert_eq!(
        line["advertise"],
        serde_json::json!(["tcp://localhost:7999"])
    );
    stop(seed);
    // ASPACE_LISTEN over the file, --listen over ASPACE_LISTEN.
    let mut command = bare_aspace(&scratch);
    command.env("ASPACE_LISTEN", "tls://127.0.0.1:0").args([
        "--config",
        &config,
        "--keystore",
        &keys,
        "seed",
    ]);
    let mut seed = Running::spawn(command);
    let line = seed.out_until("the listening line", |json| json["event"] == "listening");
    assert!(address(&line).starts_with("tls://"), "{line}");
    assert_eq!(
        line["advertise"],
        serde_json::json!([]),
        "the file's is below the variable"
    );
    stop(seed);

    // A port in use: exit 1, naming the listener.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = busy.local_addr().expect("address").port();
    let mut command = bare_aspace(&scratch);
    command.args(dev).args([
        "seed",
        "--group",
        "g",
        "--listen",
        &format!("tcp://127.0.0.1:{port}"),
    ]);
    let output = visit(command);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("cannot listen"),
        "{}",
        stderr(&output)
    );
    drop(busy);
}
