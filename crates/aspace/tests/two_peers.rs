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

//! The two-peer example (`examples/two-peers`) end to end, with this build's `aspace` and
//! nothing else: its `verify.sh` runs `two-peers.sh` (a seed founded by `aspace seed`, a writer,
//! an `aspace work` worker, a caller, and a late visitor, on a port the system chooses) and
//! checks every step of its transcript. No Java, Node, Python, or Ruby is needed, so this runs on
//! a plain CI runner.

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The longest the example may take (it takes a few seconds).
const LIMIT: Duration = Duration::from_secs(150);

#[test]
fn the_two_peer_example_verifies() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/two-peers");
    let scratch = std::env::temp_dir().join(format!("aspace-two-peers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");
    let log = scratch.join("transcript.log");
    let mut command = Command::new("/bin/sh");
    command
        .arg(example.join("verify.sh"))
        .env("ASPACE", env!("CARGO_BIN_EXE_aspace"))
        .env("PORT", "0")
        .env("TMPDIR", &scratch)
        .env("LOG", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A group of its own: a timeout ends the script and every process it started.
        .process_group(0);
    for variable in [
        "ASPACE_CONFIG",
        "ASPACE_SEEDS",
        "ASPACE_GROUP",
        "ASPACE_JOIN",
        "ASPACE_INVITE",
        "ASPACE_KEYSTORE",
        "ASPACE_PROFILE",
        "ASPACE_SPACES",
        "ASPACE_SOCKET",
        "ASPACE_LISTEN",
        "ASPACE_ADVERTISE",
        "KEEP",
    ] {
        command.env_remove(variable);
    }
    let mut child = command.spawn().expect("verify.sh starts");
    // Read both pipes on threads of their own, so a long transcript never blocks the script.
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_string(&mut text);
            }
            text
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
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            if let Some(group) = i32::try_from(child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            let transcript = std::fs::read_to_string(&log).unwrap_or_default();
            let _ = std::fs::remove_dir_all(&scratch);
            panic!("verify.sh did not finish within {LIMIT:?}:\n{transcript}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        status.success(),
        "verify.sh exited with {status}:\n{stdout}\n{stderr}"
    );
    assert!(stdout.contains("two peers: ok"), "{stdout}");
}
