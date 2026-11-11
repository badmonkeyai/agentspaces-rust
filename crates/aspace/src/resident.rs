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

//! The residents, `aspace work`, `aspace daemon`, `aspace mcp`, and `aspace seed`: what they
//! share.
//!
//! One keystore is one PeerID, and a seed takes every link of one PeerID for one member: a
//! visitor (or a second resident) that runs from the keystore of a running resident joins as
//! that member a second time, and the seed then shows it no members, cards, or entries of its
//! own. A resident marks the keystore it runs from (a `.aspace-resident-<pid>` file beside
//! `peer.key`, naming its command, removed when it stops), so every later invocation on the
//! keystore says why it may see nothing, and how to fix it (another keystore; visitors that go
//! through `aspace daemon` share its peer instead). A marker whose process is gone (a crash) is
//! ignored. A daemon's marker also names its group and its socket ([`daemons_on`]), so a visitor
//! that cannot use it (no answer, a busy daemon, another socket) refuses to join the group with
//! the daemon's PeerID instead of answering "nothing matched" from a join that sees nothing.
//!
//! Every resident also follows its link ([`watch_link`]): a lost link and its return are said on
//! standard error, and a peer that gives up redialing stops the resident.

use std::path::{Path, PathBuf};

use agentspaces::peer::PeerEvent;
use rustix::process::{Pid, getpid, test_kill_process};
use tokio::sync::{broadcast, watch};

use crate::session::note;

/// The prefix of a resident's marker file in the keystore directory.
const MARKER: &str = ".aspace-resident-";

/// The most of a marker's body read (its command, then a daemon's group and socket).
const MAX_MARKER_BODY: u64 = 4096;

/// A resident's mark on its keystore, removed when dropped.
#[derive(Debug)]
pub struct Resident {
    path: PathBuf,
}

impl Resident {
    /// Marks `keystore` as used by this process, running `command` (`aspace work`, `aspace
    /// daemon`, `aspace mcp`); `None` (said at debug level) when the marker cannot be written,
    /// which only costs the warning of later invocations.
    pub fn mark(keystore: &Path, command: &str) -> Option<Resident> {
        Resident::mark_with(keystore, command, &[])
    }

    /// [`Resident::mark`] with `details` after the command, one `<key> <value>` line each (a
    /// daemon's `group` and `socket`).
    pub fn mark_with(keystore: &Path, command: &str, details: &[(&str, &str)]) -> Option<Resident> {
        let path = keystore.join(format!("{MARKER}{}", getpid().as_raw_nonzero()));
        let mut body = format!("{command}\n");
        for (key, value) in details {
            if !value.contains('\n') {
                body.push_str(&format!("{key} {value}\n"));
            }
        }
        match std::fs::write(&path, body) {
            Ok(()) => Some(Resident { path }),
            Err(error) => {
                tracing::debug!(%error, path = %path.display(), "cannot mark the keystore");
                None
            }
        }
    }
}

impl Drop for Resident {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The live residents of `keystore` other than this process: each one's pid and the command its
/// marker names (`aspace work` for a marker of an earlier release, which named none).
pub fn others_running(keystore: &Path) -> Vec<(i32, String)> {
    let Ok(entries) = std::fs::read_dir(keystore) else {
        return Vec::new();
    };
    let me = getpid().as_raw_nonzero().get();
    let mut found: Vec<(i32, String)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(MARKER))
                .and_then(|pid| pid.parse::<i32>().ok())?;
            Some((pid, entry.path()))
        })
        .filter(|(pid, _)| *pid != me && alive(*pid))
        .map(|(pid, path)| (pid, marker_command(&path)))
        .collect();
    found.sort_unstable();
    found
}

/// The command a marker names: its first line, made printable, when it is one of `aspace`'s.
fn marker_command(path: &Path) -> String {
    marker_body(path).0
}

/// A marker's command (as [`marker_command`]) and its `<key> <value>` detail lines.
fn marker_body(path: &Path) -> (String, Vec<(String, String)>) {
    use std::io::Read as _;
    let mut body = String::new();
    let read = std::fs::File::open(path)
        .and_then(|file| file.take(MAX_MARKER_BODY).read_to_string(&mut body));
    let mut lines = body.lines();
    let line = lines.next().unwrap_or_default().trim();
    let command = match line {
        "aspace work" | "aspace daemon" | "aspace mcp" | "aspace seed" if read.is_ok() => {
            line.to_owned()
        }
        _ => "aspace work".to_owned(),
    };
    let details = lines
        .filter_map(|line| line.split_once(' '))
        .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        .collect();
    (command, details)
}

/// A running `aspace daemon` on a keystore, as its marker names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonMark {
    /// Its process id.
    pub pid: i32,
    /// The GroupID it serves, when its marker names one.
    pub group: Option<String>,
    /// The socket it listens on, when its marker names one.
    pub socket: Option<String>,
}

/// The live `aspace daemon` residents of `keystore` other than this process.
pub fn daemons_on(keystore: &Path) -> Vec<DaemonMark> {
    let Ok(entries) = std::fs::read_dir(keystore) else {
        return Vec::new();
    };
    let me = getpid().as_raw_nonzero().get();
    let mut found: Vec<DaemonMark> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(MARKER))
                .and_then(|pid| pid.parse::<i32>().ok())?;
            (pid != me && alive(pid)).then(|| (pid, entry.path()))
        })
        .filter_map(|(pid, path)| {
            let (command, details) = marker_body(&path);
            let detail = |key: &str| {
                details
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            };
            (command == "aspace daemon").then(|| DaemonMark {
                pid,
                group: detail("group"),
                socket: detail("socket"),
            })
        })
        .collect();
    found.sort_unstable_by_key(|mark| mark.pid);
    found
}

/// Whether process `pid` exists (a process of another user counts).
fn alive(pid: i32) -> bool {
    match Pid::from_raw(pid) {
        Some(pid) => match test_kill_process(pid) {
            Ok(()) => true,
            Err(error) => error == rustix::io::Errno::PERM,
        },
        None => false,
    }
}

/// Says, on standard error, that `keystore` is a running resident's, when it is.
pub fn warn_if_shared(keystore: &Path) {
    let running = others_running(keystore);
    if running.is_empty() {
        return;
    }
    let who = running
        .iter()
        .map(|(pid, command)| format!("`{command}` (pid {pid})"))
        .collect::<Vec<_>>()
        .join(", ");
    let a = if running.len() == 1 {
        "a running"
    } else {
        "running"
    };
    note(format!(
        "{a} {who} is a member with this keystore's PeerID ({}); the seed takes both for one \
         member, so this one may see no members, cards, or entries. Give one of them a keystore \
         of its own (--keystore DIR)",
        keystore.display()
    ));
}

/// Follows a resident's link: a lost link and its return are said on standard error, and
/// `gave_up` turns true when the peer gives up redialing its seeds (its reconnect window ran
/// out), which stops the resident.
pub async fn watch_link(mut events: broadcast::Receiver<PeerEvent>, gave_up: watch::Sender<bool>) {
    loop {
        match events.recv().await {
            Ok(PeerEvent::Disconnected) => note("the link to the seed is lost; redialing"),
            Ok(PeerEvent::Reconnected { .. }) => note("the link to the seed is back"),
            Ok(PeerEvent::GaveUp) => {
                note("the peer gave up redialing the seeds; stopping");
                gave_up.send_replace(true);
                return;
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_of_live_processes_count_and_their_own_and_dead_ones_do_not() {
        let dir = std::env::temp_dir().join(format!("aspace-resident-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        assert!(others_running(&dir).is_empty());
        let mark = Resident::mark(&dir, "aspace daemon").expect("marked");
        assert!(
            others_running(&dir).is_empty(),
            "this process's own mark is not another's"
        );
        assert_eq!(
            marker_command(&mark.path),
            "aspace daemon",
            "the mark names its command"
        );
        // pid 1 (launchd or init) is alive; a pid far past any limit is not.
        std::fs::write(dir.join(format!("{MARKER}1")), b"").expect("marker");
        std::fs::write(dir.join(format!("{MARKER}2147483646")), b"").expect("marker");
        std::fs::write(dir.join(format!("{MARKER}nonsense")), b"").expect("marker");
        // A marker of an earlier release (or of anything else) reads as `aspace work`.
        assert_eq!(others_running(&dir), [(1, "aspace work".to_owned())]);
        std::fs::write(dir.join(format!("{MARKER}1")), b"aspace mcp\n").expect("marker");
        assert_eq!(others_running(&dir), [(1, "aspace mcp".to_owned())]);
        std::fs::write(dir.join(format!("{MARKER}1")), b"\x1b[2Jrm -rf\n").expect("marker");
        assert_eq!(others_running(&dir), [(1, "aspace work".to_owned())]);
        // A daemon's marker names its group and socket; other residents' are not daemons.
        let daemon = dir.join(format!("{MARKER}1"));
        std::fs::write(
            &daemon,
            b"aspace daemon\ngroup zGroup\nsocket /run/aspace/daemon.sock\n",
        )
        .expect("marker");
        assert_eq!(
            daemons_on(&dir),
            [DaemonMark {
                pid: 1,
                group: Some("zGroup".to_owned()),
                socket: Some("/run/aspace/daemon.sock".to_owned()),
            }]
        );
        assert_eq!(others_running(&dir), [(1, "aspace daemon".to_owned())]);
        std::fs::write(&daemon, b"aspace work\n").expect("marker");
        assert!(daemons_on(&dir).is_empty());
        let own =
            Resident::mark_with(&dir, "aspace daemon", &[("group", "zMine")]).expect("marked");
        assert!(
            daemons_on(&dir).is_empty(),
            "this process's own mark is not another's"
        );
        assert_eq!(
            marker_body(&own.path).1,
            [("group".to_owned(), "zMine".to_owned())]
        );
        drop(own);
        let path = mark.path.clone();
        drop(mark);
        assert!(
            !path.exists(),
            "the mark is removed when the resident stops"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
