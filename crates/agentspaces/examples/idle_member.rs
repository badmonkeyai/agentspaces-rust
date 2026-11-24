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

//! A dial-only Rust member for the mixed-language idle liveness run (members of every
//! implementation idle together for ten minutes, and none may leave a view): it joins a
//! founding-text group through one seed over plain TCP, names that seed in `relay.via` (learned
//! from the seed's first frame), and then stays idle, doing only what an idle member does on its
//! own.
//!
//! ```text
//! cargo run --example idle_member -- <host> <port[,port...]> <founding text>
//! ```
//!
//! Several ports are several seeds on the host, in list order (the stagger, the first to
//! answer wins, a lost seed fails over to the next, the lost one last).
//!
//! The line protocol, one line each way, as the Java `IdleMember` of `tools/conformance/mixed`:
//!
//! - on start it prints `READY <peerId>` once it has introduced itself;
//! - `view` prints `VIEW <peerId>=<member>,<member>,...` (the members it holds, itself left out);
//! - `counters` prints `COUNTERS <json-ish debug line>` (redials, seed pings, wall steps);
//! - `quit`, or the end of standard input, closes the peer and exits 0.
//!
//! Exits non-zero when the join fails.

use std::time::Duration;

use agentspaces::group::GroupSpec;
use agentspaces::peer::{Peer, PeerConfig, PeerEvent};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::seed::Seed;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [host, port, founding] = args.as_slice() else {
        eprintln!("usage: idle_member <host> <port[,port...]> <founding text>");
        std::process::exit(2);
    };
    let Ok(ports) = port
        .split(',')
        .map(str::parse::<u16>)
        .collect::<Result<Vec<u16>, _>>()
    else {
        eprintln!("idle_member: the port list {port} is not numbers");
        std::process::exit(2);
    };
    let identity = Identity::generate().expect("an identity");
    let mut config = PeerConfig::new(identity, GroupSpec::FoundingText(founding.clone()));
    config.seeds = ports
        .iter()
        .map(|port| Seed::new(host, *port, "tcp"))
        .collect();
    config.dialers = vec![std::sync::Arc::new(agentspaces::transport::tcp::TcpDialer)];
    let peer = match Peer::start(config).await {
        Ok(peer) => peer,
        Err(error) => {
            eprintln!("idle_member: the join failed: {error}");
            std::process::exit(1);
        }
    };
    let mut events = peer.subscribe();
    let watched = peer.peer_id().to_owned();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(PeerEvent::Disconnected) => eprintln!("idle_member {watched}: link lost"),
                Ok(PeerEvent::Reconnected { reconnects }) => {
                    eprintln!("idle_member {watched}: link back ({reconnects})");
                }
                Ok(PeerEvent::Unreachable) => {
                    eprintln!("idle_member {watched}: no seed for the reconnect window; redialing");
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
    // The seed's first frames carry its PeerID, which this member then names in relay.via.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The background writes of the live run: `write <n>` writes a mixed.Note#v1 {from: rust, n} into notes (1 min
    // lease), `notes` answers, per writer, the highest n held there. Pulling the space opens it.
    if let Err(error) = peer.pull_space(NOTES).await {
        eprintln!("idle_member: the pull of {NOTES} failed: {error}");
    }
    println!("READY {}", peer.peer_id());
    // Standard input on a thread of its own, one line at a time over a channel.
    let (lines_tx, mut lines) = tokio::sync::mpsc::channel::<String>(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if lines_tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = lines.recv().await {
        match line.trim() {
            "view" => {
                let me = peer.peer_id();
                let members: Vec<String> = peer
                    .members()
                    .await
                    .into_iter()
                    .filter(|member| member != me)
                    .collect();
                println!("VIEW {me}={}", members.join(","));
            }
            "counters" => {
                let counters = peer.counters().await;
                println!(
                    "COUNTERS reconnects={} windows_lapsed={} seed_pings={} wake_pings={} \
                     links_silent={} resumes={} seed_dials={} late_seed_channels={} wall_steps={}",
                    counters.reconnects,
                    counters.windows_lapsed,
                    counters.seed_pings,
                    counters.wake_pings,
                    counters.links_silent,
                    counters.resumes,
                    counters.seed_dials,
                    counters.late_seed_channels,
                    counters.wall_steps
                );
            }
            "notes" => println!("NOTES {}", notes(&peer).await),
            "quit" => break,
            write if write.starts_with("write ") => {
                let n: i64 = write["write ".len()..].trim().parse().unwrap_or(-1);
                let mut payload = Map::new();
                payload.insert("from", "rust");
                payload.insert("n", n);
                match peer
                    .write_entry(
                        NOTES,
                        NOTE_TYPE,
                        Value::Map(payload),
                        60_000,
                        Map::new(),
                        None,
                    )
                    .await
                {
                    Ok(_) => println!("WROTE {n}"),
                    Err(error) => println!("ERROR write {error}"),
                }
            }
            "" => {}
            other => eprintln!("idle_member: unknown command {other}"),
        }
    }
    let _ = peer.close().await;
}

const NOTES: &str = "notes";
const NOTE_TYPE: &str = "mixed.Note#v1";

/// Per writer, the highest `n` of the live notes held here, as `<from>:<n>` words.
async fn notes(peer: &Peer) -> String {
    let mut highest = std::collections::BTreeMap::<String, i128>::new();
    for state in peer.space_states(NOTES).await {
        if state.get("completed").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(Value::Map(record)) = state.get("record") else {
            continue;
        };
        if record.get("type").and_then(Value::as_str) != Some(NOTE_TYPE) {
            continue;
        }
        let Some(entry_id) = record.get("entryId").and_then(Value::as_str) else {
            continue;
        };
        let Some(Value::Map(note)) = peer
            .payload_of(NOTES, entry_id)
            .await
            .and_then(|bytes| cbor::decode(&bytes).ok())
        else {
            continue;
        };
        if let (Some(from), Some(Value::Int(n))) =
            (note.get("from").and_then(Value::as_str), note.get("n"))
        {
            let best = highest.entry(from.to_owned()).or_insert(-1);
            *best = (*best).max(*n);
        }
    }
    highest
        .into_iter()
        .map(|(from, n)| format!("{from}:{n}"))
        .collect::<Vec<_>>()
        .join(" ")
}
