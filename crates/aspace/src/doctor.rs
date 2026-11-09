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

//! `aspace doctor`: a self-test report. Where each setting came from (values that could be
//! secrets redacted), the keystore (present, `peer.key` owner-only), the daemon socket (its
//! directory owner-only, whether a daemon answers and serves this configuration), the files of
//! `aspace mcp` (a token file owner-only and well formed, a policy file no one else may write;
//! no token is ever shown), each seed (resolved, dialed, its TLS attestation), the join (the
//! founding verified), the clock (no frame refused as stale or ahead), and a golden self-check of
//! the encodings every member must agree on. Exits 1 when a check fails.

use std::path::Path;
use std::time::Duration;

use agentspaces::config::{self, Config};
use agentspaces::group::{GroupSpec, Profile};
use agentspaces::keystore;
use agentspaces::peer::{Peer, default_dialers};
use agentspaces::wire::cbor;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use serde_json::{Value as Json, json};

use crate::cli::Global;
use crate::commands::print_text;
use crate::exit::Failure;
use crate::io::print_line;
use crate::session;

/// How long one seed's dial may take in the report.
const DIAL: Duration = Duration::from_secs(5);

/// One line of the report.
#[derive(Debug, Clone)]
struct Check {
    name: String,
    /// `Some(true)` passed, `Some(false)` failed, `None` skipped (not measurable here).
    ok: Option<bool>,
    detail: String,
}

impl Check {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            ok: Some(true),
            detail: detail.into(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            ok: Some(false),
            detail: detail.into(),
        }
    }

    fn skip(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            ok: None,
            detail: detail.into(),
        }
    }
}

/// `aspace doctor`; `tokens` and `policy` are the MCP files to check (over `ASPACE_MCP_TOKENS`
/// and `ASPACE_MCP_POLICY`).
pub async fn doctor(
    global: &Global,
    as_json: bool,
    tokens: Option<&Path>,
    policy: Option<&Path>,
) -> Result<(), Failure> {
    let mut checks = vec![golden()];
    let config = match session::resolve(global) {
        Ok(config) => {
            checks.extend(config_checks(&config));
            Some(config)
        }
        Err(failure) => {
            checks.push(Check::fail("config", failure.message));
            None
        }
    };
    let identity = keystore_check(global, config.as_ref(), &mut checks);
    if let Some(config) = &config {
        checks.push(daemon_check(config).await);
    }
    checks.push(tokens_check(tokens));
    checks.push(policy_check(policy));
    if let Some(config) = &config {
        let dialing = match &identity {
            Some(identity) => identity.clone(),
            None => Identity::generate()
                .map_err(|error| Failure::error(format!("cannot mint an identity: {error}")))?,
        };
        let mut reached = false;
        for seed in &config.settings.seeds {
            let check = seed_check(seed, &dialing, config.join_timeout.min(DIAL)).await;
            reached |= check.ok == Some(true);
            checks.push(check);
        }
        if reached {
            checks.extend(join_checks(config, dialing).await);
        } else {
            checks.push(Check::skip(
                "join",
                "no seed answered, so no join was tried",
            ));
        }
    }
    let failed = checks
        .iter()
        .filter(|check| check.ok == Some(false))
        .count();
    // A reader that went away (a closed pipe) stops the report, not the verdict: the exit code
    // still says whether a check failed.
    let printed = if as_json {
        let report: Vec<Json> = checks
            .iter()
            .map(|check| json!({"check": check.name, "ok": check.ok, "detail": check.detail}))
            .collect();
        print_line(&json!({"ok": failed == 0, "checks": report}))
    } else {
        checks.iter().try_for_each(|check| {
            let mark = match check.ok {
                Some(true) => "ok  ",
                Some(false) => "FAIL",
                None => "skip",
            };
            print_text(&format!("{mark}  {:<18} {}", check.name, check.detail))
        })
    };
    match printed {
        Err(closed) if closed.code == crate::exit::SUCCESS => {}
        other => other?,
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(Failure::error(format!(
            "{failed} check{} failed",
            if failed == 1 { "" } else { "s" }
        )))
    }
}

/// Where each setting came from, its value redacted where it could be a secret.
fn config_checks(config: &Config) -> Vec<Check> {
    let origin = |name: &str| crate::commands::config_origin(config, name);
    let settings = &config.settings;
    let group = match &settings.group {
        GroupSpec::FoundingText(text) => format!(
            "a founding text ({} characters, redacted) -> {}",
            text.chars().count(),
            ids::group_id_from_founding(text.as_bytes())
        ),
        GroupSpec::Join(uri) => format!("join {uri}"),
        GroupSpec::FoundingDocument(bytes) => {
            format!("a founding document of {} bytes", bytes.len())
        }
    };
    let mut checks = vec![
        Check::pass(
            "config.file",
            match &config.file {
                Some(file) => format!("{} ({})", file.display(), origin("file")),
                None => "none: the flags and ASPACE_* variables only".to_owned(),
            },
        ),
        Check::pass(
            "config.group",
            format!(
                "{group}{} ({})",
                config
                    .group_name
                    .as_deref()
                    .map(|name| format!(", group {name}"))
                    .unwrap_or_default(),
                origin("group")
            ),
        ),
        Check::pass(
            "config.seeds",
            format!("{} ({})", session::seeds_text(config), origin("seeds")),
        ),
        Check::pass(
            "config.profile",
            format!(
                "{} ({})",
                match settings.profile {
                    Profile::DevLocal => "dev-local",
                    Profile::Mtls => "mtls",
                },
                origin("profile")
            ),
        ),
        Check::pass(
            "config.keystore",
            match &settings.keystore {
                Some(dir) => format!("{} ({})", dir.display(), origin("keystore")),
                None => "none: a fresh identity each run".to_owned(),
            },
        ),
        Check::pass(
            "config.spaces",
            if settings.spaces.is_empty() {
                "none (commands name theirs with --space)".to_owned()
            } else {
                format!("{} ({})", settings.spaces.join(", "), origin("spaces"))
            },
        ),
        Check::pass(
            "config.join",
            format!(
                "join timeout {} ({})",
                session::millis_text(config.join_timeout),
                origin("join_timeout")
            ),
        ),
    ];
    if let Some(socket) = &config.socket {
        checks.push(Check::pass(
            "config.socket",
            format!("{} ({})", socket.display(), origin("socket")),
        ));
    }
    if !config.ignored.is_empty() {
        checks.push(Check::pass(
            "config.ignored",
            format!("keys this peer does not use: {}", config.ignored.join(", ")),
        ));
    }
    checks
}

/// The keystore: present, `peer.key` owner-only, the identity loads. Never creates one.
fn keystore_check(
    global: &Global,
    config: Option<&Config>,
    checks: &mut Vec<Check>,
) -> Option<Identity> {
    let dir = match config {
        Some(config) => config.settings.keystore.clone(),
        None => config::Config::keystore_from_vars(&global.overrides(), session::env)
            .ok()
            .flatten()
            .map(|(dir, _)| dir)
            .or_else(|| config::default_keystore(&session::env)),
    };
    let Some(dir) = dir else {
        checks.push(Check::skip(
            "keystore",
            "none named: a fresh identity each run",
        ));
        return None;
    };
    let private = dir.join(keystore::PRIVATE_FILE);
    if !private.exists() {
        checks.push(Check::fail(
            "keystore",
            format!(
                "{} holds no identity yet; `aspace id` creates one",
                dir.display()
            ),
        ));
        return None;
    }
    let mode = file_mode(&private);
    match session::identity(Some(&dir), global.allow_readable_key) {
        Ok(identity) => {
            let owner_only = mode.is_some_and(|mode| mode & 0o077 == 0);
            let detail = format!(
                "{} PeerID {} (peer.key mode {})",
                dir.display(),
                identity.peer_id(),
                mode.map_or_else(|| "unknown".to_owned(), |mode| format!("{mode:04o}"))
            );
            checks.push(if owner_only {
                Check::pass("keystore", detail)
            } else {
                Check::fail(
                    "keystore",
                    format!("{detail}; run chmod 600 {}", private.display()),
                )
            });
            Some(identity)
        }
        Err(failure) => {
            checks.push(Check::fail("keystore", failure.message));
            None
        }
    }
}

fn file_mode(path: &Path) -> Option<u32> {
    crate::mcp::file_mode(path)
}

/// A mode as four octal digits, or `unknown`.
fn mode_text(mode: Option<u32>) -> String {
    mode.map_or_else(|| "unknown".to_owned(), |mode| format!("{mode:04o}"))
}

/// The daemon socket: where it is, whether its directory is owner-only
/// and the user's, and whether a daemon answers there and serves this configuration. No daemon
/// passes (visitors join themselves); an unsafe directory or socket, or something on the socket
/// that does not answer as a daemon, fails.
async fn daemon_check(config: &Config) -> Check {
    use crate::daemon::client::{self, NoDaemon};
    use crate::daemon::paths;
    const NAME: &str = "daemon";
    let socket = match client::socket_of(config) {
        Ok(socket) => socket,
        Err(failure) => return Check::fail(NAME, failure.message),
    };
    let origin = if config.socket.is_some() {
        crate::commands::config_origin(config, "socket")
    } else {
        "the default".to_owned()
    };
    let at = format!("{} ({origin})", socket.display());
    let uid = paths::own_uid();
    match paths::check_dir(&socket, uid) {
        Err(failure) => return Check::fail(NAME, format!("{at}: {}", failure.message)),
        Ok(false) => {
            return Check::pass(
                NAME,
                format!("{at}: no daemon; visitors join themselves (`aspace daemon` starts one)"),
            );
        }
        Ok(true) => {}
    }
    let dir = paths::socket_dir(&socket);
    let at = format!("{at}, directory mode {}", mode_text(file_mode(dir)));
    match client::connect(&socket, uid).await {
        Ok(connection) => {
            let hello = connection.hello();
            let who = format!(
                "a daemon answers (pid {}, peer {})",
                hello.pid, hello.peer_id
            );
            match connection.serves(config) {
                Ok(()) => Check::pass(
                    NAME,
                    format!("{at}: {who} and serves this configuration; visitors go through it"),
                ),
                Err(why) => Check::pass(
                    NAME,
                    format!("{at}: {who}, but it {why}; visitors join themselves"),
                ),
            }
        }
        Err(NoDaemon::Absent(_)) => Check::pass(
            NAME,
            format!("{at}: no daemon answers; visitors join themselves"),
        ),
        Err(NoDaemon::Unsafe(failure)) => Check::fail(NAME, failure.message),
        Err(other) => Check::fail(
            NAME,
            format!("{other}; stop what listens there, or restart the daemon with this aspace"),
        ),
    }
}

/// The token file of `aspace mcp --tokens`: owner-only and well formed.
/// Names the principals, never a token.
fn tokens_check(flag: Option<&Path>) -> Check {
    const NAME: &str = "mcp.tokens";
    let Some((path, origin)) = crate::mcp::named_file(flag, "--tokens", crate::mcp::ENV_MCP_TOKENS)
    else {
        return Check::skip(
            NAME,
            format!(
                "none named (aspace mcp --http --tokens FILE, or {})",
                crate::mcp::ENV_MCP_TOKENS
            ),
        );
    };
    let at = format!(
        "{} ({origin}, mode {})",
        path.display(),
        mode_text(file_mode(&path))
    );
    match agentspaces_mcp::StaticTokens::load(&path) {
        Ok(tokens) => Check::pass(
            NAME,
            format!(
                "{at}: {} token{} for {}",
                tokens.len(),
                if tokens.len() == 1 { "" } else { "s" },
                tokens
                    .principals()
                    .iter()
                    .map(|principal| crate::io::printable(principal))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Err(error) => Check::fail(NAME, error.to_string()),
    }
}

/// The policy file of `aspace mcp --policy`: writable by no one else, and a policy.
fn policy_check(flag: Option<&Path>) -> Check {
    const NAME: &str = "mcp.policy";
    let Some((path, origin)) = crate::mcp::named_file(flag, "--policy", crate::mcp::ENV_MCP_POLICY)
    else {
        return Check::skip(
            NAME,
            format!(
                "none named (aspace mcp --policy FILE, or {}): every caller may invoke every \
                 offering listed",
                crate::mcp::ENV_MCP_POLICY
            ),
        );
    };
    let at = format!(
        "{} ({origin}, mode {})",
        path.display(),
        mode_text(file_mode(&path))
    );
    match agentspaces_mcp::Policy::load(&path) {
        Ok(policy) => {
            let scopes = policy.scopes();
            let local = match policy.local_globs() {
                None => "everything".to_owned(),
                Some([]) => "nothing".to_owned(),
                Some(globs) => globs
                    .iter()
                    .map(|glob| crate::io::printable(glob))
                    .collect::<Vec<_>>()
                    .join(", "),
            };
            Check::pass(
                NAME,
                format!(
                    "{at}: {} scope{} ({}); a caller without a token may invoke {local}",
                    scopes.len(),
                    if scopes.len() == 1 { "" } else { "s" },
                    scopes
                        .iter()
                        .map(|scope| crate::io::printable(scope))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        }
        Err(error) => Check::fail(NAME, error.to_string()),
    }
}

/// One seed: its addresses, a dial, and what its handshake attested.
async fn seed_check(
    seed: &agentspaces::wire::seed::Seed,
    identity: &Identity,
    timeout: Duration,
) -> Check {
    let name = format!("seed {seed}");
    let addresses =
        match tokio::time::timeout(timeout, tokio::net::lookup_host(seed.address())).await {
            Ok(Ok(addresses)) => addresses.map(|a| a.to_string()).collect::<Vec<_>>(),
            Ok(Err(error)) => return Check::fail(name, format!("does not resolve: {error}")),
            Err(_) => return Check::fail(name, "did not resolve in time"),
        };
    let dialers = default_dialers();
    let Some(dialer) = dialers
        .iter()
        .find(|dialer| dialer.schemes().contains(&seed.scheme.as_str()))
    else {
        return Check::fail(name, format!("no dialer for {}", seed.scheme));
    };
    match dialer.dial(seed, identity, timeout).await {
        Ok(channel) => {
            let detail = match &channel.attested {
                Some(peer) => format!(
                    "resolves to {}; dialed; TLS attests {peer}",
                    addresses.join(", ")
                ),
                None => format!(
                    "resolves to {}; dialed; plaintext {} (frames signed, not encrypted)",
                    addresses.join(", "),
                    channel.scheme
                ),
            };
            channel.closer.close();
            Check::pass(name, detail)
        }
        Err(error) => Check::fail(
            name,
            format!(
                "resolves to {} but the dial failed: {error}",
                addresses.join(", ")
            ),
        ),
    }
}

/// The join: the founding verified, the seed's member list, and the clock.
async fn join_checks(config: &Config, identity: Identity) -> Vec<Check> {
    let mut peer_config = match config.peer_config(identity) {
        Ok(peer_config) => peer_config,
        Err(error) => return vec![Check::fail("join", error.to_string())],
    };
    peer_config.dial_timeout = peer_config.dial_timeout.min(config.join_timeout);
    let peer = match tokio::time::timeout(config.join_timeout, Peer::start(peer_config)).await {
        Ok(Ok(peer)) => peer,
        Ok(Err(error)) => return vec![Check::fail("join", error.to_string())],
        Err(_) => {
            return vec![Check::fail(
                "join",
                format!(
                    "did not complete within {}",
                    session::millis_text(config.join_timeout)
                ),
            )];
        }
    };
    let founding = match &config.settings.group {
        GroupSpec::Join(_) if peer.founding().await.is_some() => {
            "the signed founding advertisement verified against the id".to_owned()
        }
        GroupSpec::Join(_) => "joined by id".to_owned(),
        GroupSpec::FoundingDocument(_) => "the founding document verified here".to_owned(),
        GroupSpec::FoundingText(_) => {
            "a group founded from text (no signed founding to verify)".to_owned()
        }
    };
    // Give the seed a moment to address a frame to this peer, so its PeerID and the clock's
    // view of its frames are known.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while (peer.seed_peer().await.is_none() || peer.members().await.is_empty())
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seed = peer.seed_peer().await;
    let members = peer.members().await;
    let counters = peer.counters().await;
    let mut checks = vec![Check::pass(
        "join",
        format!(
            "joined {} through {}: {founding}; {} member{} heard",
            peer.group_id(),
            seed.as_deref().unwrap_or("the seed"),
            members.len(),
            if members.len() == 1 { "" } else { "s" }
        ),
    )];
    let skewed = counters.filter.stale + counters.filter.ahead;
    checks.push(if skewed == 0 {
        Check::pass(
            "clock",
            "no frame was refused as stale or ahead (the offset itself is not measured)",
        )
    } else {
        Check::fail(
            "clock",
            format!(
                "{} frames refused as stale and {} as ahead: this clock and the seed's disagree; \
                 check NTP",
                counters.filter.stale, counters.filter.ahead
            ),
        )
    });
    if let Err(error) = peer.close().await {
        tracing::debug!(%error, "close");
    }
    checks
}

/// The golden self-check: the PeerID of a known key, a GroupID of a known founding text, the
/// CBOR of a known payload as JSON writes it, and a known signature (the vectors of the SPEC's
/// golden file every member is checked against).
fn golden() -> Check {
    const PRIVATE_KEY: &str = "302e020100300506032b65700422042006753ee25c2885e8d0a043effb7d19bc\
                               597f1d7185525e3c96f23d5abdfff829";
    const PEER_ID: &str = "z6M1N9PyyHGkJfLZRmQ4VjAypZUi5uuUm8UDMHK1YfieJ";
    const GROUP_ID: &str = "zBQJtZ4UK3uLsxZe6Tz9PEnCrbtp3mDH2jf4hHavarmom";
    const TASK_CBOR: &str = "bf65746f7069636e676f6c64656e20766563746f7273687072696f7269747903ff";
    const MESSAGE: &[u8] = b"aspace doctor golden self-check";
    const SIGNATURE: &str = "e62e736c1631415a642c2df42d1a9ee44091cbf77e5bd977c665062583cae667\
                             e01a5037b2f4010d6c0ce1567e9e4f5003566bf2ce07c60e3786b7c711423801";
    let mut wrong = Vec::new();
    match hex(PRIVATE_KEY).and_then(|der| Identity::from_pkcs8(&der).ok()) {
        Some(identity) => {
            if identity.peer_id() != PEER_ID {
                wrong.push("the PeerID of the golden key");
            }
            let signature = identity.sign(MESSAGE);
            if hex(SIGNATURE).as_deref() != Some(signature.as_slice()) {
                wrong.push("the Ed25519 signature");
            }
            if !Identity::verify(identity.public_raw(), MESSAGE, &signature) {
                wrong.push("the signature's verification");
            }
        }
        None => wrong.push("the golden key's PKCS#8 form"),
    }
    if ids::group_id_from_founding(b"research-fleet-demo-v1") != GROUP_ID {
        wrong.push("the GroupID of a founding text");
    }
    let task = json!({"topic": "golden vectors", "priority": 3});
    match agentspaces::json::json_to_value(&task, None) {
        Ok(value) if hex(TASK_CBOR).as_deref() == Some(cbor::encode(&value).as_slice()) => {}
        _ => wrong.push("the CBOR of a JSON payload"),
    }
    if wrong.is_empty() {
        Check::pass(
            "golden",
            "PeerID, Ed25519 signature, GroupID, and payload CBOR match the golden vectors",
        )
    } else {
        Check::fail("golden", format!("wrong: {}", wrong.join(", ")))
    }
}

/// Bytes from hex (whitespace ignored).
fn hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair[1])
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_golden_self_check_passes() {
        let check = golden();
        assert_eq!(check.ok, Some(true), "{}", check.detail);
        assert_eq!(hex("0aff"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex("0g"), None);
        assert_eq!(hex("abc"), None);
    }
}
