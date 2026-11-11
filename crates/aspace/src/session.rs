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

//! A visitor's life: resolve the configuration, load the identity, join, wait until
//! linked and the space is pulled (bounded by `--join-timeout`), do one thing, make sure the seed
//! holds what was written, and close.
//!
//! # The daemon first
//!
//! Before it joins, a visitor command (`status`, `write`, `read`, `take`, `complete`, `watch`,
//! `cards`, `call`) asks the local `aspace daemon` ([`through_daemon`]): it resolves its
//! configuration and checks its arguments as it would before joining, then connects to the
//! daemon's socket (`--socket`, `ASPACE_SOCKET`, or the default in the user's runtime
//! directory) with a short timeout. When a daemon answers, runs as this user, and serves the
//! group of the visitor's configuration with the same keystore and a profile at least as
//! strict, the command runs on the daemon's peer, prints what it would have printed, and exits
//! with the code it would have exited with, saying nothing more. Otherwise it says why on
//! standard error, in one line (`no daemon answered at ...`), and joins itself, unless a daemon
//! of its group runs on its keystore (its hello, or the keystore's resident marker, says so):
//! a join of its own would then share the daemon's PeerID and see nothing, so it refuses, naming
//! the remedy (exit 2 for a weaker profile or another socket, exit 1 for a daemon that did not
//! answer or was busy). `--no-daemon`
//! (or `ASPACE_NO_DAEMON=1`) skips the daemon and says nothing. `id`, `work`, `doctor`,
//! `completions`, `man`, `daemon`, and `mcp` never use one (`work` and `mcp` are residents with
//! peers of their own).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentspaces::config::{self, Config, Origin};
use agentspaces::keystore::{self, KeystoreOptions};
use agentspaces::peer::{Peer, PeerError, PeerEvent};
use agentspaces::space::{Fleet, Space, Template};
use agentspaces::wire::identity::Identity;
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::cli::{Command, Global};
use crate::exit::Failure;

/// How long a visitor waits for the first state of a pulled space before it takes the space to
/// be empty.
const FIRST_FOLD: Duration = Duration::from_millis(1500);
/// How long the folds of a pull may pause before the pull counts as answered.
const QUIET: Duration = Duration::from_millis(300);
/// How often a confirmation pulls again while it waits.
const REPULL: Duration = Duration::from_secs(1);
/// How long a write waits for the seed to hold it before the visitor leaves.
pub const CONFIRM: Duration = Duration::from_secs(10);
/// How long a read or a take waits for the payload blocks of the entries it found (payloads
/// over 64 KiB, fetched from their writer or the seed).
const FETCH: Duration = Duration::from_secs(10);
/// How often a visitor looks whether its seed has spoken yet.
const SEED_POLL: Duration = Duration::from_millis(50);

static QUIET_NOTES: AtomicBool = AtomicBool::new(false);

/// Silences [`note`] (`--quiet`).
pub fn set_quiet(quiet: bool) {
    QUIET_NOTES.store(quiet, Ordering::Relaxed);
}

/// A diagnostic on standard error, `aspace: ` first, unless `--quiet`.
pub fn note(message: impl AsRef<str>) {
    if !QUIET_NOTES.load(Ordering::Relaxed) {
        say(&format!("aspace: {}", message.as_ref()));
    }
}

/// One line on standard error. A write that fails (a reader that went away, a terminal that
/// hung up) is ignored: a diagnostic never ends the process, nor a handler of `aspace work`.
pub fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// The process environment as the configuration reads it.
pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The configuration of `global` over the environment and the fleet file, with the default
/// keystore (`~/.config/agentspaces/keys`) when no layer names one, so takes and completions of
/// separate invocations share an identity.
pub fn resolve(global: &Global) -> Result<Config, Failure> {
    let mut config = Config::from_env(&global.overrides())?;
    if config.settings.keystore.is_none()
        && let Some(dir) = config::default_keystore(&env)
    {
        config.settings.keystore = Some(dir);
        config.origins.push(("keystore", Origin::Default));
    }
    Ok(config)
}

/// The keystore directory a command that needs a lasting identity runs with: `--keystore`,
/// `ASPACE_KEYSTORE`, the fleet file's `keystore`, else `~/.config/agentspaces/keys`; refused
/// (exit 2) when none is named and there is no `HOME`.
pub fn keystore_dir(global: &Global) -> Result<std::path::PathBuf, Failure> {
    keystore_with_origin(global).map(|(dir, _)| dir)
}

/// [`keystore_dir`] with where it was read.
pub fn keystore_with_origin(global: &Global) -> Result<(std::path::PathBuf, Origin), Failure> {
    match Config::keystore_from_vars(&global.overrides(), env)? {
        Some(found) => Ok(found),
        None => match config::default_keystore(&env) {
            Some(dir) => Ok((dir, Origin::Default)),
            None => Err(Failure::refused(
                "no keystore named and no HOME for the default ~/.config/agentspaces/keys; \
                 pass --keystore <dir> or set ASPACE_KEYSTORE",
            )),
        },
    }
}

/// The identity in `keystore` (loaded, or minted there), or a fresh one. A private key
/// readable by its group or others is refused (exit 4) unless `allow_readable`
/// (`--allow-readable-key`) or `ASPACE_ALLOW_READABLE_KEY` accepts it.
pub fn identity(keystore: Option<&Path>, allow_readable: bool) -> Result<Identity, Failure> {
    match keystore {
        Some(dir) => Ok(keystore::load_or_create_with(
            dir,
            keystore_options(allow_readable)?,
        )?),
        None => Identity::generate()
            .map_err(|error| Failure::error(format!("cannot mint an identity: {error}"))),
    }
}

/// The keystore options of `ASPACE_ALLOW_READABLE_KEY` with the `--allow-readable-key` flag over
/// them; a variable that is not a boolean is refused (exit 2), naming it.
pub fn keystore_options(allow_readable: bool) -> Result<KeystoreOptions, Failure> {
    KeystoreOptions::from_vars(env)
        .map(|options| options.allowing_readable(allow_readable))
        .map_err(|error| Failure::refused(error.to_string()))
}

/// The variable that skips the daemon, as `--no-daemon` does: `1`, `true`, `yes`, or `on`.
pub const ENV_NO_DAEMON: &str = "ASPACE_NO_DAEMON";

/// Whether this invocation skips the daemon: `--no-daemon`, or [`ENV_NO_DAEMON`] set true.
pub fn skips_daemon(global: &Global) -> bool {
    global.no_daemon
        || env(ENV_NO_DAEMON).is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

/// The visitor path (see the [module docs](self#the-daemon-first)): runs
/// `command` through a daemon that answers and serves its configuration, answering its outcome
/// (with the same output and exit code as a join of its own); `None` when the command never
/// uses one, `--no-daemon` skips it, or no suitable daemon answered (said on standard error, in
/// one line), and the command then joins itself. A refusal of the configuration or the
/// arguments is answered here, before any connection, exactly as the command answers it.
pub async fn through_daemon(global: &Global, command: &mut Command) -> Option<Result<(), Failure>> {
    if skips_daemon(global) {
        return None;
    }
    crate::daemon::visit(global, command).await
}

/// A joined visitor: the fleet, its configuration, and the deadline of the join.
pub struct Session {
    /// The fleet joined.
    pub fleet: Fleet,
    /// The configuration it was joined with.
    pub config: Config,
    /// When `--join-timeout` runs out, counted from the start of the join.
    pub deadline: Instant,
}

impl Session {
    /// Resolves the configuration, loads the identity, and joins: the seeds are dialed, a join by
    /// id fetches and verifies the founding, and the peer introduces itself, all within the join
    /// timeout (exit 3 past it).
    pub async fn join(global: &Global) -> Result<Session, Failure> {
        Session::join_with(global, resolve(global)?).await
    }

    /// [`Session::join`] with a configuration already resolved ([`resolve`]), so a command checks
    /// what it needs of it before dialing.
    pub async fn join_with(global: &Global, config: Config) -> Result<Session, Failure> {
        let identity = identity(
            config.settings.keystore.as_deref(),
            global.allow_readable_key,
        )?;
        if let Some(keystore) = config.settings.keystore.as_deref() {
            crate::resident::warn_if_shared(keystore);
        }
        let timeout = config.join_timeout;
        let mut peer_config = config.peer_config(identity)?;
        peer_config.dial_timeout = peer_config.dial_timeout.min(timeout);
        let started = Instant::now();
        let peer = match tokio::time::timeout(timeout, Peer::start(peer_config)).await {
            Ok(Ok(peer)) => peer,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(Failure::timeout(format!(
                    "the join of {} through {} did not complete within {}; check the seeds \
                     (aspace doctor), or give it longer with --join-timeout",
                    describe_group(&config),
                    seeds_text(&config),
                    millis_text(timeout)
                )));
            }
        };
        tracing::debug!(peer = peer.peer_id(), group = peer.group_id(), "joined");
        if config.invite.is_none()
            && let Some(founder) = invite_only(&peer).await
            && founder != peer.peer_id()
        {
            let _ = peer.close().await;
            return Err(Failure::auth(format!(
                "{} admits only invited peers (INVITE), and no invite was given: pass the invite \
                 key its founder printed (aspace invite) with --invite or ASPACE_INVITE",
                describe_group(&config)
            )));
        }
        Ok(Session {
            fleet: Fleet::from_peer(peer),
            config,
            deadline: started + timeout,
        })
    }

    /// The peer.
    pub fn peer(&self) -> &Peer {
        self.fleet.peer()
    }

    /// Pulls `space` and waits until its states stop arriving: the first within 1.5 s (an empty
    /// space answers nothing), then until they pause for 300 ms, all within the join deadline.
    pub async fn pull_and_settle(&self, space: &Space) -> Result<(), Failure> {
        pull_and_settle(self.peer(), space, self.deadline).await
    }

    /// Waits until every available entry of `template` in `space` (pulled and settled) can be
    /// read: an entry whose payload travels as a block (over 64 KiB) is passed over by reads
    /// until its block arrives from its writer or the seed. Gives up after 10 s with a note;
    /// what can be read then is read.
    pub async fn await_payloads(&self, space: &Space, template: &Template) -> Result<(), Failure> {
        let pending = await_payloads(self.peer(), space, template).await?;
        if pending > 0 {
            note(payloads_note(pending, template, space.name()));
        }
        Ok(())
    }

    /// Waits until the seed holds the states of `ids` in `space` as this peer last wrote them: a
    /// pull, whose answer carries back every state the seed holds, then the fold of each id's
    /// state from the answer (pulled again every second), up to `timeout`; and, for each of them
    /// whose payload travels as a block this peer holds (over 64 KiB), until the seed holds the
    /// block too ([`confirm_blocks`]). Closing a peer drops what it has not sent, so a visitor
    /// confirms before it leaves.
    pub async fn confirm(
        &self,
        space: &str,
        ids: &[String],
        timeout: Duration,
    ) -> Result<(), Failure> {
        confirm(self.peer(), space, ids, timeout).await
    }

    /// Closes the peer.
    pub async fn close(self) {
        if let Err(error) = self.fleet.close().await {
            tracing::debug!(%error, "close");
        }
    }
}

/// The founder of the group `peer` joined when its verified founding admits only invited peers
/// (`INVITE`); `None` for an open group, or one founded from a text.
async fn invite_only(peer: &Peer) -> Option<String> {
    let founding = peer.founding().await?;
    let ad = founding.get("advertisement")?;
    (ad.get("membershipPolicy")?.as_str()? == "INVITE")
        .then(|| {
            ad.get("issuer")
                .and_then(|issuer| issuer.as_str())
                .map(str::to_owned)
        })
        .flatten()
}

/// [`Session::pull_and_settle`] on any peer: pulls `space` and waits until its states stop
/// arriving, before `deadline`. Silence counts as an empty space only once the seed has spoken
/// ([`heard_from_seed`]): a seed that accepted the connection and never answered is a timeout
/// (exit 3), never "nothing matched".
pub async fn pull_and_settle(peer: &Peer, space: &Space, deadline: Instant) -> Result<(), Failure> {
    let mut events = peer.subscribe();
    space.pull().await?;
    settle(&mut events, space.name(), deadline).await;
    if !heard(peer).await {
        heard_from_seed(peer, deadline).await?;
        // The seed spoke late: what it holds may only now be arriving.
        space.pull().await?;
        settle(&mut events, space.name(), deadline).await;
    }
    Ok(())
}

/// Whether the peer has received a verified frame (its seed speaks the protocol).
async fn heard(peer: &Peer) -> bool {
    peer.counters().await.frames_received > 0
}

/// Waits, until `deadline`, for the seed's first verified frame. A transport that accepts the
/// connection is not a seed that answers (a proxy whose backend is down, a hung process): until
/// the seed speaks, silence says nothing of what the group holds.
///
/// # Errors
///
/// A timeout (exit 3) when nothing came.
pub async fn heard_from_seed(peer: &Peer, deadline: Instant) -> Result<(), Failure> {
    loop {
        if heard(peer).await {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            let at = peer
                .link()
                .map(|link| format!(" at {}://{}", link.scheme, link.remote))
                .unwrap_or_default();
            return Err(Failure::timeout(format!(
                "the seed{at} accepted the connection but sent nothing before the join timeout \
                 ran out, so nothing can be said of what the group holds (a seed of an INVITE \
                 group sends nothing to a peer it did not admit: pass an invite with --invite); \
                 check it with aspace doctor, or give it longer with --join-timeout"
            )));
        }
        tokio::time::sleep(SEED_POLL.min(deadline - now)).await;
    }
}

/// [`Session::await_payloads`] on any peer, answering how many entries' payloads were still
/// missing when it gave up (0 when every one arrived); the caller says so.
pub async fn await_payloads(
    peer: &Peer,
    space: &Space,
    template: &Template,
) -> Result<usize, Failure> {
    let deadline = Instant::now() + FETCH;
    let mut events = peer.subscribe();
    loop {
        let pending = space.pending_payloads(template).await?;
        if pending == 0 || Instant::now() >= deadline {
            return Ok(pending);
        }
        // A block arrived, or a second passed: look again (which asks again).
        let until = (Instant::now() + REPULL).min(deadline);
        loop {
            match tokio::time::timeout_at(until, events.recv()).await {
                Ok(Ok(PeerEvent::Block { .. }))
                | Ok(Err(broadcast::error::RecvError::Lagged(_)))
                | Err(_) => break,
                Ok(Ok(_)) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return Err(Failure::error(
                        "the peer closed while payloads were fetched",
                    ));
                }
            }
        }
    }
}

/// What a visitor says of `pending` entries whose payloads [`await_payloads`] could not fetch.
pub fn payloads_note(pending: usize, template: &Template, space: &str) -> String {
    format!(
        "{pending} entr{} of {} in {space}: the payload could not be fetched within {}",
        if pending == 1 { "y" } else { "ies" },
        template.schema(),
        millis_text(FETCH)
    )
}

/// The space a command names: `--space`, else the first space of the configured group, else a
/// refusal (exit 2), decided before the join.
pub fn space_name(config: &Config, flag: Option<&str>) -> Result<String, Failure> {
    if let Some(name) = flag.map(str::trim).filter(|name| !name.is_empty()) {
        return Ok(name.to_owned());
    }
    config.settings.spaces.first().cloned().ok_or_else(|| {
        Failure::refused(
            "no space named: pass --space, set ASPACE_SPACES, or list the group's spaces under \
             agentspaces.groups[].spaces in the fleet file",
        )
    })
}

/// [`Session::pull_and_settle`]'s wait, over events subscribed before the pull: the folds of
/// `space`.
pub async fn settle(events: &mut broadcast::Receiver<PeerEvent>, space: &str, deadline: Instant) {
    settle_on(events, deadline, |event| match event {
        PeerEvent::StateFolded { space: folded, .. }
        | PeerEvent::ClaimFolded { space: folded, .. } => folded == space,
        _ => false,
    })
    .await;
}

/// Waits for the events `counts` accepts to stop: the first within 1.5 s, then until they pause
/// for 300 ms, all before `deadline`.
pub async fn settle_on(
    events: &mut broadcast::Receiver<PeerEvent>,
    deadline: Instant,
    counts: impl Fn(&PeerEvent) -> bool,
) {
    let started = Instant::now();
    let mut until = (started + FIRST_FOLD).min(deadline);
    loop {
        match tokio::time::timeout_at(until, events.recv()).await {
            Ok(Ok(event)) if counts(&event) => {
                until = (Instant::now() + QUIET).min(deadline);
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break,
        }
    }
    tracing::debug!(waited = ?started.elapsed(), "settled");
}

/// [`Session::confirm`] over a peer.
pub async fn confirm(
    peer: &Peer,
    space: &str,
    ids: &[String],
    timeout: Duration,
) -> Result<(), Failure> {
    let mut pending: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    if pending.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    let mut events = peer.subscribe();
    confirm_states(peer, space, &mut pending, &mut events, deadline, timeout).await?;
    confirm_blocks(peer, space, ids, &mut events, deadline, timeout).await
}

/// The first wait of [`confirm`]: the seed's states of `pending`.
async fn confirm_states(
    peer: &Peer,
    space: &str,
    pending: &mut BTreeSet<&str>,
    events: &mut broadcast::Receiver<PeerEvent>,
    deadline: Instant,
    timeout: Duration,
) -> Result<(), Failure> {
    peer.pull_space(space).await?;
    let mut repull = Instant::now() + REPULL;
    while !pending.is_empty() {
        let until = repull.min(deadline);
        match tokio::time::timeout_at(until, events.recv()).await {
            Ok(Ok(PeerEvent::StateFolded {
                space: folded,
                entry_id,
                outcome,
            })) if folded == space && !outcome.is_refused() => {
                pending.remove(entry_id.as_str());
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                return Err(Failure::error("the peer closed before the seed confirmed"));
            }
            Err(_) if Instant::now() >= deadline => {
                return Err(Failure::timeout(format!(
                    "the seed did not confirm {} within {}; it may still arrive",
                    pending.iter().copied().collect::<Vec<_>>().join(", "),
                    millis_text(timeout)
                )));
            }
            Err(_) => {
                peer.pull_space(space).await?;
                repull = Instant::now() + REPULL;
            }
        }
    }
    Ok(())
}

/// The second wait of [`confirm`]: a payload over the inline limit travels as a block its
/// writer holds and serves, and the seed fetches it in the background once the state reached
/// it. Until the seed holds it, closing this peer would leave an entry no member can read, so
/// each such block of `ids` is asked of the seed ([`Peer::probe_block`]) until the seed answers
/// with it ([`PeerEvent::BlockHeld`]), at 1, 2, 4, ... seconds, before `deadline`.
async fn confirm_blocks(
    peer: &Peer,
    space: &str,
    ids: &[String],
    events: &mut broadcast::Receiver<PeerEvent>,
    deadline: Instant,
    timeout: Duration,
) -> Result<(), Failure> {
    let mut pending: Vec<(String, &str)> = Vec::new();
    for id in ids {
        if let Some(cid) = peer.own_payload_block(space, id).await
            && !pending.iter().any(|(held, _)| *held == cid)
        {
            pending.push((cid, id.as_str()));
        }
    }
    let mut pause = REPULL;
    let mut ask_at = Instant::now();
    while !pending.is_empty() {
        if Instant::now() >= ask_at {
            // The seed's PeerID is learned from its first frame to this peer.
            if let Some(seed) = peer.seed_peer().await {
                for (cid, _) in &pending {
                    match peer.probe_block(cid, &seed).await {
                        Ok(()) => {}
                        Err(PeerError::Closed) => {
                            return Err(Failure::error(
                                "the peer closed before the seed held the payload blocks",
                            ));
                        }
                        // No link at the moment, or a full queue: asked again at the next round.
                        Err(error) => tracing::debug!(%error, cid, "probe a block"),
                    }
                }
            }
            ask_at = Instant::now() + pause;
            pause = pause.saturating_mul(2);
        }
        match tokio::time::timeout_at(ask_at.min(deadline), events.recv()).await {
            Ok(Ok(PeerEvent::BlockHeld { cid, by })) => {
                if peer.seed_peer().await.as_deref() == Some(by.as_str()) {
                    pending.retain(|(held, _)| *held != cid);
                }
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                return Err(Failure::error(
                    "the peer closed before the seed held the payload blocks",
                ));
            }
            Err(_) if Instant::now() >= deadline => {
                return Err(Failure::timeout(format!(
                    "the seed did not fetch the payload of {} within {} (a payload over 64 KiB \
                     travels as a block its writer serves until another member holds it); \
                     members cannot read it until the seed does: run `aspace doctor`, and check \
                     that the seed keeps blocks",
                    pending
                        .iter()
                        .map(|(_, id)| *id)
                        .collect::<Vec<_>>()
                        .join(", "),
                    millis_text(timeout)
                )));
            }
            Err(_) => {}
        }
    }
    Ok(())
}

/// The group a configuration joins, for messages.
pub fn describe_group(config: &Config) -> String {
    let id = config
        .settings
        .group
        .group_id()
        .unwrap_or_else(|| "a founding document".to_owned());
    match &config.group_name {
        Some(name) => format!("group {name} ({id})"),
        None => format!("group {id}"),
    }
}

/// The seeds, comma-separated, for messages.
pub fn seeds_text(config: &Config) -> String {
    config
        .settings
        .seeds
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A duration as `1500ms` or `10s`.
pub fn millis_text(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis.is_multiple_of(1000) {
        format!("{}s", millis / 1000)
    } else {
        format!("{millis}ms")
    }
}
