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

//! `aspace seed` and `aspace invite`: a listening member that serves one group, and the invite
//! keys of a group it founded.
//!
//! # The seed
//!
//! The seed resolves a listening configuration ([`Overrides::listening`]): the listeners from
//! `--listen`, `ASPACE_LISTEN`, or the fleet file's `bind` (by default `127.0.0.1:7700`), what
//! they advertise, and the group: one it founds (`--found NAME`, a signed founding kept beside
//! the keystore with [`group::found_or_load`], so a restart keeps the GroupID), one founded from
//! a text (`--group`), another seed's (`--join` with `--seeds`), or the fleet file's. It needs no
//! seed of its own; the seeds it is given, less its own address, are redialed for as long as it
//! runs. It replicates the spaces `--replicate` names (else the group's), and every space it
//! hears of up to `--max-spaces`, each bounded as every space is.
//!
//! Once its listeners are bound it prints one JSON line on standard output, `{"event":
//! "listening", "peer", "group", "join", "listen", "advertise", "membership"}`, and from then on
//! says on standard error whom it admits. SIGINT, SIGTERM, or SIGHUP stops it: it stops
//! accepting, gives its links [`DRAIN`] to send what they queued ([`Peer::drain`]), and closes,
//! with exit 0; a second signal closes at once.
//!
//! # Invites
//!
//! `aspace invite --found NAME` runs with the founder's keystore: it loads the founding (an
//! `INVITE` group's), mints a fresh invite key, signs a delegation of it to the group valid for
//! `--not-after`, and prints the key (`aspace-inv1-...`) with its delegation. A joiner passes it
//! with `--invite` or `ASPACE_INVITE` on any command: the configuration signs the joiner's PeerID
//! under it and presents the credential as the `aspace:join` resource hint (SPEC §5.1).

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentspaces::clock::{Clock, SystemClock};
use agentspaces::config::{self, Config, FleetFile, Founded, ListenAddress, Overrides};
use agentspaces::group::{self, Charter, GroupError, GroupSpec, MembershipPolicy};
use agentspaces::keystore;
use agentspaces::peer::{Peer, PeerError, PeerEvent};
use agentspaces::wire::seed::{self as wire_seed, Seed};
use agentspaces::wire::social::{self, GroupSecret, InviteKey};
use agentspaces::wire::{ids, time};
use serde_json::{Value as Json, json};
use tokio::sync::broadcast;

use crate::cli::Global;
use crate::exit::{Failure, SUCCESS};
use crate::io::print_line;
use crate::resident::Resident;
use crate::session::{self, note};
use crate::signals::Stop;

/// How long the links may send what they queued once the seed stops.
pub const DRAIN: Duration = Duration::from_secs(2);

/// What `aspace seed` was asked.
#[derive(Debug, Clone, Default)]
pub struct SeedOptions {
    /// `--listen`.
    pub listen: Vec<String>,
    /// `--advertise`.
    pub advertise: Vec<String>,
    /// `--found`.
    pub found: Option<String>,
    /// `--membership`.
    pub membership: Option<MembershipPolicy>,
    /// `--replicate`.
    pub replicate: Vec<String>,
    /// `--max-spaces`.
    pub max_spaces: u16,
    /// `--require-attestation`.
    pub require_attestation: bool,
}

/// `aspace seed`: listen and serve the group until interrupted.
pub async fn seed(global: &Global, options: SeedOptions) -> Result<(), Failure> {
    let mut overrides = global.overrides();
    overrides.listening = true;
    overrides.listen = options.listen.clone();
    overrides.advertise = options.advertise.clone();
    let keystore_dir = session::keystore_dir(global)?;
    let identity = session::identity(Some(&keystore_dir), global.allow_readable_key)?;
    crate::resident::warn_if_shared(&keystore_dir);
    if let Some(name) = &options.found {
        let document = found(
            &overrides,
            &keystore_dir,
            &identity,
            name,
            options.membership,
        )?;
        overrides.founded = Some(Founded {
            name: name.clone(),
            document,
        });
    }
    let mut config = Config::from_env(&overrides)?;
    if config.settings.keystore.is_none() {
        config.settings.keystore = Some(keystore_dir.clone());
    }
    check_membership(&config)?;
    if options.require_attestation
        && let Some(plain) = config
            .listen
            .iter()
            .find(|listener| listener.scheme != "tls")
    {
        return Err(Failure::refused(format!(
            "--require-attestation admits only members whose link attests them, and the listener \
             {} ({}) attests nobody; listen on tls://",
            plain.uri(),
            plain.origin
        )));
    }

    let mut peer_config = config.peer_config(identity)?;
    let before = peer_config.seeds.len();
    peer_config
        .seeds
        .retain(|seed| !config.listen.iter().any(|own| same_address(seed, own)));
    if peer_config.seeds.len() < before {
        tracing::info!("skipping this seed's own address among its seeds");
    }
    // A seed keeps linking to the others for as long as it runs (the peer clamps it to a year).
    peer_config.reconnect_window = Duration::MAX;
    peer_config.listen.replicate = if options.replicate.is_empty() {
        config.settings.spaces.clone()
    } else {
        let mut spaces: Vec<String> = Vec::new();
        for space in options.replicate.iter().map(|space| space.trim()) {
            if !space.is_empty() && !spaces.iter().any(|known| known == space) {
                spaces.push(space.to_owned());
            }
        }
        spaces
    };
    peer_config.listen.max_replicated_spaces = usize::from(options.max_spaces);
    peer_config.listen.require_attestation = options.require_attestation;
    let upstream = !peer_config.seeds.is_empty();

    let _mark = Resident::mark(&keystore_dir, "aspace seed");
    let mut stop = Stop::new()?;
    let peer = tokio::select! {
        started = Peer::start(peer_config) => started.map_err(|error| start_failure(error, &config))?,
        () = stop.requested() => return Ok(()),
    };
    let founding = peer.founding().await;
    let membership = founding
        .as_ref()
        .and_then(|signed| signed.get("advertisement"))
        .and_then(|ad| ad.get("membershipPolicy"))
        .and_then(|policy| policy.as_str())
        .unwrap_or("OPEN")
        .to_owned();
    let join = founding
        .is_some()
        .then(|| format!("{}{}", ids::URI_PREFIX, peer.group_id()));
    let listen: Vec<String> = peer
        .listen_addrs()
        .iter()
        .map(ToString::to_string)
        .collect();
    let advertise: Vec<String> = config
        .listen
        .iter()
        .filter_map(|listener| {
            listener
                .advertise
                .as_ref()
                .map(|address| format!("{}://{address}", listener.scheme))
        })
        .collect();
    let line = json!({
        "event": "listening",
        "peer": peer.peer_id(),
        "group": peer.group_id(),
        "join": join,
        "listen": listen,
        "advertise": advertise,
        "membership": membership,
    });
    if let Err(failure) = print_line(&line) {
        // Standard output closed (a reader that took the line and left): the seed serves on.
        if failure.code != SUCCESS {
            let _ = peer.close().await;
            return Err(failure);
        }
    }
    note(listening_note(&config, &peer, join.as_deref(), &listen));

    let mut events = peer.subscribe();
    if let Some(link) = peer.link() {
        note(format!(
            "linked to the seed {}://{}",
            link.scheme, link.remote
        ));
    } else if upstream {
        note("no other seed answered yet; serving on and redialing");
    }
    let outcome = serve(&peer, &mut events, &mut stop, upstream).await;
    note("stopping: no new links; the links send what they queued");
    tokio::select! {
        drained = peer.drain(DRAIN) => {
            if !matches!(drained, Ok(true)) {
                tracing::debug!(?drained, "the links did not send everything they queued");
            }
        }
        () = stop.requested() => {}
    }
    let _ = peer.close().await;
    note("stopped");
    outcome
}

/// Serves until a stop is requested: says whom the seed admits, and its upstream link's losses.
async fn serve(
    peer: &Peer,
    events: &mut broadcast::Receiver<PeerEvent>,
    stop: &mut Stop,
    upstream: bool,
) -> Result<(), Failure> {
    loop {
        tokio::select! {
            () = stop.requested() => return Ok(()),
            event = events.recv() => match event {
                Ok(PeerEvent::Admitted { peer: member }) => note(format!("admitted {member}")),
                Ok(PeerEvent::Connected(link)) if upstream => {
                    note(format!("linked to the seed {}://{}", link.scheme, link.remote));
                }
                Ok(PeerEvent::Disconnected) if upstream => {
                    note("the link to the seed is lost; serving on and redialing");
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(Failure::error(format!(
                        "the seed's peer {} closed",
                        peer.peer_id()
                    )));
                }
            },
        }
    }
}

/// What the seed says on standard error once it listens: where, and how members join.
fn listening_note(config: &Config, peer: &Peer, join: Option<&str>, listen: &[String]) -> String {
    let name = config
        .group_name
        .clone()
        .or_else(|| match &config.settings.group {
            GroupSpec::FoundingDocument(document) => group::founding_name(document),
            GroupSpec::FoundingText(text) => Some(text.clone()),
            GroupSpec::Join(_) => None,
        })
        .map(|name| format!("{name} "))
        .unwrap_or_default();
    let seeds = listen.join(",");
    let how = match (join, &config.settings.group) {
        (Some(join), _) => format!("--seeds {seeds} --join {join}"),
        (None, GroupSpec::FoundingText(text)) => format!("--seeds {seeds} --group {text:?}"),
        (None, _) => format!("--seeds {seeds}"),
    };
    format!(
        "seed of group {name}({}) listening on {}; members join with {how}",
        peer.group_id(),
        listen.join(", ")
    )
}

/// The failure of a start: a listener that cannot bind names the listeners and the fix.
fn start_failure(error: PeerError, config: &Config) -> Failure {
    match error {
        PeerError::Listen(transport) => Failure::error(format!(
            "cannot listen on {}: {transport}; another process may hold the port: pass \
             --listen (port 0 lets the system choose)",
            config
                .listen
                .iter()
                .map(ListenAddress::uri)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        other => other.into(),
    }
}

/// Whether `seed` is one of this seed's own listeners: the same scheme, and the address it binds
/// or advertises (the same port, and the same host, or a loopback host where the listener binds
/// loopback or every interface).
fn same_address(seed: &Seed, own: &ListenAddress) -> bool {
    if !seed.scheme.eq_ignore_ascii_case(&own.scheme) {
        return false;
    }
    let matches = |address: &str| {
        wire_seed::seed_address(address).is_ok_and(|(host, port)| {
            let wildcard = matches!(host.as_str(), "0.0.0.0" | "::");
            port != 0
                && seed.port == port
                && (seed.host.eq_ignore_ascii_case(&host)
                    || (config::is_loopback_host(&seed.host)
                        && (wildcard || config::is_loopback_host(&host))))
        })
    };
    matches(&own.bind) || own.advertise.as_deref().is_some_and(matches)
}

/// A group of the file a seed does not found itself must be able to carry the membership the
/// file names: a group founded from a text has no signed founding, so it is open; a founding
/// document carries its own policy.
fn check_membership(config: &Config) -> Result<(), Failure> {
    let Some((wanted, origin)) = &config.membership else {
        return Ok(());
    };
    let carried = match &config.settings.group {
        GroupSpec::FoundingText(_) => MembershipPolicy::Open,
        GroupSpec::FoundingDocument(document) => match group::founding_policy(document) {
            Some(policy) => policy,
            None => return Ok(()),
        },
        GroupSpec::Join(_) => return Ok(()),
    };
    if carried == *wanted {
        return Ok(());
    }
    let why = match &config.settings.group {
        GroupSpec::FoundingText(_) => {
            "a group founded from a text has no signed founding to carry a policy, so it admits \
             every verified peer; found an invite group with aspace seed --found NAME \
             --membership invite"
        }
        _ => "the group's founding names another, and a founding never changes",
    };
    Err(Failure::refused(format!(
        "{origin} is {}, and the group is {}: {why}",
        wanted.as_str().to_ascii_lowercase(),
        carried.as_str().to_ascii_lowercase()
    )))
}

/// The founding of group `name` beside the keystore: loaded when it is there, else founded
/// under the membership asked for (`--membership`, else the file's group of that name's
/// `membership`, else open) and written there. A membership asked for that differs from the one
/// founded is refused: a founding never changes.
fn found(
    overrides: &Overrides,
    keystore_dir: &Path,
    identity: &agentspaces::wire::identity::Identity,
    name: &str,
    flag: Option<MembershipPolicy>,
) -> Result<Vec<u8>, Failure> {
    let path = founding_path(keystore_dir, name)?;
    let requested = match flag {
        Some(policy) => Some((policy, "--membership".to_owned())),
        None => file_membership(overrides, name)?,
    };
    match group::load_founding(&path, identity).map_err(group_failure)? {
        Some(document) => {
            let policy = group::founding_policy(&document);
            if let Some((wanted, origin)) = &requested
                && policy != Some(*wanted)
            {
                return Err(Failure::refused(format!(
                    "{origin} asks for an {} group, and {name} was founded {} ({}); a founding \
                     never changes: drop {origin}, or found another group under another name",
                    wanted.as_str().to_ascii_lowercase(),
                    policy.map_or("with another policy", |policy| match policy {
                        MembershipPolicy::Invite => "invite",
                        _ => "open",
                    }),
                    path.display()
                )));
            }
            tracing::info!(path = %path.display(), "the founding of {name}");
            Ok(document)
        }
        None => {
            let policy = requested.map_or(MembershipPolicy::Open, |(policy, _)| policy);
            let document = group::found_or_load(
                &path,
                identity,
                &Charter::new(name, policy),
                SystemClock.now_ms(),
            )
            .map_err(group_failure)?;
            note(format!(
                "founded the group {name} ({}) in {}",
                policy.as_str().to_ascii_lowercase(),
                path.display()
            ));
            Ok(document)
        }
    }
}

/// The founding file of `name` beside the keystore, or a refusal of a name no file can carry.
fn founding_path(keystore_dir: &Path, name: &str) -> Result<PathBuf, Failure> {
    group::founding_path(keystore_dir, name).ok_or_else(|| {
        Failure::refused(format!(
            "--found {name:?} is not a group name a file can carry; use letters, digits, '.', \
             '-', and '_'"
        ))
    })
}

/// The `membership` the fleet file's group named `name` gives, with its key.
fn file_membership(
    overrides: &Overrides,
    name: &str,
) -> Result<Option<(MembershipPolicy, String)>, Failure> {
    let Some((path, origin)) = Config::locate(overrides, &session::env)? else {
        return Ok(None);
    };
    let file = FleetFile::read(&path, &origin, &session::env)?;
    let Some(group) = file.groups.iter().find(|group| group.name == name.trim()) else {
        return Ok(None);
    };
    let Some(text) = group
        .membership
        .as_deref()
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(None);
    };
    let key = format!("{}.membership in {}", group.key, path.display());
    match MembershipPolicy::parse(text) {
        Some(policy) => Ok(Some((policy, key))),
        None => Err(Failure::refused(format!(
            "{key}: {text:?} is not a membership; write open or invite"
        ))),
    }
}

/// The exit code of a founding that cannot be loaded or made: one another founder signed, or
/// that does not verify, is an authorization failure (exit 4).
fn group_failure(error: GroupError) -> Failure {
    let message = error.to_string();
    match error {
        GroupError::NotFounder { .. } | GroupError::Invalid(_) => Failure::auth(message),
        GroupError::Keystore(keystore) => keystore.into(),
        GroupError::Founding(_) => Failure::refused(message),
        _ => Failure::error(message),
    }
}

/// `aspace invite`: an invite key of the INVITE group `name` this keystore founded.
pub fn invite(
    global: &Global,
    name: &str,
    label: Option<&str>,
    not_after: Duration,
) -> Result<(), Failure> {
    let keystore_dir = session::keystore_dir(global)?;
    if !keystore_dir.join(keystore::PRIVATE_FILE).exists() {
        return Err(Failure::refused(format!(
            "{} holds no identity: run aspace invite with the keystore aspace seed --found {name} \
             ran with (--keystore)",
            keystore_dir.display()
        )));
    }
    let identity = session::identity(Some(&keystore_dir), global.allow_readable_key)?;
    let path = founding_path(&keystore_dir, name)?;
    let document = group::load_founding(&path, &identity)
        .map_err(group_failure)?
        .ok_or_else(|| {
            Failure::refused(format!(
                "no founding of {name} in {}: found it first with aspace seed --found {name} \
                 --membership invite",
                keystore_dir.display()
            ))
        })?;
    match group::founding_policy(&document) {
        Some(MembershipPolicy::Invite) => {}
        Some(MembershipPolicy::Open) => {
            return Err(Failure::refused(format!(
                "the group {name} is open: every verified peer joins without an invite; found an \
                 invite group under another name (aspace seed --found NAME --membership invite)"
            )));
        }
        _ => {
            return Err(Failure::refused(format!(
                "the founding of {name} names a membership aspace does not issue invites for"
            )));
        }
    }
    let group_id = group::founding_group_id(&document).ok_or_else(|| {
        Failure::auth(format!(
            "{} holds no founding document that verifies",
            path.display()
        ))
    })?;
    let secret = GroupSecret::random()
        .map_err(|error| Failure::error(format!("cannot mint an invite key: {error}")))?;
    let now = SystemClock.now_ms();
    let not_after_ms = now.saturating_add(i64::try_from(not_after.as_millis()).unwrap_or(i64::MAX));
    let label = label.map(str::trim).filter(|label| !label.is_empty());
    let delegation = social::delegate(
        &identity,
        &group_id,
        &secret.invite_public_key(),
        not_after_ms,
        label,
    );
    let key = InviteKey::of(secret)
        .with_delegation(Some(&delegation))
        .map_err(|error| Failure::error(format!("cannot make the invite key: {error}")))?;
    note(format!(
        "an invite to {name} until {}: it carries a secret, hand it over as you would a password",
        time::instant_iso(not_after_ms)
    ));
    print_line(&json!({
        "invite": key.compact().as_str(),
        "group": group_id,
        "join": format!("{}{group_id}", ids::URI_PREFIX),
        "name": name,
        "label": label.map_or(Json::Null, |label| Json::String(label.to_owned())),
        "notAfter": time::instant_iso(not_after_ms),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces::config::Origin;

    fn listener(scheme: &str, bind: &str, advertise: Option<&str>) -> ListenAddress {
        ListenAddress {
            scheme: scheme.to_owned(),
            bind: bind.to_owned(),
            advertise: advertise.map(str::to_owned),
            origin: Origin::Default,
        }
    }

    #[test]
    fn a_seed_knows_its_own_address_among_its_seeds() {
        let own = listener("tcp", "127.0.0.1:7700", None);
        assert!(same_address(&Seed::new("127.0.0.1", 7700, "tcp"), &own));
        assert!(same_address(&Seed::new("localhost", 7700, "tcp"), &own));
        assert!(!same_address(&Seed::new("127.0.0.1", 7701, "tcp"), &own));
        assert!(!same_address(&Seed::new("127.0.0.1", 7700, "tls"), &own));
        assert!(!same_address(&Seed::new("10.0.0.2", 7700, "tcp"), &own));
        let wildcard = listener("tls", "0.0.0.0:7500", Some("seed.example.com:7500"));
        assert!(same_address(
            &Seed::new("127.0.0.1", 7500, "tls"),
            &wildcard
        ));
        assert!(same_address(
            &Seed::new("seed.example.com", 7500, "tls"),
            &wildcard
        ));
        assert!(!same_address(
            &Seed::new("other.example.com", 7500, "tls"),
            &wildcard
        ));
        let any_port = listener("tcp", "127.0.0.1:0", None);
        assert!(!same_address(&Seed::new("127.0.0.1", 0, "tcp"), &any_port));
    }
}
