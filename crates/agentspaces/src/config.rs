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

//! What a peer needs to run: [`PeerSettings`], read from `ASPACE_*` variables, and [`Config`], the
//! shared fleet YAML with the variables and command-line flags over it, both checked before
//! anything is dialed.
//!
//! # Variables
//!
//! | Variable | Meaning |
//! |---|---|
//! | `ASPACE_SEEDS` | Comma-separated seeds, `scheme://host:port` or `host:port` (which dials `tcp`, as `seed.py` does). Required. |
//! | `ASPACE_GROUP` | The founding text of a group the seed founded from a text (the GroupID is its hash). Under [`Config`] it first names a group of the fleet file. |
//! | `ASPACE_JOIN` | `aspace://<group-id>` (or the bare id) of a group with a signed founding. Exactly one of `ASPACE_GROUP` and `ASPACE_JOIN` is required. |
//! | `ASPACE_KEYSTORE` | The keystore directory ([`crate::keystore`]); a leading `~/` is the home directory. Unset: a fresh identity each run. |
//! | `ASPACE_PROFILE` | `mtls` (the default) or `dev-local`. |
//! | `ASPACE_SPACES` | Comma-separated space names to pull after joining. |
//! | `ASPACE_CONFIG` | The fleet YAML file ([`Config`] only). |
//! | `ASPACE_SOCKET` | The socket of `aspace daemon` ([`Config`] only: carried in [`Config::socket`], read by the `aspace` command). |
//!
//! The `aspace` command reads a few more, outside this module: `ASPACE_NO_DAEMON` (join in the
//! process even when a daemon answers), `ASPACE_ALLOW_READABLE_KEY` (through
//! [`KeystoreOptions::from_vars`](crate::keystore::KeystoreOptions::from_vars)), and
//! `ASPACE_MCP_TOKENS` and `ASPACE_MCP_POLICY` (the files of `aspace mcp`).
//!
//! A variable set to the empty string, or to spaces only, counts as unset. Founding text is taken
//! exactly as given (it is hashed); every other value is trimmed.
//!
//! # Rules
//!
//! [`PeerSettings::validate`] refuses settings with no seed, an empty group, a zero interval, and a
//! plaintext seed (`tcp`, `ws`, `http`) whose host is not loopback unless the profile is
//! [`Profile::DevLocal`]: such a link signs every frame but encrypts nothing.
//! [`PeerSettings::from_vars`] also refuses no group, both `ASPACE_GROUP` and `ASPACE_JOIN`, a seed
//! or profile that does not parse, and an `ASPACE_JOIN` that is not a group id. Every refusal
//! ([`ConfigError`]) names the variable (and the [`PeerSettings`] field), the value, and the fix.
//!
//! [`PeerSettings::from_vars`] reads the variables alone; `ASPACE_CONFIG` only logs a warning
//! there. [`Config`] reads the fleet YAML too, and so does
//! [`Peer::join_from_env`](crate::peer::Peer::join_from_env), which joins with
//! [`Config::from_env`].
//!
//! # The fleet YAML
//!
//! Every AgentSpaces host reads the same file: the `agentspaces:` subtree of the Java starter's
//! YAML, which the Ruby `Config.load`, the Node host, and the Spring and Micronaut starters read
//! alike.
//!
//! ```yaml
//! agentspaces:
//!   keystore: ~/.config/agentspaces/keys      # peer.key and peer.pub, shared with Java, Python, Ruby
//!   security:
//!     profile: mtls                           # tls:// seeds attest; dev-local allows plaintext tcp
//!   groups:
//!     - name: research-fleet
//!       join: aspace://zQm...                 # or founding: <text>, or founding-document: <file>
//!       seeds: [ "tls://fleet.example.com:7500" ]
//!       spaces: [ { name: tasks }, { name: votes } ]
//! ```
//!
//! [`FleetFile`] reads it ([`FleetFile::read`], [`FleetFile::parse`]); [`Config::resolve`]
//! layers it:
//!
//! 1. command-line flags ([`Overrides`]: `--seeds`, `--group`, `--join`, `--keystore`,
//!    `--profile`, `--socket`, `--join-timeout`, `--config`), then
//! 2. the variables above, then
//! 3. the file: the one `--config` names, else `ASPACE_CONFIG`, else
//!    `$XDG_CONFIG_HOME/agentspaces/fleet.yaml` (`~/.config/agentspaces/fleet.yaml`) when it
//!    exists ([`default_config_path`]).
//!
//! The group is the one the highest layer names: `--join`/`ASPACE_JOIN` join by id (and take
//! the seeds and spaces of the file's group of that id, if any); `--group`/`ASPACE_GROUP` name
//! a group of the file (by name, then by GroupID), or else are a founding text; with neither,
//! the file's first group. Seeds, the keystore, the profile, and the spaces come from the
//! highest layer that sets them.
//!
//! Keys are read in kebab-case, snake_case, or camelCase (`founding-document`,
//! `founding_document`, `foundingDocument`), as Spring's relaxed binding and the Ruby `Config`
//! read them. Keys this peer does not use are ignored ([`FleetFile::ignored`]); the listener
//! keys (`bind`, `advertise`, `roles`) are logged, since this peer is dial-only. A group joins:
//!
//! - by `join: aspace://<id>` (or `group-id: <id>`): the founding advertisement is fetched from
//!   the seeds and verified against the id;
//! - by `founding: <text>`: the GroupID is the text's hash (a group a seed founded from text);
//! - by `founding-document: <file or base64>`: a signed founding advertisement this peer holds,
//!   as a file (raw CBOR, or its base64) or inline base64 CBOR as the Java starter reads it,
//!   verified when the file is read;
//! - with none of these, from its `name` as a founding text, as the Java starter does.
//!
//! The file is read under bounds ([`MAX_FLEET_FILE_BYTES`], one document, a few hundred nodes of
//! anchors and aliases at most), so an alias bomb or an oversize file is refused, never
//! expanded. Every refusal names the flag, variable, or key (with the file) it read.
#![warn(missing_docs)]

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentspaces_wire::base58;
use agentspaces_wire::crypto::DIGEST_LENGTH;
use agentspaces_wire::ids;
use agentspaces_wire::seed::{self, Seed, SeedError};
use serde_json::{Map as JsonMap, Value as Json};

use crate::group::{GroupSpec, Profile};

/// Comma-separated seeds.
pub const ENV_SEEDS: &str = "ASPACE_SEEDS";
/// The founding text of the group to join.
pub const ENV_GROUP: &str = "ASPACE_GROUP";
/// The `aspace://<group-id>` of the group to join.
pub const ENV_JOIN: &str = "ASPACE_JOIN";
/// The keystore directory.
pub const ENV_KEYSTORE: &str = "ASPACE_KEYSTORE";
/// The security profile, `mtls` or `dev-local`.
pub const ENV_PROFILE: &str = "ASPACE_PROFILE";
/// Comma-separated space names to pull.
pub const ENV_SPACES: &str = "ASPACE_SPACES";
/// The fleet YAML file ([`Config`] reads it; [`PeerSettings::from_vars`] does not).
pub const ENV_CONFIG: &str = "ASPACE_CONFIG";
/// Every variable [`PeerSettings::from_env`] reads.
pub const VARIABLES: [&str; 7] = [
    ENV_SEEDS,
    ENV_GROUP,
    ENV_JOIN,
    ENV_KEYSTORE,
    ENV_PROFILE,
    ENV_SPACES,
    ENV_CONFIG,
];

/// How long the peer waits between attempts to redial a lost seed: 5 s, as the Python peer's
/// `reconnect_interval_s`.
pub const DEFAULT_RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
/// How long the peer keeps redialing a lost seed before it gives up: 10 minutes, as the Python
/// peer's `reconnect_window_s`.
pub const DEFAULT_RECONNECT_WINDOW: Duration = Duration::from_secs(600);
/// How often the peer re-publishes its leased self-advertisement: 30 s, as the Python and Ruby
/// peers (`peer-ad-interval-millis: 30000`).
///
/// The re-lease is also the peer's keepalive with a Java seed, which drops a member it has not
/// heard from for its member TTL (30 s by default): the effective re-lease must stay at most half
/// that TTL. So, as Java's `PeerNode.refreshIntervalMillis` does, the peer re-leases every 15 s
/// at most once the group outgrows the seed's probe cycle (`(members + 1) × 1 s × 4 ≥ 30 s`),
/// whatever this interval says. See [`crate::peer::PeerConfig`].
pub const DEFAULT_PEER_AD_INTERVAL: Duration = Duration::from_secs(30);

/// The schemes whose links carry frames in the clear (signed, not encrypted).
pub const PLAINTEXT_SCHEMES: [&str; 3] = ["tcp", "ws", "http"];

/// The inputs a peer needs: which group, through which seeds, under which profile, with which
/// identity, and its timing. Build one with [`PeerSettings::new`] (then set fields) or
/// [`PeerSettings::from_env`], and check it with [`PeerSettings::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSettings {
    /// The group to join.
    pub group: GroupSpec,
    /// The seeds to dial, in order; the first that answers is used.
    pub seeds: Vec<Seed>,
    /// The security profile (default [`Profile::Mtls`]).
    pub profile: Profile,
    /// The keystore directory ([`crate::keystore::load_or_create`]); `None` runs with a fresh
    /// identity that is gone when the process ends.
    pub keystore: Option<PathBuf>,
    /// The pause between redials of a lost seed (default [`DEFAULT_RECONNECT_INTERVAL`], 5 s).
    pub reconnect_interval: Duration,
    /// How long redials go on before the peer gives up (default [`DEFAULT_RECONNECT_WINDOW`],
    /// 10 min); zero never redials.
    pub reconnect_window: Duration,
    /// How often the self-advertisement is re-published (default
    /// [`DEFAULT_PEER_AD_INTERVAL`], 30 s); in a group past the seed's probe cycle the peer
    /// re-publishes every 15 s at most, half a Java seed's member TTL.
    pub peer_ad_interval: Duration,
    /// The spaces to pull after joining, by name.
    pub spaces: Vec<String>,
}

impl PeerSettings {
    /// Settings to join `group` through `seeds` with every default: the [`Profile::Mtls`]
    /// profile, no keystore, redial every 5 s for 10 min, self-advertisement every 30 s, and no
    /// spaces.
    pub fn new(group: GroupSpec, seeds: Vec<Seed>) -> Self {
        Self {
            group,
            seeds,
            profile: Profile::default(),
            keystore: None,
            reconnect_interval: DEFAULT_RECONNECT_INTERVAL,
            reconnect_window: DEFAULT_RECONNECT_WINDOW,
            peer_ad_interval: DEFAULT_PEER_AD_INTERVAL,
            spaces: Vec::new(),
        }
    }

    /// [`PeerSettings::from_vars`] over the process environment. A variable that is set but not
    /// UTF-8 is refused ([`ConfigError::NotUnicode`]) rather than taken as unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        for variable in VARIABLES {
            if let Err(std::env::VarError::NotUnicode(_)) = std::env::var(variable) {
                return Err(ConfigError::NotUnicode { variable });
            }
        }
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// Settings from `ASPACE_*` variables looked up through `lookup` (the [module
    /// table](self)), validated ([`PeerSettings::validate`]). `HOME` is looked up too when
    /// `ASPACE_KEYSTORE` starts with `~`. Timing fields take their defaults.
    ///
    /// Refuses, in this order: seeds that do not parse or name no seed; no group, or both
    /// `ASPACE_GROUP` and `ASPACE_JOIN`; an `ASPACE_JOIN` that is not `aspace://` and a GroupID
    /// (`z` and the base58btc of 32 bytes); a profile other than `mtls` or `dev-local`; a
    /// keystore under `~` with no `HOME`; then whatever [`PeerSettings::validate`] refuses.
    pub fn from_vars(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        if let Some(path) = var(ENV_CONFIG) {
            tracing::warn!(
                path = %path,
                "{ENV_CONFIG} is set, but PeerSettings::from_vars reads the ASPACE_* variables \
                 only; read the fleet YAML with Config::from_env or Config::resolve"
            );
        }
        let seeds = parse_seeds(var(ENV_SEEDS))?;
        let group = match (var(ENV_GROUP), var(ENV_JOIN)) {
            (Some(group), Some(join)) => return Err(ConfigError::GroupAndJoin { group, join }),
            (Some(text), None) => GroupSpec::FoundingText(text),
            (None, Some(join)) => GroupSpec::Join(parse_join(&join)?),
            (None, None) => return Err(ConfigError::NoGroup),
        };
        let profile = match var(ENV_PROFILE) {
            None => Profile::default(),
            Some(value) => Profile::parse(&value).ok_or(ConfigError::BadProfile { value })?,
        };
        let keystore = match var(ENV_KEYSTORE) {
            None => None,
            Some(value) => Some(expand_home(value.trim(), var("HOME"))?),
        };
        let mut spaces: Vec<String> = Vec::new();
        for name in var(ENV_SPACES).iter().flat_map(|value| value.split(',')) {
            let name = name.trim();
            if !name.is_empty() && !spaces.iter().any(|known| known == name) {
                spaces.push(name.to_owned());
            }
        }
        let settings = Self {
            spaces,
            keystore,
            profile,
            ..Self::new(group, seeds)
        };
        settings.validate()?;
        Ok(settings)
    }

    /// Checks the settings before anything is dialed. Refuses, in this order: no seed; an empty
    /// group (blank founding text, a join URI with no id, an empty founding document); a
    /// plaintext seed (`tcp`, `ws`, `http`) whose host is not loopback unless the profile is
    /// [`Profile::DevLocal`]; and a zero `reconnect_interval` or `peer_ad_interval`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.seeds.is_empty() {
            return Err(ConfigError::NoSeeds { value: None });
        }
        match &self.group {
            GroupSpec::FoundingText(text) if text.trim().is_empty() => {
                return Err(ConfigError::EmptyFoundingText);
            }
            GroupSpec::Join(uri) if ids::parse_group_id(uri).is_none() => {
                return Err(ConfigError::BadJoin { value: uri.clone() });
            }
            GroupSpec::FoundingDocument(document) if document.is_empty() => {
                return Err(ConfigError::EmptyFoundingDocument);
            }
            _ => {}
        }
        if self.profile != Profile::DevLocal
            && let Some(seed) = self
                .seeds
                .iter()
                .find(|seed| is_plaintext_scheme(&seed.scheme) && !is_loopback_host(&seed.host))
        {
            return Err(ConfigError::PlaintextSeed {
                seed: seed.clone(),
                profile: self.profile,
            });
        }
        for (field, value) in [
            ("reconnect_interval", self.reconnect_interval),
            ("peer_ad_interval", self.peer_ad_interval),
        ] {
            if value.is_zero() {
                return Err(ConfigError::ZeroInterval { field });
            }
        }
        Ok(())
    }
}

/// Whether `scheme` carries frames in the clear: `tcp`, `ws`, or `http` ([`PLAINTEXT_SCHEMES`]),
/// in any letter case.
pub fn is_plaintext_scheme(scheme: &str) -> bool {
    PLAINTEXT_SCHEMES
        .iter()
        .any(|plain| plain.eq_ignore_ascii_case(scheme))
}

/// Whether a seed host is this machine: `localhost` (any letter case), an IPv4 address in
/// `127.0.0.0/8`, `::1`, or an IPv4-mapped loopback (`::ffff:127.0.0.1`). Other names are not
/// resolved, so a name that happens to resolve to loopback still counts as remote.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        Ok(IpAddr::V6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Err(_) => false,
    }
}

fn parse_seeds(value: Option<String>) -> Result<Vec<Seed>, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::NoSeeds { value: None });
    };
    let mut seeds: Vec<Seed> = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let parsed = seed::parse_seed(entry, seed::DEFAULT_SCHEME).map_err(|reason| {
            ConfigError::BadSeed {
                value: value.clone(),
                entry: entry.to_owned(),
                reason,
            }
        })?;
        if !seeds.contains(&parsed) {
            seeds.push(parsed);
        }
    }
    if seeds.is_empty() {
        return Err(ConfigError::NoSeeds { value: Some(value) });
    }
    Ok(seeds)
}

/// The trimmed join URI when it names a well-formed GroupID: `z` and the base58btc of a 32-byte
/// digest, after an optional `aspace://`.
fn parse_join(value: &str) -> Result<String, ConfigError> {
    let well_formed = ids::parse_group_id(value).is_some_and(|id| {
        base58::multibase_decode(id).is_ok_and(|digest| digest.len() == DIGEST_LENGTH)
    });
    if well_formed {
        Ok(value.trim().to_owned())
    } else {
        Err(ConfigError::BadJoin {
            value: value.to_owned(),
        })
    }
}

/// `~` or `~/rest` under `home`; any other path as given.
fn expand_home(value: &str, home: Option<String>) -> Result<PathBuf, ConfigError> {
    let rest = match value.strip_prefix('~') {
        Some("") => "",
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => return Ok(PathBuf::from(value)),
    };
    let home = home.ok_or_else(|| ConfigError::KeystoreHome {
        value: value.to_owned(),
    })?;
    let home = PathBuf::from(home.trim());
    Ok(if rest.is_empty() {
        home
    } else {
        home.join(rest)
    })
}

fn profile_name(profile: Profile) -> &'static str {
    match profile {
        Profile::DevLocal => "dev-local",
        Profile::Mtls => "mtls",
    }
}

/// Why settings were refused. Each message names the variable (and the [`PeerSettings`] field
/// it fills), the value it read, and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A variable is set to bytes that are not UTF-8.
    NotUnicode {
        /// The variable.
        variable: &'static str,
    },
    /// No seed to dial: `ASPACE_SEEDS` is unset (`value` `None`) or holds only separators.
    NoSeeds {
        /// The variable's value when it was set.
        value: Option<String>,
    },
    /// An entry of `ASPACE_SEEDS` is not a seed.
    BadSeed {
        /// The whole variable.
        value: String,
        /// The entry refused.
        entry: String,
        /// Why.
        reason: SeedError,
    },
    /// Neither `ASPACE_GROUP` nor `ASPACE_JOIN` is set.
    NoGroup,
    /// Both `ASPACE_GROUP` and `ASPACE_JOIN` are set.
    GroupAndJoin {
        /// `ASPACE_GROUP`.
        group: String,
        /// `ASPACE_JOIN`.
        join: String,
    },
    /// `ASPACE_JOIN` (or a [`GroupSpec::Join`]) names no GroupID.
    BadJoin {
        /// The value.
        value: String,
    },
    /// The group is a [`GroupSpec::FoundingText`] that is empty or spaces only.
    EmptyFoundingText,
    /// The group is a [`GroupSpec::FoundingDocument`] with no bytes.
    EmptyFoundingDocument,
    /// `ASPACE_PROFILE` is neither `mtls` nor `dev-local`.
    BadProfile {
        /// The value.
        value: String,
    },
    /// `ASPACE_KEYSTORE` starts with `~` and `HOME` is unset.
    KeystoreHome {
        /// The value.
        value: String,
    },
    /// A plaintext seed to a host that is not loopback, under a profile other than dev-local.
    PlaintextSeed {
        /// The seed.
        seed: Seed,
        /// The profile in force.
        profile: Profile,
    },
    /// A timing field that must be positive is zero.
    ZeroInterval {
        /// The [`PeerSettings`] field.
        field: &'static str,
    },
    /// A value a flag, variable, or key of the fleet file holds is refused ([`Config`]).
    Invalid {
        /// Where the value was read.
        origin: Box<Origin>,
        /// The value (cut to 80 characters).
        value: String,
        /// Why, and the fix.
        reason: String,
    },
    /// Something the peer needs is set nowhere ([`Config`]): no group, no seed.
    Missing {
        /// What is missing.
        what: String,
        /// Where it may be set.
        fix: String,
    },
    /// Two settings that exclude each other are both set ([`Config`]): `--group` and `--join`,
    /// a group's `join` and `founding`, two spellings of one key.
    Conflict {
        /// The first.
        first: Box<Origin>,
        /// The second.
        second: Box<Origin>,
        /// Why they exclude each other, and the fix.
        fix: String,
    },
    /// The fleet file cannot be read.
    FileUnreadable {
        /// What named the file: `--config`, `ASPACE_CONFIG`, or the default.
        origin: Box<Origin>,
        /// The file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// The fleet file is larger than [`MAX_FLEET_FILE_BYTES`].
    FileTooLarge {
        /// The file.
        path: PathBuf,
        /// The bound.
        limit: u64,
    },
    /// The fleet file is not YAML this peer reads: it does not parse, holds more than one
    /// document, is not UTF-8, or passes a bound (an alias bomb, too deep, too many nodes).
    Yaml {
        /// The file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// A plaintext seed to a host that is not loopback, under a profile other than dev-local,
    /// naming where the seed and the profile were read ([`Config`]).
    PlaintextSeedAt {
        /// The seed.
        seed: Box<Seed>,
        /// Where the seeds were read.
        seeds: Box<Origin>,
        /// The profile in force.
        profile: Profile,
        /// Where the profile was read ([`Origin::Default`] when unset).
        profile_origin: Box<Origin>,
        /// Whether the fleet file sets `allow-plain: true`, which this peer does not honour.
        allow_plain: bool,
    },
}

const SEED_EXAMPLE: &str = "tls://fleet.example.com:7500";

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode { variable } => write!(
                f,
                "{variable} is set to bytes that are not UTF-8; set it to UTF-8 text or unset it"
            ),
            Self::NoSeeds { value: None } => write!(
                f,
                "no seed to dial: {ENV_SEEDS} is unset (PeerSettings::seeds is empty); set it to \
                 the comma-separated seeds of the fleet, e.g. {ENV_SEEDS}={SEED_EXAMPLE}"
            ),
            Self::NoSeeds { value: Some(value) } => write!(
                f,
                "no seed to dial: {ENV_SEEDS}={value:?} names no seed; set it to the \
                 comma-separated seeds of the fleet, e.g. {ENV_SEEDS}={SEED_EXAMPLE}"
            ),
            Self::BadSeed {
                value,
                entry,
                reason,
            } => write!(
                f,
                "{ENV_SEEDS}={value:?}: {entry:?} is not a seed ({reason}); write each seed as \
                 scheme://host:port or host:port, separated by commas, e.g. \
                 {ENV_SEEDS}={SEED_EXAMPLE}"
            ),
            Self::NoGroup => write!(
                f,
                "no group to join: neither {ENV_GROUP} nor {ENV_JOIN} is set; set \
                 {ENV_JOIN}=aspace://<group-id> to join a group by id, or {ENV_GROUP} to the \
                 founding text of a group the seed founded from a text"
            ),
            Self::GroupAndJoin { group, join } => write!(
                f,
                "both {ENV_GROUP}={group:?} and {ENV_JOIN}={join:?} are set, and a peer joins \
                 one group; unset {ENV_GROUP} to join by id, or unset {ENV_JOIN} to join the \
                 group founded from the text"
            ),
            Self::BadJoin { value } => write!(
                f,
                "{ENV_JOIN}={value:?} (PeerSettings::group) is not a group id; set it to \
                 aspace://<group-id> (or the bare id: z and base58), as the group's founder \
                 printed it"
            ),
            Self::EmptyFoundingText => write!(
                f,
                "{ENV_GROUP} (PeerSettings::group) is an empty founding text; set it to the \
                 text the seed's group was founded from, or join by id with \
                 {ENV_JOIN}=aspace://<group-id>"
            ),
            Self::EmptyFoundingDocument => write!(
                f,
                "PeerSettings::group holds an empty founding document; pass the CBOR bytes of \
                 the signed founding advertisement, or join by id with \
                 {ENV_JOIN}=aspace://<group-id>"
            ),
            Self::BadProfile { value } => write!(
                f,
                "{ENV_PROFILE}={value:?} (PeerSettings::profile) is not a profile; set it to \
                 mtls (attested TLS, the default) or dev-local (plaintext tcp allowed; never on \
                 a shared network)"
            ),
            Self::KeystoreHome { value } => write!(
                f,
                "{ENV_KEYSTORE}={value:?} (PeerSettings::keystore) starts with ~ but HOME is \
                 unset; write the keystore directory as an absolute path"
            ),
            Self::PlaintextSeed { seed, profile } => write!(
                f,
                "{ENV_SEEDS} (PeerSettings::seeds) holds {seed}, a plaintext {scheme} seed to \
                 {host}, which is not loopback, and {ENV_PROFILE} is {profile}: such a link \
                 signs every frame but encrypts nothing; write tls://{address} to dial an \
                 attested channel, or set {ENV_PROFILE}=dev-local on a closed network",
                scheme = seed.scheme,
                host = seed.host,
                address = seed.address(),
                profile = profile_name(*profile),
            ),
            Self::ZeroInterval { field } => write!(
                f,
                "PeerSettings::{field} is zero; set a positive duration (or keep the default)"
            ),
            Self::Invalid {
                origin,
                value,
                reason,
            } => write!(f, "{origin}: {value:?} {reason}"),
            Self::Missing { what, fix } => write!(f, "{what}: {fix}"),
            Self::Conflict { first, second, fix } => {
                write!(f, "both {first} and {second} are set: {fix}")
            }
            Self::FileUnreadable {
                origin,
                path,
                reason,
            } => match origin.as_ref() {
                Origin::Default => write!(
                    f,
                    "the default fleet file {} cannot be read ({reason}); fix or remove it, or \
                     name another with {FLAG_CONFIG} or {ENV_CONFIG}",
                    path.display()
                ),
                origin => write!(
                    f,
                    "{origin} names the fleet file {}, which cannot be read ({reason}); name a \
                     readable YAML file",
                    path.display()
                ),
            },
            Self::FileTooLarge { path, limit } => write!(
                f,
                "the fleet file {} is larger than {limit} bytes; a fleet file holds the \
                 agentspaces: section only",
                path.display()
            ),
            Self::Yaml { path, reason } => write!(
                f,
                "the fleet file {} is not fleet YAML: {reason}",
                path.display()
            ),
            Self::PlaintextSeedAt {
                seed,
                seeds,
                profile,
                profile_origin,
                allow_plain,
            } => {
                write!(
                    f,
                    "{seeds} holds {seed}, a plaintext {scheme} seed to {host}, which is not \
                     loopback, and the profile is {profile} ({profile_origin}): such a link \
                     signs every frame but encrypts nothing; write tls://{address} to dial an \
                     attested channel, or set the profile to dev-local ({FLAG_PROFILE}, \
                     {ENV_PROFILE}, or agentspaces.security.profile) on a closed network",
                    scheme = seed.scheme,
                    host = seed.host,
                    address = seed.address(),
                    profile = profile_name(*profile),
                )?;
                if *allow_plain {
                    write!(
                        f,
                        "; agentspaces.allow-plain is set, but this peer follows the profile \
                         alone"
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadSeed { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The fleet YAML and the layered configuration

/// The socket of `aspace daemon`: read and carried in [`Config::socket`].
pub const ENV_SOCKET: &str = "ASPACE_SOCKET";
/// The base of the default configuration directory when set (XDG).
pub const ENV_XDG_CONFIG_HOME: &str = "XDG_CONFIG_HOME";
/// The home directory, for `~` and the default configuration directory.
pub const ENV_HOME: &str = "HOME";
/// Every variable [`Config::from_env`] reads.
pub const CONFIG_VARIABLES: [&str; 10] = [
    ENV_SEEDS,
    ENV_GROUP,
    ENV_JOIN,
    ENV_KEYSTORE,
    ENV_PROFILE,
    ENV_SPACES,
    ENV_CONFIG,
    ENV_SOCKET,
    ENV_HOME,
    ENV_XDG_CONFIG_HOME,
];

/// The flag naming the fleet file.
pub const FLAG_CONFIG: &str = "--config";
/// The flag overriding the seeds.
pub const FLAG_SEEDS: &str = "--seeds";
/// The flag naming the group (a group of the file, or a founding text).
pub const FLAG_GROUP: &str = "--group";
/// The flag joining a group by id.
pub const FLAG_JOIN: &str = "--join";
/// The flag overriding the keystore directory.
pub const FLAG_KEYSTORE: &str = "--keystore";
/// The flag overriding the security profile.
pub const FLAG_PROFILE: &str = "--profile";
/// The flag overriding the daemon socket.
pub const FLAG_SOCKET: &str = "--socket";
/// The flag overriding the join timeout.
pub const FLAG_JOIN_TIMEOUT: &str = "--join-timeout";

/// The largest fleet file read: 1 MiB. A fleet file is a few hundred bytes; the bound keeps a
/// mistaken path (a log, a device) from being read whole.
pub const MAX_FLEET_FILE_BYTES: u64 = 1024 * 1024;
/// The largest founding document file read: 64 KiB (a signed founding advertisement is a few
/// hundred bytes).
pub const MAX_FOUNDING_DOCUMENT_BYTES: u64 = 64 * 1024;
/// The most anchors, and the most aliases, a fleet file may hold.
pub const MAX_YAML_ALIASES: usize = 64;
/// The most nodes (scalars, sequences, mappings) a fleet file may hold, aliases expanded.
pub const MAX_YAML_NODES: usize = 10_000;
/// The deepest nesting a fleet file may hold.
pub const MAX_YAML_DEPTH: usize = 32;
/// The file name of the default fleet file in the configuration directory.
pub const DEFAULT_FLEET_FILE: &str = "fleet.yaml";
/// The default keystore directory's name in the configuration directory
/// (`~/.config/agentspaces/keys`).
pub const DEFAULT_KEYSTORE_DIR: &str = "keys";
/// How long a join may take by default: 10 s, the Java starter's `join-timeout-millis`.
pub const DEFAULT_JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// The subtree keys of a listener (`bind`, `advertise`, `roles`): logged and ignored, since this
/// peer is dial-only (the Ruby `Config::LISTENER_KEYS`).
pub const LISTENER_KEYS: [&str; 3] = ["bind", "advertise", "roles"];

/// Where a setting came from: a flag, a variable, a key of the fleet file, or the default.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A command-line flag ([`Overrides`]), such as `--seeds`.
    Flag(&'static str),
    /// An `ASPACE_*` variable.
    Variable(&'static str),
    /// A key of the fleet file: its dotted path (`agentspaces.groups[0].seeds`) and the file.
    Key {
        /// The fleet file.
        file: PathBuf,
        /// The key's dotted path, as written in the file.
        key: String,
    },
    /// The built-in default.
    Default,
}

impl Origin {
    fn key(file: &Path, key: impl Into<String>) -> Self {
        Origin::Key {
            file: file.to_path_buf(),
            key: key.into(),
        }
    }
}

impl fmt::Display for Origin {
    /// `--seeds`, `ASPACE_SEEDS`, `agentspaces.groups[0].seeds in /etc/fleet.yaml`, or `the
    /// default`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Flag(flag) => f.write_str(flag),
            Origin::Variable(variable) => f.write_str(variable),
            Origin::Key { file, key } => write!(f, "{key} in {}", file.display()),
            Origin::Default => f.write_str("the default"),
        }
    }
}

/// The command-line layer of a [`Config`]: what the `aspace` flags of the same names set. Every
/// field left `None` defers to the variables and then the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--config`: the fleet file (over `ASPACE_CONFIG` and the default path).
    pub config: Option<PathBuf>,
    /// `--seeds`: comma-separated seeds (over `ASPACE_SEEDS` and the group's `seeds`).
    pub seeds: Option<String>,
    /// `--group`: a group of the file by name, or else a founding text (over `ASPACE_GROUP`).
    pub group: Option<String>,
    /// `--join`: `aspace://<group-id>` (over `ASPACE_JOIN`).
    pub join: Option<String>,
    /// `--keystore`: the keystore directory (over `ASPACE_KEYSTORE` and `keystore`).
    pub keystore: Option<String>,
    /// `--profile`: the security profile (over `ASPACE_PROFILE` and `security.profile`).
    pub profile: Option<String>,
    /// `--socket`: the daemon socket (over `ASPACE_SOCKET`).
    pub socket: Option<String>,
    /// `--join-timeout`: how long a join may take (over the group's `join-timeout-millis`).
    pub join_timeout: Option<Duration>,
}

/// One group of a fleet file, checked: its name, how it is joined, its seeds and spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetGroup {
    /// The group's `name`.
    pub name: String,
    /// The group's dotted path in the file (`agentspaces.groups[0]`).
    pub key: String,
    /// How it is joined: `join` (or `group-id`), `founding`, `founding-document`, or its name as a
    /// founding text.
    pub spec: GroupSpec,
    /// The key [`FleetGroup::spec`] was read from (`agentspaces.groups[0].join`, `...name` when
    /// the name doubles as the founding text).
    pub spec_key: String,
    /// The GroupID: derived from the founding text, parsed from the join URI, or the verified
    /// founding document's.
    pub group_id: String,
    /// The group's `seeds`, in order, duplicates dropped.
    pub seeds: Vec<Seed>,
    /// The group's `spaces` by name, in order, duplicates dropped.
    pub spaces: Vec<String>,
    /// The group's `join-timeout-millis`, when set.
    pub join_timeout: Option<Duration>,
}

/// The `agentspaces:` subtree of a fleet file, read and checked ([`FleetFile::read`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetFile {
    /// The file read.
    pub path: PathBuf,
    /// `keystore`, as written (a leading `~` is expanded when the configuration is resolved).
    pub keystore: Option<String>,
    /// `security.profile`, as written.
    pub profile: Option<String>,
    /// `allow-plain` (the Ruby peer's switch for plaintext seeds outside loopback). This peer does
    /// not honour it, since the profile decides; a refusal says so.
    pub allow_plain: bool,
    /// `peer-ad-interval-millis`, when set.
    pub peer_ad_interval: Option<Duration>,
    /// `groups`, in order.
    pub groups: Vec<FleetGroup>,
    /// The keys of the subtree and its groups this peer does not use, as dotted paths (values are
    /// never kept, so a secret under an unknown key is never shown).
    pub ignored: Vec<String>,
}

/// A configuration resolved from flags, variables, and the fleet file ([`Config::resolve`]):
/// checked [`PeerSettings`] and what the settings do not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// The peer's settings, validated ([`PeerSettings::validate`]).
    pub settings: PeerSettings,
    /// The name of the fleet file's group joined, when the group came from the file.
    pub group_name: Option<String>,
    /// How long a join may take ([`PeerConfig::join_timeout`](crate::peer::PeerConfig)).
    pub join_timeout: Duration,
    /// The daemon socket, when set (`--socket`, `ASPACE_SOCKET`).
    pub socket: Option<PathBuf>,
    /// The fleet file read, if any.
    pub file: Option<PathBuf>,
    /// Where each setting came from, by name: `file`, `group`, `seeds`, `profile`, `keystore`,
    /// `spaces`, `socket`, `join_timeout`, `peer_ad_interval`.
    pub origins: Vec<(&'static str, Origin)>,
    /// The keys of the file this peer does not use ([`FleetFile::ignored`]).
    pub ignored: Vec<String>,
}

impl Config {
    /// The configuration of the fleet file at `path` alone: its first group, no variables or
    /// flags (but `HOME` for a leading `~`). Join with it through
    /// [`Fleet::join_config`](crate::space::Fleet::join_config):
    /// `Fleet::join_config(&Config::load("fleet.yaml")?)`.
    pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let home = |name: &str| {
            (name == ENV_HOME)
                .then(|| std::env::var(ENV_HOME).ok())
                .flatten()
        };
        let file = FleetFile::read(path.as_ref(), &Origin::Default, &home)?;
        Config::resolve(&Overrides::default(), home, Some(&file))
    }

    /// [`Config::from_vars`] over the process environment. A variable of [`CONFIG_VARIABLES`]
    /// that is set but not UTF-8 is refused ([`ConfigError::NotUnicode`]).
    pub fn from_env(overrides: &Overrides) -> Result<Config, ConfigError> {
        for variable in CONFIG_VARIABLES {
            if let Err(std::env::VarError::NotUnicode(_)) = std::env::var(variable) {
                return Err(ConfigError::NotUnicode { variable });
            }
        }
        Config::from_vars(overrides, |name| std::env::var(name).ok())
    }

    /// The configuration from `overrides`, the variables `lookup` answers, and the fleet file
    /// they name ([`Config::locate`]): the file is read ([`FleetFile::read`]) and the three
    /// layered ([`Config::resolve`]).
    pub fn from_vars(
        overrides: &Overrides,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Config, ConfigError> {
        let file = match Config::locate(overrides, &lookup)? {
            Some((path, origin)) => Some(FleetFile::read(&path, &origin, &lookup)?),
            None => None,
        };
        Config::resolve(overrides, lookup, file.as_ref())
    }

    /// The fleet file to read and what named it: `--config`, else `ASPACE_CONFIG` (a leading
    /// `~` expanded), else the default path ([`default_config_path`]) when a file is there.
    /// `None` when no file is named and none is at the default path. A file a flag or variable
    /// names is read whether it exists or not, so a missing one is refused by name.
    pub fn locate(
        overrides: &Overrides,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Option<(PathBuf, Origin)>, ConfigError> {
        let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        if let Some(path) = &overrides.config {
            let origin = Origin::Flag(FLAG_CONFIG);
            let text = path.to_string_lossy();
            return Ok(Some((
                expand_home_at(&text, var(ENV_HOME), &origin)?,
                origin,
            )));
        }
        if let Some(path) = var(ENV_CONFIG) {
            let origin = Origin::Variable(ENV_CONFIG);
            return Ok(Some((
                expand_home_at(path.trim(), var(ENV_HOME), &origin)?,
                origin,
            )));
        }
        Ok(default_config_path(lookup)
            .filter(|path| path.is_file())
            .map(|path| (path, Origin::Default)))
    }

    /// The keystore directory the layers name, without reading anything else of the file than
    /// its `keystore` (what `aspace id` needs): `--keystore`, `ASPACE_KEYSTORE`, the file's
    /// `keystore`, or `None`.
    pub fn keystore_from_vars(
        overrides: &Overrides,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<(PathBuf, Origin)>, ConfigError> {
        let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        let home = var(ENV_HOME);
        if let Some(value) = overrides
            .keystore
            .clone()
            .filter(|value| !value.trim().is_empty())
        {
            let origin = Origin::Flag(FLAG_KEYSTORE);
            return Ok(Some((expand_home_at(value.trim(), home, &origin)?, origin)));
        }
        if let Some(value) = var(ENV_KEYSTORE) {
            let origin = Origin::Variable(ENV_KEYSTORE);
            return Ok(Some((expand_home_at(value.trim(), home, &origin)?, origin)));
        }
        let Some((path, origin)) = Config::locate(overrides, &lookup)? else {
            return Ok(None);
        };
        let tree = read_tree(&path, &origin)?;
        let subtree = agentspaces_subtree(&tree, &path)?;
        let fields = Fields::of(subtree, &At::root(&path))?;
        match fields.get("keystore") {
            Some((key, value)) => {
                let at = At::root(&path).child(key);
                match text_of(value, &at)? {
                    Some(text) if !text.trim().is_empty() => {
                        let origin = at.origin();
                        Ok(Some((expand_home_at(text.trim(), home, &origin)?, origin)))
                    }
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Layers `overrides` over the variables `lookup` answers over `file` (the [module
    /// rules](self#the-fleet-yaml)) and checks the result.
    ///
    /// Refuses, naming the flag, variable, or key: a group named twice in one layer (`--group` and
    /// `--join`, `ASPACE_GROUP` and `ASPACE_JOIN`); a join that is not a group id; no group
    /// anywhere; seeds that do not parse, or none; a profile other than `mtls`, `dev-local`
    /// (`mtls-oidc` and `zero-trust` run as `mtls`: this peer presents no token); a `~` path with
    /// no `HOME`; and a plaintext seed outside loopback unless the profile is `dev-local`. Then
    /// whatever [`PeerSettings::validate`] refuses.
    pub fn resolve(
        overrides: &Overrides,
        lookup: impl Fn(&str) -> Option<String>,
        file: Option<&FleetFile>,
    ) -> Result<Config, ConfigError> {
        let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        let flag = |value: &Option<String>| value.clone().filter(|v| !v.trim().is_empty());
        let home = var(ENV_HOME);
        let mut origins: Vec<(&'static str, Origin)> = Vec::new();
        if let Some(file) = file {
            origins.push((
                "file",
                Origin::Key {
                    file: file.path.clone(),
                    key: "agentspaces".to_owned(),
                },
            ));
        }

        // The group: the highest layer that names one.
        let flags = layer_choice(
            flag(&overrides.group).map(|v| (v, Origin::Flag(FLAG_GROUP))),
            flag(&overrides.join).map(|v| (v, Origin::Flag(FLAG_JOIN))),
        )?;
        let choice = match flags {
            Some(choice) => Some(choice),
            None => match (var(ENV_GROUP), var(ENV_JOIN)) {
                (Some(group), Some(join)) => {
                    return Err(ConfigError::GroupAndJoin { group, join });
                }
                (Some(group), None) => Some(Choice::Name(group, Origin::Variable(ENV_GROUP))),
                (None, Some(join)) => Some(Choice::Join(join, Origin::Variable(ENV_JOIN))),
                (None, None) => None,
            },
        };
        let groups: &[FleetGroup] = file.map_or(&[], |file| file.groups.as_slice());
        let (spec, group_origin, chosen) = match choice {
            Some(Choice::Join(uri, origin)) => {
                let uri = parse_join_at(&uri, &origin)?;
                let id = ids::parse_group_id(&uri).unwrap_or_default().to_owned();
                let chosen = groups.iter().find(|group| group.group_id == id);
                (GroupSpec::Join(uri), origin, chosen)
            }
            Some(Choice::Name(text, origin)) => {
                let named = groups
                    .iter()
                    .find(|group| group.name == text.trim())
                    .or_else(|| {
                        let id = ids::group_id_from_founding(text.as_bytes());
                        groups.iter().find(|group| group.group_id == id)
                    });
                match named {
                    Some(group) => (group.spec.clone(), origin, Some(group)),
                    None => (GroupSpec::FoundingText(text), origin, None),
                }
            }
            None => match (groups.first(), file) {
                (Some(group), Some(file)) => (
                    group.spec.clone(),
                    Origin::key(&file.path, group.spec_key.clone()),
                    Some(group),
                ),
                _ => {
                    return Err(ConfigError::Missing {
                        what: "no group to join".to_owned(),
                        fix: format!(
                            "pass {FLAG_JOIN} aspace://<group-id> or {FLAG_GROUP} <name or \
                             founding text>, set {ENV_JOIN} or {ENV_GROUP}, or list the group \
                             under agentspaces.groups in {}",
                            file.map_or_else(
                                || "the fleet file (--config, ASPACE_CONFIG)".to_owned(),
                                |file| file.path.display().to_string()
                            )
                        ),
                    });
                }
            },
        };
        if let GroupSpec::FoundingText(text) = &spec
            && text.trim().is_empty()
        {
            return Err(ConfigError::Invalid {
                origin: Box::new(group_origin),
                value: text.clone(),
                reason: "is an empty founding text; name the group, or join it by id".to_owned(),
            });
        }
        origins.push(("group", group_origin));
        let group_key = chosen.map(|group| group.key.clone());

        // The seeds.
        let (seeds, seeds_origin) = if let Some(value) = flag(&overrides.seeds) {
            let origin = Origin::Flag(FLAG_SEEDS);
            (parse_seed_list(&value, &origin)?, origin)
        } else if let Some(value) = var(ENV_SEEDS) {
            let origin = Origin::Variable(ENV_SEEDS);
            (parse_seed_list(&value, &origin)?, origin)
        } else if let (Some(group), Some(file)) = (chosen, file) {
            (
                group.seeds.clone(),
                Origin::key(&file.path, format!("{}.seeds", group.key)),
            )
        } else {
            (Vec::new(), Origin::Default)
        };
        if seeds.is_empty() {
            let file_key = match (&group_key, file) {
                (Some(key), Some(file)) => format!("{key}.seeds in {}", file.path.display()),
                _ => "agentspaces.groups[].seeds in the fleet file".to_owned(),
            };
            return Err(ConfigError::Missing {
                what: "no seed to dial".to_owned(),
                fix: format!(
                    "pass {FLAG_SEEDS}, set {ENV_SEEDS}, or list them under {file_key}, e.g. \
                     {SEED_EXAMPLE}"
                ),
            });
        }
        origins.push(("seeds", seeds_origin.clone()));

        // The profile.
        let (profile_text, profile_origin) = if let Some(value) = flag(&overrides.profile) {
            (Some(value), Origin::Flag(FLAG_PROFILE))
        } else if let Some(value) = var(ENV_PROFILE) {
            (Some(value), Origin::Variable(ENV_PROFILE))
        } else if let Some((value, file)) = file.and_then(|f| f.profile.clone().map(|p| (p, f))) {
            (
                Some(value),
                Origin::key(&file.path, "agentspaces.security.profile"),
            )
        } else {
            (None, Origin::Default)
        };
        let profile = match &profile_text {
            None => Profile::default(),
            Some(text) => parse_profile_name(text).ok_or_else(|| ConfigError::Invalid {
                origin: Box::new(profile_origin.clone()),
                value: text.clone(),
                reason: "is not a profile; write mtls (attested TLS, the default) or dev-local \
                         (plaintext tcp allowed; never on a shared network)"
                    .to_owned(),
            })?,
        };
        origins.push(("profile", profile_origin.clone()));

        // The keystore.
        let keystore_value = flag(&overrides.keystore)
            .map(|v| (v, Origin::Flag(FLAG_KEYSTORE)))
            .or_else(|| var(ENV_KEYSTORE).map(|v| (v, Origin::Variable(ENV_KEYSTORE))))
            .or_else(|| {
                file.and_then(|file| {
                    file.keystore
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .map(|value| (value, Origin::key(&file.path, "agentspaces.keystore")))
                })
            });
        let keystore = match keystore_value {
            Some((value, origin)) => {
                let path = expand_home_at(value.trim(), home.clone(), &origin)?;
                origins.push(("keystore", origin));
                Some(path)
            }
            None => None,
        };

        // The spaces.
        let spaces = if let Some(value) = var(ENV_SPACES) {
            origins.push(("spaces", Origin::Variable(ENV_SPACES)));
            split_names(&value)
        } else if let (Some(group), Some(file)) = (chosen, file) {
            origins.push((
                "spaces",
                Origin::key(&file.path, format!("{}.spaces", group.key)),
            ));
            group.spaces.clone()
        } else {
            Vec::new()
        };

        // The socket.
        let socket = match flag(&overrides.socket)
            .map(|v| (v, Origin::Flag(FLAG_SOCKET)))
            .or_else(|| var(ENV_SOCKET).map(|v| (v, Origin::Variable(ENV_SOCKET))))
        {
            Some((value, origin)) => {
                let path = expand_home_at(value.trim(), home, &origin)?;
                origins.push(("socket", origin));
                Some(path)
            }
            None => None,
        };

        // The timings.
        let join_timeout = match (overrides.join_timeout, chosen.and_then(|g| g.join_timeout)) {
            (Some(timeout), _) => {
                origins.push(("join_timeout", Origin::Flag(FLAG_JOIN_TIMEOUT)));
                timeout
            }
            (None, Some(timeout)) => {
                if let (Some(group), Some(file)) = (chosen, file) {
                    origins.push((
                        "join_timeout",
                        Origin::key(&file.path, format!("{}.join-timeout-millis", group.key)),
                    ));
                }
                timeout
            }
            (None, None) => DEFAULT_JOIN_TIMEOUT,
        };
        if join_timeout.is_zero() {
            return Err(ConfigError::Invalid {
                origin: Box::new(Origin::Flag(FLAG_JOIN_TIMEOUT)),
                value: "0".to_owned(),
                reason: "is zero; give the join a positive time, e.g. 10s".to_owned(),
            });
        }
        let mut settings = PeerSettings::new(spec, seeds);
        settings.profile = profile;
        settings.keystore = keystore;
        settings.spaces = spaces;
        if let Some(interval) = file.and_then(|file| file.peer_ad_interval) {
            settings.peer_ad_interval = interval;
            if let Some(file) = file {
                origins.push((
                    "peer_ad_interval",
                    Origin::key(&file.path, "agentspaces.peer-ad-interval-millis"),
                ));
            }
        }

        // A plaintext seed outside loopback is refused unless the profile is dev-local, naming
        // where the seed and the profile came from.
        if settings.profile != Profile::DevLocal
            && let Some(seed) = settings
                .seeds
                .iter()
                .find(|seed| is_plaintext_scheme(&seed.scheme) && !is_loopback_host(&seed.host))
        {
            return Err(ConfigError::PlaintextSeedAt {
                seed: Box::new(seed.clone()),
                seeds: Box::new(seeds_origin),
                profile: settings.profile,
                profile_origin: Box::new(profile_origin),
                allow_plain: file.is_some_and(|file| file.allow_plain),
            });
        }
        settings.validate()?;
        Ok(Config {
            settings,
            group_name: chosen.map(|group| group.name.clone()),
            join_timeout,
            socket,
            file: file.map(|file| file.path.clone()),
            origins,
            ignored: file.map(|file| file.ignored.clone()).unwrap_or_default(),
        })
    }

    /// Where the setting `name` came from (`group`, `seeds`, `profile`, `keystore`, `spaces`,
    /// `socket`, `join_timeout`, `file`, `peer_ad_interval`); `None` for a setting left at its
    /// default.
    pub fn origin(&self, name: &str) -> Option<&Origin> {
        self.origins
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, origin)| origin)
    }

    /// The identity [`Config::settings`] name: the keystore's (loaded, or minted and persisted
    /// there), or a fresh one ([`crate::peer::settings_identity`]).
    pub fn identity(&self) -> Result<agentspaces_wire::identity::Identity, crate::peer::PeerError> {
        crate::peer::settings_identity(&self.settings)
    }

    /// A peer configuration for `identity` ([`PeerConfig::from_settings`]) with this
    /// configuration's join timeout.
    ///
    /// [`PeerConfig::from_settings`]: crate::peer::PeerConfig::from_settings
    pub fn peer_config(
        &self,
        identity: agentspaces_wire::identity::Identity,
    ) -> Result<crate::peer::PeerConfig, ConfigError> {
        let mut config = crate::peer::PeerConfig::from_settings(&self.settings, identity)?;
        config.join_timeout = self.join_timeout;
        Ok(config)
    }
}

/// The configuration directory: `$XDG_CONFIG_HOME/agentspaces` when that is set, else
/// `$HOME/.config/agentspaces`; `None` with neither.
pub fn default_config_dir(lookup: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let var = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
    if let Some(base) = var(ENV_XDG_CONFIG_HOME) {
        return Some(PathBuf::from(base.trim()).join("agentspaces"));
    }
    var(ENV_HOME).map(|home| PathBuf::from(home.trim()).join(".config/agentspaces"))
}

/// The default fleet file, `<config dir>/fleet.yaml` ([`default_config_dir`]). The Ruby
/// `Config.load` has no default path (its command takes the file as an argument, and its Rails
/// Railtie reads `config/agentspaces.yml` of the application); this peer never reads a file of
/// the working directory unasked, so a checked-out repository cannot point it at a fleet.
pub fn default_config_path(lookup: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    default_config_dir(lookup).map(|dir| dir.join(DEFAULT_FLEET_FILE))
}

/// The default keystore directory, `<config dir>/keys` (`~/.config/agentspaces/keys`), for a
/// command that needs a lasting identity when no layer names one.
pub fn default_keystore(lookup: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    default_config_dir(lookup).map(|dir| dir.join(DEFAULT_KEYSTORE_DIR))
}

/// The security profile a name selects: `dev-local`, `mtls`, and the Java starter's `mtls-oidc`
/// and `zero-trust`, which run as [`Profile::Mtls`] here (attested TLS; this peer presents no
/// OIDC token). `None` for any other name. Case-insensitive, trimmed.
pub fn parse_profile_name(text: &str) -> Option<Profile> {
    match text.trim().to_ascii_lowercase().as_str() {
        "mtls-oidc" | "zero-trust" => {
            tracing::warn!(
                profile = text.trim(),
                "this peer runs the {} profile as mtls: attested TLS, no OIDC token",
                text.trim()
            );
            Some(Profile::Mtls)
        }
        other => Profile::parse(other),
    }
}

impl FleetFile {
    /// Reads and checks the fleet file at `path`, which `origin` named: at most
    /// [`MAX_FLEET_FILE_BYTES`], UTF-8, one YAML document within the alias, node, and depth
    /// bounds. `lookup` answers `HOME` for a founding document under `~`.
    pub fn read(
        path: &Path,
        origin: &Origin,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<FleetFile, ConfigError> {
        let tree = read_tree(path, origin)?;
        FleetFile::from_tree(&tree, path, lookup)
    }

    /// Checks fleet YAML `text` as if read from `path` ([`FleetFile::read`] without the file).
    pub fn parse(
        text: &str,
        path: &Path,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<FleetFile, ConfigError> {
        if text.len() as u64 > MAX_FLEET_FILE_BYTES {
            return Err(ConfigError::FileTooLarge {
                path: path.to_path_buf(),
                limit: MAX_FLEET_FILE_BYTES,
            });
        }
        let tree = parse_yaml(text, path)?;
        FleetFile::from_tree(&tree, path, lookup)
    }

    fn from_tree(
        tree: &Json,
        path: &Path,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<FleetFile, ConfigError> {
        let subtree = agentspaces_subtree(tree, path)?;
        let root = At::root(path);
        let fields = Fields::of(subtree, &root)?;
        let mut file = FleetFile {
            path: path.to_path_buf(),
            keystore: None,
            profile: None,
            allow_plain: false,
            peer_ad_interval: None,
            groups: Vec::new(),
            ignored: Vec::new(),
        };
        for (normal, key, value) in &fields.entries {
            let at = root.child(key);
            match normal.as_str() {
                "keystore" => file.keystore = text_of(value, &at)?,
                "security" => {
                    if let Some(security) = map_of(value, &at)? {
                        let security_fields = Fields::of(security, &at)?;
                        for (normal, key, value) in &security_fields.entries {
                            let at = at.child(key);
                            if normal == "profile" {
                                file.profile = text_of(value, &at)?;
                            } else {
                                file.ignored.push(at.key);
                            }
                        }
                    }
                }
                "allowplain" => file.allow_plain = value.as_bool().unwrap_or(false),
                "peeradintervalmillis" => file.peer_ad_interval = millis_of(value, &at)?,
                "groups" => {
                    for (index, group) in list_of(value).into_iter().enumerate() {
                        let (group, ignored) =
                            FleetGroup::from_tree(group, &at.index(index), lookup)?;
                        file.ignored.extend(ignored);
                        if let Some(earlier) = file.groups.iter().find(|g| g.name == group.name) {
                            return Err(ConfigError::Invalid {
                                origin: Box::new(at.index(index).child("name").origin()),
                                value: group.name.clone(),
                                reason: format!(
                                    "names a group {} already names; give each group its own name",
                                    earlier.key
                                ),
                            });
                        }
                        file.groups.push(group);
                    }
                }
                _ => {
                    if LISTENER_KEYS.contains(&normal.as_str()) {
                        tracing::info!(
                            key = %at.key,
                            file = %path.display(),
                            "a listener setting; this peer is dial-only and ignores it"
                        );
                    }
                    file.ignored.push(at.key);
                }
            }
        }
        Ok(file)
    }
}

impl FleetGroup {
    /// The group at `at` and the keys of it this peer does not use.
    fn from_tree(
        tree: &Json,
        at: &At<'_>,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<(FleetGroup, Vec<String>), ConfigError> {
        // A bare string names the group (the Ruby Config reads it so).
        if let Json::String(name) = tree {
            let empty = Parts::default();
            return Ok((FleetGroup::named(name, at, empty, lookup)?, Vec::new()));
        }
        let Some(object) = tree.as_object() else {
            return Err(at.refuse(
                tree,
                "is not a group; write a mapping with a name and a join, founding, or \
                 founding-document",
            ));
        };
        let fields = Fields::of(object, at)?;
        let name = match fields.get("name") {
            Some((key, value)) => text_of(value, &at.child(key))?,
            None => None,
        }
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| ConfigError::Invalid {
            origin: Box::new(at.child("name").origin()),
            value: String::new(),
            reason: "is missing; every group needs a name".to_owned(),
        })?;
        let mut ignored = Vec::new();
        let mut join: Option<(String, At<'_>)> = None;
        let mut group_id: Option<(String, At<'_>)> = None;
        let mut founding: Option<(String, At<'_>)> = None;
        let mut document: Option<(String, At<'_>)> = None;
        let mut seeds = Vec::new();
        let mut spaces = Vec::new();
        let mut join_timeout = None;
        for (normal, key, value) in &fields.entries {
            let field = at.child(key);
            let text = |value: &Json| -> Result<Option<String>, ConfigError> {
                Ok(text_of(value, &field)?.filter(|text| !text.trim().is_empty()))
            };
            match normal.as_str() {
                "name" => {}
                "join" => join = text(value)?.map(|t| (t, field.clone())),
                "groupid" => group_id = text(value)?.map(|t| (t, field.clone())),
                "founding" => founding = text(value)?.map(|t| (t, field.clone())),
                "foundingdocument" => document = text(value)?.map(|t| (t, field.clone())),
                "seeds" => {
                    for (index, item) in names_of(value, &field)?.into_iter().enumerate() {
                        let item_at = field.index(index);
                        let seed =
                            seed::parse_seed(&item, seed::DEFAULT_SCHEME).map_err(|reason| {
                                ConfigError::Invalid {
                                    origin: Box::new(item_at.origin()),
                                    value: item.clone(),
                                    reason: format!(
                                        "is not a seed ({reason}); write scheme://host:port or \
                                     host:port, e.g. {SEED_EXAMPLE}"
                                    ),
                                }
                            })?;
                        if !seeds.contains(&seed) {
                            seeds.push(seed);
                        }
                    }
                }
                "spaces" => {
                    for space in names_of(value, &field)? {
                        if !spaces.contains(&space) {
                            spaces.push(space);
                        }
                    }
                }
                "jointimeoutmillis" => join_timeout = millis_of(value, &field)?,
                _ => ignored.push(field.key.clone()),
            }
        }
        // `join` and `group-id` are one way to say it; both must name the same group.
        let join = match (join, group_id) {
            (Some((a, a_at)), Some((b, b_at))) => {
                let id_a = parse_join_at(&a, &a_at.origin())?;
                let id_b = parse_join_at(&b, &b_at.origin())?;
                if ids::parse_group_id(&id_a) != ids::parse_group_id(&id_b) {
                    return Err(ConfigError::Conflict {
                        first: Box::new(a_at.origin()),
                        second: Box::new(b_at.origin()),
                        fix: "both name the group joined by id, and they name different groups; \
                              keep one"
                            .to_owned(),
                    });
                }
                Some((a, a_at))
            }
            (one, other) => one.or(other),
        };
        let set: Vec<&At<'_>> = [&join, &founding, &document]
            .into_iter()
            .flatten()
            .map(|(_, at)| at)
            .collect();
        if let [first, second, ..] = set.as_slice() {
            return Err(ConfigError::Conflict {
                first: Box::new(first.origin()),
                second: Box::new(second.origin()),
                fix: "a group is joined by its GroupID URI (join), founded from a text \
                      (founding), or joined with a signed founding document it holds \
                      (founding-document); keep one"
                    .to_owned(),
            });
        }
        let parts = Parts {
            join,
            founding,
            document,
            seeds,
            spaces,
            join_timeout,
        };
        Ok((FleetGroup::named(&name, at, parts, lookup)?, ignored))
    }

    fn named(
        name: &str,
        at: &At<'_>,
        parts: Parts<'_>,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<FleetGroup, ConfigError> {
        let Parts {
            join,
            founding,
            document,
            seeds,
            spaces,
            join_timeout,
        } = parts;
        let name = name.trim().to_owned();
        let (spec, spec_key, group_id) = if let Some((uri, uri_at)) = join {
            let uri = parse_join_at(&uri, &uri_at.origin())?;
            let id = ids::parse_group_id(&uri).unwrap_or_default().to_owned();
            (GroupSpec::Join(uri), uri_at.key, id)
        } else if let Some((text, text_at)) = founding {
            let id = ids::group_id_from_founding(text.as_bytes());
            (GroupSpec::FoundingText(text), text_at.key, id)
        } else if let Some((value, doc_at)) = document {
            let bytes = founding_document_bytes(&value, &doc_at, lookup)?;
            let id = verified_founding(&bytes).ok_or_else(|| {
                doc_at.refuse_text(
                    &value,
                    "is not a signed founding advertisement that verifies (SPEC §5.1); pass the \
                     group's founding document as its founder exported it",
                )
            })?;
            (GroupSpec::FoundingDocument(bytes), doc_at.key, id)
        } else {
            let id = ids::group_id_from_founding(name.as_bytes());
            (
                GroupSpec::FoundingText(name.clone()),
                at.child("name").key,
                id,
            )
        };
        Ok(FleetGroup {
            name,
            key: at.key.clone(),
            spec,
            spec_key,
            group_id,
            seeds,
            spaces,
            join_timeout,
        })
    }
}

/// What a group's keys say, checked one by one, before they are put together.
#[derive(Default)]
struct Parts<'a> {
    join: Option<(String, At<'a>)>,
    founding: Option<(String, At<'a>)>,
    document: Option<(String, At<'a>)>,
    seeds: Vec<Seed>,
    spaces: Vec<String>,
    join_timeout: Option<Duration>,
}

/// The GroupID a signed founding advertisement's CBOR bytes verify to, `None` when they do not
/// decode or verify.
fn verified_founding(bytes: &[u8]) -> Option<String> {
    let signed = agentspaces_wire::cbor::decode(bytes).ok()?;
    agentspaces_wire::founding::verify_signed_group_ad(&signed)
}

/// The bytes of a `founding-document` value: a file (after `~`) holding raw CBOR or its base64,
/// or else the value itself as base64 (the Java starter's form).
fn founding_document_bytes(
    value: &str,
    at: &At<'_>,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Vec<u8>, ConfigError> {
    use base64::Engine as _;
    let trimmed = value.trim();
    let home = lookup(ENV_HOME).filter(|home| !home.trim().is_empty());
    let candidate = expand_home_at(trimmed, home, &at.origin())?;
    if candidate.is_file() {
        let bytes = read_bounded(&candidate, MAX_FOUNDING_DOCUMENT_BYTES).map_err(|problem| {
            at.refuse_text(
                trimmed,
                &format!("names a file that cannot be read: {problem}"),
            )
        })?;
        // A CBOR map head (major type 5), definite or indefinite: the raw document.
        if bytes.first().is_some_and(|b| (0xa0..=0xbf).contains(b)) {
            return Ok(bytes);
        }
        let text = String::from_utf8_lossy(&bytes);
        let compact: String = text.split_whitespace().collect();
        return base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| {
                at.refuse_text(
                    trimmed,
                    "names a file that holds neither CBOR nor base64 CBOR; export the signed \
                     founding advertisement again",
                )
            });
    }
    let compact: String = trimmed.split_whitespace().collect();
    match base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => Err(at.refuse_text(
            trimmed,
            "is neither a readable file nor base64 CBOR; name the file of the signed founding \
             advertisement, or paste its base64 as the Java starter takes it",
        )),
    }
}

/// The group a layer names: by name (or founding text), or by id.
enum Choice {
    Name(String, Origin),
    Join(String, Origin),
}

/// One layer's group: refuses both a name and a join in the same layer.
fn layer_choice(
    name: Option<(String, Origin)>,
    join: Option<(String, Origin)>,
) -> Result<Option<Choice>, ConfigError> {
    match (name, join) {
        (Some((_, first)), Some((_, second))) => Err(ConfigError::Conflict {
            first: Box::new(first),
            second: Box::new(second),
            fix: "a peer joins one group; name it, or join it by id".to_owned(),
        }),
        (Some((name, origin)), None) => Ok(Some(Choice::Name(name, origin))),
        (None, Some((join, origin))) => Ok(Some(Choice::Join(join, origin))),
        (None, None) => Ok(None),
    }
}

/// [`parse_join`] naming `origin` in its refusal.
fn parse_join_at(value: &str, origin: &Origin) -> Result<String, ConfigError> {
    parse_join(value).map_err(|_| ConfigError::Invalid {
        origin: Box::new(origin.clone()),
        value: value.to_owned(),
        reason: "is not a group id; write aspace://<group-id> (or the bare id: z and base58), as \
                 the group's founder printed it"
            .to_owned(),
    })
}

/// Comma-separated seeds, naming `origin` in a refusal.
fn parse_seed_list(value: &str, origin: &Origin) -> Result<Vec<Seed>, ConfigError> {
    let mut seeds: Vec<Seed> = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let parsed = seed::parse_seed(entry, seed::DEFAULT_SCHEME).map_err(|reason| {
            ConfigError::Invalid {
                origin: Box::new(origin.clone()),
                value: value.to_owned(),
                reason: format!(
                    "holds {entry:?}, which is not a seed ({reason}); write each seed as \
                     scheme://host:port or host:port, separated by commas, e.g. {SEED_EXAMPLE}"
                ),
            }
        })?;
        if !seeds.contains(&parsed) {
            seeds.push(parsed);
        }
    }
    Ok(seeds)
}

/// Comma-separated names, trimmed, empty ones skipped, duplicates dropped.
fn split_names(value: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// [`expand_home`] naming `origin` when `HOME` is missing.
fn expand_home_at(
    value: &str,
    home: Option<String>,
    origin: &Origin,
) -> Result<PathBuf, ConfigError> {
    expand_home(value, home).map_err(|_| ConfigError::Invalid {
        origin: Box::new(origin.clone()),
        value: value.to_owned(),
        reason: "starts with ~ but HOME is unset; write the path as an absolute path".to_owned(),
    })
}

/// Reads at most `limit` bytes of `path`; a longer file is an error.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("it is not a regular file".to_owned());
    }
    if metadata.len() > limit {
        return Err(format!(
            "it holds {} bytes, more than {limit}",
            metadata.len()
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!("it holds more than {limit} bytes"));
    }
    Ok(bytes)
}

/// The YAML tree of the fleet file at `path`, read within [`MAX_FLEET_FILE_BYTES`].
fn read_tree(path: &Path, origin: &Origin) -> Result<Json, ConfigError> {
    use std::io::Read as _;
    let unreadable = |reason: String| ConfigError::FileUnreadable {
        origin: Box::new(origin.clone()),
        path: path.to_path_buf(),
        reason,
    };
    let file = std::fs::File::open(path).map_err(|error| unreadable(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| unreadable(error.to_string()))?;
    if !metadata.is_file() {
        return Err(unreadable("it is not a regular file".to_owned()));
    }
    let too_large = || ConfigError::FileTooLarge {
        path: path.to_path_buf(),
        limit: MAX_FLEET_FILE_BYTES,
    };
    if metadata.len() > MAX_FLEET_FILE_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FLEET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(error.to_string()))?;
    if bytes.len() as u64 > MAX_FLEET_FILE_BYTES {
        return Err(too_large());
    }
    let text = String::from_utf8(bytes).map_err(|_| ConfigError::Yaml {
        path: path.to_path_buf(),
        reason: "the file is not UTF-8 text".to_owned(),
    })?;
    parse_yaml(&text, path)
}

/// One YAML document as a tree, within the alias, node, and depth bounds. Anchors, aliases, and
/// merge keys (`<<: *default`) are read, as the Ruby `Config` reads them, but a file that would
/// expand past [`MAX_YAML_NODES`] (an alias bomb) is refused, never expanded.
fn parse_yaml(text: &str, path: &Path) -> Result<Json, ConfigError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let blank = text.lines().all(|line| {
        let line = line.trim();
        line.is_empty() || line.starts_with('#') || line == "---" || line == "..."
    });
    if blank {
        return Ok(Json::Null);
    }
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(MAX_FLEET_FILE_BYTES as usize),
            max_events: MAX_YAML_NODES * 2,
            max_aliases: MAX_YAML_ALIASES,
            max_anchors: MAX_YAML_ALIASES,
            max_depth: MAX_YAML_DEPTH,
            max_documents: 1,
            max_nodes: MAX_YAML_NODES,
            max_total_scalar_bytes: MAX_FLEET_FILE_BYTES as usize,
            max_merge_keys: MAX_YAML_ALIASES,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: MAX_YAML_NODES,
            max_replay_stack_depth: 16,
            max_alias_expansions_per_anchor: MAX_YAML_ALIASES,
        },
        with_snippet: false,
        reject_non_finite_typeless_float: false,
    };
    serde_saphyr::from_str_with_options::<Json>(text, options).map_err(|error| ConfigError::Yaml {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// The `agentspaces:` subtree of the document, or the document itself when it has no such key
/// (the Ruby `Config` reads a bare subtree so); an empty document is an empty subtree.
fn agentspaces_subtree<'a>(
    tree: &'a Json,
    path: &Path,
) -> Result<&'a JsonMap<String, Json>, ConfigError> {
    static EMPTY: std::sync::OnceLock<JsonMap<String, Json>> = std::sync::OnceLock::new();
    let root = match tree {
        Json::Null => return Ok(EMPTY.get_or_init(JsonMap::new)),
        Json::Object(root) => root,
        _ => {
            return Err(ConfigError::Yaml {
                path: path.to_path_buf(),
                reason: "the document is not a mapping; write an agentspaces: section".to_owned(),
            });
        }
    };
    let found = root
        .iter()
        .find(|(key, _)| normalize_key(key) == "agentspaces");
    match found {
        Some((_, Json::Object(subtree))) => Ok(subtree),
        Some((_, Json::Null)) => Ok(EMPTY.get_or_init(JsonMap::new)),
        Some((key, other)) => Err(ConfigError::Invalid {
            origin: Box::new(Origin::key(path, key.clone())),
            value: short_json(other),
            reason: "is not a mapping; write the fleet settings under it".to_owned(),
        }),
        None => Ok(root),
    }
}

/// A key as compared: lower case, without `-` and `_` (Spring's relaxed binding and the Ruby
/// `Config`'s snake_case forms read alike).
fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// A mapping's entries with their normalized keys, refusing two keys that normalize alike.
struct Fields<'a> {
    entries: Vec<(String, &'a str, &'a Json)>,
}

impl<'a> Fields<'a> {
    fn of(object: &'a JsonMap<String, Json>, at: &At<'_>) -> Result<Self, ConfigError> {
        let mut entries: Vec<(String, &'a str, &'a Json)> = Vec::with_capacity(object.len());
        for (key, value) in object {
            let normal = normalize_key(key);
            if let Some((_, earlier, _)) = entries.iter().find(|(n, _, _)| *n == normal) {
                return Err(ConfigError::Conflict {
                    first: Box::new(at.child(earlier).origin()),
                    second: Box::new(at.child(key).origin()),
                    fix: "the two spellings name the same setting; keep one".to_owned(),
                });
            }
            entries.push((normal, key.as_str(), value));
        }
        Ok(Fields { entries })
    }

    fn get(&self, normal: &str) -> Option<(&'a str, &'a Json)> {
        self.entries
            .iter()
            .find(|(n, _, _)| n == normal)
            .map(|(_, key, value)| (*key, *value))
    }
}

/// A place in the fleet file, for refusals.
#[derive(Clone)]
struct At<'a> {
    file: &'a Path,
    key: String,
}

impl<'a> At<'a> {
    fn root(file: &'a Path) -> Self {
        At {
            file,
            key: "agentspaces".to_owned(),
        }
    }

    fn child(&self, key: &str) -> At<'a> {
        At {
            file: self.file,
            key: format!("{}.{key}", self.key),
        }
    }

    fn index(&self, index: usize) -> At<'a> {
        At {
            file: self.file,
            key: format!("{}[{index}]", self.key),
        }
    }

    fn origin(&self) -> Origin {
        Origin::key(self.file, self.key.clone())
    }

    fn refuse(&self, value: &Json, reason: &str) -> ConfigError {
        ConfigError::Invalid {
            origin: Box::new(self.origin()),
            value: short_json(value),
            reason: reason.to_owned(),
        }
    }

    fn refuse_text(&self, value: &str, reason: &str) -> ConfigError {
        ConfigError::Invalid {
            origin: Box::new(self.origin()),
            value: shorten(value),
            reason: reason.to_owned(),
        }
    }
}

/// A scalar as text: a string, a number, or a boolean; `None` for null.
fn text_of(value: &Json, at: &At<'_>) -> Result<Option<String>, ConfigError> {
    match value {
        Json::Null => Ok(None),
        Json::String(text) => Ok(Some(text.clone())),
        Json::Number(number) => Ok(Some(number.to_string())),
        Json::Bool(flag) => Ok(Some(flag.to_string())),
        other => Err(at.refuse(other, "is not text; write a single value")),
    }
}

/// A mapping, or `None` for null.
fn map_of<'a>(
    value: &'a Json,
    at: &At<'_>,
) -> Result<Option<&'a JsonMap<String, Json>>, ConfigError> {
    match value {
        Json::Null => Ok(None),
        Json::Object(object) => Ok(Some(object)),
        other => Err(at.refuse(other, "is not a mapping")),
    }
}

/// A sequence's items (a single non-sequence value is one item; null is none).
fn list_of(value: &Json) -> Vec<&Json> {
    match value {
        Json::Null => Vec::new(),
        Json::Array(items) => items.iter().collect(),
        other => vec![other],
    }
}

/// Names from a sequence of text or `{name: ...}` mappings, or one comma-separated text, trimmed;
/// empty ones skipped.
fn names_of(value: &Json, at: &At<'_>) -> Result<Vec<String>, ConfigError> {
    let mut names = Vec::new();
    match value {
        Json::Null => {}
        Json::String(text) => names.extend(split_names(text)),
        Json::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let item_at = at.index(index);
                let text = match item {
                    Json::Object(object) => {
                        let fields = Fields::of(object, &item_at)?;
                        match fields.get("name") {
                            Some((key, value)) => text_of(value, &item_at.child(key))?,
                            None => {
                                return Err(item_at.refuse(item, "has no name; write {name: ...}"));
                            }
                        }
                    }
                    other => text_of(other, &item_at)?,
                };
                if let Some(text) = text.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()) {
                    names.push(text);
                }
            }
        }
        other => {
            if let Some(text) = text_of(other, at)? {
                names.extend(split_names(&text));
            }
        }
    }
    Ok(names)
}

/// A positive number of milliseconds, or `None` for null.
fn millis_of(value: &Json, at: &At<'_>) -> Result<Option<Duration>, ConfigError> {
    match value {
        Json::Null => Ok(None),
        Json::Number(number) => match number.as_u64() {
            Some(millis) if millis > 0 => Ok(Some(Duration::from_millis(millis))),
            _ => Err(at.refuse(value, "is not a positive number of milliseconds")),
        },
        Json::String(text) => match text.trim().parse::<u64>() {
            Ok(millis) if millis > 0 => Ok(Some(Duration::from_millis(millis))),
            _ => Err(at.refuse(value, "is not a positive number of milliseconds")),
        },
        other => Err(at.refuse(other, "is not a positive number of milliseconds")),
    }
}

/// A value as compact JSON, at most 80 characters.
fn short_json(value: &Json) -> String {
    shorten(&value.to_string())
}

/// Text cut to 80 characters, with an ellipsis when cut.
fn shorten(text: &str) -> String {
    const MAX: usize = 80;
    if text.chars().count() <= MAX {
        text.to_owned()
    } else {
        let cut: String = text.chars().take(MAX).collect();
        format!("{cut}...")
    }
}
