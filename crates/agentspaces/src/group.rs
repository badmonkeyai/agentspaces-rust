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

//! How a peer names the group it joins, the security profile it runs, and how a founder founds a
//! group with a signed founding document ([`found`], [`found_or_load`]) that newcomers can join by
//! its GroupID alone (SPEC §4.4, §5.1).

use std::path::{Path, PathBuf};

use agentspaces_wire::cbor::{self, Value};
use agentspaces_wire::founding::{self, FoundingError};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::{ids, time};

use crate::keystore::{self, KeystoreError};

/// The group a peer joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSpec {
    /// A group founded from a text, as the Java demos and `founding:` configuration found them.
    /// The GroupID is `multibase(sha-256(text))`. Such a group has no signed founding, so it can
    /// only be joined this way, never by id (a seed holding only the text answers no GROUP_AD).
    FoundingText(String),
    /// Join by GroupID (`aspace://<id>` or the bare id): the peer asks the seed for the signed
    /// founding advertisement (GROUP_AD_WANT, GROUP_AD) and verifies it with the four checks of
    /// SPEC §5.1 before it introduces itself.
    Join(String),
    /// A signed founding advertisement the caller holds (its CBOR bytes), verified locally.
    FoundingDocument(Vec<u8>),
}

impl GroupSpec {
    /// The GroupID when it is known without asking the network: derived from a founding text,
    /// parsed from a join URI, or `None` for a document not yet verified.
    pub fn group_id(&self) -> Option<String> {
        match self {
            Self::FoundingText(text) => Some(ids::group_id_from_founding(text.as_bytes())),
            Self::Join(uri) => ids::parse_group_id(uri).map(str::to_owned),
            Self::FoundingDocument(_) => None,
        }
    }
}

/// The security profile: what the peer requires of its links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Signed frames over any transport, plaintext `tcp` allowed. Never on a shared network.
    DevLocal,
    /// TLS 1.3 with attested channel certificates; a plaintext seed outside loopback is refused.
    #[default]
    Mtls,
}

impl Profile {
    /// Parses `dev-local` or `mtls` (case-insensitive).
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "dev-local" => Some(Self::DevLocal),
            "mtls" => Some(Self::Mtls),
            _ => None,
        }
    }
}

/// Who may join a group a founder founds (SPEC §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MembershipPolicy {
    /// Every peer whose signed advertisement verifies.
    #[default]
    Open,
    /// Only peers presenting a credential the founder issued or delegated (the `aspace:join`
    /// resource hint).
    Invite,
}

impl MembershipPolicy {
    /// The policy's wire name (`OPEN`, `INVITE`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Invite => "INVITE",
        }
    }

    /// Parses `open` or `invite` (any letter case, surrounding space trimmed), as the fleet file's
    /// `membership` key and the wire name spell them.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "invite" => Some(Self::Invite),
            _ => None,
        }
    }
}

/// What a founder fixes when it founds a group (SPEC §5.1's founding fields), with Java's
/// defaults for what it leaves alone: the `LEASE_RACE` conflict strategy, a gossip fanout of 3
/// and a period of one second, and a lifetime of 365 days.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Charter {
    /// The group's name.
    pub name: String,
    /// Who may join.
    pub policy: MembershipPolicy,
    /// The default conflict strategy of its spaces (`LEASE_RACE`, `AUCTION`, `ORDERED`).
    pub strategy: String,
    /// The gossip fanout (at least 1).
    pub fanout: i64,
    /// The gossip period, as `java.time.Duration` text (`PT1S`).
    pub period: String,
    /// The founding's lifetime, as `java.time.Duration` text (`PT8760H`).
    pub ttl: String,
}

impl Charter {
    /// The charter of group `name` under `policy`, with the defaults above.
    pub fn new(name: impl Into<String>, policy: MembershipPolicy) -> Self {
        Self {
            name: name.into(),
            policy,
            strategy: "LEASE_RACE".to_owned(),
            fanout: 3,
            period: "PT1S".to_owned(),
            ttl: "PT8760H".to_owned(),
        }
    }
}

/// Why a group could not be founded or its founding loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GroupError {
    /// The charter holds a value the founding fields refuse.
    #[error(transparent)]
    Founding(#[from] FoundingError),
    /// The founding file could not be read or written.
    #[error("founding file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What failed.
        source: std::io::Error,
    },
    /// The founding file could not be written.
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    /// The founding file holds no founding document that verifies (SPEC §5.1's four checks).
    #[error("{0} holds no founding document that verifies")]
    Invalid(PathBuf),
    /// The founding file names another founder than this identity.
    #[error("{path} was founded by {founder}, not by {identity}")]
    NotFounder {
        /// The file.
        path: PathBuf,
        /// The founder it names.
        founder: String,
        /// The identity loading it.
        identity: String,
    },
}

/// Founds a group as `identity` under `charter`, issued at `now_ms` (whole seconds): the signed
/// founding document's CBOR (`{advertisement, founderPublicKey, signature}`), which a peer starts
/// with as [`GroupSpec::FoundingDocument`] and serves to newcomers as a GROUP_AD. Its GroupID is
/// self-certifying ([`founding_group_id`]).
pub fn found(identity: &Identity, charter: &Charter, now_ms: i64) -> Result<Vec<u8>, GroupError> {
    let issued = time::instant_iso(now_ms.div_euclid(1000).saturating_mul(1000));
    let signed = founding::found_group(
        identity,
        &charter.name,
        charter.policy.as_str(),
        &charter.strategy,
        charter.fanout,
        &charter.period,
        &issued,
        &charter.ttl,
    )?;
    Ok(cbor::encode(&Value::Map(signed)))
}

/// The GroupID a founding document's CBOR verifies to (SPEC §5.1's four checks), or `None`.
pub fn founding_group_id(document: &[u8]) -> Option<String> {
    cbor::decode(document)
        .ok()
        .and_then(|signed| founding::verify_signed_group_ad(&signed))
}

/// The founder's PeerID a founding document names.
pub fn founder_of(document: &[u8]) -> Option<String> {
    let signed = cbor::decode(document).ok()?;
    let issuer = signed.get("advertisement")?.get("issuer")?.as_str()?;
    Some(issuer.to_owned())
}

/// The membership policy a founding document names (`OPEN`, `INVITE`); `None` for a document
/// that does not decode, or a policy this peer does not admit under (`POLICY`).
pub fn founding_policy(document: &[u8]) -> Option<MembershipPolicy> {
    let signed = cbor::decode(document).ok()?;
    let policy = signed
        .get("advertisement")?
        .get("membershipPolicy")?
        .as_str()?;
    match policy {
        "OPEN" => Some(MembershipPolicy::Open),
        "INVITE" => Some(MembershipPolicy::Invite),
        _ => None,
    }
}

/// The group name a founding document names (`name`), when it names one.
pub fn founding_name(document: &[u8]) -> Option<String> {
    let signed = cbor::decode(document).ok()?;
    let name = signed.get("advertisement")?.get("name")?.as_str()?;
    Some(name.to_owned())
}

/// The founding file of group `name` beside a keystore: `<keystore>/founding-<name>.cbor`.
/// `None` for a name a file could not safely carry ([`keystore::is_safe_name`]).
pub fn founding_path(keystore_dir: &Path, name: &str) -> Option<PathBuf> {
    keystore::is_safe_name(name).then(|| keystore_dir.join(format!("founding-{name}.cbor")))
}

/// The founding document at `path`, founded by `identity`: loaded and verified when the file
/// exists (so a restart keeps the same GroupID), else founded now under `charter` and written
/// there atomically (the directory created when missing). A file that does not verify, or that
/// another founder signed, is refused and left as it is.
pub fn found_or_load(
    path: &Path,
    identity: &Identity,
    charter: &Charter,
    now_ms: i64,
) -> Result<Vec<u8>, GroupError> {
    match load_founding(path, identity)? {
        Some(document) => Ok(document),
        None => {
            let document = found(identity, charter, now_ms)?;
            keystore::write_key_file(path, &document, false)?;
            Ok(document)
        }
    }
}

/// The founding document at `path`, founded by `identity`, loaded and verified; `None` when the
/// file does not exist. A file that does not verify, or that another founder signed, is
/// refused. A file larger than any founding document (64 KiB) is refused unread.
pub fn load_founding(path: &Path, identity: &Identity) -> Result<Option<Vec<u8>>, GroupError> {
    use std::io::Read as _;
    const MAX_FOUNDING_BYTES: u64 = 64 * 1024;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(GroupError::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut document = Vec::new();
    file.take(MAX_FOUNDING_BYTES + 1)
        .read_to_end(&mut document)
        .map_err(|source| GroupError::Io {
            path: path.to_owned(),
            source,
        })?;
    if document.len() as u64 > MAX_FOUNDING_BYTES || founding_group_id(&document).is_none() {
        return Err(GroupError::Invalid(path.to_owned()));
    }
    let founder = founder_of(&document).unwrap_or_default();
    if founder != identity.peer_id() {
        return Err(GroupError::NotFounder {
            path: path.to_owned(),
            founder,
            identity: identity.peer_id().to_owned(),
        });
    }
    Ok(Some(document))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_founding_is_written_once_and_loaded_after() {
        let dir = std::env::temp_dir().join(format!(
            "aspace-founding-{}-{}",
            std::process::id(),
            time::instant_iso(0).len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = Identity::generate().expect("identity");
        let path = founding_path(&dir, "crew").expect("a safe name");
        let charter = Charter::new("crew", MembershipPolicy::Invite);
        let first = found_or_load(&path, &identity, &charter, 1_767_225_600_000).expect("found");
        let again = found_or_load(&path, &identity, &charter, 1_767_225_700_000).expect("load");
        assert_eq!(first, again, "a restart keeps the founding");
        let id = founding_group_id(&first).expect("it verifies");
        assert!(!id.is_empty());
        let other = Identity::generate().expect("identity");
        assert!(matches!(
            found_or_load(&path, &other, &charter, 0),
            Err(GroupError::NotFounder { .. })
        ));
        std::fs::write(&path, b"garbage").expect("write");
        assert!(matches!(
            found_or_load(&path, &identity, &charter, 0),
            Err(GroupError::Invalid(_))
        ));
        assert!(founding_path(&dir, "../escape").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_ids_come_from_text_or_uri() {
        let text = GroupSpec::FoundingText("research-fleet-demo-v1".into());
        let id = text.group_id().expect("derived");
        assert_eq!(
            GroupSpec::Join(format!("aspace://{id}"))
                .group_id()
                .as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            GroupSpec::Join(id.clone()).group_id().as_deref(),
            Some(id.as_str())
        );
        assert_eq!(GroupSpec::FoundingDocument(vec![]).group_id(), None);
        assert_eq!(Profile::parse("DEV-LOCAL"), Some(Profile::DevLocal));
        assert_eq!(Profile::parse("nope"), None);
    }
}
