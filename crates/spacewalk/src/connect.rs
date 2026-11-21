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
//! Joining the group and starting the services spacewalk runs on: the peer (through the same
//! configuration layers as `aspace`: flags, `ASPACE_*` variables, the fleet YAML), the content
//! swarm with persistent trees, the refs, and the file share. The content swarm and the trees
//! always run here, whatever a shared YAML's `agentspaces.content.enabled` or
//! `agentspaces.pdt.enabled` says: spacewalk does nothing without them.

use std::sync::Arc;
use std::time::Duration;

use agentspaces::config::{Config, Overrides};
use agentspaces::content::{Content, ContentConfig, FilePieces, MemoryPieces, PieceStore};
use agentspaces::keystore;
use agentspaces::peer::Peer;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::pdt::store::{MemoryNodes, Nodes};
use agentspaces_pdt::{FileNodes, FileShare, FileShareConfig, Pdt, PdtConfig};

/// What a beacon document gave: the group to join by id and its seeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconJoin {
    /// The group's name in the document.
    pub name: String,
    /// `aspace://<group-id>`.
    pub join: String,
    /// The seeds, comma-separated `scheme://host:port`.
    pub seeds: String,
    /// The signer, when the document is signed.
    pub signer: Option<String>,
}

/// The URL of a beacon document: `url` as given when it names a path, else the well-known path
/// under it.
pub fn beacon_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .ok_or_else(|| format!("{trimmed} is no beacon URL; give http:// or https:// as the console's Copy beacon URL does"))?;
    Ok(match rest.find('/') {
        Some(at) if rest.len() > at + 1 => trimmed.to_string(),
        _ => format!("{}{}", trimmed.trim_end_matches('/'), agentspaces::wire::beacon::WELL_KNOWN),
    })
}

/// Reads a beacon document's bytes: the group (by `name` when given, else the only one), checked
/// as Java's URL locator checks it (a carried signature must verify), with the seeds this peer
/// dials.
pub fn beacon_join(bytes: &[u8], name: Option<&str>) -> Result<BeaconJoin, String> {
    use agentspaces::wire::beacon;
    let doc = beacon::BeaconDocument::parse(bytes).map_err(|e| format!("the beacon document: {e}"))?;
    let signer = beacon::verify_document(&doc, None).map_err(|e| format!("the beacon document: {e}"))?;
    let group = beacon::group_from_document(&doc, None, name).map_err(|e| format!("the beacon document: {e}"))?;
    let id = match (&group.founding, &group.id) {
        (Some(f), _) if !f.is_empty() => format!("aspace://{}", beacon::verified_group_id(group, None).map_err(|e| e.to_string())?),
        (_, Some(id)) => id.clone(),
        _ => return Err(format!("the beacon's group {} has no id to join by", group.name)),
    };
    let seeds: Vec<String> = beacon::seeds_of(group, &["tcp", "tls"]).iter().map(ToString::to_string).collect();
    if seeds.is_empty() {
        return Err(format!("the beacon's group {} lists no tcp or tls seed", group.name));
    }
    Ok(BeaconJoin { name: group.name.clone(), join: id, seeds: seeds.join(","), signer })
}

/// Fetches a beacon document (10 s, at most the document bound) and reads it.
pub async fn fetch_beacon(url: &str, name: Option<&str>) -> Result<BeaconJoin, String> {
    let url = beacon_url(url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("an HTTP client: {e}"))?;
    let response = client.get(&url).send().await.map_err(|e| {
        let mut cause = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(inner) = source {
            cause = inner.to_string();
            source = inner.source();
        }
        format!("fetching {url}: {cause}; is the share that served this URL still open?")
    })?;
    if !response.status().is_success() {
        return Err(format!("fetching {url}: HTTP {}", response.status()));
    }
    let bytes = response.bytes().await.map_err(|e| format!("reading {url}: {e}"))?;
    if bytes.len() > agentspaces::wire::beacon::MAX_DOCUMENT_BYTES {
        return Err(format!("{url} answered {} bytes, past the beacon document bound", bytes.len()));
    }
    beacon_join(&bytes, name)
}

/// The spaces this member can name: the fleet file's for the group, the spaces the group
/// advertises, and the spaces the file-share map holds keys under, sorted.
pub async fn known_spaces(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = conn.spaces.clone();
    for ad in conn.peer.ads("SpaceAdvertisement").await {
        if let Some(name) = ad.get("spaceName").and_then(agentspaces::wire::cbor::Value::as_str) {
            out.push(name.to_string());
        }
    }
    if let Ok(map) = conn.files.map().deref_map().await
        && let Ok(items) = map.items(&**conn.pdt.nodes())
    {
        for (k, _) in items {
            if let Ok(agentspaces::wire::cbor::Value::Text(key)) = agentspaces::wire::cbor::decode(&k)
                && let Some((space, _)) = key.split_once('/')
            {
                out.push(space.to_string());
            }
        }
    }
    out.retain(|s| !s.is_empty() && s != "pdt" && s != "content");
    out.sort();
    out.dedup();
    out
}

/// Everything spacewalk runs on.
pub struct Connection {
    /// The peer.
    pub peer: Peer,
    /// The content swarm.
    pub content: Content,
    /// The persistent trees.
    pub pdt: Pdt,
    /// The file share.
    pub files: FileShare,
    /// The group, as the configuration names it.
    pub group: String,
    /// The spaces the configuration lists for the group.
    pub spaces: Vec<String>,
}

/// How to join.
#[derive(Debug, Clone, Default)]
pub struct JoinOptions {
    /// The configuration layer of the flags.
    pub overrides: Overrides,
    /// The size limit of the file share.
    pub max_bytes: u64,
    /// A durable node store's directory; `None` keeps nodes in memory.
    pub store: Option<std::path::PathBuf>,
}

/// Joins the group and starts the services, within the join timeout.
pub async fn connect(options: JoinOptions) -> Result<Connection, String> {
    let config = Config::from_env(&options.overrides).map_err(|e| e.to_string())?;
    let identity = match config.settings.keystore.as_deref() {
        Some(dir) => keystore::load_or_create(dir).map_err(|e| format!("the keystore {}: {e}", dir.display()))?,
        None => Identity::generate().map_err(|e| format!("cannot mint an identity: {e}"))?,
    };
    let named = config.group_name.clone();
    let group = named.clone().unwrap_or_else(|| "the group".to_string());
    let spaces = config.settings.spaces.clone();
    let timeout = config.join_timeout;
    let mut peer_config = config.peer_config(identity).map_err(|e| e.to_string())?;
    peer_config.dial_timeout = peer_config.dial_timeout.min(timeout);
    let seeds: Vec<String> = config.settings.seeds.iter().map(ToString::to_string).collect();
    let peer = match tokio::time::timeout(timeout, Peer::start(peer_config)).await {
        Ok(Ok(peer)) => peer,
        Ok(Err(e)) => return Err(format!("joining {group}: {e}")),
        Err(_) => {
            return Err(format!(
                "joining {group} through {} did not complete within {} s; check that the seed runs \
                 (the Groovy console's notebook peer, or aspace seed), or pass --join-timeout",
                seeds.join(", "),
                timeout.as_secs()
            ));
        }
    };
    let group = named.unwrap_or_else(|| peer.group_id().to_string());
    let (nodes, pieces, ledger): (Arc<dyn Nodes>, Arc<dyn PieceStore>, Option<std::path::PathBuf>) = match &options.store {
        Some(dir) => {
            let store = FileNodes::open(dir).map_err(|e| format!("the node store {}: {e}", dir.display()))?;
            let pieces = FilePieces::open(&dir.join("pieces"), u64::MAX).map_err(|e| format!("the piece store {}: {e}", dir.display()))?;
            (Arc::new(store), Arc::new(pieces), Some(dir.join("shared.txt")))
        }
        None => (Arc::new(MemoryNodes::new()), Arc::new(MemoryPieces::new()), None),
    };
    let content = Content::start_with(peer.clone(), nodes, pieces, ContentConfig::default()).await.map_err(|e| e.to_string())?;
    let pdt = Pdt::new(content.clone(), PdtConfig::default());
    pdt.spawn_ticker(Duration::from_secs(1));
    let max_bytes = if options.max_bytes == 0 { agentspaces_pdt::files::MAX_FILE_BYTES } else { options.max_bytes };
    let files = FileShare::new(pdt.clone(), FileShareConfig { max_bytes, ledger, ..FileShareConfig::default() }).map_err(|e| e.to_string())?;
    let resumed = files.resume().await;
    if resumed > 0 {
        tracing::info!(resumed, "holding again the files this store shared before");
    }
    tracing::info!(group = %group, peer = %peer.peer_id(), "joined");
    Ok(Connection { peer, content, pdt, files, group, spaces })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_urls_take_the_well_known_path() {
        assert_eq!(beacon_url("http://127.0.0.1:63554").unwrap(), "http://127.0.0.1:63554/.well-known/agentspaces/beacon.json");
        assert_eq!(beacon_url("http://h:1/").unwrap(), "http://h:1/.well-known/agentspaces/beacon.json");
        assert_eq!(beacon_url("https://h/j/abc").unwrap(), "https://h/j/abc");
        assert!(beacon_url("tcp://h:1").is_err());
    }

    #[test]
    fn a_beacon_names_the_group_and_its_seeds() {
        let doc = br#"{"v":1,"ttl":300,"groups":[{"name":"readiness","id":"aspace://z93ZbrUvdPW2yeGTUwLJqrRDfKcyTV8LzeKJrGwWNNjuz",
            "seeds":[{"transport":"tcp","address":"127.0.0.1:63338","priority":1},{"transport":"tcp","address":"127.0.0.1:63336","priority":0},
            {"transport":"webrtc","address":"x:1","priority":2}]}]}"#;
        let join = beacon_join(doc, None).unwrap();
        assert_eq!(join.name, "readiness");
        assert_eq!(join.join, "aspace://z93ZbrUvdPW2yeGTUwLJqrRDfKcyTV8LzeKJrGwWNNjuz");
        assert_eq!(join.seeds, "tcp://127.0.0.1:63336,tcp://127.0.0.1:63338");
        assert!(beacon_join(doc, Some("other")).is_err());
        let forged = br#"{"v":1,"issuer":"zX","issuerKey":"AAAA","issued":"2026-11-21T00:00:00Z","ttl":300,"groups":[],"signature":"AAAA"}"#;
        assert!(beacon_join(forged, None).is_err(), "a signature that does not verify is refused");
    }
}
