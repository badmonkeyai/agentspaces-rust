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

//! The file share: the Groovy console's "Add to space" in Rust, with download and withdraw.
//!
//! A shared file is three things, written in this order: its bytes as a `PBlob` held in the
//! content swarm; an entry of the group's `file-share` tree ref under `<space>/<relative path>`
//! whose value is a `FileEntry` naming the blob's root; and a `SharedFile` record in the space,
//! leased 30 minutes and tagged `location=file-share` and `key=<key>`, the console's record under
//! the console's type name. The map is the source of truth; the record tells a space's readers.
//!
//! A share refuses a symbolic link, anything but a regular file, a path outside the root
//! directory, and more than the size limit (64 MiB by default, counted while reading). A
//! download refuses a key whose path could leave the target directory, verifies every node by
//! its CID and the size against the entry, writes through a temporary file and a rename, never
//! replaces a file unless asked, and never sets the executable bit.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentspaces::content::FetchOptions;
use agentspaces::peer::Peer;
use agentspaces::space::{EntryId, Lease, Template};
use agentspaces::wire::cbor::{self, Map, Value};
use agentspaces::wire::pdt::blob;
use agentspaces::wire::pdt::file_entry::{self, FileEntry};
use agentspaces::wire::pdt::store::Flusher;

use crate::refs::{Pdt, PdtError, Ref};

/// The tree ref every member shares files under.
pub const MAP_NAME: &str = "file-share";
/// The `location` of a `SharedFile` record.
pub const LOCATION: &str = "file-share";
/// The Groovy console's record type.
pub const SHARED_FILE_TYPE: &str = "ai.badmonkey.agentspaces.groovy.console.files.SharedFile#v1";
/// The default size limit, the console's.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// The lease of a `SharedFile` record.
pub const RECORD_LEASE: Duration = Duration::from_secs(30 * 60);
/// The most files one directory share takes.
pub const MAX_FILES_PER_SHARE: usize = 1000;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Why a file-share operation failed. Each message says what to do next.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// The path or key is refused.
    #[error("{0}")]
    Refused(String),
    /// Reading or writing a local file failed.
    #[error("{0}")]
    Io(String),
    /// The ref or the content swarm failed.
    #[error("{0}")]
    Pdt(#[from] PdtError),
    /// The key is not in the map.
    #[error("no file is shared under {0}")]
    NoSuchKey(String),
    /// The target exists and replacing it was not asked for.
    #[error("{0} exists; pass overwrite to replace it")]
    Exists(String),
}

fn io(what: &str, e: impl std::fmt::Display) -> ShareError {
    ShareError::Io(format!("{what}: {e}"))
}

/// A file ready to share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    /// The file's real path.
    pub path: PathBuf,
    /// Its path relative to the root directory, with `/` separators.
    pub relative: String,
    /// The map key, `<space>/<relative>`.
    pub key: String,
    /// The file name.
    pub name: String,
    /// The bytes.
    pub size: u64,
    /// The media type, from the extension.
    pub media_type: String,
}

/// What a share wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The map key.
    pub key: String,
    /// The blob root.
    pub root: String,
    /// The bytes.
    pub size: u64,
    /// The space.
    pub space: String,
    /// The `SharedFile` record.
    pub record: EntryId,
}

/// One shared file as a reader lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The map key.
    pub key: String,
    /// The key without its `<space>/` prefix.
    pub relative: String,
    /// The map's entry.
    pub entry: FileEntry,
    /// The sharer's PeerID, from the live `SharedFile` record, when there is one.
    pub sharer: Option<String>,
    /// When the record says the file was shared, epoch milliseconds.
    pub shared_at: Option<i64>,
    /// Whether this member wrote the record.
    pub mine: bool,
}

/// How the file share runs.
#[derive(Debug, Clone)]
pub struct FileShareConfig {
    /// The size limit, both ways.
    pub max_bytes: u64,
    /// How long a download waits for the blob's holders.
    pub fetch_timeout: Duration,
    /// A file that lists what this member shared (key and root, one per line), so a restart over
    /// a durable node store resumes holding them; `None` keeps no list.
    pub ledger: Option<PathBuf>,
}

impl Default for FileShareConfig {
    fn default() -> Self {
        FileShareConfig { max_bytes: MAX_FILE_BYTES, fetch_timeout: Duration::from_secs(120), ledger: None }
    }
}

struct OwnRecord {
    entry: EntryId,
    space: String,
    renewed: Instant,
}

/// The file share over a [`Pdt`]. Cheap to clone.
#[derive(Clone)]
pub struct FileShare {
    pdt: Pdt,
    map: Ref,
    config: FileShareConfig,
    records: Arc<Mutex<HashMap<String, OwnRecord>>>,
}

impl std::fmt::Debug for FileShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileShare").field("max_bytes", &self.config.max_bytes).finish()
    }
}

/// The media type of a file name, from its extension.
pub fn media_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "parquet" => "application/vnd.apache.parquet",
        "groovy" => "text/x-groovy",
        "java" => "text/x-java",
        "py" => "text/x-python",
        "rs" => "text/x-rust",
        _ => file_entry::OCTET_STREAM,
    }
}

/// The path under a target directory that the relative part of a key names, or a refusal when
/// it could leave the directory or names something no file system holds safely.
pub fn safe_relative(relative: &str) -> Result<PathBuf, ShareError> {
    let refuse = |why: &str| ShareError::Refused(format!("refused to write {relative:?}: {why}"));
    if relative.is_empty() || relative.len() > 4096 {
        return Err(refuse("empty or too long"));
    }
    if relative.starts_with('/') || relative.contains('\\') {
        return Err(refuse("absolute, or holds a backslash"));
    }
    let mut out = PathBuf::new();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(refuse("an empty, '.' or '..' component"));
        }
        if part.chars().any(|c| c.is_control()) || part.contains(':') {
            return Err(refuse("a control character or ':'"));
        }
        let stem = part.split('.').next().unwrap_or_default().to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit());
        if reserved || part.ends_with(' ') || part.ends_with('.') {
            return Err(refuse("a name Windows reserves"));
        }
        out.push(part);
    }
    if out.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(refuse("not a plain relative path"));
    }
    Ok(out)
}

/// A key's text item, the map's key form.
fn key_item(key: &str) -> Vec<u8> {
    cbor::encode(&Value::from(key))
}

/// The record's payload, fields in the console's order.
fn shared_file(key: &str, name: &str, root: &str, size: u64, media_type: &str) -> Value {
    let mut m = Map::new();
    m.insert("location", LOCATION);
    m.insert("key", key);
    m.insert("name", name);
    m.insert("root", root);
    m.insert("size", Value::Int(i128::from(size)));
    m.insert("mediaType", media_type);
    m.insert("sharedAt", Value::Int(i128::from(now_ms())));
    Value::Map(m)
}

impl FileShare {
    /// The file share over `pdt`.
    pub fn new(pdt: Pdt, config: FileShareConfig) -> Result<FileShare, ShareError> {
        let map = pdt.tree_ref(MAP_NAME)?;
        Ok(FileShare { pdt, map, config, records: Arc::new(Mutex::new(HashMap::new())) })
    }

    /// Holds again every root the ledger lists whose tree is complete in the node store; returns
    /// how many it holds. Call it once after start over a durable store.
    pub async fn resume(&self) -> usize {
        let Some(ledger) = &self.config.ledger else { return 0 };
        let Ok(text) = std::fs::read_to_string(ledger) else { return 0 };
        let mut held = 0;
        let mut seen = std::collections::HashSet::new();
        for line in text.lines() {
            let Some((_, root)) = line.split_once(' ') else { continue };
            if !seen.insert(root.to_string()) || agentspaces::wire::pdt::cid::parse(root).is_err() {
                continue;
            }
            if self.pdt.content().hold_tree(root).await.is_ok() {
                held += 1;
            }
        }
        held
    }

    fn note_shared(&self, key: &str, root: &str) {
        let Some(ledger) = &self.config.ledger else { return };
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(ledger) {
            let _ = writeln!(f, "{key} {root}");
        }
    }

    /// The size limit.
    pub fn max_bytes(&self) -> u64 {
        self.config.max_bytes
    }

    /// The `file-share` ref.
    pub fn map(&self) -> &Ref {
        &self.map
    }

    fn peer(&self) -> &Peer {
        self.pdt.content().peer()
    }

    /// Checks a file for sharing into `space` from `root_dir`.
    pub fn inspect(&self, space: &str, root_dir: &Path, path: &Path) -> Result<Inspected, ShareError> {
        if space.is_empty() || space.contains('/') {
            return Err(ShareError::Refused(format!("{space:?} is no space name")));
        }
        let root = root_dir.canonicalize().map_err(|e| io(&format!("the root directory {}", root_dir.display()), e))?;
        let meta = std::fs::symlink_metadata(path).map_err(|e| io(&path.display().to_string(), e))?;
        if meta.file_type().is_symlink() {
            return Err(ShareError::Refused(format!("{} is a symbolic link; share a regular file", path.display())));
        }
        if !meta.is_file() {
            return Err(ShareError::Refused(format!("{} is not a regular file", path.display())));
        }
        let real = path.canonicalize().map_err(|e| io(&path.display().to_string(), e))?;
        let relative = real.strip_prefix(&root).map_err(|_| {
            ShareError::Refused(format!("{} is outside {}; share a file inside the root directory", path.display(), root.display()))
        })?;
        let relative: Vec<String> = relative.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        let relative = relative.join("/");
        safe_relative(&relative)?;
        if meta.len() > self.config.max_bytes {
            return Err(ShareError::Refused(format!(
                "{} is {} bytes; file sharing takes files up to {} bytes",
                path.display(),
                meta.len(),
                self.config.max_bytes
            )));
        }
        let name = real.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        Ok(Inspected {
            key: format!("{space}/{relative}"),
            media_type: media_type(&name).to_string(),
            path: real,
            relative,
            name,
            size: meta.len(),
        })
    }

    /// The regular files under `dir` (inside `root_dir`), at most [`MAX_FILES_PER_SHARE`],
    /// skipping symbolic links and dot files; the paths skipped come back too.
    pub fn files_under(&self, dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), ShareError> {
        let mut files = Vec::new();
        let mut skipped = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let mut entries: Vec<_> = std::fs::read_dir(&d)
                .map_err(|e| io(&d.display().to_string(), e))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect();
            entries.sort();
            for p in entries {
                let hidden = p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'));
                let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
                if hidden || meta.file_type().is_symlink() {
                    skipped.push(p);
                } else if meta.is_dir() {
                    stack.push(p);
                } else if meta.is_file() {
                    if files.len() >= MAX_FILES_PER_SHARE {
                        skipped.push(p);
                    } else {
                        files.push(p);
                    }
                }
            }
        }
        Ok((files, skipped))
    }

    /// Shares one file: its blob held, the map entry swapped in, the record written.
    /// `progress` hears the bytes read so far.
    pub async fn publish(
        &self,
        space: &str,
        root_dir: &Path,
        path: &Path,
        progress: impl FnMut(u64) + Send + 'static,
    ) -> Result<Receipt, ShareError> {
        let inspected = self.inspect(space, root_dir, path)?;
        let nodes = self.pdt.nodes().clone();
        let source = inspected.path.clone();
        let limit = self.config.max_bytes;
        let written = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&source).map_err(|e| io(&source.display().to_string(), e))?;
            blob::write_stream(std::io::BufReader::new(file), limit, &mut Flusher::new(&*nodes), progress)
                .map_err(|e| ShareError::Refused(format!("{}: {e}", source.display())))
        })
        .await
        .map_err(|e| io("the share task", e))??;
        self.pdt.content().hold_tree(&written.root).await.map_err(PdtError::from)?;
        let entry = FileEntry::new(&written.root, written.size, file_entry::REGULAR, &inspected.media_type)
            .map_err(|e| ShareError::Refused(e.to_string()))?;
        let item = entry.encode();
        let key = inspected.key.clone();
        self.map.swap_map(move |nodes, m| m.assoc(nodes, &key_item(&key), &item)).await?;
        self.note_shared(&inspected.key, &written.root);
        let record = self.write_record(space, &inspected.key, &inspected.name, &written.root, written.size, &inspected.media_type).await?;
        Ok(Receipt { key: inspected.key, root: written.root, size: written.size, space: space.to_string(), record })
    }

    async fn write_record(&self, space: &str, key: &str, name: &str, root: &str, size: u64, media: &str) -> Result<EntryId, ShareError> {
        let mut tags = Map::new();
        tags.insert("location", LOCATION);
        tags.insert("key", key);
        let lease = Lease::from_millis(RECORD_LEASE.as_millis() as i64).map_err(|e| ShareError::Refused(e.to_string()))?;
        let id = self
            .peer()
            .space(space)
            .write_value(SHARED_FILE_TYPE, shared_file(key, name, root, size, media), lease, cbor::canonical_map(&tags))
            .await
            .map_err(|e| ShareError::Pdt(PdtError::Space(e.to_string())))?;
        let previous = {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records.insert(key.to_string(), OwnRecord { entry: id.clone(), space: space.to_string(), renewed: Instant::now() })
        };
        if let Some(old) = previous {
            let _ = self.peer().space(&old.space).cancel(&old.entry).await;
        }
        Ok(id)
    }

    /// The files shared into `space`, by key, joined with the space's live records.
    pub async fn list(&self, space: &str) -> Result<Vec<Listed>, ShareError> {
        let map = self.map.deref_map().await?;
        let nodes = self.pdt.nodes();
        let prefix = format!("{space}/");
        let template = Template::new(SHARED_FILE_TYPE).tag_eq("location", LOCATION);
        let records = self
            .peer()
            .space(space)
            .read_all(&template, 4096)
            .await
            .map_err(|e| ShareError::Pdt(PdtError::Space(e.to_string())))?;
        let me = self.peer().peer_id().to_string();
        let mut by_key: HashMap<String, (String, i64)> = HashMap::new();
        for r in records {
            let Some(key) = r.payload().get("key").and_then(Value::as_str) else { continue };
            let at = r.payload().get("sharedAt").and_then(Value::as_i64).unwrap_or(0);
            let sharer = r.issuer().split('/').next().unwrap_or_default().to_string();
            if by_key.get(key).is_none_or(|(_, t)| at >= *t) {
                by_key.insert(key.to_string(), (sharer, at));
            }
        }
        let mut out = Vec::new();
        for (k, v) in map.items(&**nodes).map_err(PdtError::from)? {
            let Ok(Value::Text(key)) = cbor::decode(&k) else { continue };
            let Some(relative) = key.strip_prefix(&prefix) else { continue };
            let Ok(entry) = FileEntry::decode(&v) else { continue };
            let record = by_key.get(&key);
            out.push(Listed {
                relative: relative.to_string(),
                sharer: record.map(|(s, _)| s.clone()),
                shared_at: record.map(|(_, t)| *t),
                mine: record.is_some_and(|(s, _)| *s == me),
                key,
                entry,
            });
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// Downloads the file shared under `key` into `target_dir` at its relative path; refuses to
    /// replace an existing file unless `overwrite`. `progress` hears the bytes written so far.
    pub async fn download(
        &self,
        space: &str,
        key: &str,
        target_dir: &Path,
        overwrite: bool,
        mut progress: impl FnMut(u64) + Send + 'static,
    ) -> Result<PathBuf, ShareError> {
        let relative = key
            .strip_prefix(&format!("{space}/"))
            .ok_or_else(|| ShareError::Refused(format!("{key} is not a key of space {space}")))?;
        let relative_path = safe_relative(relative)?;
        let map = self.map.deref_map().await?;
        let nodes = self.pdt.nodes().clone();
        let item = map.get(&*nodes, &key_item(key)).map_err(PdtError::from)?.ok_or_else(|| ShareError::NoSuchKey(key.to_string()))?;
        let entry = FileEntry::decode(&item).map_err(|e| ShareError::Refused(e.to_string()))?;
        if entry.is_symlink() {
            return Err(ShareError::Refused(format!("{key} is a symbolic link; spacewalk does not write links")));
        }
        if entry.size > self.config.max_bytes {
            return Err(ShareError::Refused(format!("{key} claims {} bytes, past the {}-byte limit", entry.size, self.config.max_bytes)));
        }
        let target_root = target_dir.canonicalize().map_err(|e| io(&target_dir.display().to_string(), e))?;
        let target = target_root.join(&relative_path);
        // every directory on the way must be a real directory inside the target, never a link
        let mut dir = target_root.clone();
        if let Some(parent) = relative_path.parent() {
            for part in parent.components() {
                dir.push(part);
                match std::fs::symlink_metadata(&dir) {
                    Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                        return Err(ShareError::Refused(format!("{} is not a plain directory", dir.display())));
                    }
                    Ok(_) => {}
                    Err(_) => std::fs::create_dir(&dir).map_err(|e| io(&dir.display().to_string(), e))?,
                }
            }
        }
        match std::fs::symlink_metadata(&target) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                return Err(ShareError::Refused(format!("{} exists and is not a regular file", target.display())));
            }
            Ok(_) if !overwrite => return Err(ShareError::Exists(target.display().to_string())),
            _ => {}
        }
        // the sharer and the holders the content space names
        let mut prefer: Vec<String> = Vec::new();
        if let Ok(listed) = self.list(space).await
            && let Some(sharer) = listed.iter().find(|l| l.key == key).and_then(|l| l.sharer.clone())
        {
            prefer.push(sharer);
        }
        let options = FetchOptions { prefer, timeout: Some(self.config.fetch_timeout), ..Default::default() };
        self.pdt.content().fetch_tree(&entry.root, options).await.map_err(PdtError::from)?;
        let size = entry.size;
        let root = entry.root.clone();
        let final_path = target.clone();
        tokio::task::spawn_blocking(move || {
            let chunks = blob::chunks(&*nodes, &root).map_err(|e| ShareError::Refused(e.to_string()))?;
            let total: u64 = chunks.iter().map(|c| c.length).sum();
            if total != size {
                return Err(ShareError::Refused(format!("the blob holds {total} bytes where the entry says {size}")));
            }
            let parent = final_path.parent().unwrap_or(Path::new("."));
            let temp = parent.join(format!(".spacewalk-{}-{}.part", std::process::id(), now_ms()));
            let result = (|| {
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp).map_err(|e| io(&temp.display().to_string(), e))?;
                let mut done = 0u64;
                for c in &chunks {
                    let bytes = blob::chunk(&*nodes, c).map_err(|e| ShareError::Refused(e.to_string()))?;
                    file.write_all(&bytes).map_err(|e| io(&temp.display().to_string(), e))?;
                    done += bytes.len() as u64;
                    progress(done);
                }
                file.sync_all().map_err(|e| io(&temp.display().to_string(), e))?;
                std::fs::rename(&temp, &final_path).map_err(|e| io(&final_path.display().to_string(), e))
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&temp);
            }
            result
        })
        .await
        .map_err(|e| io("the download task", e))??;
        Ok(target)
    }

    /// Removes `key` from the map and withdraws this member's record of it.
    pub async fn withdraw(&self, space: &str, key: &str) -> Result<(), ShareError> {
        if !key.starts_with(&format!("{space}/")) {
            return Err(ShareError::Refused(format!("{key} is not a key of space {space}")));
        }
        let k = key_item(key);
        self.map.swap_map(move |nodes, m| m.dissoc(nodes, &k)).await?;
        let own = self.records.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
        if let Some(own) = own {
            let _ = self.peer().space(&own.space).cancel(&own.entry).await;
        }
        Ok(())
    }

    /// Renews this member's records at half their lease (call it on a timer while running).
    pub async fn renew_records(&self) {
        let due: Vec<(String, EntryId, String)> = {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .iter()
                .filter(|(_, r)| r.renewed.elapsed() >= RECORD_LEASE / 2)
                .map(|(k, r)| (k.clone(), r.entry.clone(), r.space.clone()))
                .collect()
        };
        for (key, entry, space) in due {
            if let Ok(lease) = Lease::from_millis(RECORD_LEASE.as_millis() as i64) {
                let _ = self.peer().space(&space).renew_write(&entry, lease).await;
            }
            if let Some(r) = self.records.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&key) {
                r.renewed = Instant::now();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_keys_are_refused() {
        for bad in ["", "/etc/passwd", "../x", "a/../../x", "a//b", "a/./b", "a\\b", "a/\u{1b}[2Jb", "CON", "dir/lpt1.txt", "c:x", "trailing."] {
            assert!(safe_relative(bad).is_err(), "{bad:?}");
        }
        assert_eq!(safe_relative("data/report.csv").unwrap(), PathBuf::from("data/report.csv"));
        assert_eq!(safe_relative("console.txt").unwrap(), PathBuf::from("console.txt"));
    }

    #[test]
    fn media_types_come_from_extensions() {
        assert_eq!(media_type("report.CSV"), "text/csv");
        assert_eq!(media_type("noext"), file_entry::OCTET_STREAM);
    }
}
