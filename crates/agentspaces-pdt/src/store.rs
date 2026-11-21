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
//! A durable node store: one file per node under a directory, so a member keeps what it shared
//! and fetched across restarts.
//!
//! A node lives at `<dir>/nodes/<last two characters of its CID>/<CID>`. A write goes through a
//! temporary file and a rename, so a crash never leaves half a node under its name; a read
//! verifies the bytes against the CID and removes a file that fails, which then reads as
//! missing and is fetched again. The set of CIDs held is kept in memory after one scan, so
//! `has` never touches the disk.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentspaces::wire::pdt::cid;
use agentspaces::wire::pdt::store::Nodes;

/// Nodes in files under a directory.
#[derive(Debug)]
pub struct FileNodes {
    dir: PathBuf,
    held: Mutex<HashSet<String>>,
    bytes: Mutex<u64>,
}

impl FileNodes {
    /// The store under `dir`, created when missing; scans what it already holds.
    pub fn open(dir: &Path) -> std::io::Result<FileNodes> {
        let nodes = dir.join("nodes");
        std::fs::create_dir_all(&nodes)?;
        let mut held = HashSet::new();
        let mut bytes = 0u64;
        for fan in std::fs::read_dir(&nodes)? {
            let fan = fan?.path();
            if !fan.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&fan)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if cid::is_cid(&name) {
                    bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                    held.insert(name);
                } else if name.ends_with(".part") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        Ok(FileNodes { dir: dir.to_path_buf(), held: Mutex::new(held), bytes: Mutex::new(bytes) })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The nodes held.
    pub fn len(&self) -> usize {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the store holds no node.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes held.
    pub fn total_bytes(&self) -> u64 {
        *self.bytes.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn path_of(&self, c: &str) -> PathBuf {
        let fan = &c[c.len().saturating_sub(2)..];
        self.dir.join("nodes").join(fan).join(c)
    }

    fn forget(&self, c: &str) {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).remove(c);
    }
}

impl Nodes for FileNodes {
    fn get(&self, c: &str) -> Option<Arc<[u8]>> {
        if !cid::is_cid(c) || !self.has(c) {
            return None;
        }
        let path = self.path_of(c);
        let bytes = std::fs::read(&path).ok();
        match bytes {
            Some(b) if cid::verifies(c, &b) => Some(Arc::from(b)),
            _ => {
                // missing or corrupt on disk: forgotten, so the next read fetches it again
                let _ = std::fs::remove_file(&path);
                self.forget(c);
                None
            }
        }
    }

    fn has(&self, c: &str) -> bool {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).contains(c)
    }

    fn put(&self, c: &str, data: &[u8]) -> bool {
        if !cid::is_cid(c) || self.has(c) {
            return false;
        }
        let path = self.path_of(c);
        let Some(parent) = path.parent() else { return false };
        if std::fs::create_dir_all(parent).is_err() {
            return false;
        }
        let temp = parent.join(format!("{c}.{}.part", std::process::id()));
        let written = std::fs::File::create(&temp)
            .and_then(|mut f| f.write_all(data).and_then(|()| f.sync_data()))
            .and_then(|()| std::fs::rename(&temp, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
            return false;
        }
        self.held.lock().unwrap_or_else(|e| e.into_inner()).insert(c.to_string());
        *self.bytes.lock().unwrap_or_else(|e| e.into_inner()) += data.len() as u64;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces::wire::pdt::blob;
    use agentspaces::wire::pdt::store::Flusher;

    #[test]
    fn nodes_survive_a_reopen_and_corruption_reads_as_missing() {
        let dir = std::env::temp_dir().join(format!("filenodes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let data: Vec<u8> = (0..700_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 7) as u8).collect();
        let root = {
            let store = FileNodes::open(&dir).unwrap();
            let written = blob::write_bytes(&data, &mut Flusher::new(&store)).unwrap();
            assert!(store.len() > 1);
            written.root
        };
        let store = FileNodes::open(&dir).unwrap();
        assert_eq!(blob::read_all(&store, &root).unwrap(), data);
        // corrupt one chunk on disk: it reads as missing, never as wrong bytes
        let chunk = blob::chunks(&store, &root).unwrap()[0].cid.clone();
        std::fs::write(store.path_of(&chunk), b"not the chunk").unwrap();
        assert!(store.get(&chunk).is_none());
        assert!(!store.has(&chunk));
        assert!(blob::read_all(&store, &root).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
