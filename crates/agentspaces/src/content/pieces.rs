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
//! Where artifact pieces live: the [`PieceStore`] trait, [`MemoryPieces`], [`FilePieces`] (a
//! directory that survives restarts), and [`InPlace`] (an existing file served without a copy).
//!
//! A store keeps verified pieces only: the fetch checks each piece against the manifest's table
//! before it writes. The file store keeps, per root, the manifest, a data file of the artifact's
//! size, and the held bitfield, which it syncs every 8 pieces and when an artifact completes, so
//! an interrupted fetch resumes from what it held; it refuses an artifact past its quota.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::wire::content::Manifest;

/// The bytes of piece `index` of a manifest.
pub fn piece_length(m: &Manifest, index: i64) -> i64 {
    (m.size - index * m.piece_size).clamp(0, m.piece_size)
}

/// A store of artifact pieces.
pub trait PieceStore: Send + Sync {
    /// Prepares storage for an artifact (idempotent).
    fn open(&self, manifest: &Manifest) -> std::io::Result<()>;
    /// The manifest of a root held here.
    fn manifest(&self, root: &str) -> Option<Manifest>;
    /// Which pieces are held.
    fn have(&self, root: &str) -> Vec<bool>;
    /// A range of a held piece.
    fn read(&self, root: &str, index: i64, offset: i64, length: i64) -> Option<Vec<u8>>;
    /// Stores a whole verified piece.
    fn write(&self, root: &str, index: i64, data: &[u8]) -> std::io::Result<()>;
    /// The roots held.
    fn roots(&self) -> Vec<String>;
    /// Drops a root.
    fn forget(&self, root: &str);
    /// Flushes what is buffered.
    fn flush(&self) {}
}

/// Each root's manifest and its pieces, held or not.
type HeldPieces = HashMap<String, (Manifest, Vec<Option<Vec<u8>>>)>;

/// Pieces in memory.
#[derive(Debug, Default)]
pub struct MemoryPieces {
    held: Mutex<HeldPieces>,
}

impl MemoryPieces {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PieceStore for MemoryPieces {
    fn open(&self, m: &Manifest) -> std::io::Result<()> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.entry(m.root.clone()).or_insert_with(|| (m.clone(), vec![None; m.pieces as usize]));
        Ok(())
    }

    fn manifest(&self, root: &str) -> Option<Manifest> {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).get(root).map(|(m, _)| m.clone())
    }

    fn have(&self, root: &str) -> Vec<bool> {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).get(root).map(|(_, p)| p.iter().map(Option::is_some).collect()).unwrap_or_default()
    }

    fn read(&self, root: &str, index: i64, offset: i64, length: i64) -> Option<Vec<u8>> {
        let held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let piece = held.get(root)?.1.get(usize::try_from(index).ok()?)?.as_ref()?;
        let (start, end) = (usize::try_from(offset).ok()?, usize::try_from(offset + length).ok()?);
        piece.get(start..end).map(<[u8]>::to_vec)
    }

    fn write(&self, root: &str, index: i64, data: &[u8]) -> std::io::Result<()> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let (_, pieces) = held.get_mut(root).ok_or_else(|| std::io::Error::other("root not open"))?;
        let slot = pieces.get_mut(index as usize).ok_or_else(|| std::io::Error::other("no such piece"))?;
        *slot = Some(data.to_vec());
        Ok(())
    }

    fn roots(&self) -> Vec<String> {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect()
    }

    fn forget(&self, root: &str) {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).remove(root);
    }
}

/// Pieces in files under a directory: `<dir>/<root>/{manifest.cbor, data, have}`.
#[derive(Debug)]
pub struct FilePieces {
    dir: PathBuf,
    quota: u64,
    roots: Mutex<HashMap<String, FileRootState>>,
}

#[derive(Debug)]
struct FileRootState {
    manifest: Manifest,
    have: Vec<bool>,
    unsynced: usize,
}

impl FilePieces {
    /// The store under `dir` with a byte quota; loads what it already holds.
    pub fn open(dir: &Path, quota: u64) -> std::io::Result<FilePieces> {
        std::fs::create_dir_all(dir)?;
        let mut roots = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let Ok(bytes) = std::fs::read(path.join("manifest.cbor")) else { continue };
            let Some(manifest) = Manifest::decode(&bytes) else { continue };
            let have_bytes = std::fs::read(path.join("have")).unwrap_or_default();
            let have = (0..manifest.pieces as usize).map(|i| have_bytes.get(i).is_some_and(|b| *b == 1)).collect();
            roots.insert(manifest.root.clone(), FileRootState { manifest, have, unsynced: 0 });
        }
        Ok(FilePieces { dir: dir.to_path_buf(), quota, roots: Mutex::new(roots) })
    }

    fn root_dir(&self, root: &str) -> PathBuf {
        self.dir.join(root)
    }

    fn used(&self, roots: &HashMap<String, FileRootState>) -> u64 {
        roots.values().map(|r| r.manifest.size.max(0) as u64).sum()
    }

    fn sync(&self, root: &str, state: &mut FileRootState) -> std::io::Result<()> {
        let bits: Vec<u8> = state.have.iter().map(|h| u8::from(*h)).collect();
        let dir = self.root_dir(root);
        let temp = dir.join("have.part");
        std::fs::write(&temp, bits)?;
        std::fs::rename(&temp, dir.join("have"))?;
        state.unsynced = 0;
        Ok(())
    }
}

impl PieceStore for FilePieces {
    fn open(&self, m: &Manifest) -> std::io::Result<()> {
        let mut roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
        if roots.contains_key(&m.root) {
            return Ok(());
        }
        if self.used(&roots) + m.size.max(0) as u64 > self.quota {
            return Err(std::io::Error::other(format!(
                "the piece store's quota of {} bytes cannot take {} more",
                self.quota, m.size
            )));
        }
        let dir = self.root_dir(&m.root);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("manifest.cbor"), m.encode())?;
        let data = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("data"))?;
        data.set_len(m.size.max(0) as u64)?;
        let mut state = FileRootState { manifest: m.clone(), have: vec![false; m.pieces as usize], unsynced: 0 };
        self.sync(&m.root, &mut state)?;
        roots.insert(m.root.clone(), state);
        Ok(())
    }

    fn manifest(&self, root: &str) -> Option<Manifest> {
        self.roots.lock().unwrap_or_else(|e| e.into_inner()).get(root).map(|r| r.manifest.clone())
    }

    fn have(&self, root: &str) -> Vec<bool> {
        self.roots.lock().unwrap_or_else(|e| e.into_inner()).get(root).map(|r| r.have.clone()).unwrap_or_default()
    }

    fn read(&self, root: &str, index: i64, offset: i64, length: i64) -> Option<Vec<u8>> {
        let start = {
            let roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
            let r = roots.get(root)?;
            if !*r.have.get(usize::try_from(index).ok()?)? || offset < 0 || offset + length > piece_length(&r.manifest, index) {
                return None;
            }
            index * r.manifest.piece_size + offset
        };
        let mut f = std::fs::File::open(self.root_dir(root).join("data")).ok()?;
        f.seek(SeekFrom::Start(start as u64)).ok()?;
        let mut buf = vec![0u8; length as usize];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    fn write(&self, root: &str, index: i64, data: &[u8]) -> std::io::Result<()> {
        let mut roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
        let state = roots.get_mut(root).ok_or_else(|| std::io::Error::other("root not open"))?;
        let at = (index * state.manifest.piece_size) as u64;
        let mut f = std::fs::OpenOptions::new().write(true).open(self.root_dir(root).join("data"))?;
        f.seek(SeekFrom::Start(at))?;
        f.write_all(data)?;
        if let Some(h) = state.have.get_mut(index as usize) {
            *h = true;
        }
        state.unsynced += 1;
        if state.unsynced >= 8 || state.have.iter().all(|h| *h) {
            f.sync_data()?;
            let root = root.to_string();
            let state = roots.get_mut(&root).ok_or_else(|| std::io::Error::other("root not open"))?;
            self.sync(&root, state)?;
        }
        Ok(())
    }

    fn roots(&self) -> Vec<String> {
        self.roots.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect()
    }

    fn forget(&self, root: &str) {
        self.roots.lock().unwrap_or_else(|e| e.into_inner()).remove(root);
        let _ = std::fs::remove_dir_all(self.root_dir(root));
    }

    fn flush(&self) {
        let mut roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = roots.iter().filter(|(_, s)| s.unsynced > 0).map(|(k, _)| k.clone()).collect();
        for name in names {
            if let Some(state) = roots.get_mut(&name) {
                let _ = self.sync(&name, state);
            }
        }
    }
}

/// An existing file served without a copy. It refuses to serve once the file's size changed, or
/// when a sampled piece no longer hashes to the table.
#[derive(Debug, Clone)]
pub struct InPlace {
    /// The file.
    pub path: PathBuf,
    /// Its manifest.
    pub manifest: Manifest,
    /// The piece table.
    pub table: Vec<u8>,
}

impl InPlace {
    /// Whether the file still matches: its size, and the first, middle, and last pieces.
    pub fn intact(&self) -> bool {
        let Ok(meta) = std::fs::metadata(&self.path) else { return false };
        if meta.len() != self.manifest.size as u64 {
            return false;
        }
        let n = self.manifest.pieces;
        let mut picks = vec![0, n / 2, n - 1];
        picks.dedup();
        picks.into_iter().filter(|i| *i >= 0).all(|i| {
            self.read(i, 0, piece_length(&self.manifest, i))
                .is_some_and(|p| crate::wire::pdt::sha256(&p)[..] == self.table[(i as usize) * 32..(i as usize) * 32 + 32])
        })
    }

    /// A range of piece `index`.
    pub fn read(&self, index: i64, offset: i64, length: i64) -> Option<Vec<u8>> {
        if index < 0 || index >= self.manifest.pieces || offset < 0 || offset + length > piece_length(&self.manifest, index) {
            return None;
        }
        let mut f = std::fs::File::open(&self.path).ok()?;
        f.seek(SeekFrom::Start((index * self.manifest.piece_size + offset) as u64)).ok()?;
        let mut buf = vec![0u8; length as usize];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }
}

/// The piece table and size of a file, read piece by piece.
pub fn hash_file(path: &Path, piece_size: i64) -> std::io::Result<(Vec<u8>, i64)> {
    let mut f = std::fs::File::open(path)?;
    let mut table = Vec::new();
    let mut size = 0i64;
    let mut buf = vec![0u8; piece_size as usize];
    loop {
        let mut filled = 0;
        while filled < buf.len() {
            let n = f.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        table.extend_from_slice(&crate::wire::pdt::sha256(&buf[..filled]));
        size += filled as i64;
        if filled < buf.len() {
            break;
        }
    }
    Ok((table, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::content;

    fn manifest_of(data: &[u8], piece_size: i64) -> (Manifest, Vec<u8>) {
        let table: Vec<u8> = data.chunks(piece_size as usize).flat_map(crate::wire::pdt::sha256).collect();
        let m = Manifest {
            v: 1,
            root: content::content_root(&table),
            size: data.len() as i64,
            piece_size,
            pieces: content::pieces_of(data.len() as i64, piece_size),
            table: Some(table.clone()),
            table_ref: None,
            table_refs: None,
            name: None,
            media_type: None,
            sealing: "none".into(),
            key_epoch: None,
            hashing: "plain".into(),
            origin: "zOrigin".into(),
            created: 0,
            attrs: None,
            layout: None,
        };
        (m, table)
    }

    #[test]
    fn the_file_store_resumes_and_keeps_its_quota() {
        let dir = std::env::temp_dir().join(format!("filepieces-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
        let (m, _) = manifest_of(&data, 65_536);
        {
            let store = FilePieces::open(&dir, 1 << 20).unwrap();
            store.open(&m).unwrap();
            store.write(&m.root, 1, &data[65_536..131_072]).unwrap();
            store.write(&m.root, 4, &data[262_144..]).unwrap();
            store.flush();
        }
        let store = FilePieces::open(&dir, 1 << 20).unwrap();
        assert_eq!(store.have(&m.root), vec![false, true, false, false, true]);
        assert_eq!(store.read(&m.root, 4, 0, (300_000 - 262_144) as i64).unwrap(), &data[262_144..]);
        assert!(store.read(&m.root, 0, 0, 10).is_none());
        let (big, _) = manifest_of(&vec![1u8; 900_000], 65_536);
        assert!(store.open(&big).is_err(), "past the quota");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_in_place_file_stops_serving_once_it_changes() {
        let path = std::env::temp_dir().join(format!("inplace-{}", std::process::id()));
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 13) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let (table, size) = hash_file(&path, 65_536).unwrap();
        assert_eq!(size, 200_000);
        let (m, t) = manifest_of(&data, 65_536);
        assert_eq!(table, t);
        let place = InPlace { path: path.clone(), manifest: m, table };
        assert!(place.intact());
        std::fs::write(&path, b"changed").unwrap();
        assert!(!place.intact());
        let _ = std::fs::remove_file(&path);
    }
}
