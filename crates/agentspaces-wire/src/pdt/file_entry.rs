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

//! `FileEntry`, the value of a tree ref's map (annex H, blobs: "a directory is a `PMap` from
//! relative path to a value holding the blob root as text, the size, the mode, and the media
//! type"; Java `pdt.blob.FileEntry`). It embeds as the CBOR of `{root, size, mode, mediaType}`
//! in that order, which is what the Groovy console's file share writes under each key.

use crate::cbor::{self, Map, Value};

use super::{PdtError, Result, cid};

/// A regular file.
pub const REGULAR: &str = "100644";
/// An executable file.
pub const EXECUTABLE: &str = "100755";
/// A symbolic link whose blob holds the target path.
pub const SYMLINK: &str = "120000";
/// The media type of a file no table knows.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// One file of a tree: its blob root, size, mode, and media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The blob root, as CID text.
    pub root: String,
    /// The bytes.
    pub size: u64,
    /// [`REGULAR`], [`EXECUTABLE`], or [`SYMLINK`].
    pub mode: String,
    /// The media type.
    pub media_type: String,
}

impl FileEntry {
    /// A validated entry.
    pub fn new(root: &str, size: u64, mode: &str, media_type: &str) -> Result<FileEntry> {
        cid::parse(root).map_err(|e| PdtError::Invalid(format!("file entry root: {}", e.rule)))?;
        if ![REGULAR, EXECUTABLE, SYMLINK].contains(&mode) {
            return Err(PdtError::Invalid(format!("unknown mode '{mode}'")));
        }
        if size > i64::MAX as u64 {
            return Err(PdtError::Invalid(format!("size {size} past a Java long")));
        }
        Ok(FileEntry {
            root: root.to_string(),
            size,
            mode: mode.to_string(),
            media_type: media_type.to_string(),
        })
    }

    /// The CBOR value, fields in declaration order.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("root", self.root.as_str());
        map.insert("size", Value::Int(i128::from(self.size)));
        map.insert("mode", self.mode.as_str());
        map.insert("mediaType", self.media_type.as_str());
        Value::Map(map)
    }

    /// The embedded CBOR item.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// An entry from its embedded CBOR item.
    pub fn decode(item: &[u8]) -> Result<FileEntry> {
        let value = cbor::decode(item).map_err(|e| PdtError::Invalid(format!("file entry: {e}")))?;
        let refuse = || PdtError::Invalid("file entry needs root, size, mode, and mediaType".to_string());
        let root = value.get("root").and_then(Value::as_str).ok_or_else(refuse)?;
        let size = value.get("size").and_then(Value::as_u64).ok_or_else(refuse)?;
        let mode = value.get("mode").and_then(Value::as_str).ok_or_else(refuse)?;
        let media_type = value.get("mediaType").and_then(Value::as_str).ok_or_else(refuse)?;
        FileEntry::new(root, size, mode, media_type)
    }

    /// Whether the entry is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode == SYMLINK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_in_declaration_order() {
        let root = cid::of(b"report", cid::RAW);
        let e = FileEntry::new(&root, 6, REGULAR, "text/csv").unwrap();
        let bytes = e.encode();
        assert_eq!(bytes[0], 0xBF, "an indefinite map, as Java's codec writes it");
        assert_eq!(&bytes[1..6], b"\x64root");
        assert_eq!(FileEntry::decode(&bytes).unwrap(), e);
        assert!(FileEntry::new(&root, 1, "777", "x").is_err());
    }
}
