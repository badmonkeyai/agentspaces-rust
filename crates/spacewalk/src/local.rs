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

//! The local pane: the root directory as a lazy tree, read only where it is expanded.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One visible row of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRow {
    /// The path.
    pub path: PathBuf,
    /// The path relative to the root, with `/` separators.
    pub relative: String,
    /// Indentation.
    pub depth: usize,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// Whether a directory row is expanded.
    pub expanded: bool,
    /// Whether it is a symbolic link (never shared).
    pub is_link: bool,
    /// The bytes of a file.
    pub size: u64,
}

/// The tree: which directories are expanded, and whether dot files show.
#[derive(Debug, Clone)]
pub struct LocalTree {
    root: PathBuf,
    expanded: HashSet<PathBuf>,
    /// Whether dot files show.
    pub show_hidden: bool,
}

impl LocalTree {
    /// The tree of `root`, nothing expanded.
    pub fn new(root: &Path) -> LocalTree {
        LocalTree { root: root.to_path_buf(), expanded: HashSet::new(), show_hidden: false }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Expands a directory, or collapses it when expanded.
    pub fn toggle(&mut self, dir: &Path) {
        if !self.expanded.remove(dir) {
            self.expanded.insert(dir.to_path_buf());
        }
    }

    /// The visible rows: directories first, then files, by name; expanded directories inline.
    pub fn rows(&self) -> Vec<LocalRow> {
        let mut out = Vec::new();
        self.read(&self.root, 0, &mut out);
        out
    }

    fn read(&self, dir: &Path, depth: usize, out: &mut Vec<LocalRow>) {
        if depth > 32 || out.len() > 20_000 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        let mut items: Vec<(PathBuf, std::fs::Metadata)> = entries
            .filter_map(Result::ok)
            .filter(|e| self.show_hidden || !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| std::fs::symlink_metadata(e.path()).ok().map(|m| (e.path(), m)))
            .collect();
        items.sort_by(|a, b| b.1.is_dir().cmp(&a.1.is_dir()).then_with(|| a.0.file_name().cmp(&b.0.file_name())));
        for (path, meta) in items {
            let relative = path
                .strip_prefix(&self.root)
                .map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"))
                .unwrap_or_default();
            let is_dir = meta.is_dir();
            let expanded = is_dir && self.expanded.contains(&path);
            out.push(LocalRow {
                relative,
                depth,
                is_dir,
                expanded,
                is_link: meta.file_type().is_symlink(),
                size: if meta.is_file() { meta.len() } else { 0 },
                path: path.clone(),
            });
            if expanded {
                self.read(&path, depth + 1, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_lazily_and_hides_dot_files() {
        let root = std::env::temp_dir().join(format!("spacewalk-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("data/report.csv"), b"a,b").unwrap();
        std::fs::write(root.join("README.md"), b"x").unwrap();
        std::fs::write(root.join(".env"), b"secret").unwrap();
        let mut tree = LocalTree::new(&root);
        let names: Vec<String> = tree.rows().into_iter().map(|r| r.relative).collect();
        assert_eq!(names, ["data", "README.md"]);
        tree.toggle(&root.join("data"));
        let names: Vec<String> = tree.rows().into_iter().map(|r| r.relative).collect();
        assert_eq!(names, ["data", "data/report.csv", "README.md"]);
        tree.show_hidden = true;
        assert!(tree.rows().iter().any(|r| r.relative == ".env"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
