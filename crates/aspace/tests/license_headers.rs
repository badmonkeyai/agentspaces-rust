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

//! Every source file in the repository carries the Apache 2.0 header with the Bad Monkey, Inc.
//! copyright near its top: Rust, Java, shell, JavaScript, Ruby, Python, TOML, XML, and YAML.
//! Markdown, JSON, lock files, and test snapshots are not checked.
//!
//! The test walks the workspace from this crate's manifest directory. Run from a packaged crate
//! (no workspace above it), it has nothing to check and passes.

use std::fs;
use std::path::{Path, PathBuf};

/// Extensions whose files must carry the header.
const CHECKED: &[&str] = &[
    "rs", "java", "sh", "mjs", "js", "ts", "rb", "py", "toml", "xml", "yml", "yaml",
];

/// Directories never walked: build output, version control, and installed packages.
const SKIPPED_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// How many leading lines the header must appear within (it may follow a shebang or an XML
/// declaration).
const HEADER_WINDOW: usize = 25;

/// The workspace root: two directories above this crate, when a workspace manifest is there.
fn workspace_root() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).ok()?;
    manifest.contains("[workspace]").then_some(root)
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_ref()) {
                walk(&path, found);
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| CHECKED.contains(&ext))
        {
            found.push(path);
        }
    }
}

fn has_header(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let head: Vec<&str> = text.lines().take(HEADER_WINDOW).collect();
    let head = head.join("\n");
    head.contains("Bad Monkey, Inc.")
        && head.contains("Copyright 20")
        && head.contains("Licensed under the Apache License, Version 2.0")
        && head.contains("https://www.apache.org/licenses/LICENSE-2.0")
}

#[test]
fn every_source_file_carries_the_apache_header() {
    let Some(root) = workspace_root() else {
        eprintln!("no workspace above this crate: nothing to check");
        return;
    };
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 100,
        "expected the workspace's sources, found {} files under {}",
        files.len(),
        root.display()
    );
    let mut missing: Vec<String> = files
        .iter()
        .filter(|path| !has_header(path))
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "{} file(s) lack the Apache 2.0 header (Copyright 2026 Bad Monkey, Inc.; see any \
         existing source file for the text):\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}
