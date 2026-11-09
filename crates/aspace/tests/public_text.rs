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

//! The repository's text is public: no source file or Markdown page cites an internal design
//! document, requirement id, finding id, or private project.
//!
//! The test walks the same files as `license_headers.rs` (Rust, Java, shell, JavaScript, Ruby,
//! Python, TOML, XML, and YAML) plus Markdown, and skips the same directories. It skips this
//! file, which holds the marker list. The vendored JSON vector files are not walked: they are
//! generated on the Java side and compared byte for byte.
//!
//! Every marker is case-sensitive. The matchers are small hand-written functions over ASCII
//! bytes, so the test needs no regex crate.
//!
//! Run from a packaged crate (no workspace above it), it has nothing to check and passes.

use std::fs;
use std::path::{Path, PathBuf};

/// Extensions whose files are scanned: the license header test's list plus Markdown.
const CHECKED: &[&str] = &[
    "rs", "java", "sh", "mjs", "js", "ts", "rb", "py", "toml", "xml", "yml", "yaml", "md",
];

/// Directories never walked: build output, version control, and installed packages.
const SKIPPED_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Files never scanned, as paths from the workspace root: this test, whose marker list would
/// match itself.
const SKIPPED_FILES: &[&str] = &["crates/aspace/tests/public_text.rs"];

/// How a marker is found in a line.
enum Rule {
    /// The text anywhere in the line.
    Text(&'static str),
    /// The text with a word boundary before it, followed by anything.
    Prefix(&'static str),
    /// `\b` + the text + `[0-9]+\b`.
    Numbered(&'static str),
    /// `\b` + the text + `[0-9]+-[0-9]+\b`.
    Paired(&'static str),
    /// A shape matcher, tried at every byte offset of the line.
    Shape(fn(&[u8], usize) -> bool),
}

/// An internal marker: the regex it stands for (shown in failures) and how to find it.
struct Marker {
    pattern: &'static str,
    rule: Rule,
}

const MARKERS: &[Marker] = &[
    Marker {
        pattern: r"\bsrad",
        rule: Rule::Prefix("srad"),
    },
    Marker {
        pattern: r"\bSRAD",
        rule: Rule::Prefix("SRAD"),
    },
    Marker {
        pattern: r"\bRS-[A-Z]+(-[A-Z]+)?-[0-9]+\b",
        rule: Rule::Shape(requirement_id),
    },
    Marker {
        pattern: r"\bRS[0-9]+-[A-Z]",
        rule: Rule::Shape(round_finding_id),
    },
    Marker {
        pattern: r"\bASF-[0-9]+\b",
        rule: Rule::Shape(finding_id),
    },
    Marker {
        pattern: r"\bQA[0-9]+\b",
        rule: Rule::Numbered("QA"),
    },
    Marker {
        pattern: r"\bA[0-9]+-[0-9]+\b",
        rule: Rule::Paired("A"),
    },
    Marker {
        pattern: r"\bP[0-9]+-[0-9]+\b",
        rule: Rule::Paired("P"),
    },
    Marker {
        pattern: r"\bSEC-[0-9]+\b",
        rule: Rule::Numbered("SEC-"),
    },
    Marker {
        pattern: r"\bMCP-[0-9]+\b",
        rule: Rule::Numbered("MCP-"),
    },
    Marker {
        pattern: r"\bFR-[0-9]+\b",
        rule: Rule::Numbered("FR-"),
    },
    Marker {
        pattern: r"\bSecurity F[0-9]+\b",
        rule: Rule::Numbered("Security F"),
    },
    Marker {
        pattern: r"\bDaemon F[0-9]+\b",
        rule: Rule::Numbered("Daemon F"),
    },
    Marker {
        pattern: r"\bdecision D[0-9]+\b",
        rule: Rule::Numbered("decision D"),
    },
    Marker {
        pattern: r"\bphase [0-9]+\b",
        rule: Rule::Numbered("phase "),
    },
    Marker {
        pattern: r"\bPhase [0-9]+\b",
        rule: Rule::Numbered("Phase "),
    },
    Marker {
        pattern: "ISSUE-[A-Z][A-Za-z]+",
        rule: Rule::Shape(issue_name),
    },
    Marker {
        pattern: "HLC round",
        rule: Rule::Text("HLC round"),
    },
    Marker {
        pattern: "ROADMAP",
        rule: Rule::Text("ROADMAP"),
    },
    Marker {
        pattern: r"FEATURES\.md",
        rule: Rule::Text("FEATURES.md"),
    },
    Marker {
        pattern: "reviews/",
        rule: Rule::Text("reviews/"),
    },
    Marker {
        pattern: r"ROBUSTNESS\.md",
        rule: Rule::Text("ROBUSTNESS.md"),
    },
    Marker {
        pattern: "agentspaces-desktop",
        rule: Rule::Text("agentspaces-desktop"),
    },
    Marker {
        pattern: "agentspaces-harness",
        rule: Rule::Text("agentspaces-harness"),
    },
    Marker {
        pattern: "enterprise-platform",
        rule: Rule::Text("enterprise-platform"),
    },
    Marker {
        pattern: "Rust team report",
        rule: Rule::Text("Rust team report"),
    },
    Marker {
        pattern: "owner ruled",
        rule: Rule::Text("owner ruled"),
    },
];

/// A regex word character: ASCII letter, digit, or underscore.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// A word boundary (`\b`) sits before `at`: exactly one of the bytes either side is a word
/// character. Every marker starts with a word character, and ends with one wherever a boundary
/// follows it, so this reduces to "the outside neighbour is not one".
fn boundary_before(line: &[u8], at: usize) -> bool {
    at == 0 || !is_word(line[at - 1])
}

fn boundary_after(line: &[u8], at: usize) -> bool {
    at >= line.len() || !is_word(line[at])
}

/// The length of the run of bytes matching `class` that starts at `at`.
fn run(line: &[u8], at: usize, class: fn(&u8) -> bool) -> usize {
    line.get(at..)
        .map_or(0, |rest| rest.iter().take_while(|byte| class(byte)).count())
}

/// `line[at..]` starts with `prefix`.
fn starts_with(line: &[u8], at: usize, prefix: &[u8]) -> bool {
    line.get(at..).is_some_and(|rest| rest.starts_with(prefix))
}

/// `\bRS-[A-Z]+(-[A-Z]+)?-[0-9]+\b`. Letters, digits, and hyphens are disjoint classes, so
/// consuming each run greedily decides the match without backtracking.
fn requirement_id(line: &[u8], at: usize) -> bool {
    if !boundary_before(line, at) || !starts_with(line, at, b"RS-") {
        return false;
    }
    let mut pos = at + 3;
    let letters = run(line, pos, u8::is_ascii_uppercase);
    if letters == 0 {
        return false;
    }
    pos += letters;
    if !starts_with(line, pos, b"-") {
        return false;
    }
    pos += 1;
    let letters = run(line, pos, u8::is_ascii_uppercase);
    if letters > 0 {
        pos += letters;
        if !starts_with(line, pos, b"-") {
            return false;
        }
        pos += 1;
    }
    let digits = run(line, pos, u8::is_ascii_digit);
    digits > 0 && boundary_after(line, pos + digits)
}

/// `\bRS[0-9]+-[A-Z]`.
fn round_finding_id(line: &[u8], at: usize) -> bool {
    if !boundary_before(line, at) || !starts_with(line, at, b"RS") {
        return false;
    }
    let digits = run(line, at + 2, u8::is_ascii_digit);
    digits > 0
        && starts_with(line, at + 2 + digits, b"-")
        && line
            .get(at + 3 + digits)
            .is_some_and(u8::is_ascii_uppercase)
}

/// `\b` + `prefix` + `[0-9]+`, and the end of that digit run.
fn numbered(line: &[u8], at: usize, prefix: &str) -> Option<usize> {
    if !boundary_before(line, at) || !starts_with(line, at, prefix.as_bytes()) {
        return None;
    }
    let pos = at + prefix.len();
    let digits = run(line, pos, u8::is_ascii_digit);
    (digits > 0).then_some(pos + digits)
}

/// `\bASF-[0-9]+\b`.
fn finding_id(line: &[u8], at: usize) -> bool {
    if !boundary_before(line, at) || !starts_with(line, at, b"ASF-") {
        return false;
    }
    let digits = run(line, at + 4, u8::is_ascii_digit);
    digits > 0 && boundary_after(line, at + 4 + digits)
}

/// `ISSUE-[A-Z][A-Za-z]+`.
fn issue_name(line: &[u8], at: usize) -> bool {
    if !starts_with(line, at, b"ISSUE-") {
        return false;
    }
    let pos = at + 6;
    line.get(pos).is_some_and(u8::is_ascii_uppercase)
        && run(line, pos + 1, u8::is_ascii_alphabetic) > 0
}

/// The marker occurs somewhere in the line.
fn occurs(rule: &Rule, line: &str) -> bool {
    let bytes = line.as_bytes();
    match rule {
        Rule::Text(text) => line.contains(text),
        Rule::Prefix(text) => line
            .match_indices(text)
            .any(|(at, _)| boundary_before(bytes, at)),
        Rule::Numbered(text) => line
            .match_indices(text)
            .any(|(at, _)| numbered(bytes, at, text).is_some_and(|end| boundary_after(bytes, end))),
        Rule::Paired(text) => line.match_indices(text).any(|(at, _)| {
            numbered(bytes, at, text).is_some_and(|end| {
                let digits = run(bytes, end + 1, u8::is_ascii_digit);
                starts_with(bytes, end, b"-")
                    && digits > 0
                    && boundary_after(bytes, end + 1 + digits)
            })
        }),
        Rule::Shape(shape) => (0..bytes.len()).any(|at| shape(bytes, at)),
    }
}

/// The patterns of every marker the line contains.
fn markers_in(line: &str) -> Vec<&'static str> {
    MARKERS
        .iter()
        .filter(|marker| occurs(&marker.rule, line))
        .map(|marker| marker.pattern)
        .collect()
}

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

/// The path from the workspace root, with `/` between components on every platform.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn the_matchers_find_each_marker_shape_and_nothing_else() {
    let found = markers_in;

    assert_eq!(
        found("see RS-B-03 here"),
        [r"\bRS-[A-Z]+(-[A-Z]+)?-[0-9]+\b"]
    );
    assert_eq!(
        found("(RS-Q-SEC-12)"),
        [r"\bRS-[A-Z]+(-[A-Z]+)?-[0-9]+\b", r"\bSEC-[0-9]+\b"]
    );
    assert_eq!(found("RS-CR-7."), [r"\bRS-[A-Z]+(-[A-Z]+)?-[0-9]+\b"]);
    for clean in [
        "RS-B-03a",
        "XRS-B-03",
        "RS-B-C-D-03",
        "RS-b-03",
        "RS--03",
        "RS-B-",
    ] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }

    assert_eq!(found("fixes ASF-017,"), [r"\bASF-[0-9]+\b"]);
    for clean in ["ASF-", "ASF-01x", "_ASF-01", "asf-01"] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }

    assert_eq!(
        found("ISSUE-Motion FR-4"),
        [r"\bFR-[0-9]+\b", "ISSUE-[A-Z][A-Za-z]+"]
    );
    for clean in ["ISSUE-M", "ISSUE-motion", "ISSUE-12", "Issue-Motion"] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }

    for (line, pattern) in [
        ("per the SRAD.", r"\bSRAD"),
        ("the SRADs", r"\bSRAD"),
        ("srad/x.md", r"\bsrad"),
        ("srad_file", r"\bsrad"),
    ] {
        assert_eq!(found(line), [pattern], "{line}");
    }
    for clean in ["the_SRAD", "xsrad", "Srad/"] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }

    for (line, pattern) in [
        ("RS3-B-02", r"\bRS[0-9]+-[A-Z]"),
        ("after QA4,", r"\bQA[0-9]+\b"),
        ("(A4-7)", r"\bA[0-9]+-[0-9]+\b"),
        ("P3-01.", r"\bP[0-9]+-[0-9]+\b"),
        ("SEC-2", r"\bSEC-[0-9]+\b"),
        ("MCP-02", r"\bMCP-[0-9]+\b"),
        ("FR-16", r"\bFR-[0-9]+\b"),
        ("Security F8", r"\bSecurity F[0-9]+\b"),
        ("Daemon F3", r"\bDaemon F[0-9]+\b"),
        ("decision D3", r"\bdecision D[0-9]+\b"),
        ("in phase 5", r"\bphase [0-9]+\b"),
        ("Phase 0:", r"\bPhase [0-9]+\b"),
    ] {
        assert_eq!(found(line), [pattern], "{line}");
    }
    for clean in [
        "RS3",
        "RS3-b",
        "QA",
        "QA4b",
        "A4",
        "A4-",
        "XA4-7",
        "P-256",
        "P256",
        "SEC-",
        "MCP",
        "F8",
        "Security F",
        "decision",
        "multiphase 2",
        "phases 5",
        "phase five",
    ] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }

    for (line, pattern) in [
        ("HLC round five", "HLC round"),
        ("the ROADMAP", "ROADMAP"),
        ("FEATURES.md row", r"FEATURES\.md"),
        ("reviews/x", "reviews/"),
        ("ROBUSTNESS.md", r"ROBUSTNESS\.md"),
        ("agentspaces-desktop", "agentspaces-desktop"),
        ("agentspaces-harness", "agentspaces-harness"),
        ("enterprise-platform", "enterprise-platform"),
        ("Rust team report", "Rust team report"),
        ("the owner ruled", "owner ruled"),
    ] {
        assert_eq!(found(line), [pattern], "{line}");
    }
    for clean in ["FEATURESxmd", "hlc round", "Roadmap", "reviews"] {
        assert!(found(clean).is_empty(), "{clean} should not match");
    }
}

#[test]
fn no_file_names_an_internal_document_or_id() {
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
    let mut named: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|path| (relative(&root, &path), path))
        .filter(|(name, _)| !SKIPPED_FILES.contains(&name.as_str()))
        .collect();
    named.sort();
    let mut hits = Vec::new();
    for (name, path) in &named {
        let Ok(bytes) = fs::read(path) else {
            hits.push(format!("{name}: unreadable"));
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            let markers = markers_in(line);
            if !markers.is_empty() {
                let excerpt: String = line.trim().chars().take(120).collect();
                hits.push(format!(
                    "{name}:{}: {}: {excerpt}",
                    index + 1,
                    markers.join(", ")
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{} line(s) name an internal document, requirement, finding, or private project; \
         cite the public SPEC or say it in plain words:\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}
