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

//! The Rust reader of `audit-vectors.json` for the cross-language conformance table (SPEC annex
//! I.6): it folds every set and descent with this crate and writes `{row: "agree" | "disagree:
//! <what>"}` as JSON, then prints a one-line summary.
//!
//! ```text
//! cargo run -q -p agentspaces-wire --example audit_conformance -- <audit-vectors.json> <out.json>
//! ```

#[path = "../tests/audit_fold/mod.rs"]
mod audit_fold;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [vectors, out] = args.as_slice() else {
        eprintln!("usage: audit_conformance <audit-vectors.json> <out.json>");
        return ExitCode::from(2);
    };
    let doc: serde_json::Value = match std::fs::read_to_string(vectors)
        .map_err(|error| error.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
    {
        Ok(doc) => doc,
        Err(error) => {
            eprintln!("{vectors}: {error}");
            return ExitCode::from(2);
        }
    };
    let rows = audit_fold::rows(&doc);
    let text = serde_json::to_string_pretty(&rows).unwrap_or_default();
    if let Err(error) = std::fs::write(out, text + "\n") {
        eprintln!("{out}: {error}");
        return ExitCode::from(2);
    }
    let bad = rows.values().filter(|verdict| *verdict != "agree").count();
    println!(
        "rust audit: {} rows; {} agree; {bad} disagree",
        rows.len(),
        rows.len() - bad
    );
    if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
