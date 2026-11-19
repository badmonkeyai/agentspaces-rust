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
//! The late-head runner: the heads of each case of a shared `late.json` (a ref's versions, some
//! still loading, with the heads expected by hand) as this crate's ref head rule computes them,
//! written as `{case id: [labels]}` for the cross-language table.
//!
//! `cargo run -q -p agentspaces-wire --example late_heads -- <late.json> <out.json>`

use std::process::ExitCode;

use agentspaces_wire::ref_heads::{RefVersion, loaded_heads};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cases, out] = args.as_slice() else {
        eprintln!("usage: late_heads <late.json> <out.json>");
        return ExitCode::from(2);
    };
    let doc: serde_json::Value = match std::fs::read_to_string(cases)
        .map_err(|error| error.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
    {
        Ok(doc) => doc,
        Err(error) => {
            eprintln!("cannot read {cases}: {error}");
            return ExitCode::from(2);
        }
    };
    let mut answers = serde_json::Map::new();
    for case in doc["cases"].as_array().map_or(&[][..], Vec::as_slice) {
        let Some(id) = case["id"].as_str() else {
            continue;
        };
        let versions = case["versions"].as_array().map_or(&[][..], Vec::as_slice);
        let mut live = Vec::new();
        let mut loaded = std::collections::HashSet::new();
        for (index, version) in versions.iter().enumerate() {
            let label = version["label"].as_str().unwrap_or_default();
            let root = format!("r-{label}");
            if version["loaded"].as_bool().unwrap_or(false) {
                loaded.insert(root.clone());
            }
            live.push(RefVersion {
                root,
                base: version["base"]
                    .as_array()
                    .map_or(&[][..], Vec::as_slice)
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(|base| format!("r-{base}"))
                    .collect(),
                seq: version["seq"].as_i64().unwrap_or(0),
                issued_physical: 1000 + i64::try_from(index).unwrap_or(0),
                issued_logical: 0,
                issuer: "zA".to_owned(),
                entry_id: format!("e-{label}"),
            });
        }
        let mut heads: Vec<String> = loaded_heads(&live, |version| loaded.contains(&version.root))
            .into_iter()
            .map(|head| head.root[2..].to_owned())
            .collect();
        heads.sort();
        answers.insert(id.to_owned(), serde_json::Value::from(heads));
    }
    let text = serde_json::to_string_pretty(&answers).unwrap_or_default();
    if let Err(error) = std::fs::write(out, text + "\n") {
        eprintln!("cannot write {out}: {error}");
        return ExitCode::FAILURE;
    }
    println!("rust late heads: {} cases", answers.len());
    ExitCode::SUCCESS
}
