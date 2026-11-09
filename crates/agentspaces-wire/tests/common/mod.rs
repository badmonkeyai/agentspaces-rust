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

//! Shared helpers for the golden tests: the vector files, read once.
#![allow(dead_code)]
use std::sync::OnceLock;

pub fn golden() -> &'static serde_json::Value {
    static G: OnceLock<serde_json::Value> = OnceLock::new();
    G.get_or_init(|| {
        serde_json::from_str(include_str!("../golden.json")).expect("golden.json parses")
    })
}

pub fn social_golden() -> &'static serde_json::Value {
    static G: OnceLock<serde_json::Value> = OnceLock::new();
    G.get_or_init(|| {
        serde_json::from_str(include_str!("../social-golden.json"))
            .expect("social-golden.json parses")
    })
}

/// A golden entry's string value.
pub fn s(name: &str) -> &'static str {
    golden()[name]
        .as_str()
        .unwrap_or_else(|| panic!("golden {name} is not a string"))
}

/// A golden entry's hex value as bytes.
pub fn hex(name: &str) -> Vec<u8> {
    hex::decode(s(name)).unwrap_or_else(|e| panic!("golden {name} is not hex: {e}"))
}
