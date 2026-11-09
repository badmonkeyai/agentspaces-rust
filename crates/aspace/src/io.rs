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

//! JSON in and out: entries print with their wire names and schema string, one object
//! per line; JSON read from a flag, a file, or standard input becomes a payload under the number
//! rule of [`agentspaces::json`], with the widths of the schema's entries when the space holds
//! one ([`widths_hint`]).

use std::io::{Read, Write};

use agentspaces::json::{json_to_value, value_to_json};
use agentspaces::space::{EntryView, Space, SpaceEvent, Template};
use agentspaces::wire::cbor::{Map, Value};
use serde_json::{Map as JsonMap, Value as Json, json};

use crate::exit::{Failure, SUCCESS};

/// The most bytes of JSON read from standard input or a file: 8 MiB, the most a payload block
/// carries.
pub const MAX_JSON_INPUT: u64 = 8 * 1024 * 1024;

/// Prints `value` as one line on standard output and flushes it. A reader that went away (a
/// closed pipe) ends the command quietly with exit 0.
pub fn print_line(value: &Json) -> Result<(), Failure> {
    let mut out = std::io::stdout().lock();
    let written = serde_json::to_writer(&mut out, value)
        .map_err(std::io::Error::from)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Err(Failure {
            code: SUCCESS,
            message: String::new(),
        }),
        Err(error) => Err(Failure::error(format!(
            "cannot write standard output: {error}"
        ))),
    }
}

/// Text another peer wrote (a card's names and descriptions, an entry id) for a terminal or a
/// log: every control character (C0 and C1, so no escape sequence of another peer's text
/// reaches the terminal) becomes a space.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// An entry as `read` prints it.
pub fn entry_json(view: &EntryView, space: &str) -> Json {
    json!({
        "id": view.entry_id().as_str(),
        "schema": view.schema(),
        "space": space,
        "entry": value_to_json(view.payload()),
        "tags": tags_json(view.tags()),
        "issuer": view.issuer(),
        "attestation": view.attestation().as_str(),
        "expiresAt": view.expires_at_millis(),
    })
}

/// An event as `watch` prints it: the kind, the entry, its holder, and whether it is completed.
pub fn event_json(event: &SpaceEvent, space: &str) -> Json {
    let mut object = match entry_json(&event.entry, space) {
        Json::Object(object) => object,
        _ => JsonMap::new(),
    };
    let mut line = JsonMap::with_capacity(object.len() + 3);
    line.insert("kind".to_owned(), Json::from(event.kind.as_str()));
    line.append(&mut object);
    line.insert(
        "holder".to_owned(),
        event.entry.holder().map_or(Json::Null, Json::from),
    );
    line.insert("completed".to_owned(), Json::Bool(event.entry.completed()));
    Json::Object(line)
}

/// Tags as a JSON object.
pub fn tags_json(tags: &Map) -> Json {
    value_to_json(&Value::Map(tags.clone()))
}

/// Tags from `key=value` pairs.
pub fn tags_map(tags: &[(String, String)]) -> Map {
    let mut map = Map::new();
    for (key, value) in tags {
        map.insert(key.as_str(), value.as_str());
    }
    map
}

/// The JSON object a flag gives: its text, `-` for standard input, or `@file`; refused (exit 2)
/// when it is not one JSON object.
pub fn read_object(argument: &str, flag: &str) -> Result<JsonMap<String, Json>, Failure> {
    let text = if argument == "-" {
        read_bounded(std::io::stdin().lock(), "standard input")?
    } else if let Some(path) = argument.strip_prefix('@') {
        let file = std::fs::File::open(path)
            .map_err(|error| Failure::refused(format!("{flag} @{path}: {error}")))?;
        read_bounded(file, path)?
    } else {
        argument.to_owned()
    };
    match serde_json::from_str::<Json>(&text) {
        Ok(Json::Object(object)) => Ok(object),
        Ok(other) => Err(Failure::refused(format!(
            "{flag} is {}, not a JSON object; write the entry's fields as {{\"field\": value}}",
            kind_of(&other)
        ))),
        Err(error) => Err(Failure::refused(format!(
            "{flag} is not JSON ({error}); write the entry's fields as {{\"field\": value}}"
        ))),
    }
}

fn read_bounded(reader: impl Read, what: &str) -> Result<String, Failure> {
    let mut text = String::new();
    reader
        .take(MAX_JSON_INPUT + 1)
        .read_to_string(&mut text)
        .map_err(|error| Failure::refused(format!("cannot read {what}: {error}")))?;
    if text.len() as u64 > MAX_JSON_INPUT {
        return Err(Failure::refused(format!(
            "{what} holds more than {MAX_JSON_INPUT} bytes of JSON"
        )));
    }
    Ok(text)
}

fn kind_of(value: &Json) -> &'static str {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "a boolean",
        Json::Number(_) => "a number",
        Json::String(_) => "a string",
        Json::Array(_) => "an array",
        Json::Object(_) => "an object",
    }
}

/// Whether a JSON object holds a number anywhere (only then do the schema's widths matter).
pub fn has_numbers(object: &JsonMap<String, Json>) -> bool {
    fn any(value: &Json) -> bool {
        match value {
            Json::Number(_) => true,
            Json::Array(items) => items.iter().any(any),
            Json::Object(object) => object.values().any(any),
            _ => false,
        }
    }
    object.values().any(any)
}

/// A payload of `schema` from a JSON object: numbers take the widths of an entry of the same
/// schema the space holds ([`widths_hint`]), else an integral number is an integer and any other
/// a double.
pub async fn payload(
    space: &Space,
    schema: &str,
    object: JsonMap<String, Json>,
) -> Result<Value, Failure> {
    let hint = widths_hint(space, schema).await;
    Ok(json_to_value(&Json::Object(object), hint.as_ref())?)
}

/// The number widths of `schema` as its entries carry them: the payload of one entry of the
/// schema the space holds, with every value that is not a number (or a map or array of them)
/// blanked, so only integer-or-double decisions carry over (a string is never read as bytes
/// because of another writer's entry). `None` when the space holds none.
pub async fn widths_hint(space: &Space, schema: &str) -> Option<Value> {
    let found = space.read_all(&Template::new(schema), 1).await.ok()?;
    found.first().map(|view| widths_only(view.payload()))
}

/// `value` with only its numbers kept.
pub fn widths_only(value: &Value) -> Value {
    match value {
        Value::Int(_) | Value::Float(_) => value.clone(),
        Value::Array(items) => Value::Array(items.iter().map(widths_only).collect()),
        Value::Map(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, item) in map {
                out.insert(key.clone(), widths_only(item));
            }
            Value::Map(out)
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_keep_numbers_only() {
        let payload = Value::Map(
            [
                ("score", Value::Float(0.5)),
                ("count", Value::Int(3)),
                ("blob", Value::Bytes(vec![1, 2])),
                ("name", Value::from("x")),
                ("points", Value::Array(vec![Value::Float(1.0)])),
            ]
            .into_iter()
            .collect(),
        );
        let hint = widths_only(&payload);
        let json = serde_json::json!({"score": 1, "count": 2.0, "blob": "not base64!", "name": "n", "points": [1, 2]});
        let value = json_to_value(&json, Some(&hint)).expect("converts");
        let map = value.as_map().expect("a map");
        assert_eq!(map.get("score"), Some(&Value::Float(1.0)));
        assert_eq!(map.get("count"), Some(&Value::Int(2)));
        assert_eq!(map.get("blob"), Some(&Value::from("not base64!")));
        assert_eq!(
            map.get("points"),
            Some(&Value::Array(vec![Value::Float(1.0), Value::Float(2.0)]))
        );
        // Without a hint: integral numbers are integers, any other a double.
        let value = json_to_value(&serde_json::json!({"a": 1, "b": 1.5}), None).expect("converts");
        assert_eq!(value.get("a"), Some(&Value::Int(1)));
        assert_eq!(value.get("b"), Some(&Value::Float(1.5)));
    }

    #[test]
    fn peer_text_is_made_printable() {
        assert_eq!(printable("ok text"), "ok text");
        assert_eq!(printable("a\u{1b}]0;owned\u{7}b"), "a ]0;owned b");
        assert_eq!(printable("nul\0and\u{9b}csi"), "nul and csi");
        assert_eq!(printable("tab\tline\n"), "tab line ");
    }

    #[test]
    fn numbers_are_found_anywhere_in_an_object() {
        let object = |json: serde_json::Value| json.as_object().cloned().expect("an object");
        assert!(has_numbers(&object(serde_json::json!({"a": 1}))));
        assert!(has_numbers(&object(
            serde_json::json!({"a": {"b": [true, 2.5]}})
        )));
        assert!(!has_numbers(&object(
            serde_json::json!({"a": "1", "b": [null, false]})
        )));
    }

    #[test]
    fn objects_are_read_from_text_and_refused_otherwise() {
        let object = read_object("{\"topic\":\"x\",\"priority\":2}", "--json").expect("an object");
        assert_eq!(object.keys().collect::<Vec<_>>(), ["topic", "priority"]);
        let error = read_object("[1]", "--json").expect_err("an array");
        assert_eq!(error.code, crate::exit::REFUSED);
        assert!(error.message.contains("an array, not a JSON object"));
        let error = read_object("{nope", "--json").expect_err("not JSON");
        assert!(error.message.contains("--json is not JSON"));
        let error = read_object("@/no/such/file.json", "--json").expect_err("no file");
        assert_eq!(error.code, crate::exit::REFUSED);
    }
}
