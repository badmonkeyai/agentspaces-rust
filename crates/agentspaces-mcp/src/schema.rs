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

//! Tool schemas. Cards name an entry's schema (`com.acme.Task#v1`) but carry no field
//! list, so a tool's input schema is, by default, an object with a required `input` object of the
//! entry's wire fields (any field allowed) and an optional `timeout`:
//!
//! ```json
//! {"type": "object",
//!  "properties": {
//!    "input": {"type": "object", "title": "com.acme.Task#v1", "additionalProperties": true},
//!    "timeout": {"type": "string"}},
//!  "required": ["input"],
//!  "additionalProperties": false}
//! ```
//!
//! When a [`SchemaProvider`] knows the consumed schema as a JSON Schema (2020-12) of an object,
//! that schema is the tool's input schema and the call's arguments are the entry's fields
//! themselves (the call waits [`ServerOptions::call_timeout`](crate::ServerOptions::call_timeout)).
//! A known schema that is not an object's (an enum's `anyOf`, an array's) describes the default
//! `input` under `allOf`, its `$defs` (and `definitions`) moved to the tool schema's root so
//! its references resolve there, and its `$schema` dropped (the root names the dialect).
//! Arguments are judged against a known schema before anything is written
//! ([`crate::validate`]): a call whose arguments do not match is a tool error naming the field,
//! and nothing reaches the fleet.
//!
//! When it knows the produced schema, that is the tool's output schema; otherwise a tool has none.
//! A result is then rendered for that schema ([`render_result`]: an integer the schema calls
//! `integer` is a JSON number even past 2^53) and judged against it: a result entry that does
//! not match is answered as a tool error carrying its JSON, never as structured content that
//! breaks the declared schema.
//!
//! The consumed schema's name in the default input schema (its `title` and `description`) is
//! card text, cleaned and capped as every other piece a tool shows ([`crate::text::clean`]).
//! A known schema also decides how JSON numbers become CBOR ([`hint_from_schema`]): a `number`
//! field is written as a double even when the caller wrote `3`, an `integer` as an integer, as
//! the Java record of the same schema has them.
//!
//! [`SchemaRegistry`] is the provider of a host that knows its types: schemas inserted by hand,
//! or (feature `schemars`, on by default) derived from a Rust type with
//! [`SchemaRegistry::register`]:
//!
//! ```
//! # #[cfg(feature = "schemars")] {
//! use agentspaces::Entry;
//! use agentspaces_mcp::SchemaRegistry;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, Entry, schemars::JsonSchema)]
//! #[entry(schema = "com.acme.Task#v1")]
//! #[serde(rename_all = "camelCase")]
//! struct Task {
//!     topic: String,
//!     max_words: i64,
//! }
//!
//! let mut schemas = SchemaRegistry::new();
//! schemas.register::<Task>();
//! assert!(schemas.get("com.acme.Task#v1").is_some());
//! # }
//! ```

use std::collections::HashMap;

use agentspaces::catalog::Offering;
use agentspaces::json::{INT_KEY, value_to_json};
use agentspaces::wire::cbor::{Map, Value};
use rmcp::model::JsonObject;
use serde_json::{Value as Json, json};

/// The JSON Schema dialect tool schemas are written in (MCP's default).
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The argument naming the entry's fields when the tool's schema is the default.
pub const INPUT: &str = "input";

/// The argument naming how long to wait for the result when the tool's schema is the default.
pub const TIMEOUT: &str = "timeout";

/// The deepest a schema is followed for a number hint (nested objects, arrays, references).
const MAX_HINT_DEPTH: usize = 32;

/// Knows the JSON Schema (2020-12) of some entry schemas, by their wire schema string.
pub trait SchemaProvider: Send + Sync + 'static {
    /// The JSON Schema of entries of `schema` (`com.acme.Task#v1`), when known.
    fn schema(&self, schema: &str) -> Option<Json>;
}

impl<F> SchemaProvider for F
where
    F: Fn(&str) -> Option<Json> + Send + Sync + 'static,
{
    fn schema(&self, schema: &str) -> Option<Json> {
        self(schema)
    }
}

/// Entry schemas a host knows, as JSON Schemas by wire schema string; see the [module
/// docs](self).
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    schemas: HashMap<String, Json>,
}

impl SchemaRegistry {
    /// An empty registry.
    pub fn new() -> SchemaRegistry {
        SchemaRegistry::default()
    }

    /// Knows `json_schema` as the JSON Schema of entries of `schema`; replaces one known.
    pub fn insert(&mut self, schema: impl Into<String>, json_schema: Json) -> &mut SchemaRegistry {
        self.schemas.insert(schema.into(), json_schema);
        self
    }

    /// [`SchemaRegistry::insert`], by value.
    #[must_use]
    pub fn with(mut self, schema: impl Into<String>, json_schema: Json) -> SchemaRegistry {
        self.insert(schema, json_schema);
        self
    }

    /// Knows `T`'s JSON Schema, as `schemars` derives it (2020-12, field names as serde writes
    /// them, so the wire names), under `T`'s wire schema.
    #[cfg(feature = "schemars")]
    pub fn register<T>(&mut self) -> &mut SchemaRegistry
    where
        T: agentspaces::Entry + schemars::JsonSchema,
    {
        let schema = schemars::schema_for!(T);
        self.insert(T::SCHEMA, schema.to_value())
    }

    /// [`SchemaRegistry::register`], by value.
    #[cfg(feature = "schemars")]
    #[must_use]
    pub fn with_type<T>(mut self) -> SchemaRegistry
    where
        T: agentspaces::Entry + schemars::JsonSchema,
    {
        self.register::<T>();
        self
    }

    /// The JSON Schema known for `schema`.
    pub fn get(&self, schema: &str) -> Option<&Json> {
        self.schemas.get(schema)
    }

    /// How many schemas are known.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether none is known.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }
}

impl SchemaProvider for SchemaRegistry {
    fn schema(&self, schema: &str) -> Option<Json> {
        self.schemas.get(schema).cloned()
    }
}

/// How a tool's arguments carry the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputShape {
    /// The default schema: the entry's fields under [`INPUT`], an optional [`TIMEOUT`].
    Wrapped,
    /// A known schema: the arguments are the entry's fields.
    Typed,
}

/// Whether `schema` describes an object (what an MCP tool schema must be at its root).
fn is_object_schema(schema: &Json) -> bool {
    match schema.get("type") {
        Some(Json::String(kind)) => kind == "object",
        Some(Json::Array(kinds)) => kinds.len() == 1 && kinds[0] == "object",
        _ => false,
    }
}

/// The shape a tool's arguments take when the consumed schema's JSON Schema is `known`.
pub fn input_shape(known: Option<&Json>) -> InputShape {
    if known.is_some_and(is_object_schema) {
        InputShape::Typed
    } else {
        InputShape::Wrapped
    }
}

/// The tool input schema of `offering`, and the shape its arguments take: `known` (the
/// consumed schema's JSON Schema) when it describes an object, else the default; see the
/// [module docs](self).
pub fn input_schema(
    offering: &Offering,
    known: Option<&Json>,
    default_timeout: &str,
    max_timeout: &str,
) -> (JsonObject, InputShape) {
    if let Some(Json::Object(object)) = known.filter(|schema| is_object_schema(schema)) {
        let mut object = object.clone();
        object
            .entry("$schema".to_owned())
            .or_insert_with(|| Json::from(DIALECT));
        return (object, InputShape::Typed);
    }
    let consumes = crate::text::clean(offering.consumes(), crate::text::MAX_FIELD);
    let mut input = json!({
        "type": "object",
        "title": consumes,
        "description": format!(
            "The fields of the {consumes} entry, by their wire names. Integers beyond 2^53 are \
             written {{\"$int\": \"<digits>\"}} and bytes {{\"$bytes\": \"<base64>\"}}."
        ),
        "additionalProperties": true,
    });
    // A known schema that is not an object's still describes the input; its definitions move
    // to the root, where its local references (`#/$defs/...`) resolve.
    let mut hoisted = JsonObject::new();
    if let (Some(Json::Object(known)), Json::Object(input)) = (known, &mut input) {
        let mut embedded = known.clone();
        embedded.remove("$schema");
        for key in ["$defs", "definitions"] {
            if let Some(definitions) = embedded.remove(key) {
                hoisted.insert(key.to_owned(), definitions);
            }
        }
        input.insert(
            "allOf".to_owned(),
            Json::Array(vec![Json::Object(embedded)]),
        );
    }
    let schema = json!({
        "type": "object",
        "properties": {
            INPUT: input,
            TIMEOUT: {
                "type": "string",
                "description": format!(
                    "How long to wait for the result, such as \"30s\" or \"2m\" (default \
                     {default_timeout}, at most {max_timeout}). After it the task stays leased \
                     for a late worker."
                ),
                "pattern": "^\\s*[0-9]+\\s*(ms|s|m|h|d)\\s*$",
            },
        },
        "required": [INPUT],
        "additionalProperties": false,
    });
    match schema {
        Json::Object(mut object) => {
            object.append(&mut hoisted);
            (object, InputShape::Wrapped)
        }
        _ => (JsonObject::new(), InputShape::Wrapped),
    }
}

/// A result entry's payload as structured content for a tool whose output schema is `declared`:
/// [`value_to_json`], then each integer the schema calls `integer` that the payload rules tag
/// (`{"$int": "<digits>"}`, past 2^53) written as a plain JSON number when it fits a 64-bit
/// integer, as a client reading the schema expects it ([`hint_from_schema`]'s walk).
pub fn render_result(payload: &Value, declared: &Json) -> Json {
    let mut json = value_to_json(payload);
    if let Some(hint) = hint_from_schema(declared) {
        untag_integers(&mut json, &hint, 0);
    }
    json
}

/// Rewrites, in `json`, each `$int` object where `hint` holds an integer as a plain number.
fn untag_integers(json: &mut Json, hint: &Value, depth: usize) {
    if depth > MAX_HINT_DEPTH {
        return;
    }
    match (hint, json) {
        (Value::Int(_), json @ Json::Object(_)) => {
            let digits = json
                .as_object()
                .filter(|object| object.len() == 1)
                .and_then(|object| object.get(INT_KEY))
                .and_then(Json::as_str);
            let number = digits.and_then(|digits| {
                digits
                    .parse::<i64>()
                    .map(Json::from)
                    .or_else(|_| digits.parse::<u64>().map(Json::from))
                    .ok()
            });
            if let Some(number) = number {
                *json = number;
            }
        }
        (Value::Map(hints), Json::Object(object)) => {
            for (key, hint) in hints {
                if let Some(name) = key.as_str()
                    && let Some(field) = object.get_mut(name)
                {
                    untag_integers(field, hint, depth + 1);
                }
            }
        }
        (Value::Array(hints), Json::Array(items)) => {
            if let Some(hint) = hints.first() {
                for item in items {
                    untag_integers(item, hint, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// The tool output schema for a produced schema whose JSON Schema is `known`: only an object's
/// (MCP's `structuredContent` is an object), with the dialect named.
pub fn output_schema(known: Option<&Json>) -> Option<JsonObject> {
    match known.filter(|schema| is_object_schema(schema)) {
        Some(Json::Object(object)) => {
            let mut object = object.clone();
            object
                .entry("$schema".to_owned())
                .or_insert_with(|| Json::from(DIALECT));
            Some(object)
        }
        _ => None,
    }
}

/// The number hint ([`agentspaces::json::json_to_value`]) a JSON Schema gives: a payload of the
/// same shape holding a double where the schema says `number`, an integer where it says
/// `integer`, and null elsewhere. Local references (`#/$defs/...`, `#/definitions/...`), nullable
/// types (`["number", "null"]`, `anyOf` with a null branch), object properties, and array items
/// are followed. `None` when the schema says nothing of numbers.
pub fn hint_from_schema(schema: &Json) -> Option<Value> {
    let hint = hint_at(schema, schema, 0);
    (!matches!(hint, Value::Null)).then_some(hint)
}

fn hint_at(root: &Json, schema: &Json, depth: usize) -> Value {
    if depth > MAX_HINT_DEPTH {
        return Value::Null;
    }
    let Json::Object(object) = schema else {
        return Value::Null;
    };
    if let Some(Json::String(reference)) = object.get("$ref") {
        return resolve(root, reference)
            .map_or(Value::Null, |target| hint_at(root, target, depth + 1));
    }
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(Json::Array(branches)) = object.get(combinator) {
            // The one branch that says something of numbers (a nullable value's).
            let hints: Vec<Value> = branches
                .iter()
                .map(|branch| hint_at(root, branch, depth + 1))
                .filter(|hint| !matches!(hint, Value::Null))
                .collect();
            if let [only] = hints.as_slice() {
                return only.clone();
            }
            return Value::Null;
        }
    }
    let kinds: Vec<&str> = match object.get("type") {
        Some(Json::String(kind)) => vec![kind.as_str()],
        Some(Json::Array(kinds)) => kinds
            .iter()
            .filter_map(Json::as_str)
            .filter(|kind| *kind != "null")
            .collect(),
        _ => Vec::new(),
    };
    match kinds.as_slice() {
        ["number"] => Value::Float(0.0),
        ["integer"] => Value::Int(0),
        ["object"] => {
            let Some(Json::Object(properties)) = object.get("properties") else {
                return Value::Null;
            };
            let mut map = Map::with_capacity(properties.len());
            let mut any = false;
            for (name, property) in properties {
                let hint = hint_at(root, property, depth + 1);
                any |= !matches!(hint, Value::Null);
                map.insert(name.as_str(), hint);
            }
            if any { Value::Map(map) } else { Value::Null }
        }
        ["array"] => {
            let items = object
                .get("items")
                .or_else(|| match object.get("prefixItems") {
                    Some(Json::Array(prefix)) => prefix.first(),
                    _ => None,
                });
            match items.map(|items| hint_at(root, items, depth + 1)) {
                Some(Value::Null) | None => Value::Null,
                Some(hint) => Value::Array(vec![hint]),
            }
        }
        _ => Value::Null,
    }
}

/// The schema a local reference names (`#/$defs/Name`, JSON Pointer escapes undone).
fn resolve<'a>(root: &'a Json, reference: &str) -> Option<&'a Json> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        return Some(root);
    }
    root.pointer(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_follow_numbers_through_objects_arrays_and_references() {
        let schema = json!({
            "type": "object",
            "properties": {
                "score": {"type": "number"},
                "count": {"type": "integer"},
                "maybe": {"type": ["number", "null"]},
                "name": {"type": "string"},
                "points": {"type": "array", "items": {"type": "number"}},
                "child": {"$ref": "#/$defs/Child"},
                "optional": {"anyOf": [{"$ref": "#/$defs/Child"}, {"type": "null"}]},
            },
            "$defs": {"Child": {"type": "object", "properties": {"weight": {"type": "number"}}}},
        });
        let hint = hint_from_schema(&schema).expect("a hint");
        let map = hint.as_map().expect("a map");
        assert_eq!(map.get("score"), Some(&Value::Float(0.0)));
        assert_eq!(map.get("count"), Some(&Value::Int(0)));
        assert_eq!(map.get("maybe"), Some(&Value::Float(0.0)));
        assert_eq!(map.get("name"), Some(&Value::Null));
        assert_eq!(
            map.get("points"),
            Some(&Value::Array(vec![Value::Float(0.0)]))
        );
        let child = map.get("child").and_then(Value::as_map).expect("child");
        assert_eq!(child.get("weight"), Some(&Value::Float(0.0)));
        assert!(map.get("optional").and_then(Value::as_map).is_some());
        assert!(
            hint_from_schema(&json!({"type": "object", "properties": {"a": {"type": "string"}}}))
                .is_none()
        );
        // A reference cycle ends at the depth bound.
        let cyclic = json!({"$ref": "#/$defs/A", "$defs": {"A": {"$ref": "#/$defs/A"}}});
        assert!(hint_from_schema(&cyclic).is_none());
    }

    #[test]
    fn output_schemas_are_objects_only() {
        assert!(output_schema(Some(&json!({"type": "string"}))).is_none());
        assert!(output_schema(None).is_none());
        let object = output_schema(Some(&json!({"type": "object"}))).expect("an object");
        assert_eq!(object.get("$schema"), Some(&Json::from(DIALECT)));
    }
}
