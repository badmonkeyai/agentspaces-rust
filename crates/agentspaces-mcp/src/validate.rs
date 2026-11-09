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

//! A bounded JSON Schema (2020-12) check of the subset a host's known schemas use (what
//! `schemars` derives, and what is written by hand for an entry): `type` (one or a list, with
//! `integer` a number with no fraction), `enum`, `const`, `properties`, `required`,
//! `additionalProperties`, `items`, `prefixItems`, `minItems`, `maxItems`, `minLength`,
//! `maxLength`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, local `$ref` (into
//! `$defs` or `definitions`), `allOf`, `anyOf`, `oneOf`, and `not`. Other keywords (`format`,
//! `pattern`, ...) are not judged. The walk is bounded ([`MAX_DEPTH`]), so a reference cycle
//! ends.
//!
//! The gateway judges a call's arguments with it before anything is written ([`Mode::Input`]:
//! the tagged forms of [`agentspaces::json`] stand for the values they carry), and a result
//! before it is answered as structured content conforming to the tool's output schema
//! ([`Mode::Output`]: JSON as the client will see it).

use std::fmt;

use agentspaces::json::{BYTES_KEY, FLOAT_KEY, INT_KEY};
use serde_json::{Map as JsonMap, Value as Json};

/// How deep the walk follows nested schemas and values.
pub const MAX_DEPTH: usize = 64;

/// What the JSON judged is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A call's arguments: `{"$int": "<digits>"}` and `{"$float": "NaN"}` count as numbers
    /// (integers for `$int`), and `{"$bytes": "<base64>"}` as a string or an array, as
    /// [`agentspaces::json::json_to_value`] reads them.
    Input,
    /// A result as structured content: JSON as it is, tagged objects being objects.
    Output,
}

/// Where and why a value does not match its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The value's place: `topic`, `items[2].name`, or empty for the whole value.
    pub path: String,
    /// What is wrong there.
    pub message: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// Judges `value` against `schema` (its own root for references) in `mode`.
///
/// # Errors
///
/// The first [`Mismatch`] found.
pub fn validate(schema: &Json, value: &Json, mode: Mode) -> Result<(), Mismatch> {
    Walk { root: schema, mode }.check(schema, value, "", 0)
}

struct Walk<'a> {
    root: &'a Json,
    mode: Mode,
}

fn mismatch(path: &str, message: impl Into<String>) -> Mismatch {
    Mismatch {
        path: path.to_owned(),
        message: message.into(),
    }
}

fn field_path(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}.{name}")
    }
}

fn index_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

/// The JSON type names a value has (an integer is a number too).
fn kinds_of(value: &Json, mode: Mode) -> &'static [&'static str] {
    if mode == Mode::Input
        && let Some(tag) = tag_of(value)
    {
        return match tag {
            INT_KEY => &["integer", "number"],
            FLOAT_KEY => &["number"],
            _ => &["string", "array"],
        };
    }
    match value {
        Json::Null => &["null"],
        Json::Bool(_) => &["boolean"],
        Json::String(_) => &["string"],
        Json::Array(_) => &["array"],
        Json::Object(_) => &["object"],
        Json::Number(number) => {
            let integral = number.is_i64()
                || number.is_u64()
                || number
                    .as_f64()
                    .is_some_and(|float| float.is_finite() && float.fract() == 0.0);
            if integral {
                &["integer", "number"]
            } else {
                &["number"]
            }
        }
    }
}

/// The tag of a tagged object (`$int`, `$float`, `$bytes` with a text value), as the payload
/// rules read it.
fn tag_of(value: &Json) -> Option<&'static str> {
    let Json::Object(object) = value else {
        return None;
    };
    if object.len() != 1 {
        return None;
    }
    let (key, inner) = object.iter().next()?;
    if !inner.is_string() {
        return None;
    }
    [INT_KEY, FLOAT_KEY, BYTES_KEY]
        .into_iter()
        .find(|tag| key == tag)
}

fn describe(value: &Json) -> &'static str {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "a boolean",
        Json::Number(_) => "a number",
        Json::String(_) => "a string",
        Json::Array(_) => "an array",
        Json::Object(_) => "an object",
    }
}

/// A number as a float, for the bounds.
fn number_of(value: &Json) -> Option<f64> {
    value.as_f64()
}

impl Walk<'_> {
    fn check(&self, schema: &Json, value: &Json, path: &str, depth: usize) -> Result<(), Mismatch> {
        if depth > MAX_DEPTH {
            return Err(mismatch(
                path,
                format!("nests deeper than {MAX_DEPTH} levels"),
            ));
        }
        let object = match schema {
            Json::Bool(true) => return Ok(()),
            Json::Bool(false) => return Err(mismatch(path, "is not allowed here")),
            Json::Object(object) => object,
            // Not a schema: nothing to judge by.
            _ => return Ok(()),
        };
        if let Some(Json::String(reference)) = object.get("$ref") {
            match resolve(self.root, reference) {
                Some(target) => self.check(target, value, path, depth + 1)?,
                None => {
                    return Err(mismatch(
                        path,
                        format!("the schema's reference {reference:?} does not resolve"),
                    ));
                }
            }
        }
        self.check_type(object, value, path)?;
        self.check_values(object, value, path)?;
        self.check_combinators(object, value, path, depth)?;
        match value {
            Json::Object(fields) if tag_of(value).is_none() || self.mode == Mode::Output => {
                self.check_object(object, fields, path, depth)?;
            }
            Json::Array(items) => self.check_array(object, items, path, depth)?,
            Json::String(text) => check_string(object, text, path)?,
            Json::Number(_) => check_number(object, value, path)?,
            _ => {}
        }
        Ok(())
    }

    fn check_type(
        &self,
        object: &JsonMap<String, Json>,
        value: &Json,
        path: &str,
    ) -> Result<(), Mismatch> {
        let wanted: Vec<&str> = match object.get("type") {
            Some(Json::String(kind)) => vec![kind.as_str()],
            Some(Json::Array(kinds)) => kinds.iter().filter_map(Json::as_str).collect(),
            _ => return Ok(()),
        };
        let has = kinds_of(value, self.mode);
        if wanted.iter().any(|kind| has.contains(kind)) {
            return Ok(());
        }
        Err(mismatch(
            path,
            format!("expected {}, not {}", wanted.join(" or "), describe(value)),
        ))
    }

    fn check_values(
        &self,
        object: &JsonMap<String, Json>,
        value: &Json,
        path: &str,
    ) -> Result<(), Mismatch> {
        if let Some(Json::Array(allowed)) = object.get("enum")
            && !allowed.iter().any(|candidate| equal(candidate, value))
        {
            return Err(mismatch(path, "is not one of the values the schema allows"));
        }
        if let Some(constant) = object.get("const")
            && !equal(constant, value)
        {
            return Err(mismatch(path, "is not the value the schema requires"));
        }
        Ok(())
    }

    fn check_combinators(
        &self,
        object: &JsonMap<String, Json>,
        value: &Json,
        path: &str,
        depth: usize,
    ) -> Result<(), Mismatch> {
        if let Some(Json::Array(branches)) = object.get("allOf") {
            for branch in branches {
                self.check(branch, value, path, depth + 1)?;
            }
        }
        if let Some(Json::Array(branches)) = object.get("anyOf") {
            let mut first = None;
            let mut matched = false;
            for branch in branches {
                match self.check(branch, value, path, depth + 1) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(error) => {
                        first.get_or_insert(error);
                    }
                }
            }
            if !matched {
                return Err(first.unwrap_or_else(|| mismatch(path, "matches no allowed form")));
            }
        }
        if let Some(Json::Array(branches)) = object.get("oneOf") {
            let mut first = None;
            let mut matched = 0usize;
            for branch in branches {
                match self.check(branch, value, path, depth + 1) {
                    Ok(()) => matched += 1,
                    Err(error) => {
                        first.get_or_insert(error);
                    }
                }
            }
            match matched {
                1 => {}
                0 => return Err(first.unwrap_or_else(|| mismatch(path, "matches no allowed form"))),
                _ => {
                    return Err(mismatch(
                        path,
                        "matches more than one of the forms where exactly one is allowed",
                    ));
                }
            }
        }
        if let Some(negated) = object.get("not")
            && self.check(negated, value, path, depth + 1).is_ok()
        {
            return Err(mismatch(path, "matches a form the schema forbids"));
        }
        Ok(())
    }

    fn check_object(
        &self,
        object: &JsonMap<String, Json>,
        fields: &JsonMap<String, Json>,
        path: &str,
        depth: usize,
    ) -> Result<(), Mismatch> {
        if let Some(Json::Array(required)) = object.get("required") {
            for name in required.iter().filter_map(Json::as_str) {
                if !fields.contains_key(name) {
                    return Err(mismatch(
                        path,
                        format!("missing required property {}", shown(name)),
                    ));
                }
            }
        }
        let properties = match object.get("properties") {
            Some(Json::Object(properties)) => Some(properties),
            _ => None,
        };
        // Names another keyword governs are not "additional" (a pattern is not judged here).
        let patterned = object.contains_key("patternProperties");
        for (name, field) in fields {
            let place = field_path(path, &shown(name));
            match properties.and_then(|properties| properties.get(name)) {
                Some(property) => self.check(property, field, &place, depth + 1)?,
                None if patterned => {}
                None => match object.get("additionalProperties") {
                    Some(Json::Bool(false)) => {
                        return Err(mismatch(path, format!("unknown property {}", shown(name))));
                    }
                    Some(additional @ Json::Object(_)) => {
                        self.check(additional, field, &place, depth + 1)?;
                    }
                    _ => {}
                },
            }
        }
        Ok(())
    }

    fn check_array(
        &self,
        object: &JsonMap<String, Json>,
        items: &[Json],
        path: &str,
        depth: usize,
    ) -> Result<(), Mismatch> {
        if let Some(least) = object.get("minItems").and_then(Json::as_u64)
            && (items.len() as u64) < least
        {
            return Err(mismatch(path, format!("has fewer than {least} items")));
        }
        if let Some(most) = object.get("maxItems").and_then(Json::as_u64)
            && (items.len() as u64) > most
        {
            return Err(mismatch(path, format!("has more than {most} items")));
        }
        let prefix: &[Json] = match object.get("prefixItems") {
            Some(Json::Array(prefix)) => prefix,
            _ => match object.get("items") {
                // An older draft's tuple form.
                Some(Json::Array(prefix)) => prefix,
                _ => &[],
            },
        };
        let rest = match object.get("items") {
            Some(items @ (Json::Object(_) | Json::Bool(_))) => Some(items),
            _ => None,
        };
        for (index, item) in items.iter().enumerate() {
            let place = index_path(path, index);
            match prefix.get(index) {
                Some(schema) => self.check(schema, item, &place, depth + 1)?,
                None => {
                    if let Some(schema) = rest {
                        self.check(schema, item, &place, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn check_string(object: &JsonMap<String, Json>, text: &str, path: &str) -> Result<(), Mismatch> {
    let length = text.chars().count() as u64;
    if let Some(least) = object.get("minLength").and_then(Json::as_u64)
        && length < least
    {
        return Err(mismatch(
            path,
            format!("is shorter than {least} characters"),
        ));
    }
    if let Some(most) = object.get("maxLength").and_then(Json::as_u64)
        && length > most
    {
        return Err(mismatch(path, format!("is longer than {most} characters")));
    }
    Ok(())
}

fn check_number(object: &JsonMap<String, Json>, value: &Json, path: &str) -> Result<(), Mismatch> {
    let Some(number) = number_of(value) else {
        return Ok(());
    };
    let bound = |key: &str| object.get(key).and_then(number_of);
    if let Some(least) = bound("minimum")
        && number < least
    {
        return Err(mismatch(path, format!("is less than {least}")));
    }
    if let Some(most) = bound("maximum")
        && number > most
    {
        return Err(mismatch(path, format!("is more than {most}")));
    }
    if let Some(least) = bound("exclusiveMinimum")
        && number <= least
    {
        return Err(mismatch(path, format!("is not more than {least}")));
    }
    if let Some(most) = bound("exclusiveMaximum")
        && number >= most
    {
        return Err(mismatch(path, format!("is not less than {most}")));
    }
    Ok(())
}

/// JSON Schema equality: numbers by value (`1` equals `1.0`), the rest structurally.
fn equal(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(x), Some(y)) => x == y,
            _ => match (x.as_u64(), y.as_u64()) {
                (Some(x), Some(y)) => x == y,
                _ => x.as_f64() == y.as_f64(),
            },
        },
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| equal(x, y))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, value)| y.get(key).is_some_and(|other| equal(value, other)))
        }
        _ => a == b,
    }
}

/// A property name as an error shows it: cleaned and capped (it may be the caller's text).
fn shown(name: &str) -> String {
    crate::text::clean(name, 64)
}

/// The schema a local reference names (`#/$defs/Name`, JSON Pointer escapes undone).
pub(crate) fn resolve<'a>(root: &'a Json, reference: &str) -> Option<&'a Json> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        return Some(root);
    }
    root.pointer(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn judged(schema: &Json, value: &Json) -> Result<(), String> {
        validate(schema, value, Mode::Input).map_err(|error| error.to_string())
    }

    #[test]
    fn objects_judge_types_required_and_unknown_properties() {
        let schema = json!({
            "type": "object",
            "properties": {"topic": {"type": "string"}, "count": {"type": "integer", "minimum": 0}},
            "required": ["topic"],
        });
        assert_eq!(judged(&schema, &json!({"topic": "kites"})), Ok(()));
        assert_eq!(
            judged(&schema, &json!({"topic": 42})),
            Err("topic: expected string, not a number".to_owned())
        );
        assert_eq!(
            judged(&schema, &json!({})),
            Err("missing required property topic".to_owned())
        );
        assert_eq!(
            judged(&schema, &json!({"topic": "x", "count": 1.5})),
            Err("count: expected integer, not a number".to_owned())
        );
        assert_eq!(
            judged(&schema, &json!({"topic": "x", "count": 2.0})),
            Ok(())
        );
        assert_eq!(
            judged(&schema, &json!({"topic": "x", "count": -1})),
            Err("count: is less than 0".to_owned())
        );
        let closed =
            json!({"type": "object", "properties": {"a": {}}, "additionalProperties": false});
        assert_eq!(
            judged(&closed, &json!({"a": 1, "tpoic": 2})),
            Err("unknown property tpoic".to_owned())
        );
        // A number field takes an integer too.
        assert_eq!(judged(&json!({"type": "number"}), &json!(3)), Ok(()));
    }

    #[test]
    fn references_nullables_and_combinators_are_followed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "child": {"$ref": "#/$defs/Child"},
                "maybe": {"anyOf": [{"$ref": "#/$defs/Child"}, {"type": "null"}]},
                "kind": {"enum": ["a", "b"]},
                "list": {"type": "array", "items": {"type": "integer"}, "maxItems": 2},
            },
            "$defs": {"Child": {"type": "object", "properties": {"w": {"type": "number"}}, "required": ["w"]}},
        });
        assert_eq!(
            judged(
                &schema,
                &json!({"child": {"w": 1}, "maybe": null, "kind": "a", "list": [1, 2]})
            ),
            Ok(())
        );
        assert_eq!(
            judged(&schema, &json!({"child": {}})),
            Err("child: missing required property w".to_owned())
        );
        assert!(judged(&schema, &json!({"maybe": {"w": "x"}})).is_err());
        assert!(judged(&schema, &json!({"kind": "c"})).is_err());
        assert_eq!(
            judged(&schema, &json!({"list": [1, "2"]})),
            Err("list[1]: expected integer, not a string".to_owned())
        );
        assert!(judged(&schema, &json!({"list": [1, 2, 3]})).is_err());
        let one = json!({"oneOf": [{"type": "integer"}, {"type": "number"}]});
        assert!(judged(&one, &json!(1)).is_err(), "both forms match");
        assert_eq!(judged(&one, &json!(1.5)), Ok(()));
        // A reference cycle ends at the depth bound.
        let cyclic = json!({"$ref": "#/$defs/A", "$defs": {"A": {"$ref": "#/$defs/A"}}});
        assert!(judged(&cyclic, &json!(1)).is_err());
        assert!(judged(&json!({"$ref": "#/$defs/Missing"}), &json!(1)).is_err());
    }

    #[test]
    fn tagged_values_count_as_what_they_carry_only_as_input() {
        let schema = json!({"type": "object", "properties": {"at": {"type": "integer"}}});
        let tagged = json!({"at": {"$int": "18446744073709551615"}});
        assert_eq!(judged(&schema, &tagged), Ok(()));
        assert_eq!(
            validate(&schema, &tagged, Mode::Output).map_err(|error| error.to_string()),
            Err("at: expected integer, not an object".to_owned())
        );
        let floats = json!({"type": "number"});
        assert!(validate(&floats, &json!({"$float": "NaN"}), Mode::Output).is_err());
        assert_eq!(judged(&floats, &json!({"$float": "NaN"})), Ok(()));
    }
}
