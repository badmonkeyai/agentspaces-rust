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

//! The JSON bridge: entry payloads as JSON for the CLI, the MCP gateway, and language bindings,
//! and JSON written by scripts as payloads.
//!
//! CBOR has more kinds of value than JSON, so a few take a tagged form, a one-key object whose
//! key starts with `$`:
//!
//! | CBOR [`Value`] | JSON ([`value_to_json`]) |
//! |---|---|
//! | null, bool, text | `null`, `true`/`false`, a string |
//! | int within ±(2^53 - 1) ([`MAX_SAFE_INTEGER`]) | a number |
//! | int beyond it, bignum (a Java `BigInteger`) | `{"$int": "18446744073709551615"}`, decimal text ([`INT_KEY`]) |
//! | decimal (a Java `BigDecimal`) | `{"$decimal": "1.25"}`, Java's `BigDecimal.toString` ([`DECIMAL_KEY`]) |
//! | float, finite | a number, always with a fraction or exponent (`2.0`, `1e300`) |
//! | float NaN, ±infinity | `{"$float": "NaN"}`, `"Infinity"`, `"-Infinity"` ([`FLOAT_KEY`]) |
//! | bytes | `{"$bytes": "AAH/"}`, standard base64 with padding ([`BYTES_KEY`]) |
//! | array | an array |
//! | map | an object, in the map's order |
//!
//! - **Integers.** JavaScript reads a number beyond 2^53 - 1 inexactly, so such an integer
//!   (a 64-bit hash, a nonce) is written as decimal text in a `$int` object, which round-trips
//!   exactly; timestamps in milliseconds stay plain numbers. Any integer a Java `BigInteger`
//!   carries on the wire (a bignum of up to [`MAX_BIGNUM_BYTES`] bytes) reads and writes this
//!   way, and one outside Java's `long` range is written as a bignum, as Java writes it.
//! - **Decimals.** A `$decimal` text reads as Java's `new BigDecimal(String)` reads it (`1.50`,
//!   `-12.5`, `1E+3`) and is written normalized (`1.50` as `1.5`, the bytes Java writes).
//! - **Map keys.** A JSON key is text. A text key is written as itself, an integer key as its
//!   decimal digits, and any other key (a byte string; the decoder admits no other) in CBOR
//!   diagnostic notation (`h'00ff'`). This direction is one way: [`json_to_value`] reads every
//!   key as text. When two keys render alike (`7` and `"7"`), the later value is kept.
//! - **Reserved objects.** A map whose only key is `$bytes`, `$int`, `$decimal`, or `$float`
//!   with a text value reads back as the tagged value, not as a map.
//!
//! [`json_to_value`] reads JSON back with these rules:
//!
//! - A number written without a fraction or exponent (`3`, `-7`) becomes an integer; any other
//!   (`3.0`, `1e3`) becomes a float. A *hint* (a template payload of the same shape, such as
//!   [`to_value`] of a default value) overrides this per field: where the hint holds a float, an
//!   integer becomes a float (`3` writes as `3.0`, the bytes Java writes for a `double`); where
//!   it holds an integer, a whole float becomes an integer; where it holds bytes, a string is
//!   read as base64. An array's element takes the hint of the same index, or the hint's last element,
//!   so a one-element template covers every element; an object's field takes the hint of the
//!   same key.
//! - Object keys keep their order (serde_json's `preserve_order`), so a script that writes
//!   `{"topic": ..., "priority": ...}` writes a payload in that field order, as a record.
//!
//! [`to_json`] and [`from_json`] go between JSON and a serde type through [`Value`]; a typed
//! read needs no hint, since [`from_value`] reads an integer into a float field. Note that
//! [`to_value`] of a `serde_json::Value` is not [`json_to_value`]: serde sees a JSON object as a
//! map, which [`to_value`] writes in canonical order, where [`json_to_value`] keeps the object's
//! order as a record's.

use std::collections::HashMap;

use agentspaces_wire::cbor::{
    Decimal, INT_MAX, INT_MIN, MAX_BIGNUM_BYTES, Map, Value, parse_integer,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map as JsonMap, Number, Value as Json};

use crate::entry::{EntryError, build_map, from_value, is_plain_name, to_value};

/// The key of a byte string's tagged form: `{"$bytes": "<standard base64>"}`.
pub const BYTES_KEY: &str = "$bytes";

/// The key of the tagged form of an integer beyond [`MAX_SAFE_INTEGER`]:
/// `{"$int": "<decimal>"}`.
pub const INT_KEY: &str = "$int";

/// The key of a decimal's tagged form (a Java `BigDecimal`): `{"$decimal": "<decimal>"}`.
pub const DECIMAL_KEY: &str = "$decimal";

/// The key of the tagged form of a float JSON has no number for: `{"$float": "NaN"}`,
/// `"Infinity"`, or `"-Infinity"`.
pub const FLOAT_KEY: &str = "$float";

/// The largest integer magnitude written as a JSON number: 2^53 - 1, JavaScript's
/// `Number.MAX_SAFE_INTEGER`.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Why JSON did not read as a payload: a malformed tagged object, or a string a bytes hint
/// covers that is not base64.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot read JSON at {path}: {message}")]
pub struct JsonError {
    /// Where the offending value is, from the root `$` (`$.digest`, `$.lines[2]`).
    pub path: String,
    /// What is wrong with it.
    pub message: String,
}

impl JsonError {
    fn new(message: impl Into<String>) -> Self {
        JsonError {
            path: String::new(),
            message: message.into(),
        }
    }

    fn within(mut self, segment: &str) -> Self {
        self.path.insert_str(0, segment);
        self
    }

    fn rooted(mut self) -> Self {
        self.path.insert(0, '$');
        self
    }
}

/// A path segment for an object key: `.name`, or `["a key"]` when the key is not a plain name.
fn key_segment(key: &str) -> String {
    if is_plain_name(key) {
        format!(".{key}")
    } else {
        format!("[{key:?}]")
    }
}

// ---------------------------------------------------------------------------------------------
// CBOR to JSON

/// A payload as JSON, by the rules of the [module documentation](self).
pub fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(n) => int_to_json(*n),
        Value::BigInt(big) => tagged(INT_KEY, big.to_string()),
        Value::Decimal(decimal) => tagged(DECIMAL_KEY, decimal.to_string()),
        Value::Float(x) => float_to_json(*x),
        Value::Bytes(bytes) => tagged(BYTES_KEY, STANDARD.encode(bytes)),
        Value::Text(text) => Json::String(text.clone()),
        Value::Array(items) => Json::Array(items.iter().map(value_to_json).collect()),
        Value::Map(map) => {
            let mut object = JsonMap::with_capacity(map.len());
            for (key, item) in map {
                object.insert(key_text(key), value_to_json(item));
            }
            Json::Object(object)
        }
    }
}

fn tagged(key: &str, text: String) -> Json {
    let mut object = JsonMap::with_capacity(1);
    object.insert(key.to_owned(), Json::String(text));
    Json::Object(object)
}

fn int_to_json(n: i128) -> Json {
    match i64::try_from(n) {
        Ok(small) if small.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() => {
            Json::Number(Number::from(small))
        }
        _ => tagged(INT_KEY, n.to_string()),
    }
}

fn float_to_json(x: f64) -> Json {
    match Number::from_f64(x) {
        Some(number) => Json::Number(number),
        None if x.is_nan() => tagged(FLOAT_KEY, "NaN".to_owned()),
        None if x > 0.0 => tagged(FLOAT_KEY, "Infinity".to_owned()),
        None => tagged(FLOAT_KEY, "-Infinity".to_owned()),
    }
}

/// A map key as JSON object key text.
fn key_text(key: &Value) -> String {
    match key {
        Value::Text(text) => text.clone(),
        Value::Int(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// JSON to CBOR

/// A payload from JSON, by the rules of the [module documentation](self); `hint` is a template
/// payload whose floats, integers, and byte strings decide how numbers and strings at the same
/// place convert.
///
/// # Errors
///
/// [`JsonError`] for a tagged object that does not hold what its key says: base64 that does not
/// decode, an `$int` that is not an integer of at most [`MAX_BIGNUM_BYTES`] bytes, a `$decimal`
/// that is not a decimal of the wire, or an unknown `$float`; also for a string the hint says is
/// bytes that is not base64.
pub fn json_to_value(json: &Json, hint: Option<&Value>) -> Result<Value, JsonError> {
    convert(json, hint).map_err(JsonError::rooted)
}

fn convert(json: &Json, hint: Option<&Value>) -> Result<Value, JsonError> {
    match json {
        Json::Null => Ok(Value::Null),
        Json::Bool(b) => Ok(Value::Bool(*b)),
        Json::Number(number) => Ok(number_to_value(number, hint)),
        Json::String(text) => match hint {
            Some(Value::Bytes(_)) => base64(text).map(Value::Bytes),
            _ => Ok(Value::Text(text.clone())),
        },
        Json::Array(items) => {
            let hints = hint.and_then(Value::as_array);
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let hint = hints.and_then(|hints| hints.get(index).or(hints.last()));
                out.push(convert(item, hint).map_err(|error| error.within(&format!("[{index}]")))?);
            }
            Ok(Value::Array(out))
        }
        Json::Object(object) => {
            if let Some(value) = tagged_value(object)? {
                return Ok(value);
            }
            let hints = FieldHints::new(hint);
            let mut entries = Vec::with_capacity(object.len());
            for (key, item) in object {
                let value = convert(item, hints.get(key))
                    .map_err(|error| error.within(&key_segment(key)))?;
                entries.push((Value::Text(key.clone()), value));
            }
            // A JSON object's keys are unique, so this never finds a duplicate.
            build_map(entries).map(Value::Map).map_err(|key| {
                JsonError::new("duplicate key").within(&key_segment(key.as_str().unwrap_or("")))
            })
        }
    }
}

/// The hints of an object's fields: the text-keyed entries of a map hint, indexed when the hint
/// is large, so a large object with a large hint converts in linear time.
enum FieldHints<'a> {
    None,
    Scan(&'a Map),
    Index(HashMap<&'a str, &'a Value>),
}

impl<'a> FieldHints<'a> {
    fn new(hint: Option<&'a Value>) -> Self {
        match hint.and_then(Value::as_map) {
            None => FieldHints::None,
            Some(map) if map.len() <= 16 => FieldHints::Scan(map),
            Some(map) => FieldHints::Index(
                map.iter()
                    .filter_map(|(key, value)| key.as_str().map(|key| (key, value)))
                    .collect(),
            ),
        }
    }

    fn get(&self, key: &str) -> Option<&'a Value> {
        match self {
            FieldHints::None => None,
            FieldHints::Scan(map) => map.get(key),
            FieldHints::Index(index) => index.get(key).copied(),
        }
    }
}

fn number_to_value(number: &Number, hint: Option<&Value>) -> Value {
    let wants_float = matches!(hint, Some(Value::Float(_)));
    let integer = number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
        // Under serde_json's arbitrary_precision a number keeps its text, so an integer beyond
        // 64 bits still reads exactly; otherwise this text is a float's and does not parse.
        .or_else(|| {
            number
                .to_string()
                .parse::<i128>()
                .ok()
                .filter(|n| (INT_MIN..=INT_MAX).contains(n))
        });
    match integer {
        // Rounds to the nearest double, the documented intent of a float hint.
        Some(n) if wants_float => Value::Float(n as f64),
        Some(n) => Value::Int(n),
        None => {
            // Always a double without arbitrary_precision; with it, NaN marks the impossible.
            let x = number.as_f64().unwrap_or(f64::NAN);
            match hint {
                Some(Value::Int(_)) if x.is_finite() && x.trunc() == x && in_int_range(x) => {
                    // A whole number in the CBOR range, so the conversion is exact.
                    Value::Int(x as i128)
                }
                _ => Value::Float(x),
            }
        }
    }
}

/// Whether a whole double lies in the CBOR integer range, `-2^64..=2^64-1`.
fn in_int_range(x: f64) -> bool {
    // -2^64 is exact as a double; 2^64 is the first double above the range.
    (-18_446_744_073_709_551_616.0..18_446_744_073_709_551_616.0).contains(&x)
}

/// The value of a tagged object, `None` when the object is not one.
fn tagged_value(object: &JsonMap<String, Json>) -> Result<Option<Value>, JsonError> {
    if object.len() != 1 {
        return Ok(None);
    }
    let Some((key, Json::String(text))) = object.iter().next() else {
        return Ok(None);
    };
    let value = match key.as_str() {
        BYTES_KEY => Value::Bytes(base64(text).map_err(|error| error.within(&key_segment(key)))?),
        INT_KEY => match parse_integer(text.trim()) {
            Some(n) => n,
            None => {
                return Err(JsonError::new(format!(
                    "{:?} is not an integer of at most {MAX_BIGNUM_BYTES} bytes",
                    preview(text)
                ))
                .within(&key_segment(key)));
            }
        },
        DECIMAL_KEY => match text.trim().parse::<Decimal>() {
            Ok(decimal) => Value::Decimal(decimal),
            Err(_) => {
                return Err(JsonError::new(format!(
                    "{:?} is not a decimal (digits, a point, an exponent of at most 2^31 - 1)",
                    preview(text)
                ))
                .within(&key_segment(key)));
            }
        },
        FLOAT_KEY => match text.as_str() {
            "NaN" => Value::Float(f64::NAN),
            "Infinity" => Value::Float(f64::INFINITY),
            "-Infinity" => Value::Float(f64::NEG_INFINITY),
            other => match other.trim().parse::<f64>() {
                Ok(x) => Value::Float(x),
                Err(_) => {
                    return Err(JsonError::new(format!(
                        "{text:?} is not a number, NaN, Infinity, or -Infinity"
                    ))
                    .within(&key_segment(key)));
                }
            },
        },
        _ => return Ok(None),
    };
    Ok(Some(value))
}

/// The first characters of a text, for an error message.
fn preview(text: &str) -> String {
    text.chars().take(64).collect()
}

/// Standard base64, padded or not.
fn base64(text: &str) -> Result<Vec<u8>, JsonError> {
    STANDARD_PAD_INDIFFERENT
        .decode(text)
        .map_err(|error| JsonError::new(format!("not standard base64: {error}")))
}

// ---------------------------------------------------------------------------------------------
// Typed

/// A serde value as JSON: [`to_value`], then [`value_to_json`].
///
/// # Errors
///
/// As [`to_value`].
pub fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<Json, EntryError> {
    to_value(value).map(|value| value_to_json(&value))
}

/// A serde value from JSON: [`json_to_value`] without a hint, then [`from_value`].
///
/// # Errors
///
/// [`EntryError::Decode`] for a malformed tagged object or a value that does not fit `T`.
pub fn from_json<T: DeserializeOwned>(json: &Json) -> Result<T, EntryError> {
    let value = json_to_value(json, None).map_err(|error| EntryError::Decode {
        path: error.path,
        message: error.message,
    })?;
    from_value(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::{cbor_array, cbor_map};
    use serde_json::json;

    fn read(json: &Json) -> Value {
        json_to_value(json, None).unwrap()
    }

    #[test]
    fn scalars_both_ways() {
        let value = cbor_array![
            Value::Null,
            true,
            0,
            -7,
            MAX_SAFE_INTEGER,
            -MAX_SAFE_INTEGER,
            2.0,
            0.1,
            -0.0,
            "text",
        ];
        let json = value_to_json(&value);
        assert_eq!(
            serde_json::to_string(&json).unwrap(),
            r#"[null,true,0,-7,9007199254740991,-9007199254740991,2.0,0.1,-0.0,"text"]"#
        );
        // Through JSON text and back, every width survives.
        let reparsed: Json = serde_json::from_str(&serde_json::to_string(&json).unwrap()).unwrap();
        assert_eq!(read(&reparsed), value);
    }

    #[test]
    fn integers_beyond_the_safe_range_are_tagged() {
        let value = cbor_array![
            MAX_SAFE_INTEGER + 1,
            -MAX_SAFE_INTEGER - 1,
            u64::MAX,
            Value::Int(INT_MIN),
        ];
        let json = value_to_json(&value);
        assert_eq!(
            json,
            json!([
                {"$int": "9007199254740992"},
                {"$int": "-9007199254740992"},
                {"$int": "18446744073709551615"},
                {"$int": "-18446744073709551616"},
            ])
        );
        assert_eq!(read(&json), value);
        // A plain JSON number of 64 bits reads exactly too.
        assert_eq!(read(&json!(u64::MAX)), Value::Int(i128::from(u64::MAX)));
        assert_eq!(read(&json!(i64::MIN)), Value::Int(i128::from(i64::MIN)));
        // Past 64 bits an integer is a bignum (a Java BigInteger); past 1000 bytes Java reads
        // none, so neither is it read here.
        let big = read(&json!({"$int": "18446744073709551616"}));
        assert_eq!(
            big.as_big_int().map(ToString::to_string).as_deref(),
            Some("18446744073709551616")
        );
        assert_eq!(value_to_json(&big), json!({"$int": "18446744073709551616"}));
        let error = json_to_value(&json!({"x": {"$int": "9".repeat(2_500)}}), None);
        assert_eq!(error.unwrap_err().path, "$.x.$int");
        assert!(json_to_value(&json!({"$int": "1.5"}), None).is_err());
    }

    /// A bignum and a decimal (a Java `BigInteger` and `BigDecimal`) go both ways as `$int` and
    /// `$decimal`, and an `aspace write --json` payload of 2^64 - 1 and 1.25 encodes to exactly the
    /// bytes Java writes for `Price("x", 1.25, 2^64 - 1)`, which its strict reader accepts; a plain
    /// `1b ff..` it refuses.
    #[test]
    fn big_numbers_and_decimals_are_tagged() {
        let value = cbor_map! {
            "serial" => parse_integer("123456789012345678901234567890").unwrap(),
            "amount" => Value::Decimal("1.50".parse().unwrap()),
            "tiny" => Value::Decimal("-0.0000125".parse().unwrap()),
            "huge" => Value::Decimal("1E+2147483647".parse().unwrap()),
        };
        let json = value_to_json(&value);
        assert_eq!(
            json,
            json!({
                "serial": {"$int": "123456789012345678901234567890"},
                "amount": {"$decimal": "1.5"},
                "tiny": {"$decimal": "-0.0000125"},
                "huge": {"$decimal": "1E+2147483647"},
            })
        );
        assert_eq!(read(&json), value);
        let price = read(&json!({
            "item": "x",
            "amount": {"$decimal": "1.25"},
            "serial": {"$int": "18446744073709551615"},
        }));
        assert_eq!(
            hex::encode(agentspaces_wire::cbor::encode(&price)),
            "bf646974656d617866616d6f756e74c48221187d6673657269616cc24900ffffffffffffffffff"
        );
        assert!(json_to_value(&json!({"$decimal": "1.2.3"}), None).is_err());
        let error = json_to_value(&json!({"x": {"$decimal": "1E+2147483648"}}), None);
        assert_eq!(error.unwrap_err().path, "$.x.$decimal");
    }

    #[test]
    fn non_finite_floats_are_tagged() {
        let value = cbor_array![f64::NAN, f64::INFINITY, f64::NEG_INFINITY];
        let json = value_to_json(&value);
        assert_eq!(
            json,
            json!([{"$float": "NaN"}, {"$float": "Infinity"}, {"$float": "-Infinity"}])
        );
        assert_eq!(read(&json), value);
        assert_eq!(read(&json!({"$float": "2.5"})), Value::Float(2.5));
        assert!(json_to_value(&json!({"$float": "lots"}), None).is_err());
    }

    #[test]
    fn bytes_are_base64() {
        let value = cbor_map! { "digest" => vec![0u8, 1, 0xff], "empty" => Vec::<u8>::new() };
        let json = value_to_json(&value);
        assert_eq!(
            json,
            json!({"digest": {"$bytes": "AAH/"}, "empty": {"$bytes": ""}})
        );
        assert_eq!(read(&json), value);
        // Unpadded base64 reads too.
        assert_eq!(read(&json!({"$bytes": "AAE"})), Value::Bytes(vec![0, 1]));
        let error = json_to_value(&json!({"blob": {"$bytes": "not base64!"}}), None).unwrap_err();
        assert_eq!(error.path, "$.blob.$bytes");
        assert!(
            error
                .to_string()
                .starts_with("cannot read JSON at $.blob.$bytes: not standard base64")
        );
        // A one-key object that is not a tagged form is a map.
        assert_eq!(read(&json!({"$bytes": 3})), cbor_map! { "$bytes" => 3 });
        assert_eq!(read(&json!({"$other": "x"})), cbor_map! { "$other" => "x" });
    }

    #[test]
    fn large_objects_keep_their_order_and_hints() {
        let mut object = JsonMap::new();
        let mut hint = Map::new();
        for i in (0..300).rev() {
            object.insert(format!("f{i}"), json!(i));
            hint.insert(format!("f{i}"), if i % 2 == 0 { 0.0 } else { 0.5 });
        }
        let value = json_to_value(&Json::Object(object), Some(&Value::Map(hint))).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 300);
        assert_eq!(map.keys().next(), Some(&Value::from("f299")));
        assert_eq!(map.get("f7"), Some(&Value::Float(7.0)));
        assert_eq!(value_to_json(&value)["f0"], json!(0.0));
    }

    #[test]
    fn objects_keep_their_order() {
        let json: Json =
            serde_json::from_str(r#"{"zeta": 1, "alpha": 2, "mid": {"b": 1, "a": 2}}"#).unwrap();
        let value = read(&json);
        assert_eq!(
            value,
            cbor_map! { "zeta" => 1, "alpha" => 2, "mid" => cbor_map! { "b" => 1, "a" => 2 } }
        );
        assert_eq!(
            serde_json::to_string(&value_to_json(&value)).unwrap(),
            r#"{"zeta":1,"alpha":2,"mid":{"b":1,"a":2}}"#
        );
    }

    #[test]
    fn non_text_keys_render_as_text() {
        let mut map = Map::new();
        map.insert(7, "seven");
        map.insert(vec![0u8, 0xff], "bytes");
        map.insert("plain", "text");
        assert_eq!(
            value_to_json(&Value::Map(map)),
            json!({"7": "seven", "h'00ff'": "bytes", "plain": "text"})
        );
    }

    #[test]
    fn hints_decide_number_widths_and_bytes() {
        let hint = cbor_map! {
            "price" => 0.0,
            "count" => 0,
            "weights" => cbor_array![0.0],
            "digest" => Vec::<u8>::new(),
            "nested" => cbor_map! { "ratio" => 0.0 },
        };
        let json = json!({
            "price": 3,
            "count": 4.0,
            "weights": [1, 2.5, 3],
            "digest": "AAH/",
            "nested": {"ratio": 1},
            "free": 5,
        });
        assert_eq!(
            json_to_value(&json, Some(&hint)).unwrap(),
            cbor_map! {
                "price" => 3.0,
                "count" => 4,
                "weights" => cbor_array![1.0, 2.5, 3.0],
                "digest" => vec![0u8, 1, 0xff],
                "nested" => cbor_map! { "ratio" => 1.0 },
                "free" => 5,
            }
        );
        // Without a hint the written form decides.
        assert_eq!(
            read(&json!({"price": 3, "count": 4.0})),
            cbor_map! { "price" => 3, "count" => 4.0 }
        );
        // An integer hint leaves a fraction alone.
        assert_eq!(
            json_to_value(&json!(2.5), Some(&Value::Int(0))).unwrap(),
            Value::Float(2.5)
        );
        let error = json_to_value(&json!({"digest": "**"}), Some(&hint)).unwrap_err();
        assert_eq!(error.path, "$.digest");
    }

    #[test]
    fn typed_values_go_through_json() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Quote {
            item: String,
            price: f64,
            #[serde(with = "serde_bytes")]
            sig: Vec<u8>,
        }
        let quote = Quote {
            item: "fig".into(),
            price: 2.0,
            sig: vec![1, 2],
        };
        let json = to_json(&quote).unwrap();
        assert_eq!(
            json,
            json!({"item": "fig", "price": 2.0, "sig": {"$bytes": "AQI="}})
        );
        assert_eq!(from_json::<Quote>(&json).unwrap(), quote);
        // A script's integer price reads into the f64 field without a hint.
        let script = json!({"item": "fig", "price": 2, "sig": {"$bytes": "AQI="}});
        assert_eq!(from_json::<Quote>(&script).unwrap(), quote);
        let bad = json!({"item": "fig", "price": 2, "sig": {"$bytes": "*"}});
        assert!(matches!(
            from_json::<Quote>(&bad),
            Err(EntryError::Decode { path, .. }) if path == "$.sig.$bytes"
        ));
    }
}
