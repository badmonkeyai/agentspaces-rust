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

//! Crate-private helpers that several modules share: the CBOR of a map written in place, the
//! field readers that treat an absent field and a null one alike (as Python's `dict.get` does),
//! and Java's `String.compareTo` order.

use std::cmp::Ordering;

use crate::cbor::{self, Map, Value};

/// The CBOR of a map, the bytes [`cbor::encode`] writes for the equivalent [`Value::Map`]:
/// `0xBF`, each key and value in order, `0xFF`. Written in place, so a map holding a large body
/// is not cloned into a [`Value`] first. These are the bytes every signature, tag, and hash over
/// a map covers.
pub(crate) fn encode_map(map: &Map) -> Vec<u8> {
    let mut out = Vec::new();
    encode_map_into(map, &mut out);
    out
}

/// Appends the CBOR of a map to `out` (see [`encode_map`]).
pub(crate) fn encode_map_into(map: &Map, out: &mut Vec<u8>) {
    out.push(0xBF);
    for (key, value) in map {
        cbor::encode_into(key, out);
        cbor::encode_into(value, out);
    }
    out.push(0xFF);
}

/// A value that is present and not null: Python's `dict.get(...) is not None`, which treats an
/// absent field and a null one alike.
pub(crate) fn non_null(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// A field that is present and not null (see [`non_null`]).
pub(crate) fn present<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    non_null(map.get(key))
}

/// A field's value, null when absent: Python's `dict.get`.
pub(crate) fn field(map: &Map, key: &str) -> Value {
    map.get(key).cloned().unwrap_or(Value::Null)
}

/// A text field.
pub(crate) fn text<'a>(map: &'a Map, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Java `String.compareTo`: UTF-16 code unit order. It equals the code point order Rust and
/// Python compare by unless a supplementary character (above U+FFFF) meets one in
/// `U+E000..=U+FFFF`; the lattice, dot, stamp, ballot, and JSON key orders and the filter grammar
/// must agree with Java there too.
pub(crate) fn java_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_map_encoding_is_the_value_encoding() {
        let mut map = Map::new();
        map.insert("a", 1);
        map.insert("b", Value::Null);
        map.insert("c", vec![1u8, 2, 3]);
        assert_eq!(encode_map(&map), cbor::encode(&Value::Map(map.clone())));
        assert_eq!(encode_map(&Map::new()), [0xBF, 0xFF]);
    }

    #[test]
    fn absent_and_null_are_alike() {
        let mut map = Map::new();
        map.insert("null", Value::Null);
        map.insert("one", 1);
        assert_eq!(present(&map, "null"), None);
        assert_eq!(present(&map, "absent"), None);
        assert_eq!(present(&map, "one"), Some(&Value::Int(1)));
        assert_eq!(field(&map, "absent"), Value::Null);
        assert_eq!(text(&map, "one"), None);
    }

    #[test]
    fn java_order_is_utf16_order() {
        assert_eq!(java_order("\u{FFFD}", "\u{1F600}"), Ordering::Greater);
        assert_eq!("\u{FFFD}".cmp("\u{1F600}"), Ordering::Less);
        assert_eq!(java_order("a", "b"), Ordering::Less);
        assert_eq!(java_order("", ""), Ordering::Equal);
    }
}
