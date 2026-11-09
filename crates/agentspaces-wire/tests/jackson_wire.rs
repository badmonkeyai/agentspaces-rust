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

//! The wire encoding (Java `WellFormedCbor` rules S1 to S12) against the installed Java codec:
//! big numbers both ways, and the verdict on every document.
//!
//! `jackson-wire-vectors.json` is written by `interop/jackson-vectors` (`WireVectors`, see its
//! README) from `CborCodec.defaultCodec()`:
//!
//! - `numbers`: a `BigInteger` or `BigDecimal` alone, in a record, a map, and a list, and the
//!   bytes Java wrote. Each must encode here to those bytes and decode from them to its value, so
//!   a big number crosses between Rust and Java in both directions.
//! - `documents`: inputs for every rule, both sides of each boundary, with what Java makes of
//!   each: `checkDocument` (the item rules alone) and `fromDocument` (the item rules, then
//!   Jackson, whose number-length constraint refuses a bignum past 1000 bytes). [`cbor::decode`],
//!   the reader of every network document, must accept exactly what `fromDocument` accepts, and
//!   re-encode what it accepts to the same bytes.

use std::sync::OnceLock;

use agentspaces_wire::cbor::{self, CborError, Decimal, Map, Value};
use agentspaces_wire::{cbor_array, cbor_map};
use serde_json::Value as Json;

fn vectors() -> &'static Json {
    static VECTORS: OnceLock<Json> = OnceLock::new();
    VECTORS.get_or_init(|| {
        serde_json::from_str(include_str!("jackson-wire-vectors.json"))
            .expect("jackson-wire-vectors.json parses")
    })
}

fn entries(section: &str) -> &'static [Json] {
    vectors()[section]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("a {section} section"))
}

fn text<'a>(entry: &'a Json, field: &str) -> &'a str {
    entry[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {entry}"))
}

/// The value of a number vector's text: an integer (`Value::Int` or `Value::BigInt`) or a
/// decimal, normalized as Java's encoder writes it.
fn number(entry: &Json) -> Value {
    let written = text(entry, "text");
    match text(entry, "kind") {
        "integer" => cbor::parse_integer(written).unwrap_or_else(|| panic!("{written}")),
        _ => Value::Decimal(
            written
                .parse::<Decimal>()
                .unwrap_or_else(|error| panic!("{written}: {error}")),
        ),
    }
}

/// The value Java wrapped a number in (`WireVectors.main`): `Price("p", amount, serial)` with
/// the other component 1, `Map.of("k", n)`, and a list of two, bare for an integer and inside
/// `Amounts(amounts)` for a decimal.
fn wrap(entry: &Json) -> Value {
    let n = number(entry);
    let integer = text(entry, "kind") == "integer";
    let one_decimal = Value::Decimal(Decimal::new(0, Value::Int(1)).expect("1"));
    match text(entry, "context") {
        "value" => n,
        "field" if integer => cbor_map! { "item" => "p", "amount" => one_decimal, "serial" => n },
        "field" => cbor_map! { "item" => "p", "amount" => n, "serial" => 1 },
        "mapValue" => cbor_map! { "k" => n },
        "arrayElement" if integer => cbor_array![n.clone(), n],
        "arrayElement" => cbor_map! { "amounts" => cbor_array![n.clone(), n] },
        other => panic!("an unknown context {other}"),
    }
}

#[test]
fn the_vectors_cover_every_rule_and_both_number_kinds() {
    let numbers = entries("numbers");
    assert!(numbers.len() >= 160, "{} numbers", numbers.len());
    for kind in ["integer", "decimal"] {
        assert!(numbers.iter().any(|n| n["kind"] == kind));
    }
    let documents = entries("documents");
    for rule in [
        "S1 ",
        "S2 ",
        "S3 ",
        "S4 ",
        "S5 ",
        "S6 ",
        "S7 ",
        "S8 ",
        "S9 ",
        "S10 ",
        "S11 ",
        "S12 ",
        "stamp row 10",
        "stamp row 11",
    ] {
        assert!(
            documents.iter().any(|d| text(d, "name").starts_with(rule)),
            "{rule}"
        );
    }
    let accepted = documents
        .iter()
        .filter(|d| d["fromDocument"] == "accept")
        .count();
    assert!(accepted > 40 && accepted < documents.len() - 100);
}

/// Rust to Java: every big number encodes to the bytes Java writes, whatever wraps it.
#[test]
fn every_java_number_encodes_byte_for_byte() {
    for entry in entries("numbers") {
        let label = format!("{} in {}", text(entry, "text"), text(entry, "context"));
        let java = hex::decode(text(entry, "hex")).expect("hex");
        assert_eq!(
            hex::encode(cbor::encode(&wrap(entry))),
            hex::encode(&java),
            "{label}"
        );
    }
}

/// Java to Rust: every big number Java writes decodes on the wire to its value, prints as
/// Java prints it, and re-encodes to the bytes it came as.
#[test]
fn every_java_number_decodes_to_its_value() {
    for entry in entries("numbers") {
        let label = format!("{} in {}", text(entry, "text"), text(entry, "context"));
        let java = hex::decode(text(entry, "hex")).expect("hex");
        let decoded = cbor::decode(&java).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(decoded, wrap(entry), "{label}");
        assert_eq!(cbor::encode(&decoded), java, "{label}");
        if text(entry, "context") == "value" {
            let printed = match &decoded {
                Value::Int(n) => n.to_string(),
                Value::BigInt(big) => big.to_string(),
                Value::Decimal(decimal) => decimal.to_string(),
                other => panic!("{label}: {other:?}"),
            };
            let java_text = entry["normalized"].as_str().unwrap_or(text(entry, "text"));
            assert_eq!(printed, java_text, "{label}");
        }
    }
}

/// The wire decoder accepts exactly the documents Java's `fromDocument` accepts, and
/// what it accepts re-encodes to the same bytes (a float32 excepted, which re-encodes as a
/// double); the lenient decoder reads everything the wire decoder reads.
#[test]
fn every_document_is_judged_as_java_judges_it() {
    let mut disagreements = Vec::new();
    for entry in entries("documents") {
        let name = text(entry, "name");
        let bytes = hex::decode(text(entry, "hex")).expect("hex");
        let java = text(entry, "fromDocument");
        let rust = cbor::decode(&bytes);
        if rust.is_ok() != (java == "accept") {
            disagreements.push(format!("{name}: Rust {rust:?}, Java {java}"));
            continue;
        }
        if let Ok(value) = rust {
            assert!(cbor::decode_lenient(&bytes).is_ok(), "{name}");
            if !name.starts_with("S10 fa") {
                assert_eq!(
                    hex::encode(cbor::encode(&value)),
                    hex::encode(&bytes),
                    "{name}"
                );
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of {} documents judged otherwise than Java:\n{}",
        disagreements.len(),
        entries("documents").len(),
        disagreements.join("\n")
    );
}

/// Java's item rules alone accept a bignum of more than 1000 bytes, which Jackson then refuses;
/// the wire decoder refuses it as the whole read does, naming the limit.
#[test]
fn a_bignum_past_jacksons_limit_is_refused_as_java_refuses_it() {
    let differing: Vec<&Json> = entries("documents")
        .iter()
        .filter(|d| d["checkDocument"] != d["fromDocument"])
        .collect();
    assert_eq!(differing.len(), 3);
    for entry in differing {
        assert_eq!(entry["checkDocument"], "accept");
        assert!(text(entry, "fromDocument").contains("maximum allowed (1000"));
        let bytes = hex::decode(text(entry, "hex")).expect("hex");
        assert!(
            matches!(
                cbor::decode(&bytes),
                Err(CborError::BignumTooLong { length: 1001, .. })
            ),
            "{}",
            text(entry, "name")
        );
    }
}

/// A JSON-shaped record: what Java wrote for `Price("x", 1.25, 2^64 - 1)`
/// decodes here, and the same value built here encodes to Java's bytes.
#[test]
fn a_java_price_crosses_both_ways() {
    let java = hex::decode(
        "bf646974656d617866616d6f756e74c48221187d6673657269616cc24900ffffffffffffffffff",
    )
    .expect("hex");
    let mut price = Map::new();
    price.insert("item", "x");
    price.insert(
        "amount",
        Value::Decimal("1.25".parse::<Decimal>().expect("1.25")),
    );
    price.insert("serial", u64::MAX);
    assert_eq!(cbor::decode(&java), Ok(Value::Map(price.clone())));
    assert_eq!(cbor::encode(&Value::Map(price)), java);
}
