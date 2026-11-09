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

//! The portable field filter grammar and the Java matchers (SPEC §7.2) against the golden vectors
//! Java produced (`filter_grammar_cases`, `filter_grammar_malformed`, `java_double_strings`), the
//! cases `test_filters.py`, `filters.test.ts`, and `golden_test.rb` add, `test_layer34.py`'s
//! template test, and edge cases whose verdicts the Java `FieldFilter`, `Matchers.decimal`, and
//! `Double.toString` (JDK 25) gave when run over them.

mod common;

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::filters::{
    Condition, Conditions, FieldFilter, FilterError, FilterOp, Matcher, filter_compare,
    filter_form, java_double_string, parse_filter,
};
use common::golden;
use std::cmp::Ordering;

/// A golden JSON value as the decoded CBOR value Java's codec would hand the filter: a JSON
/// integer is an integer, a JSON number with a fraction or exponent is a double.
fn value_of(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) if !n.is_f64() => Value::Int(i128::from(i)),
            (_, Some(x)) => Value::Float(x),
            _ => panic!("an unreadable number {n}"),
        },
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => panic!("no such case value {other}"),
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn decides(clause: &str, value: &Value) -> bool {
    parse_filter(clause)
        .unwrap_or_else(|e| panic!("{clause:?}: {e}"))
        .test(value)
}

// ---------------------------------------------------------------------------------------------
// Golden vectors

#[test]
fn every_golden_case_decides_as_java_does() {
    let cases = golden()["filter_grammar_cases"]
        .as_array()
        .expect("filter_grammar_cases");
    assert_eq!(cases.len(), 25);
    for case in cases {
        let clause = case["filter"].as_str().expect("a clause");
        let value = value_of(&case["value"]);
        let expected = case["matches"].as_bool().expect("a verdict");
        assert_eq!(decides(clause, &value), expected, "{clause} on {value:?}");

        // A whole number decides alike as an integer and as a double (filters.test.ts).
        let as_double = match value {
            Value::Int(n) => Some(Value::Float(n as f64)),
            Value::Float(x) if x.fract() == 0.0 => Some(Value::Int(x as i128)),
            _ => None,
        };
        if let Some(other) = as_double {
            assert_eq!(decides(clause, &other), expected, "{clause} on {other:?}");
        }

        // And through a template: the field in a payload, null as an absent field.
        let filter = parse_filter(clause).expect("a clause");
        let conditions = Conditions::new().with_clause(clause).expect("a clause");
        let mut payload = Map::new();
        if !value.is_null() {
            payload.insert(filter.field(), value.clone());
        }
        assert_eq!(
            conditions.matches(&payload, &Map::new()),
            expected,
            "{clause}"
        );
    }
}

#[test]
fn every_golden_malformed_clause_is_refused() {
    let malformed = golden()["filter_grammar_malformed"]
        .as_array()
        .expect("filter_grammar_malformed");
    assert_eq!(malformed.len(), 7);
    for clause in malformed {
        let clause = clause.as_str().expect("a clause");
        let refusal = parse_filter(clause).expect_err(clause);
        assert_eq!(refusal, FilterError::Malformed(clause.to_owned()));
        assert!(
            refusal.to_string().starts_with("malformed field filter"),
            "{refusal}"
        );
        assert!(Conditions::new().with_clause(clause).is_err());
        assert!(clause.parse::<FieldFilter>().is_err());
    }
    // test_filters.py and filters.test.ts list the same ones inline, and two more.
    for clause in [
        "!=x", "=3", "<x", " in a,b", "nonsense", "topic!", "", "x in", "  ",
    ] {
        assert!(parse_filter(clause).is_err(), "{clause:?}");
    }
}

#[test]
fn java_double_strings_are_reproduced() {
    let forms = golden()["java_double_strings"]
        .as_object()
        .expect("java_double_strings");
    assert_eq!(forms.len(), 19);
    for (key, java) in forms {
        let value: f64 = key.parse().unwrap_or_else(|e| panic!("{key}: {e}"));
        let java = java.as_str().expect("a form");
        assert_eq!(java_double_string(value), java, "{key}");
        let negated = java
            .strip_prefix('-')
            .map_or_else(|| format!("-{java}"), str::to_owned);
        assert_eq!(java_double_string(-value), negated, "-{key}");
        assert_eq!(filter_form(&Value::Float(value)), java);
    }
}

#[test]
fn double_strings_match_java_where_rounding_is_hard() {
    // Double.toString on JDK 25, which these were taken from.
    let cases: [(u64, &str); 14] = [
        // Exact ties between two shortest decimals: Java keeps the even last digit.
        (0xc31da7bf958de91d, "-2.0868039035766472E15"),
        (0x42bdbb98591e7550, "3.2691552067189312E13"),
        (0x4309308c8f7c4d2a, "8.862818348261492E14"),
        // One digit would do, but two are closer.
        (2, "9.9E-324"),
        (4, "2.0E-323"),
        (0x0010000000000000, "2.2250738585072014E-308"),
        (1e23f64.to_bits(), "1.0E23"),
        (2e23f64.to_bits(), "2.0E23"),
        ((-1e-3f64).to_bits(), "-0.001"),
        (
            (1e-3f64 * 0.9999999999999999).to_bits(),
            "9.999999999999998E-4",
        ),
        (9_999_999.999_999_998f64.to_bits(), "9999999.999999998"),
        ((-0.0f64).to_bits(), "-0.0"),
        (f64::NAN.to_bits(), "NaN"),
        (f64::NEG_INFINITY.to_bits(), "-Infinity"),
    ];
    for (bits, java) in cases {
        assert_eq!(java_double_string(f64::from_bits(bits)), java, "{bits:#x}");
    }
    assert_eq!(java_double_string(f64::INFINITY), "Infinity");
}

// ---------------------------------------------------------------------------------------------
// The grammar

#[test]
fn the_earliest_operator_is_the_operator() {
    // filters.test.ts and golden_test.rb.
    assert!(decides("a<b<=c", &text("a")), "a < \"b<=c\" as strings");
    assert!(decides("topic=a in b", &text("a in b")));

    // (clause, field, op, literal) as Java FieldFilter.parse splits them.
    let parts = [
        ("priority >= 3", "priority", FilterOp::Gte, "3"),
        ("a!=b!=c", "a", FilterOp::Ne, "b!=c"),
        ("a<=b<c", "a", FilterOp::Lte, "b<c"),
        ("topic=a=b", "topic", FilterOp::Eq, "a=b"),
        ("x in a,b in c", "x", FilterOp::In, "a,b in c"),
        ("x in  , 3", "x", FilterOp::In, ", 3"),
        ("x =", "x", FilterOp::Eq, ""),
        ("x=\u{1F}", "x", FilterOp::Eq, ""),
        ("\u{0}x=1\u{0}", "x", FilterOp::Eq, "1"),
        // Java trims up to U+0020 only, so a no-break space is part of the field or literal.
        ("\u{A0}=3", "\u{A0}", FilterOp::Eq, "3"),
        ("x\u{2003}=3", "x\u{2003}", FilterOp::Eq, "3"),
        ("f=\u{A0}3", "f", FilterOp::Eq, "\u{A0}3"),
    ];
    for (clause, field, op, literal) in parts {
        let filter = parse_filter(clause).unwrap_or_else(|e| panic!("{clause:?}: {e}"));
        assert_eq!(
            (filter.field(), filter.op(), filter.literal()),
            (field, op, literal),
            "{clause:?}"
        );
    }
    // A field Java's isBlank calls blank is refused even though trim keeps it.
    assert_eq!(
        parse_filter("\u{2003}=3"),
        Err(FilterError::BlankField("\u{2003}=3".to_owned()))
    );
}

#[test]
fn a_filter_prints_as_java_prints_it() {
    for (clause, printed) in [
        ("priority >= 3", "priority>=3"),
        ("region in eu, us", "region in eu, us"),
        (" topic != index ", "topic!=index"),
        ("x =", "x="),
    ] {
        let filter: FieldFilter = clause.parse().expect("a clause");
        assert_eq!(filter.to_string(), printed);
        assert_eq!(parse_filter(printed), Ok(filter));
    }
    let ops = [
        FilterOp::Eq,
        FilterOp::Ne,
        FilterOp::Lt,
        FilterOp::Lte,
        FilterOp::Gt,
        FilterOp::Gte,
        FilterOp::In,
    ];
    let names: Vec<&str> = ops.iter().map(|op| op.as_str()).collect();
    assert_eq!(names, ["=", "!=", "<", "<=", ">", ">=", "in"]);
}

#[test]
fn edge_verdicts_match_javas() {
    let emoji = "\u{1F600}";
    let replacement = "\u{FFFD}";
    let ten_million = Value::Float(1e7);
    let cases: Vec<(&str, Value, bool)> = vec![
        // Strings order by UTF-16 units: a supplementary character sorts before U+FFFD.
        ("f<\u{1F600}", text(replacement), false),
        ("f<\u{FFFD}", text(emoji), true),
        ("f>\u{FFFD}", text(emoji), false),
        ("f<\u{1F600}", text("\u{e9}"), true),
        ("f>=\u{663}", text(emoji), true),
        ("f>=\u{663}", text("3"), false),
        // A double prints as Java prints it, and compares by value.
        ("f=1.0E7", Value::Int(10_000_000), true),
        ("f=1.0E7", ten_million.clone(), true),
        ("f>9999999", ten_million.clone(), true),
        ("priority<1e7", Value::Int(9_999_999), true),
        ("priority<1e7", Value::Int(10_000_000), false),
        ("f=1.0E-4", Value::Float(1e-4), true),
        ("f=4.9E-324", Value::Float(f64::from_bits(1)), true),
        ("f=NaN", Value::Float(f64::NAN), true),
        ("f>Infinity", Value::Float(f64::NAN), true),
        ("f=1e2147483648", Value::Float(f64::INFINITY), false),
        (
            "f=18446744073709551615",
            Value::Int(18_446_744_073_709_551_615),
            true,
        ),
        (
            "f<-18446744073709551616",
            Value::Int(-18_446_744_073_709_551_616),
            false,
        ),
        // A literal Java's BigDecimal cannot read compares as text.
        ("f>1e-2147483648", text("abc"), true),
        ("f>1e-2147483648", Value::Int(3), true),
        ("f>1e99999999999", Value::Int(9_999_999), true),
        ("f>1e99999999999", Value::Int(10_000_000), false),
        ("f<0.1e-2147483647", text(" 3"), true),
        ("f=0x10", Value::Int(16), false),
        ("f=1_000", Value::Int(1000), false),
        // Spaces: the form and the literal are trimmed to read numbers, not to compare text.
        ("f=3", text(" 3"), true),
        ("f=3", text("3 "), true),
        ("f=3", text("\u{A0}3"), false),
        ("f=\u{A0}3", text("\u{A0}3"), true),
        ("f=\t3", Value::Int(3), true),
        // Booleans, lists, and maps compare by their Java forms.
        ("f=true", Value::Bool(true), true),
        ("f>false", Value::Bool(true), true),
        (
            "f=[1, 2]",
            Value::Array(vec![Value::Int(1), text("x"), Value::Float(2.5)]),
            false,
        ),
        (
            "f={a=1}",
            Value::Map([("a", Value::Int(1))].into_iter().collect()),
            true,
        ),
        ("f=null", Value::Array(vec![Value::Null]), false),
        // An in-list keeps its empty elements.
        ("x in a,", text(""), true),
        ("x in ,", text(""), true),
        ("x in 1e7, 3.0 ,abc", ten_million, true),
        ("x in 1e7, 3.0 ,abc", Value::Int(3), true),
        ("x in 1e7, 3.0 ,abc", text("abc"), true),
        ("x =", text(""), true),
    ];
    for (clause, value, java) in cases {
        assert_eq!(decides(clause, &value), java, "{clause:?} on {value:?}");
    }
}

#[test]
fn values_take_their_java_string_forms() {
    assert_eq!(filter_form(&text("a b")), "a b");
    assert_eq!(filter_form(&Value::Int(-7)), "-7");
    assert_eq!(filter_form(&Value::Float(3.0)), "3.0");
    assert_eq!(filter_form(&Value::Bool(false)), "false");
    assert_eq!(filter_form(&Value::Null), "null");
    assert_eq!(
        filter_form(&Value::Array(vec![
            Value::Int(1),
            text("x"),
            Value::Float(2.5),
            Value::Null
        ])),
        "[1, x, 2.5, null]"
    );
    let map: Map = [
        ("a", Value::Int(1)),
        ("b", Value::Array(vec![])),
        ("c", Value::Map(Map::new())),
    ]
    .into_iter()
    .collect();
    assert_eq!(filter_form(&Value::Map(map)), "{a=1, b=[], c={}}");
    // Java's form is "[B@" and an identity hash; this one stops before the hash.
    assert_eq!(filter_form(&Value::Bytes(vec![1, 2])), "[B@");
}

#[test]
fn compare_is_numeric_only_when_both_sides_are_numbers() {
    assert_eq!(filter_compare("3.0", "3"), Ordering::Equal);
    assert_eq!(filter_compare(" 10 ", "9"), Ordering::Greater);
    assert_eq!(filter_compare("10", "9x"), Ordering::Less);
    assert_eq!(filter_compare("-0", "0e5"), Ordering::Equal);
    assert_eq!(filter_compare("1.0E7", "9999999"), Ordering::Greater);
    assert_eq!(filter_compare("b", "a"), Ordering::Greater);
    assert_eq!(filter_compare("\u{1F600}", "\u{FFFD}"), Ordering::Less);
}

// ---------------------------------------------------------------------------------------------
// The matchers

#[test]
fn matchers_compare_numbers_by_value_across_int_and_float() {
    let three = Value::Int(3);
    assert!(Matcher::Eq(Value::Float(3.0)).matches(Some(&three)));
    assert!(Matcher::Eq(three.clone()).matches(Some(&Value::Float(3.0))));
    assert!(!Matcher::Ne(Value::Float(3.0)).matches(Some(&three)));
    assert!(Matcher::Gte(Value::Int(3)).matches(Some(&Value::Float(3.0))));
    assert!(Matcher::Gt(Value::Float(2.5)).matches(Some(&three)));
    assert!(Matcher::Lt(Value::Float(3.5)).matches(Some(&three)));
    assert!(Matcher::Lte(Value::Float(-0.0)).matches(Some(&Value::Int(0))));
    assert!(Matcher::In(vec![text("3"), Value::Float(3.0)]).matches(Some(&three)));
    // A double reads as the decimal Double.toString prints (BigDecimal.valueOf).
    let ten_to_23 = Value::Int(100_000_000_000_000_000_000_000);
    assert!(Matcher::Eq(Value::Float(1e23)).matches(Some(&ten_to_23)));
    assert!(Matcher::Lt(Value::Float(0.1)).matches(Some(&Value::Int(0))));
    assert!(!Matcher::Eq(Value::Float(0.1)).matches(Some(&Value::Int(0))));
    // Every CBOR integer lies inside the infinities.
    let largest = Value::Int(18_446_744_073_709_551_615);
    assert!(Matcher::Lt(Value::Float(f64::INFINITY)).matches(Some(&largest)));
    assert!(Matcher::Gt(Value::Float(f64::NEG_INFINITY)).matches(Some(&Value::Int(-(1 << 64)))));
    assert!(Matcher::Eq(Value::Float(f64::INFINITY)).matches(Some(&Value::Float(f64::INFINITY))));
}

/// The matchers that order or equate against `bound`.
fn ordering_and_equality(bound: &Value) -> [Matcher; 6] {
    [
        Matcher::Gt(bound.clone()),
        Matcher::Gte(bound.clone()),
        Matcher::Lt(bound.clone()),
        Matcher::Lte(bound.clone()),
        Matcher::Eq(bound.clone()),
        Matcher::In(vec![bound.clone()]),
    ]
}

#[test]
fn nan_orders_against_nothing_and_equals_nothing() {
    let nan = Value::Float(f64::NAN);
    for bound in [Value::Int(0), Value::Float(0.0), nan.clone()] {
        for matcher in ordering_and_equality(&bound) {
            assert!(!matcher.matches(Some(&nan)), "{matcher:?} on NaN");
        }
        assert!(Matcher::Ne(bound).matches(Some(&nan)));
    }
    for matcher in ordering_and_equality(&nan) {
        assert!(!matcher.matches(Some(&Value::Int(0))), "{matcher:?} on 0");
        assert!(
            !matcher.matches(Some(&Value::Float(0.0))),
            "{matcher:?} on 0.0"
        );
    }
}

#[test]
fn matchers_follow_javas_rules_for_everything_else() {
    let absent = None;
    let null = Some(&Value::Null);
    for missing in [absent, null] {
        assert!(Matcher::IsNull.matches(missing));
        assert!(!Matcher::NotNull.matches(missing));
        assert!(Matcher::Eq(Value::Null).matches(missing));
        assert!(!Matcher::Eq(text("x")).matches(missing));
        assert!(Matcher::Ne(text("x")).matches(missing));
        assert!(!Matcher::Gt(Value::Int(0)).matches(missing));
        assert!(!Matcher::Contains(String::new()).matches(missing));
        assert!(Matcher::In(vec![Value::Null]).matches(missing));
        assert!(!Matcher::In(vec![text("x")]).matches(missing));
    }
    let indexing = text("indexing");
    assert!(Matcher::Contains("index".into()).matches(Some(&indexing)));
    assert!(!Matcher::Contains("index".into()).matches(Some(&Value::Int(1))));
    assert!(Matcher::NotNull.matches(Some(&indexing)));
    // Text orders in Java string order, booleans false first, and nothing across kinds.
    assert!(Matcher::Gt(text("\u{1F600}")).matches(Some(&text("\u{FFFD}"))));
    assert!(Matcher::Lt(text("b")).matches(Some(&text("a"))));
    assert!(Matcher::Gt(Value::Bool(false)).matches(Some(&Value::Bool(true))));
    assert!(!Matcher::Gt(Value::Int(1)).matches(Some(&text("2"))));
    assert!(!Matcher::Lt(text("2")).matches(Some(&Value::Int(1))));
    assert!(!Matcher::Gte(Value::Array(vec![])).matches(Some(&Value::Array(vec![]))));
    assert!(!Matcher::Gte(Value::Null).matches(Some(&Value::Int(1))));
    // Equality outside numbers is the value's: a boolean is not a number.
    assert!(!Matcher::Eq(Value::Int(1)).matches(Some(&Value::Bool(true))));
    assert!(Matcher::Eq(Value::Bytes(vec![1])).matches(Some(&Value::Bytes(vec![1]))));
    assert!(!Matcher::Eq(text("3")).matches(Some(&Value::Int(3))));
}

// ---------------------------------------------------------------------------------------------
// Conditions

fn payload(entries: &[(&str, Value)]) -> Map {
    entries.iter().cloned().collect()
}

#[test]
fn conditions_match_fields_and_tags_as_a_template_does() {
    // test_layer34.py's template test.
    let template = Conditions::new()
        .with_field("priority", Matcher::Gte(Value::Int(3)))
        .with_field("topic", Matcher::Contains("index".into()))
        .with_tag("region", Matcher::In(vec![text("eu"), text("uk")]));
    let eu = payload(&[("region", text("eu"))]);
    let us = payload(&[("region", text("us"))]);
    let task = |priority: i128| {
        payload(&[
            ("topic", text("indexing")),
            ("priority", Value::Int(priority)),
        ])
    };
    assert!(template.matches(&task(3), &eu));
    assert!(!template.matches(&task(2), &eu));
    assert!(!template.matches(&task(3), &us));
    assert!(template.matches_tags(&eu) && !template.matches_tags(&us));

    let tagged = Conditions::new().with_tag("region", Matcher::NotNull);
    assert!(tagged.matches(&Map::new(), &payload(&[("region", text("x"))])));
    assert!(!tagged.matches(&Map::new(), &Map::new()));
    let exact = Conditions::new().with_field("topic", Matcher::Eq(text("exact")));
    assert!(exact.matches(&payload(&[("topic", text("exact"))]), &Map::new()));

    // filters.test.ts: clauses beside matchers.
    let mixed = Conditions::new()
        .with_field("topic", Matcher::Eq(text("index")))
        .with_clause("priority>=3")
        .and_then(|c| c.with_clause("region in eu,us"))
        .expect("clauses");
    let row = |topic: &str, priority: i128, region: &str| {
        payload(&[
            ("topic", text(topic)),
            ("priority", Value::Int(priority)),
            ("region", text(region)),
        ])
    };
    assert!(mixed.matches(&row("index", 5, "eu"), &Map::new()));
    assert!(!mixed.matches(&row("index", 2, "eu"), &Map::new()));
    assert!(!mixed.matches(&row("index", 5, "ap"), &Map::new()));
    assert!(!mixed.matches(&row("other", 5, "eu"), &Map::new()));
}

#[test]
fn every_condition_on_a_field_must_hold() {
    let band = Conditions::new()
        .with_clause("n>=3")
        .and_then(|c| c.with_clause("n<5"))
        .expect("clauses")
        .with_field("n", Matcher::Ne(Value::Int(4)));
    let n = |v: i128| payload(&[("n", Value::Int(v))]);
    let verdicts: Vec<bool> = (1..=6).map(|v| band.matches(&n(v), &Map::new())).collect();
    assert_eq!(verdicts, [false, false, true, false, false, false]);
    assert_eq!(band.field_conditions().len(), 3);
    assert!(band.tag_conditions().is_empty());
    assert!(matches!(band.field_conditions()[0].1, Condition::Filter(_)));
    // An absent field is null: only != and the null matchers hold for it.
    let missing = Conditions::new()
        .with_clause("topic!=index")
        .expect("a clause");
    assert!(missing.matches(&Map::new(), &Map::new()));
    assert!(Condition::Matcher(Matcher::IsNull).matches(None));
    // No conditions match everything.
    assert!(Conditions::new().is_empty());
    assert!(Conditions::new().matches(&n(1), &n(2)));
}
