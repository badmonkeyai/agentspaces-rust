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

//! The entry layer against Java: Rust types derived with `#[derive(Entry)]` encode to exactly
//! the payload bytes Jackson writes for the equivalent Java records, read those bytes back, and
//! go through JSON without losing a width.
//!
//! Two sources of Java bytes:
//!
//! - the wire crate's golden vectors (`task_payload_cbor`, `sign_view_cbor`, `record_signature`,
//!   from `tools/golden/GoldenVectors.java`'s `record ResearchTask(String topic, int priority)`);
//! - [`JAVA_ORDER`] and its siblings, printed by the Java codec (`CborCodec.defaultCodec()`,
//!   agentspaces-common 0.5.0, Jackson 2.21.7) from this program:
//!
//! ```java
//! public enum Kind { STANDARD, EXPRESS }
//! public record Line(String sku, int quantity, double price) {}
//! public record Order(String orderId, Kind kind, List<Line> lines, Line primary,
//!                     Map<String, Integer> counts, Map<Integer, String> byNumber,
//!                     byte[] digest, double weight, long big, int delta, Integer note,
//!                     boolean rush, char grade, short shelf, byte level, List<String> notes) {}
//! public record Floaty(float f) {}
//!
//! Map<String, Integer> counts = new LinkedHashMap<>();   // pear 2, fig 1, banana 5, apple 3
//! Map<Integer, String> byNumber = new LinkedHashMap<>(); // 10 ten, 9 nine, 100 hundred, -1 minus one
//! Order order = new Order("o-1", Kind.EXPRESS,
//!         List.of(new Line("apple", 3, 1.25), new Line("fig", -2, 0.5)),
//!         new Line("pear", 1, 2.0), counts, byNumber, new byte[] {0, 1, 2, (byte) 0xff}, 2.0,
//!         9_007_199_254_740_993L, -7, null, true, 'B', (short) 300, (byte) -5, List.of());
//! codec.toBytes(order);                // JAVA_ORDER
//! codec.toBytes(counts);               // JAVA_COUNTS
//! codec.toBytes(new Floaty(1.5f));     // JAVA_FLOATY
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use agentspaces::entry::{
    Entry, EntryError, EntryValue, Registry, decode_entry, from_value, serde_bytes, to_value,
};
use agentspaces::json::{self, from_json, json_to_value, to_json, value_to_json};
use agentspaces::wire::cbor::{self, Value};
use agentspaces::wire::identity::Identity;
use agentspaces::wire::records::sign_view;
use agentspaces::wire::{cbor_array, cbor_map};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// `Order` as the Java codec writes it (see the module documentation).
const JAVA_ORDER: &str = "bf676f726465724964636f2d31646b696e646745585052455353656c696e657382bf63736b75656170706c65687175616e7469747903657072696365fb3ff4000000000000ffbf63736b7563666967687175616e7469747921657072696365fb3fe0000000000000ff677072696d617279bf63736b756470656172687175616e7469747901657072696365fb4000000000000000ff66636f756e7473bf6366696701647065617202656170706c65036662616e616e6105ff6862794e756d626572bf6139646e696e65622d31696d696e7573206f6e656231306374656e633130306768756e64726564ff6664696765737444000102ff66776569676874fb4000000000000000636269671b00200000000000016564656c746126646e6f7465f66472757368f56567726164656142657368656c6619012c656c6576656c24656e6f74657380ff";

/// The `counts` map alone, as the Java codec writes a `java.util.Map`: canonical order.
const JAVA_COUNTS: &str = "bf6366696701647065617202656170706c65036662616e616e6105ff";

/// `Floaty(1.5f)`: Jackson writes a Java `float` as a 32-bit float (`0xFA`).
const JAVA_FLOATY: &str = "bf6166fa3fc00000ff";

/// The golden vectors' entry id, as `records_golden.rs` uses it.
const GOLDEN_ENTRY: &str = "11111111-2222-3333-4444-555555555555";

// ------------------------------------------------------------------------------- types

/// The interop seed's `record Task(String topic, int priority)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
struct Task {
    topic: String,
    priority: i32,
}

/// The golden vectors' `record ResearchTask(String topic, int priority)`, through the
/// `agentspaces::entry::Entry` import that names both the trait and its derive, and with the
/// crate path spelled out.
#[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "GoldenVectors$ResearchTask#v1", crate = "agentspaces")]
struct ResearchTask {
    topic: String,
    priority: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Kind {
    Standard,
    Express,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Line {
    sku: String,
    quantity: i32,
    price: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "EntryVectors$Order#v1")]
#[serde(rename_all = "camelCase")]
struct Order {
    order_id: String,
    kind: Kind,
    lines: Vec<Line>,
    primary: Line,
    counts: HashMap<String, i32>,
    by_number: HashMap<i32, String>,
    #[serde(with = "serde_bytes")]
    digest: Vec<u8>,
    weight: f64,
    big: i64,
    delta: i32,
    note: Option<i32>,
    rush: bool,
    grade: char,
    shelf: i16,
    level: i8,
    notes: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Floaty {
    f: f32,
}

/// The Java program's order, its maps filled in the Java insertion order.
fn order() -> Order {
    Order {
        order_id: "o-1".into(),
        kind: Kind::Express,
        lines: vec![
            Line {
                sku: "apple".into(),
                quantity: 3,
                price: 1.25,
            },
            Line {
                sku: "fig".into(),
                quantity: -2,
                price: 0.5,
            },
        ],
        primary: Line {
            sku: "pear".into(),
            quantity: 1,
            price: 2.0,
        },
        counts: [("pear", 2), ("fig", 1), ("banana", 5), ("apple", 3)]
            .map(|(k, v)| (k.to_owned(), v))
            .into(),
        by_number: [
            (10, "ten"),
            (9, "nine"),
            (100, "hundred"),
            (-1, "minus one"),
        ]
        .map(|(k, v)| (k, v.to_owned()))
        .into(),
        digest: vec![0, 1, 2, 0xff],
        weight: 2.0,
        big: 9_007_199_254_740_993,
        delta: -7,
        note: None,
        rush: true,
        grade: 'B',
        shelf: 300,
        level: -5,
        notes: vec![],
    }
}

// ------------------------------------------------------------------------------- helpers

fn golden() -> &'static serde_json::Value {
    static GOLDEN: OnceLock<serde_json::Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        serde_json::from_str(include_str!("../../agentspaces-wire/tests/golden.json"))
            .unwrap_or_else(|error| panic!("golden.json does not parse: {error}"))
    })
}

fn golden_text(name: &str) -> &'static str {
    golden()[name]
        .as_str()
        .unwrap_or_else(|| panic!("golden {name} is not a string"))
}

fn golden_hex(name: &str) -> Vec<u8> {
    unhex(golden_text(name))
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|error| panic!("not hex: {error}"))
}

fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
    cbor::encode(&to_value(value).unwrap())
}

fn decoded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    from_value(&cbor::decode(bytes).unwrap()).unwrap()
}

// ------------------------------------------------------------------------------- golden

#[test]
fn a_task_struct_writes_the_golden_payload() {
    let golden = golden_hex("task_payload_cbor");
    let research = ResearchTask {
        topic: "golden vectors".into(),
        priority: 3,
    };
    assert_eq!(encoded(&research), golden);
    // The seed's Task has the same components, so the same payload.
    let task = Task {
        topic: "golden vectors".into(),
        priority: 3,
    };
    assert_eq!(encoded(&task), golden);
    assert_eq!(task.to_payload().unwrap(), cbor::decode(&golden).unwrap());
    assert_eq!(decoded::<ResearchTask>(&golden), research);
    assert_eq!(decoded::<Task>(&golden), task);

    assert_eq!(
        Task::SCHEMA,
        "ai.badmonkey.agentspaces.interop.Seed$Task#v1"
    );
    assert_eq!(ResearchTask::SCHEMA, "GoldenVectors$ResearchTask#v1");
}

#[test]
fn a_derived_entry_signs_the_golden_record() {
    let identity = Identity::from_pkcs8(&golden_hex("private_key_pkcs8")).unwrap();
    let payload = cbor::encode(
        &ResearchTask {
            topic: "golden vectors".into(),
            priority: 3,
        }
        .to_payload()
        .unwrap(),
    );
    let view = sign_view(
        GOLDEN_ENTRY,
        golden_text("space_id"),
        ResearchTask::SCHEMA,
        Some(&payload),
        &identity.agent("python"),
        golden_text("hlc_encoded"),
        None,
        None,
        None,
    );
    let view = cbor::encode(&Value::Map(view));
    assert_eq!(view, golden_hex("sign_view_cbor"));
    assert_eq!(
        identity.sign(&view).as_slice(),
        golden_hex("record_signature")
    );
}

// ------------------------------------------------------------------------------- Jackson

#[test]
fn a_nested_entry_writes_the_bytes_jackson_writes() {
    let order = order();
    assert_eq!(hex::encode(encoded(&order)), JAVA_ORDER);
    // HashMap iteration order varies by process; the canonical order does not.
    for _ in 0..8 {
        let mut shuffled = order.clone();
        shuffled.counts = order.counts.clone().into_iter().collect();
        shuffled.by_number = order.by_number.clone().into_iter().collect();
        assert_eq!(hex::encode(encoded(&shuffled)), JAVA_ORDER);
    }
    assert_eq!(hex::encode(encoded(&order.counts)), JAVA_COUNTS);
    let sorted: BTreeMap<_, _> = order.counts.iter().collect();
    assert_eq!(hex::encode(encoded(&sorted)), JAVA_COUNTS);
}

#[test]
fn jackson_bytes_read_into_the_rust_types() {
    let order: Order = decoded(&unhex(JAVA_ORDER));
    assert_eq!(order, self::order());
    assert_eq!(
        order.by_number.get(&-1).map(String::as_str),
        Some("minus one")
    );
    assert_eq!(order.note, None);
    // Through the trait and the schema check as well.
    let payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    assert_eq!(Order::from_payload(&payload).unwrap(), self::order());
    assert_eq!(
        decode_entry::<Order>("EntryVectors$Order#v1", &payload).unwrap(),
        self::order()
    );
    assert!(matches!(
        decode_entry::<Order>("EntryVectors$Refund#v1", &payload),
        Err(EntryError::WrongSchema { .. })
    ));
}

#[test]
fn a_java_float_reads_but_writes_as_a_double() {
    let floaty: Floaty = decoded(&unhex(JAVA_FLOATY));
    assert_eq!(floaty, Floaty { f: 1.5 });
    // The wire codec writes every float as a 64-bit double, so only `f64` components match a
    // Java record byte for byte.
    assert_eq!(hex::encode(encoded(&floaty)), "bf6166fb3ff8000000000000ff");
}

#[test]
fn a_newer_writer_s_fields_are_ignored() {
    let mut payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    let map = payload.as_map_mut().unwrap();
    map.insert("addedInV2", cbor_map! { "nested" => cbor_array![1, 2, 3] });
    map.remove("note");
    let order: Order = from_value(&payload).unwrap();
    assert_eq!(order, self::order());
}

#[test]
fn a_wrong_type_names_the_path() {
    let mut payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    let lines = payload
        .get_mut("lines")
        .and_then(Value::as_array_mut)
        .unwrap();
    lines[1]
        .as_map_mut()
        .unwrap()
        .insert("quantity", "minus two");
    let error = from_value::<Order>(&payload).unwrap_err();
    assert_eq!(
        error,
        EntryError::Decode {
            path: "$.lines[1].quantity".into(),
            message: "expected i32, found the text \"minus two\"".into(),
        }
    );
    assert_eq!(
        error.to_string(),
        "cannot decode $.lines[1].quantity: expected i32, found the text \"minus two\""
    );

    let mut payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    payload
        .get_mut("byNumber")
        .and_then(Value::as_map_mut)
        .unwrap()
        .insert("ten", "10");
    let error = from_value::<Order>(&payload).unwrap_err();
    assert!(
        matches!(&error, EntryError::Decode { path, .. } if path == "$.byNumber.ten"),
        "{error}"
    );

    let mut payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    payload.as_map_mut().unwrap().insert("level", 128);
    let error = from_value::<Order>(&payload).unwrap_err();
    assert_eq!(
        error.to_string(),
        "cannot decode $.level: the integer 128 is out of range for i8"
    );
}

// ------------------------------------------------------------------------------- registry

#[test]
fn a_registry_types_what_it_knows_and_keeps_the_rest() {
    let mut registry = Registry::new();
    registry
        .register::<Task>()
        .and_then(|registry| registry.register::<Order>())
        .unwrap();
    assert_eq!(
        registry.schemas(),
        [
            "EntryVectors$Order#v1",
            "ai.badmonkey.agentspaces.interop.Seed$Task#v1"
        ]
    );

    let order_payload = cbor::decode(&unhex(JAVA_ORDER)).unwrap();
    let read = registry.decode(Order::SCHEMA, &order_payload).unwrap();
    assert_eq!(read.downcast_ref::<Order>(), Some(&order()));
    assert_eq!(read.downcast_ref::<Task>(), None);
    assert_eq!(read.to_payload().unwrap(), order_payload);

    let research = cbor::decode(&golden_hex("task_payload_cbor")).unwrap();
    let unknown = registry.decode(ResearchTask::SCHEMA, &research).unwrap();
    match &unknown {
        EntryValue::Unknown { schema, value } => {
            assert_eq!(schema, ResearchTask::SCHEMA);
            assert_eq!(value, &research);
        }
        EntryValue::Typed(entry) => panic!("{} is not registered", entry.type_name()),
    }
    // A tool without the Rust type still shows it.
    assert_eq!(
        value_to_json(&unknown.to_payload().unwrap()),
        json!({"topic": "golden vectors", "priority": 3})
    );
    let task = registry.decode(Task::SCHEMA, &research).unwrap();
    assert_eq!(
        task.downcast::<Task>().unwrap(),
        Task {
            topic: "golden vectors".into(),
            priority: 3
        }
    );
}

// ------------------------------------------------------------------------------- JSON

#[test]
fn a_script_s_json_task_writes_the_golden_payload() {
    // A script writes the record as JSON; the object's order is the field order.
    let script: serde_json::Value =
        serde_json::from_str(r#"{"topic": "golden vectors", "priority": 3}"#).unwrap();
    let payload = json_to_value(&script, None).unwrap();
    assert_eq!(cbor::encode(&payload), golden_hex("task_payload_cbor"));
    assert_eq!(
        from_json::<Task>(&script).unwrap(),
        Task {
            topic: "golden vectors".into(),
            priority: 3
        }
    );
}

#[test]
fn an_entry_round_trips_through_json_text() {
    let order = order();
    let json = to_json(&order).unwrap();
    assert_eq!((json::BYTES_KEY, json::INT_KEY), ("$bytes", "$int"));
    assert_eq!(json["digest"], json!({"$bytes": "AAEC/w=="}));
    assert_eq!(json["weight"], json!(2.0));
    // 2^53 + 1 is beyond JavaScript's exact integers, so it is tagged.
    assert_eq!(json["big"], json!({"$int": "9007199254740993"}));
    assert_eq!(
        json["byNumber"],
        json!({"9": "nine", "-1": "minus one", "10": "ten", "100": "hundred"})
    );
    let text = serde_json::to_string(&json).unwrap();
    let back: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(from_json::<Order>(&back).unwrap(), order);
    // The untyped path keeps every width too: the same bytes as Java's.
    let payload = json_to_value(&back, None).unwrap();
    assert_eq!(hex::encode(cbor::encode(&payload)), JAVA_ORDER);
}

#[test]
fn a_hint_restores_float_widths_from_javascript_json() {
    // JavaScript's JSON.stringify writes 2.0 as 2, which reads as an integer...
    let script = json!({"sku": "pear", "quantity": 1, "price": 2});
    let plain = json_to_value(&script, None).unwrap();
    assert_eq!(plain.get("price"), Some(&Value::Int(2)));
    // ...so a template of the type tells the bridge which fields are doubles.
    let template = to_value(&Line {
        sku: String::new(),
        quantity: 0,
        price: 0.0,
    })
    .unwrap();
    let hinted = json_to_value(&script, Some(&template)).unwrap();
    assert_eq!(hinted, to_value(&order().primary).unwrap());
    // A typed read needs no hint: an integer reads into an f64 field.
    assert_eq!(from_json::<Line>(&script).unwrap(), order().primary);
}

#[test]
fn json_errors_name_the_path() {
    let bad = json!({"digest": {"$bytes": "%%%"}});
    let error = json_to_value(&bad, None).unwrap_err();
    assert_eq!(error.path, "$.digest.$bytes");
    let error = from_json::<Order>(&json!({"orderId": 5})).unwrap_err();
    assert!(
        matches!(&error, EntryError::Decode { path, .. } if path == "$.orderId"),
        "{error}"
    );
}
