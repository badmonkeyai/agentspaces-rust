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

//! The derive's happy paths: the schema constant, a generic type, a renamed crate path, and the
//! trait's provided payload methods on a derived type.

use agentspaces::entry::Entry;
use agentspaces::wire::cbor_map;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize, agentspaces::Entry)]
#[entry(schema = "shop.Order#v1")]
struct Order {
    item: String,
    quantity: u32,
}

/// The trait and its derive under one import, as with serde.
#[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "https://example.org/claims#Claim", crate = "::agentspaces")]
struct Claim {
    id: u64,
}

/// A generic entry: an entry for every `T` that makes it serializable.
#[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Batch#v1")]
struct Batch<T> {
    items: Vec<T>,
}

/// A generic entry with bounds of its own, which the impl keeps.
#[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Keyed#v1")]
struct Keyed<K: Ord, const N: usize>
where
    K: Clone,
{
    keys: Vec<K>,
}

/// A unit-variant enum is an entry too (a Java enum constant on the wire).
#[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
#[entry(schema = "shop.Status#v1")]
enum Status {
    Open,
    Closed,
}

fn schema_of<T: Entry>() -> &'static str {
    T::SCHEMA
}

#[test]
fn the_schema_is_the_attribute_s() {
    assert_eq!(Order::SCHEMA, "shop.Order#v1");
    assert_eq!(schema_of::<Claim>(), "https://example.org/claims#Claim");
    assert_eq!(schema_of::<Batch<String>>(), "shop.Batch#v1");
    assert_eq!(schema_of::<Keyed<u8, 3>>(), "shop.Keyed#v1");
    assert_eq!(schema_of::<Status>(), "shop.Status#v1");
}

#[test]
fn derived_entries_convert_through_the_trait() {
    let order = Order {
        item: "fig".into(),
        quantity: 2,
    };
    let payload = order.to_payload().unwrap();
    assert_eq!(payload, cbor_map! { "item" => "fig", "quantity" => 2 });
    assert_eq!(Order::from_payload(&payload).unwrap(), order);

    let batch = Batch {
        items: vec![1u8, 2],
    };
    assert_eq!(
        Batch::<u8>::from_payload(&batch.to_payload().unwrap()).unwrap(),
        batch
    );
    assert_eq!(
        Status::Closed.to_payload().unwrap(),
        agentspaces::wire::cbor::Value::from("Closed")
    );
}
