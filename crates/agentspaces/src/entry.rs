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

//! Entries: how Rust types become AgentSpaces payloads and back.
//!
//! An entry in a space is a schema name (the record's `type`, such as
//! `"shop.Order#v1"`) and a payload, a CBOR [`Value`]. The Java node writes a payload with
//! Jackson from a Java record; [`to_value`] writes the payload Jackson writes for the equivalent
//! record, so a Rust struct and a Java record of the same components produce the same bytes, and
//! [`from_value`] reads a payload back into a Rust type. [`Entry`] binds a type to its schema
//! name, usually with `#[derive(Entry)]`; a [`Registry`] maps schema names to types, so a reader
//! of many types decodes each into its own and keeps the ones it does not know as
//! [`EntryValue::Unknown`].
//!
//! ```
//! use agentspaces::entry::{self, Entry};
//! use agentspaces::wire::cbor;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
//! #[entry(schema = "ai.badmonkey.agentspaces.interop.Seed$Task#v1")]
//! struct Task {
//!     topic: String,
//!     priority: i32,
//! }
//!
//! let task = Task { topic: "index".into(), priority: 3 };
//! let payload = entry::to_value(&task)?;
//! // Fields in declared order, as Jackson writes `record Task(String topic, int priority)`.
//! assert_eq!(cbor::encode(&payload), b"\xbf\x65topic\x65index\x68priority\x03\xff");
//! assert_eq!(entry::from_value::<Task>(&payload)?, task);
//! assert_eq!(Task::SCHEMA, "ai.badmonkey.agentspaces.interop.Seed$Task#v1");
//! # Ok::<(), agentspaces::entry::EntryError>(())
//! ```
//!
//! # Writing ([`to_value`])
//!
//! | Rust (serde data model) | wire [`Value`] | Java (Jackson) |
//! |---|---|---|
//! | struct, struct variant content | [`Value::Map`], fields in declared order | record components |
//! | `HashMap`, `BTreeMap`, any serde map | [`Value::Map`], text keys, canonical order | `java.util.Map` |
//! | `i8`..`i128`, `u8`..`u128` | [`Value::Int`] (a bignum beyond `i64`) | `byte`, `short`, `int`, `long`, `BigInteger` |
//! | `f32`, `f64` | [`Value::Float`] (always a 64-bit double) | `double` |
//! | `bool` | [`Value::Bool`] | `boolean` |
//! | `String`, `&str`, `char` | [`Value::Text`] | `String`, `char` |
//! | `Option::None`, `()`, unit structs | [`Value::Null`] | `null` |
//! | `Option::Some(x)`, newtype structs | the value of `x` | the value |
//! | unit variants | [`Value::Text`], the variant name | an `enum` constant |
//! | newtype, tuple, struct variants | a one-entry map `{name: content}` | `@JsonTypeInfo(use = NAME, include = WRAPPER_OBJECT)` |
//! | `Vec`, slices, arrays, tuples, sets | [`Value::Array`] | `List`, `Set`, arrays |
//! | [`serde_bytes`] fields | [`Value::Bytes`] | `byte[]` |
//!
//! - **Field order.** A struct is a map in field order, the order a Java record declares its
//!   components in and Jackson writes them in. Rename fields to the Java component names
//!   (`#[serde(rename_all = "camelCase")]`) and enum variants to the Java constant names
//!   (`#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`) to match a Java type.
//! - **Canonical maps.** Every serde map is written in the wire v3 canonical order
//!   ([`cbor::canonical_map`]: shorter UTF-8 key first, then bytewise), the order the Java codec
//!   writes every `java.util.Map` in (SPEC 9), so a map's bytes depend on its content and not on
//!   how it was built. `#[serde(flatten)]` makes serde write the whole struct as a map, so a
//!   struct with a flattened field is written in canonical order, not field order.
//! - **Map keys are text.** Jackson writes every map key as a string, so integer, `bool`, and
//!   `char` keys and unit variants are written as their text (`10` as `"10"`, sorted as text:
//!   `"9"` before `"10"`). Float, byte-string, option, and container keys are refused.
//! - **Bytes.** serde writes a `Vec<u8>` as a sequence of integers, which is a CBOR array, not
//!   Java's `byte[]`. Mark byte fields `#[serde(with = "serde_bytes")]` (re-exported here as
//!   [`serde_bytes`]) or use [`serde_bytes::ByteBuf`] to write [`Value::Bytes`].
//! - **Floats.** The wire codec writes every float as a 64-bit double. Jackson writes a Java
//!   `float` as a 32-bit float, so only `f64` matches a Java component byte for byte; an `f32`
//!   still reads Java's 32-bit floats back.
//! - **Big numbers.** An integer outside Java's `long` range is written as a bignum, as Jackson
//!   writes a `BigInteger`. A Java `BigDecimal` ([`Value::Decimal`]) or a `BigInteger` past 64
//!   bits ([`Value::BigInt`]) reads into an `f32` or `f64` field as the nearest float, as
//!   Jackson reads one into a `double`, and as the nearest `f64` where any value is wanted.
//! - **Sets.** A `HashSet` is written in its iteration order, which varies; use a `BTreeSet` or
//!   a `Vec` when the bytes must be reproducible.
//! - **Binary mode.** The serializer reports itself as not human readable, as binary formats do:
//!   a `uuid::Uuid` is written as 16 bytes, which is how Jackson writes a `java.util.UUID` to
//!   CBOR. Other types that pick their form by human readability write their compact binary
//!   form too, not Java's text: an `IpAddr` or `SocketAddr` is a map such as `{"V4": [1, 2, 3,
//!   4]}` (Java's `InetAddress` is text), and a `time` crate date or time is a tuple. Use a
//!   `String` field, or `#[serde(with = ...)]` a text adapter, to match the Java component.
//! - **Time.** The Java codec writes `java.time` values as ISO-8601 text (Jackson's
//!   `JavaTimeModule` with `WRITE_DATES_AS_TIMESTAMPS` and `WRITE_DURATIONS_AS_TIMESTAMPS`
//!   off): an `Instant` as `"2026-11-08T10:00:00Z"`, a `Duration` as `"PT30S"`. serde writes
//!   `std::time::Duration` as a map `{secs, nanos}` and `std::time::SystemTime` as
//!   `{secs_since_epoch, nanos_since_epoch}`, whichever mode: Java cannot read either, and a
//!   Rust field of those types fails to decode Java's text, so the typed verbs pass over every
//!   entry Java wrote ([`crate::space::typed`]). For a Java `Instant` or `Duration` component use
//!   a `String` field, or a text adapter: chrono's `DateTime<Utc>` (RFC 3339 text in either
//!   mode), `time::OffsetDateTime` with `#[serde(with = "time::serde::rfc3339")]`, or an ISO-8601
//!   duration adapter of your own.
//!
//!   ```
//!   use std::time::Duration;
//!   use agentspaces::entry;
//!   use agentspaces::wire::cbor_map;
//!   use serde::{Deserialize, Serialize};
//!
//!   #[derive(Debug, Serialize, Deserialize)]
//!   struct StdTime {
//!       ttl: Duration,
//!   }
//!
//!   #[derive(Debug, Serialize, Deserialize)]
//!   struct JavaTime {
//!       ttl: String,
//!   }
//!
//!   // What Java writes for `record Hold(Duration ttl)`.
//!   let from_java = cbor_map! { "ttl" => "PT30S" };
//!   assert!(entry::from_value::<StdTime>(&from_java).is_err());
//!   assert_eq!(entry::from_value::<JavaTime>(&from_java)?.ttl, "PT30S");
//!   // What std's `Duration` writes, which Java cannot read.
//!   let std_form = entry::to_value(&StdTime { ttl: Duration::from_secs(30) })?;
//!   assert_eq!(std_form, cbor_map! { "ttl" => cbor_map! { "secs" => 30, "nanos" => 0 } });
//!   # Ok::<(), agentspaces::entry::EntryError>(())
//!   ```
//! - A duplicate map key or struct field is refused, because every decoder on the wire refuses
//!   a map with one.
//!
//! # Reading ([`from_value`])
//!
//! - A float field reads an integer ([`Value::Int`]), as Jackson does; an integer field reads a
//!   float only when it is a whole number in the field's range.
//! - An enum reads a variant name ([`Value::Text`]) or a one-entry map `{name: content}`.
//! - An `Option` reads [`Value::Null`] as `None`, and a missing `Option` field is `None`.
//! - Map keys read text as integers, booleans, and chars where the key type asks for one, so a
//!   map written by Jackson reads back into a `HashMap<i32, _>`.
//! - A byte field reads [`Value::Bytes`] or an array of small integers; a plain `Vec<u8>` reads
//!   [`Value::Bytes`] too.
//! - Unknown map keys are ignored, so a reader keeps working when a newer writer adds a field
//!   (Jackson's `FAIL_ON_UNKNOWN_PROPERTIES` is off in the Java codec too); opt out per type with
//!   `#[serde(deny_unknown_fields)]`.
//! - Anything else of the wrong type is refused with an [`EntryError::Decode`] that names the
//!   path to the offending value, such as `$.lines[1].quantity`.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;

use agentspaces_wire::cbor::{self, INT_MAX, INT_MIN, Map, Value};
use serde::de::value::{BorrowedStrDeserializer, U8Deserializer};
use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer as _, Visitor};
use serde::ser::{self, Impossible, Serialize};

/// `#[derive(Entry)]`, so `use agentspaces::entry::Entry` brings the trait and its derive, as
/// `use serde::Serialize` does.
pub use agentspaces_derive::Entry;
pub use serde;
pub use serde_bytes;

// ---------------------------------------------------------------------------------------------
// Errors

/// Why a value did not convert to or from an entry payload, or why a registration failed.
///
/// The `path` of [`EntryError::Encode`] and [`EntryError::Decode`] names the offending value from
/// the payload's root `$`: `.name` for a struct field or a map key, `[2]` for an array index,
/// `["a key"]` for a map key that is not a plain name, and `.Variant` for the content of an enum
/// variant, so `$.lines[1].quantity` is the `quantity` of the second element of `lines`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// A Rust value has no payload form: an integer outside the CBOR range, a float map key, a
    /// duplicate key, or an error the type's own `Serialize` reported.
    #[error("cannot encode {path}: {message}")]
    Encode {
        /// Where the value is, from `$`.
        path: String,
        /// What is wrong with it.
        message: String,
    },
    /// A payload does not fit the Rust type: a type mismatch, an integer out of range, a missing
    /// field, an unknown enum variant, or an error the type's own `Deserialize` reported.
    #[error("cannot decode {path}: {message}")]
    Decode {
        /// Where the value is, from `$`.
        path: String,
        /// What is wrong with it.
        message: String,
    },
    /// [`Registry::register`] was asked to bind a schema name another type already has.
    #[error("schema {schema:?} is already registered to {registered}, not {attempted}")]
    SchemaTaken {
        /// The schema name.
        schema: String,
        /// The type that has it.
        registered: &'static str,
        /// The type that asked for it.
        attempted: &'static str,
    },
    /// [`decode_entry`] was given an entry of another schema than the type's.
    #[error("expected an entry of schema {expected:?}, found {found:?}")]
    WrongSchema {
        /// The schema of the type asked for.
        expected: &'static str,
        /// The schema of the entry.
        found: String,
    },
}

impl EntryError {
    fn encode(message: impl Into<String>) -> Self {
        EntryError::Encode {
            path: String::new(),
            message: message.into(),
        }
    }

    fn decode(message: impl Into<String>) -> Self {
        EntryError::Decode {
            path: String::new(),
            message: message.into(),
        }
    }

    /// A decode error: `found` is not the `expected` kind of value.
    fn mismatch(expected: &str, found: &Value) -> Self {
        EntryError::decode(format!("expected {expected}, found {}", describe(found)))
    }

    /// The error with `segment` put in front of its path, as it leaves the value at `segment`.
    fn within(mut self, segment: Segment<'_>) -> Self {
        if let EntryError::Encode { path, .. } | EntryError::Decode { path, .. } = &mut self {
            path.insert_str(0, &segment.to_string());
        }
        self
    }

    /// The error with its path anchored at the payload's root, `$`.
    fn rooted(mut self) -> Self {
        if let EntryError::Encode { path, .. } | EntryError::Decode { path, .. } = &mut self {
            path.insert(0, '$');
        }
        self
    }
}

impl ser::Error for EntryError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        EntryError::encode(message.to_string())
    }
}

impl de::Error for EntryError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        EntryError::decode(message.to_string())
    }
}

/// One step of an error path.
#[derive(Clone, Copy)]
enum Segment<'a> {
    /// A struct field.
    Field(&'a str),
    /// An array element.
    Index(usize),
    /// A map key.
    Key(&'a Value),
    /// The content of an enum variant.
    Variant(&'a str),
}

impl fmt::Display for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Segment::Field(name) | Segment::Variant(name) => *name,
            Segment::Key(Value::Text(name)) => name.as_str(),
            Segment::Index(index) => return write!(f, "[{index}]"),
            Segment::Key(key) => return write!(f, "[{key:?}]"),
        };
        if is_plain_name(name) {
            write!(f, ".{name}")
        } else {
            write!(f, "[{name:?}]")
        }
    }
}

/// Whether a name prints bare in a path: a letter, `_`, or `$`, then letters, digits, `_`, `$`.
pub(crate) fn is_plain_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// A short description of a value for an error message: its kind, and a scalar's value.
fn describe(value: &Value) -> String {
    const PREVIEW: usize = 32;
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => format!("the bool {b}"),
        Value::Int(n) => format!("the int {n}"),
        Value::BigInt(big) => format!("a bignum of {} bytes", big.magnitude().len()),
        Value::Decimal(decimal) => format!(
            "the decimal {}",
            decimal
                .to_string()
                .chars()
                .take(PREVIEW)
                .collect::<String>()
        ),
        Value::Float(x) => format!("the float {x:?}"),
        Value::Text(text) if text.chars().count() > PREVIEW => {
            let head: String = text.chars().take(PREVIEW).collect();
            format!("the text {head:?}...")
        }
        Value::Text(text) => format!("the text {text:?}"),
        Value::Bytes(bytes) => format!("{} bytes", bytes.len()),
        Value::Array(items) => format!("an array of {} items", items.len()),
        Value::Map(map) => format!("a map of {} entries", map.len()),
    }
}

// ---------------------------------------------------------------------------------------------
// The public conversions

/// The wire payload of a value: what Jackson writes for the equivalent Java record (see the
/// [module documentation](self) for the mapping).
///
/// # Errors
///
/// [`EntryError::Encode`] when a value has no payload form: an integer outside
/// [`INT_MIN`]`..=`[`INT_MAX`], a map key that is not text, an integer, a `bool`, a `char`, or a
/// unit variant, a duplicate map key or field, or an error from the type's `Serialize`.
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, EntryError> {
    value.serialize(ValueSerializer).map_err(EntryError::rooted)
}

/// A value read from its wire payload (see the [module documentation](self) for the rules).
///
/// # Errors
///
/// [`EntryError::Decode`], naming the path to the value that does not fit `T`.
pub fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T, EntryError> {
    T::deserialize(ValueDeserializer::new(value)).map_err(EntryError::rooted)
}

/// A typed entry read from a schema name and a payload, refusing a payload of another schema.
///
/// # Errors
///
/// [`EntryError::WrongSchema`] when `schema` is not `T::SCHEMA`; [`EntryError::Decode`] when the
/// payload does not fit `T`.
pub fn decode_entry<T: Entry>(schema: &str, value: &Value) -> Result<T, EntryError> {
    if schema != T::SCHEMA {
        return Err(EntryError::WrongSchema {
            expected: T::SCHEMA,
            found: schema.to_owned(),
        });
    }
    T::from_payload(value)
}

// ---------------------------------------------------------------------------------------------
// Entry

/// A Rust type bound to the schema name the fleet knows it by.
///
/// The schema name is the entry's wire `type`: under the Java default registry a record's binary
/// class name plus `#v1` (`"ai.badmonkey.agentspaces.interop.Seed$Task#v1"`), or the name a
/// schema registry assigns (`"https://example.org/claims#Claim"`). Derive it with
/// `#[derive(Entry)]` and `#[entry(schema = "...")]`, beside `Serialize` and `Deserialize`:
///
/// ```
/// use agentspaces::Entry;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, Entry)]
/// #[entry(schema = "shop.Order#v1")]
/// #[serde(rename_all = "camelCase")]
/// struct Order {
///     order_id: String,
///     quantity: u32,
/// }
///
/// assert_eq!(<Order as agentspaces::entry::Entry>::SCHEMA, "shop.Order#v1");
/// ```
pub trait Entry: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The wire schema name of the type.
    const SCHEMA: &'static str;

    /// This entry's wire payload, [`to_value`].
    ///
    /// # Errors
    ///
    /// As [`to_value`].
    fn to_payload(&self) -> Result<Value, EntryError> {
        to_value(self)
    }

    /// An entry read from its wire payload, [`from_value`].
    ///
    /// # Errors
    ///
    /// As [`from_value`].
    fn from_payload(payload: &Value) -> Result<Self, EntryError> {
        from_value(payload)
    }
}

// ---------------------------------------------------------------------------------------------
// Registry

/// A boxed entry of a registered type.
type AnyEntry = Box<dyn Any + Send + Sync>;

/// What the registry keeps for one schema.
#[derive(Clone, Copy)]
struct Binding {
    schema: &'static str,
    type_id: TypeId,
    type_name: &'static str,
    decode: fn(&Value) -> Result<AnyEntry, EntryError>,
    encode: fn(&(dyn Any + Send + Sync)) -> Result<Value, EntryError>,
}

fn decode_any<T: Entry>(value: &Value) -> Result<AnyEntry, EntryError> {
    Ok(Box::new(T::from_payload(value)?))
}

fn encode_any<T: Entry>(value: &(dyn Any + Send + Sync)) -> Result<Value, EntryError> {
    match value.downcast_ref::<T>() {
        Some(entry) => entry.to_payload(),
        None => Err(EntryError::encode(format!(
            "the entry is not a {}",
            std::any::type_name::<T>()
        ))
        .rooted()),
    }
}

/// An explicit table from schema names to Rust entry types, for readers of many types: a space
/// browser, a relay, a tool that prints whatever a space holds.
///
/// ```
/// use agentspaces::Entry;
/// use agentspaces::entry::{EntryValue, Registry};
/// use agentspaces::wire::cbor_map;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, PartialEq, Serialize, Deserialize, Entry)]
/// #[entry(schema = "shop.Order#v1")]
/// struct Order {
///     item: String,
/// }
///
/// let mut registry = Registry::new();
/// registry.register::<Order>()?;
///
/// let known = registry.decode("shop.Order#v1", &cbor_map! { "item" => "fig" })?;
/// assert_eq!(known.downcast_ref::<Order>(), Some(&Order { item: "fig".into() }));
///
/// let unknown = registry.decode("shop.Refund#v1", &cbor_map! { "amount" => 3 })?;
/// assert!(matches!(unknown, EntryValue::Unknown { .. }));
/// # Ok::<(), agentspaces::entry::EntryError>(())
/// ```
#[derive(Clone, Default)]
pub struct Registry {
    bindings: HashMap<&'static str, Binding>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Registry::default()
    }

    /// Binds `T::SCHEMA` to `T`. Registering the same type again does nothing.
    ///
    /// # Errors
    ///
    /// [`EntryError::SchemaTaken`] when another type already has the schema name.
    pub fn register<T: Entry>(&mut self) -> Result<&mut Self, EntryError> {
        let type_name = std::any::type_name::<T>();
        if let Some(existing) = self.bindings.get(T::SCHEMA) {
            if existing.type_id == TypeId::of::<T>() {
                return Ok(self);
            }
            return Err(EntryError::SchemaTaken {
                schema: T::SCHEMA.to_owned(),
                registered: existing.type_name,
                attempted: type_name,
            });
        }
        self.bindings.insert(
            T::SCHEMA,
            Binding {
                schema: T::SCHEMA,
                type_id: TypeId::of::<T>(),
                type_name,
                decode: decode_any::<T>,
                encode: encode_any::<T>,
            },
        );
        Ok(self)
    }

    /// Whether a type is registered under `schema`.
    pub fn contains(&self, schema: &str) -> bool {
        self.bindings.contains_key(schema)
    }

    /// The Rust type name registered under `schema`.
    pub fn type_name(&self, schema: &str) -> Option<&'static str> {
        self.bindings.get(schema).map(|binding| binding.type_name)
    }

    /// The registered schema names, sorted.
    pub fn schemas(&self) -> Vec<&'static str> {
        let mut schemas: Vec<_> = self.bindings.keys().copied().collect();
        schemas.sort_unstable();
        schemas
    }

    /// The number of registered schemas.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether no schema is registered.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// An entry read from its schema name and payload: [`EntryValue::Typed`] when a type is
    /// registered under `schema`, else [`EntryValue::Unknown`] holding a copy of the payload, so
    /// a reader keeps (and can show or relay) entries it has no type for.
    ///
    /// # Errors
    ///
    /// [`EntryError::Decode`] when a type is registered under `schema` and the payload does not
    /// fit it.
    pub fn decode(&self, schema: &str, value: &Value) -> Result<EntryValue, EntryError> {
        match self.bindings.get(schema) {
            Some(binding) => Ok(EntryValue::Typed(TypedEntry {
                schema: binding.schema,
                type_name: binding.type_name,
                value: (binding.decode)(value)?,
                encode: binding.encode,
            })),
            None => Ok(EntryValue::Unknown {
                schema: schema.to_owned(),
                value: value.clone(),
            }),
        }
    }
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bindings: Vec<_> = self.bindings.values().collect();
        bindings.sort_unstable_by_key(|binding| binding.schema);
        f.debug_map()
            .entries(
                bindings
                    .into_iter()
                    .map(|binding| (binding.schema, binding.type_name)),
            )
            .finish()
    }
}

/// An entry decoded into its registered Rust type, held as [`Any`].
pub struct TypedEntry {
    schema: &'static str,
    type_name: &'static str,
    value: AnyEntry,
    encode: fn(&(dyn Any + Send + Sync)) -> Result<Value, EntryError>,
}

impl TypedEntry {
    /// The schema name.
    pub fn schema(&self) -> &'static str {
        self.schema
    }

    /// The Rust type name of the value.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// Whether the value is a `T`.
    pub fn is<T: Entry>(&self) -> bool {
        self.value.is::<T>()
    }

    /// The value, when it is a `T`.
    pub fn downcast_ref<T: Entry>(&self) -> Option<&T> {
        self.value.downcast_ref::<T>()
    }

    /// The value, when it is a `T`; else this entry back.
    ///
    /// # Errors
    ///
    /// This entry, unchanged, when the value is not a `T`.
    pub fn downcast<T: Entry>(self) -> Result<T, TypedEntry> {
        match self.value.downcast::<T>() {
            Ok(value) => Ok(*value),
            Err(value) => Err(TypedEntry { value, ..self }),
        }
    }

    /// The value as a [`Value`] payload again, through its type's `Serialize`.
    ///
    /// # Errors
    ///
    /// As [`to_value`].
    pub fn to_payload(&self) -> Result<Value, EntryError> {
        (self.encode)(self.value.as_ref())
    }
}

impl fmt::Debug for TypedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedEntry")
            .field("schema", &self.schema)
            .field("type_name", &self.type_name)
            .finish_non_exhaustive()
    }
}

/// An entry as a [`Registry`] reads it: typed when its schema is registered, else the raw payload.
#[derive(Debug)]
pub enum EntryValue {
    /// A registered type.
    Typed(TypedEntry),
    /// A schema this registry has no type for: the schema name and the payload as it arrived, so
    /// tools without Rust types still read, show, and relay it.
    Unknown {
        /// The schema name.
        schema: String,
        /// The payload.
        value: Value,
    },
}

impl EntryValue {
    /// The schema name.
    pub fn schema(&self) -> &str {
        match self {
            EntryValue::Typed(entry) => entry.schema(),
            EntryValue::Unknown { schema, .. } => schema,
        }
    }

    /// Whether the entry decoded into a registered type.
    pub fn is_typed(&self) -> bool {
        matches!(self, EntryValue::Typed(_))
    }

    /// The typed value, when it is a `T`.
    pub fn downcast_ref<T: Entry>(&self) -> Option<&T> {
        match self {
            EntryValue::Typed(entry) => entry.downcast_ref(),
            EntryValue::Unknown { .. } => None,
        }
    }

    /// The typed value, when it is a `T`; else this entry back.
    ///
    /// # Errors
    ///
    /// This entry, unchanged, when it is not a `T`.
    pub fn downcast<T: Entry>(self) -> Result<T, EntryValue> {
        match self {
            EntryValue::Typed(entry) => entry.downcast().map_err(EntryValue::Typed),
            unknown @ EntryValue::Unknown { .. } => Err(unknown),
        }
    }

    /// The payload as a [`Value`]: the raw payload of an unknown entry, or a typed value
    /// encoded again.
    ///
    /// # Errors
    ///
    /// As [`to_value`], for a typed value.
    pub fn to_payload(&self) -> Result<Value, EntryError> {
        match self {
            EntryValue::Typed(entry) => entry.to_payload(),
            EntryValue::Unknown { value, .. } => Ok(value.clone()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Serializer

/// Serializes into a [`Value`].
struct ValueSerializer;

/// Serializes a nested value, putting `segment` in front of an error's path.
fn nested<T: Serialize + ?Sized>(value: &T, segment: Segment<'_>) -> Result<Value, EntryError> {
    value
        .serialize(ValueSerializer)
        .map_err(|error| error.within(segment))
}

/// A one-entry map `{variant: content}`, serde's external tagging and Jackson's
/// `WRAPPER_OBJECT`.
fn variant_map(variant: &'static str, content: Value) -> Value {
    let mut map = Map::with_capacity(1);
    map.insert(variant, content);
    Value::Map(map)
}

fn int128(n: i128) -> Result<Value, EntryError> {
    if (INT_MIN..=INT_MAX).contains(&n) {
        Ok(Value::Int(n))
    } else {
        Err(EntryError::encode(format!(
            "the integer {n} is outside the CBOR range -2^64..=2^64-1"
        )))
    }
}

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = EntryError;
    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = TupleVariantSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = StructSerializer;
    type SerializeStructVariant = StructVariantSerializer;

    fn serialize_bool(self, v: bool) -> Result<Value, EntryError> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_i16(self, v: i16) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_i32(self, v: i32) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_i64(self, v: i64) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_i128(self, v: i128) -> Result<Value, EntryError> {
        int128(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_u16(self, v: u16) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_u32(self, v: u32) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_u64(self, v: u64) -> Result<Value, EntryError> {
        Ok(Value::Int(i128::from(v)))
    }

    fn serialize_u128(self, v: u128) -> Result<Value, EntryError> {
        match i128::try_from(v) {
            Ok(n) => int128(n),
            Err(_) => Err(EntryError::encode(format!(
                "the integer {v} is outside the CBOR range -2^64..=2^64-1"
            ))),
        }
    }

    fn serialize_f32(self, v: f32) -> Result<Value, EntryError> {
        Ok(Value::Float(f64::from(v)))
    }

    fn serialize_f64(self, v: f64) -> Result<Value, EntryError> {
        Ok(Value::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<Value, EntryError> {
        Ok(Value::Text(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Value, EntryError> {
        Ok(Value::Text(v.to_owned()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value, EntryError> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Value, EntryError> {
        Ok(Value::Null)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Value, EntryError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value, EntryError> {
        Ok(Value::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, EntryError> {
        Ok(Value::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Value, EntryError> {
        Ok(Value::Text(variant.to_owned()))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, EntryError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, EntryError> {
        let content = nested(value, Segment::Variant(variant))?;
        Ok(variant_map(variant, content))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSerializer, EntryError> {
        Ok(SeqSerializer::with_capacity(len.unwrap_or(0)))
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqSerializer, EntryError> {
        Ok(SeqSerializer::with_capacity(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqSerializer, EntryError> {
        Ok(SeqSerializer::with_capacity(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<TupleVariantSerializer, EntryError> {
        Ok(TupleVariantSerializer {
            variant,
            items: SeqSerializer::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapSerializer, EntryError> {
        Ok(MapSerializer {
            // A length hint from a hostile `Serialize` must not reserve memory out of proportion.
            entries: Vec::with_capacity(len.unwrap_or(0).min(1024)),
            key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<StructSerializer, EntryError> {
        Ok(StructSerializer {
            map: Map::with_capacity(len.min(1024)),
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<StructVariantSerializer, EntryError> {
        Ok(StructVariantSerializer {
            variant,
            fields: StructSerializer {
                map: Map::with_capacity(len.min(1024)),
            },
        })
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// Builds a [`Value::Array`].
struct SeqSerializer {
    items: Vec<Value>,
}

impl SeqSerializer {
    fn with_capacity(len: usize) -> Self {
        // A length hint from a hostile `Serialize` must not reserve memory out of proportion.
        SeqSerializer {
            items: Vec::with_capacity(len.min(1024)),
        }
    }

    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        let item = nested(value, Segment::Index(self.items.len()))?;
        self.items.push(item);
        Ok(())
    }
}

impl ser::SerializeSeq for SeqSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTuple for SeqSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTupleStruct for SeqSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(Value::Array(self.items))
    }
}

/// Builds `{variant: [items]}`.
struct TupleVariantSerializer {
    variant: &'static str,
    items: SeqSerializer,
}

impl ser::SerializeTupleVariant for TupleVariantSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        self.items
            .push(value)
            .map_err(|error| error.within(Segment::Variant(self.variant)))
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(variant_map(self.variant, Value::Array(self.items.items)))
    }
}

/// Builds a map in canonical order, with text keys.
struct MapSerializer {
    entries: Vec<(Value, Value)>,
    key: Option<Value>,
}

impl ser::SerializeMap for MapSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), EntryError> {
        self.key = Some(key.serialize(MapKeySerializer)?);
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EntryError> {
        let Some(key) = self.key.take() else {
            return Err(EntryError::encode("a map value came before its key"));
        };
        let value = nested(value, Segment::Key(&key))?;
        self.entries.push((key, value));
        Ok(())
    }

    fn end(self) -> Result<Value, EntryError> {
        let mut map = build_map(self.entries)
            .map_err(|key| EntryError::encode("duplicate map key").within(Segment::Key(&key)))?;
        map.sort_canonical();
        Ok(Value::Map(map))
    }
}

/// Maps up to this many entries are built with [`Map::insert`], whose duplicate scan costs
/// linear time per key; larger ones go through the decoder.
const SMALL_MAP: usize = 64;

/// A map of `entries` in their order, or the first key that repeats.
///
/// [`Map`] has no bulk constructor, and building a large map by [`Map::insert`] costs quadratic
/// time (20 000 keys took over a second). A large map is therefore encoded and decoded: the
/// decoder builds a map in linear time and checks duplicate keys by hashing, and decoding the
/// encoding of a value gives back an equal value. The lenient decoder reads it, since these
/// bytes never leave the process and a hand-built map may hold integer or byte-string keys,
/// which the wire encoding refuses. When the decoder refuses (a duplicate key, more than
/// `MAX_FRAME_BYTES`, nesting past `MAX_CBOR_DEPTH`), the map is built entry by entry, which
/// finds the duplicate or builds what the decoder would not.
pub(crate) fn build_map(entries: Vec<(Value, Value)>) -> Result<Map, Value> {
    if entries.len() > SMALL_MAP {
        let mut bytes = vec![0xBF];
        for (key, value) in &entries {
            cbor::encode_into(key, &mut bytes);
            cbor::encode_into(value, &mut bytes);
        }
        bytes.push(0xFF);
        if let Ok(Value::Map(map)) = cbor::decode_lenient(&bytes) {
            return Ok(map);
        }
    }
    let mut map = Map::with_capacity(entries.len());
    for (key, value) in entries {
        if map.get_value(&key).is_some() {
            return Err(key);
        }
        map.insert(key, value);
    }
    Ok(map)
}

/// Builds a map in field order.
struct StructSerializer {
    map: Map,
}

impl ser::SerializeStruct for StructSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EntryError> {
        let value = nested(value, Segment::Field(key))?;
        if self.map.contains_key(key) {
            return Err(EntryError::encode("duplicate field").within(Segment::Field(key)));
        }
        self.map.insert(key, value);
        Ok(())
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(Value::Map(self.map))
    }
}

/// Builds `{variant: {fields}}`.
struct StructVariantSerializer {
    variant: &'static str,
    fields: StructSerializer,
}

impl ser::SerializeStructVariant for StructVariantSerializer {
    type Ok = Value;
    type Error = EntryError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EntryError> {
        ser::SerializeStruct::serialize_field(&mut self.fields, key, value)
            .map_err(|error| error.within(Segment::Variant(self.variant)))
    }

    fn end(self) -> Result<Value, EntryError> {
        Ok(variant_map(self.variant, Value::Map(self.fields.map)))
    }
}

/// Serializes a map key into its text, the way Jackson writes map keys.
struct MapKeySerializer;

fn key_refused(kind: &str) -> EntryError {
    EntryError::encode(format!(
        "a map key must be text, an integer, a bool, a char, or a unit variant, not {kind}"
    ))
}

fn text_key(text: impl Into<String>) -> Result<Value, EntryError> {
    Ok(Value::Text(text.into()))
}

impl ser::Serializer for MapKeySerializer {
    type Ok = Value;
    type Error = EntryError;
    type SerializeSeq = Impossible<Value, EntryError>;
    type SerializeTuple = Impossible<Value, EntryError>;
    type SerializeTupleStruct = Impossible<Value, EntryError>;
    type SerializeTupleVariant = Impossible<Value, EntryError>;
    type SerializeMap = Impossible<Value, EntryError>;
    type SerializeStruct = Impossible<Value, EntryError>;
    type SerializeStructVariant = Impossible<Value, EntryError>;

    fn serialize_bool(self, v: bool) -> Result<Value, EntryError> {
        text_key(if v { "true" } else { "false" })
    }

    fn serialize_i8(self, v: i8) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_i16(self, v: i16) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_i32(self, v: i32) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_i64(self, v: i64) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_i128(self, v: i128) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_u8(self, v: u8) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_u16(self, v: u16) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_u32(self, v: u32) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_u64(self, v: u64) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_u128(self, v: u128) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_f32(self, _v: f32) -> Result<Value, EntryError> {
        Err(key_refused(
            "a float (Java's text form of a double is not Rust's)",
        ))
    }

    fn serialize_f64(self, _v: f64) -> Result<Value, EntryError> {
        Err(key_refused(
            "a float (Java's text form of a double is not Rust's)",
        ))
    }

    fn serialize_char(self, v: char) -> Result<Value, EntryError> {
        text_key(v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<Value, EntryError> {
        text_key(v)
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Value, EntryError> {
        Err(key_refused("a byte string"))
    }

    fn serialize_none(self) -> Result<Value, EntryError> {
        Err(key_refused("an option"))
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<Value, EntryError> {
        Err(key_refused("an option"))
    }

    fn serialize_unit(self) -> Result<Value, EntryError> {
        Err(key_refused("a unit"))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, EntryError> {
        Err(key_refused("a unit struct"))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Value, EntryError> {
        text_key(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, EntryError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Value, EntryError> {
        Err(key_refused("an enum variant with data"))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, EntryError> {
        Err(key_refused("a sequence"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, EntryError> {
        Err(key_refused("a tuple"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, EntryError> {
        Err(key_refused("a tuple struct"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, EntryError> {
        Err(key_refused("an enum variant with data"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, EntryError> {
        Err(key_refused("a map"))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, EntryError> {
        Err(key_refused("a struct"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, EntryError> {
        Err(key_refused("an enum variant with data"))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------------------------
// Deserializer

/// The bounds of the `i128` range as doubles: `-2^127` is exact, and every double below `2^127`
/// converts to an `i128` without saturating.
const I128_LOW: f64 = -170_141_183_460_469_231_731_687_303_715_884_105_728.0;
const I128_HIGH: f64 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0;

/// Deserializes from a borrowed [`Value`]. In key mode (a map key) text also reads as an
/// integer, a float, or a bool, and an integer as text, because Jackson writes every map key as
/// text and other writers may not.
#[derive(Clone, Copy)]
struct ValueDeserializer<'de> {
    value: &'de Value,
    key: bool,
}

impl<'de> ValueDeserializer<'de> {
    fn new(value: &'de Value) -> Self {
        ValueDeserializer { value, key: false }
    }

    fn key(value: &'de Value) -> Self {
        ValueDeserializer { value, key: true }
    }

    fn mismatch(&self, expected: &str) -> EntryError {
        EntryError::mismatch(expected, self.value)
    }

    /// The integer the value holds, in range for `T` (named `name` in errors): an integer, a
    /// float that is a whole number, or (as a key) text.
    fn integer<T: TryFrom<i128>>(&self, name: &str) -> Result<T, EntryError> {
        let n = match self.value {
            Value::Int(n) => *n,
            Value::Float(x) => {
                let x = *x;
                if !x.is_finite() || x.trunc() != x {
                    return Err(self.mismatch(name));
                }
                if !(I128_LOW..I128_HIGH).contains(&x) {
                    return Err(EntryError::decode(format!(
                        "the float {x:?} is out of range for {name}"
                    )));
                }
                // A whole number in the i128 range, so the conversion is exact.
                x as i128
            }
            Value::Text(text) if self.key => text
                .parse::<i128>()
                .map_err(|_| self.mismatch(&format!("{name} (as a map key)")))?,
            _ => return Err(self.mismatch(name)),
        };
        T::try_from(n)
            .map_err(|_| EntryError::decode(format!("the integer {n} is out of range for {name}")))
    }

    /// The number the value holds: a float, an integer, a bignum, or a decimal (rounded to the
    /// nearest double, as Jackson reads one into a `double`), or (as a key) text.
    fn float(&self, name: &str) -> Result<f64, EntryError> {
        match self.value {
            Value::Float(x) => Ok(*x),
            // Rounds to the nearest double, the documented intent.
            Value::Int(n) => Ok(*n as f64),
            Value::BigInt(_) | Value::Decimal(_) => {
                nearest_f64(self.value).ok_or_else(|| self.mismatch(name))
            }
            Value::Text(text) if self.key => text
                .parse::<f64>()
                .map_err(|_| self.mismatch(&format!("{name} (as a map key)"))),
            _ => Err(self.mismatch(name)),
        }
    }
}

/// The double nearest a bignum or a decimal (infinite past the double range), as Java's
/// `doubleValue` gives it: parsed from its decimal text, which Rust rounds correctly.
fn nearest_f64(value: &Value) -> Option<f64> {
    match value {
        Value::BigInt(big) => big.to_string().parse().ok(),
        Value::Decimal(decimal) => decimal.to_string().parse().ok(),
        _ => None,
    }
}

macro_rules! deserialize_integer {
    ($($method:ident => $visit:ident: $t:ty),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
            let n: $t = self.integer(stringify!($t))?;
            visitor.$visit(n)
        }
    )*};
}

impl<'de> de::Deserializer<'de> for ValueDeserializer<'de> {
    type Error = EntryError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::Int(n) => {
                if let Ok(n) = u64::try_from(*n) {
                    visitor.visit_u64(n)
                } else if let Ok(n) = i64::try_from(*n) {
                    visitor.visit_i64(n)
                } else {
                    visitor.visit_i128(*n)
                }
            }
            Value::BigInt(_) | Value::Decimal(_) => match nearest_f64(self.value) {
                Some(x) => visitor.visit_f64(x),
                None => Err(self.mismatch("a number")),
            },
            Value::Float(x) => visitor.visit_f64(*x),
            Value::Bytes(bytes) => visitor.visit_borrowed_bytes(bytes),
            Value::Text(text) => visitor.visit_borrowed_str(text),
            Value::Array(items) => visit_array(items, visitor),
            Value::Map(map) => visitor.visit_map(MapDeserializer::new(map)),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::Text(text) if self.key && text == "true" => visitor.visit_bool(true),
            Value::Text(text) if self.key && text == "false" => visitor.visit_bool(false),
            _ => Err(self.mismatch("a bool")),
        }
    }

    deserialize_integer! {
        deserialize_i8 => visit_i8: i8,
        deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32,
        deserialize_i64 => visit_i64: i64,
        deserialize_i128 => visit_i128: i128,
        deserialize_u8 => visit_u8: u8,
        deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32,
        deserialize_u64 => visit_u64: u64,
        deserialize_u128 => visit_u128: u128,
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        // A double narrowed to the nearest f32; an f32 written by `to_value` comes back exactly.
        visitor.visit_f32(self.float("f32")? as f32)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        visitor.visit_f64(self.float("f64")?)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        if let Value::Text(text) = self.value {
            let mut chars = text.chars();
            if let (Some(c), None) = (chars.next(), chars.next()) {
                return visitor.visit_char(c);
            }
        }
        Err(self.mismatch("a single character"))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Text(text) => visitor.visit_borrowed_str(text),
            Value::Int(n) if self.key => visitor.visit_string(n.to_string()),
            _ => Err(self.mismatch("text")),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Bytes(bytes) => visitor.visit_borrowed_bytes(bytes),
            Value::Array(items) => visit_array(items, visitor),
            _ => Err(self.mismatch("bytes")),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Null => visitor.visit_unit(),
            _ => Err(self.mismatch("null")),
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Null => visitor.visit_unit(),
            Value::Map(map) if map.is_empty() => visitor.visit_unit(),
            _ => Err(self.mismatch("null or an empty map")),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Array(items) => visit_array(items, visitor),
            Value::Bytes(bytes) => visitor.visit_seq(ByteSeq {
                bytes: bytes.iter(),
            }),
            _ => Err(self.mismatch("an array")),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Map(map) => visitor.visit_map(MapDeserializer::new(map)),
            _ => Err(self.mismatch("a map")),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Text(variant) => visitor.visit_enum(EnumDeserializer {
                variant,
                content: None,
            }),
            Value::Map(map) if map.len() == 1 => match map.as_slice() {
                [(Value::Text(variant), content)] => visitor.visit_enum(EnumDeserializer {
                    variant,
                    content: Some(content),
                }),
                _ => Err(self.mismatch("a variant name or a one-entry map keyed by one")),
            },
            _ => Err(self.mismatch("a variant name or a one-entry map keyed by one")),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        match self.value {
            Value::Text(text) => visitor.visit_borrowed_str(text),
            Value::Int(n) => match u64::try_from(*n) {
                Ok(n) => visitor.visit_u64(n),
                Err(_) => Err(self.mismatch("a field or variant name")),
            },
            _ => Err(self.mismatch("a field or variant name")),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EntryError> {
        // Nothing to skip in a value already in memory.
        visitor.visit_unit()
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// Visits an array, refusing one with items the visitor left unread (a tuple of the wrong
/// length).
fn visit_array<'de, V: Visitor<'de>>(
    items: &'de [Value],
    visitor: V,
) -> Result<V::Value, EntryError> {
    let mut seq = SeqDeserializer {
        items: items.iter(),
        index: 0,
    };
    let value = visitor.visit_seq(&mut seq)?;
    if !seq.items.as_slice().is_empty() {
        return Err(EntryError::decode(format!(
            "expected an array of {} items, found {}",
            seq.index,
            items.len()
        )));
    }
    Ok(value)
}

/// The elements of an array.
struct SeqDeserializer<'de> {
    items: std::slice::Iter<'de, Value>,
    index: usize,
}

impl<'de> de::SeqAccess<'de> for SeqDeserializer<'de> {
    type Error = EntryError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, EntryError> {
        let Some(item) = self.items.next() else {
            return Ok(None);
        };
        let index = self.index;
        self.index += 1;
        seed.deserialize(ValueDeserializer::new(item))
            .map(Some)
            .map_err(|error| error.within(Segment::Index(index)))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

/// The bytes of a byte string as a sequence of `u8`, for a plain `Vec<u8>` field.
struct ByteSeq<'de> {
    bytes: std::slice::Iter<'de, u8>,
}

impl<'de> de::SeqAccess<'de> for ByteSeq<'de> {
    type Error = EntryError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, EntryError> {
        match self.bytes.next() {
            Some(byte) => {
                let byte: U8Deserializer<EntryError> = byte.into_deserializer();
                seed.deserialize(byte).map(Some)
            }
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.bytes.len())
    }
}

/// The entries of a map; keys deserialize in key mode.
struct MapDeserializer<'de> {
    entries: std::slice::Iter<'de, (Value, Value)>,
    pending: Option<&'de (Value, Value)>,
}

impl<'de> MapDeserializer<'de> {
    fn new(map: &'de Map) -> Self {
        MapDeserializer {
            entries: map.as_slice().iter(),
            pending: None,
        }
    }
}

impl<'de> de::MapAccess<'de> for MapDeserializer<'de> {
    type Error = EntryError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, EntryError> {
        let Some(entry) = self.entries.next() else {
            return Ok(None);
        };
        self.pending = Some(entry);
        seed.deserialize(ValueDeserializer::key(&entry.0))
            .map(Some)
            .map_err(|error| error.within(Segment::Key(&entry.0)))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, EntryError> {
        let Some((key, value)) = self.pending.take() else {
            return Err(EntryError::decode(
                "a map value was asked for before its key",
            ));
        };
        seed.deserialize(ValueDeserializer::new(value))
            .map_err(|error| error.within(Segment::Key(key)))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

/// An enum: a variant name and, for a variant with data, its content.
struct EnumDeserializer<'de> {
    variant: &'de str,
    content: Option<&'de Value>,
}

impl<'de> de::EnumAccess<'de> for EnumDeserializer<'de> {
    type Error = EntryError;
    type Variant = VariantDeserializer<'de>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, VariantDeserializer<'de>), EntryError> {
        let name: BorrowedStrDeserializer<'de, EntryError> =
            BorrowedStrDeserializer::new(self.variant);
        let variant = seed.deserialize(name)?;
        Ok((
            variant,
            VariantDeserializer {
                variant: self.variant,
                content: self.content,
            },
        ))
    }
}

/// The content of one enum variant.
struct VariantDeserializer<'de> {
    variant: &'de str,
    content: Option<&'de Value>,
}

impl<'de> VariantDeserializer<'de> {
    fn content(&self, expected: &str) -> Result<&'de Value, EntryError> {
        self.content.ok_or_else(|| {
            EntryError::decode(format!(
                "the variant {:?} carries {expected}, found only its name",
                self.variant
            ))
        })
    }
}

impl<'de> de::VariantAccess<'de> for VariantDeserializer<'de> {
    type Error = EntryError;

    fn unit_variant(self) -> Result<(), EntryError> {
        match self.content {
            None | Some(Value::Null) => Ok(()),
            Some(content) => Err(EntryError::mismatch("null (a unit variant)", content)
                .within(Segment::Variant(self.variant))),
        }
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, EntryError> {
        let content = self.content("a value")?;
        seed.deserialize(ValueDeserializer::new(content))
            .map_err(|error| error.within(Segment::Variant(self.variant)))
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        let content = self.content("an array")?;
        de::Deserializer::deserialize_seq(ValueDeserializer::new(content), visitor)
            .map_err(|error| error.within(Segment::Variant(self.variant)))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EntryError> {
        let content = self.content("a map")?;
        de::Deserializer::deserialize_map(ValueDeserializer::new(content), visitor)
            .map_err(|error| error.within(Segment::Variant(self.variant)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces_wire::cbor::{self, canonical_map};
    use agentspaces_wire::{cbor_array, cbor_map};

    /// A `u64` past Java's `long` is written as the bignum Java writes for a `BigInteger`, and a
    /// Java `BigDecimal` or a bignum past 64 bits reads into a float field as the nearest double,
    /// and as a number where any value is wanted.
    #[test]
    fn big_numbers_cross_as_java_writes_and_reads_them() {
        assert_eq!(
            hex::encode(cbor::encode(&to_value(&u64::MAX).unwrap())),
            "c24900ffffffffffffffff"
        );
        assert_eq!(
            from_value::<u64>(&to_value(&u64::MAX).unwrap()).unwrap(),
            u64::MAX
        );

        #[derive(Debug, PartialEq, serde::Deserialize)]
        struct Price {
            item: String,
            amount: f64,
            serial: f64,
        }
        // Price("x", 1.25, 2^72) as Java writes it.
        let java = hex::decode(concat!(
            "bf646974656d6178",
            "66616d6f756e74c48221187d",
            "6673657269616cc24a01000000000000000000",
            "ff"
        ))
        .unwrap();
        let decoded = cbor::decode(&java).unwrap();
        assert_eq!(
            decoded
                .get("serial")
                .and_then(Value::as_big_int)
                .map(ToString::to_string),
            Some("4722366482869645213696".to_owned())
        );
        let price: Price = from_value(&decoded).unwrap();
        assert_eq!(
            price,
            Price {
                item: "x".into(),
                amount: 1.25,
                serial: 4_722_366_482_869_645_213_696.0,
            }
        );
        let any: serde_json::Value = from_value(&decoded).unwrap();
        assert_eq!(any["amount"], serde_json::json!(1.25));
        assert!(from_value::<u64>(decoded.get("serial").unwrap()).is_err());
    }
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, HashMap};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Line {
        sku: String,
        quantity: i32,
        price: f64,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    enum Kind {
        Standard,
        Express,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Shape {
        Point,
        Circle(f64),
        Pair(i32, i32),
        Rect { w: u32, h: u32 },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Order {
        order_id: String,
        kind: Kind,
        lines: Vec<Line>,
        note: Option<String>,
    }

    impl Entry for Order {
        const SCHEMA: &'static str = "shop.Order#v1";
    }

    fn order() -> Order {
        Order {
            order_id: "o-1".into(),
            kind: Kind::Express,
            lines: vec![Line {
                sku: "fig".into(),
                quantity: 2,
                price: 0.5,
            }],
            note: None,
        }
    }

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_map()
            .map(|map| map.keys().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    fn decode_error<T: DeserializeOwned + fmt::Debug>(value: &Value) -> (String, String) {
        match from_value::<T>(value) {
            Err(EntryError::Decode { path, message }) => (path, message),
            other => panic!("expected a decode error, got {other:?}"),
        }
    }

    #[test]
    fn struct_fields_keep_declared_order() {
        #[derive(Serialize)]
        struct Backwards {
            zeta: i32,
            alpha: i32,
            mid: i32,
        }
        let value = to_value(&Backwards {
            zeta: 1,
            alpha: 2,
            mid: 3,
        })
        .unwrap();
        assert_eq!(keys(&value), ["zeta", "alpha", "mid"]);
    }

    #[test]
    fn serde_maps_are_written_in_canonical_order() {
        let mut counts = HashMap::new();
        for (key, n) in [
            ("pear", 2),
            ("fig", 1),
            ("banana", 5),
            ("apple", 3),
            ("é", 9),
        ] {
            counts.insert(key.to_owned(), n);
        }
        let value = to_value(&counts).unwrap();
        // Shorter UTF-8 first: "é" is two bytes.
        assert_eq!(keys(&value), ["é", "fig", "pear", "apple", "banana"]);
        let map = value.as_map().unwrap();
        assert_eq!(map, &canonical_map(map));
        // A BTreeMap (sorted by Rust's string order) comes out in the same canonical order.
        let sorted: BTreeMap<String, i32> = counts.into_iter().collect();
        assert_eq!(to_value(&sorted).unwrap(), value);
    }

    #[test]
    fn integer_keys_are_written_as_text_in_text_order() {
        let by_number: BTreeMap<i32, &str> = [
            (10, "ten"),
            (9, "nine"),
            (100, "hundred"),
            (-1, "minus one"),
        ]
        .into();
        let value = to_value(&by_number).unwrap();
        assert_eq!(keys(&value), ["9", "-1", "10", "100"]);
        let back: BTreeMap<i32, String> = from_value(&value).unwrap();
        assert_eq!(back.get(&-1).map(String::as_str), Some("minus one"));
        // Integer keys another writer put on the wire read too.
        let raw = cbor_map! { 7 => "seven" };
        let back: HashMap<i64, String> = from_value(&raw).unwrap();
        assert_eq!(back.get(&7).map(String::as_str), Some("seven"));
        let back: HashMap<String, String> = from_value(&raw).unwrap();
        assert_eq!(back.get("7").map(String::as_str), Some("seven"));
    }

    #[test]
    fn other_key_kinds() {
        let flags: BTreeMap<bool, char> = [(true, 'y'), (false, 'n')].into();
        let value = to_value(&flags).unwrap();
        assert_eq!(value, cbor_map! { "true" => "y", "false" => "n" });
        assert_eq!(from_value::<BTreeMap<bool, char>>(&value).unwrap(), flags);

        let kinds: BTreeMap<Kind, u8> = BTreeMap::new();
        assert_eq!(to_value(&kinds).unwrap(), cbor_map! {});
        #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
        enum Color {
            Red,
            Blue,
        }
        let colors: BTreeMap<Color, u8> = [(Color::Red, 1), (Color::Blue, 2)].into();
        let value = to_value(&colors).unwrap();
        assert_eq!(value, cbor_map! { "Red" => 1, "Blue" => 2 });
        assert_eq!(from_value::<BTreeMap<Color, u8>>(&value).unwrap(), colors);
    }

    #[test]
    fn unsupported_keys_are_refused_with_the_path() {
        #[derive(Serialize)]
        struct Weights {
            groups: HashMap<String, BTreeMap<Vec<u8>, u8>>,
        }
        let inner: BTreeMap<Vec<u8>, u8> = [(vec![1], 1)].into();
        let weights = Weights {
            groups: [("a b".to_owned(), inner)].into(),
        };
        match to_value(&weights) {
            Err(EntryError::Encode { path, message }) => {
                assert_eq!(path, "$.groups[\"a b\"]");
                assert!(message.ends_with("not a sequence"), "{message}");
            }
            other => panic!("expected an encode error, got {other:?}"),
        }

        struct FloatKeyed;
        impl Serialize for FloatKeyed {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use ser::SerializeMap as _;
                let mut map = s.serialize_map(Some(1))?;
                map.serialize_entry(&1.5f64, &1)?;
                map.end()
            }
        }
        let error = to_value(&FloatKeyed).unwrap_err();
        assert!(error.to_string().contains("not a float"), "{error}");
    }

    #[test]
    fn large_maps_build_in_linear_time_with_the_same_rules() {
        let big: HashMap<String, u32> = (0..500).map(|i| (format!("k{i}"), i)).collect();
        let value = to_value(&big).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 500);
        assert_eq!(map, &canonical_map(map));
        assert_eq!(from_value::<HashMap<String, u32>>(&value).unwrap(), big);

        // Through the decoder or entry by entry, the same map.
        let entries: Vec<(Value, Value)> = (0..200)
            .map(|i| {
                let value = cbor_map! { "n" => i, "f" => 0.5, "b" => vec![1u8], "z" => f64::NAN };
                (Value::from(format!("k{i}")), value)
            })
            .collect();
        let mut slow = Map::new();
        for (key, value) in entries.clone() {
            slow.insert(key, value);
        }
        assert_eq!(build_map(entries).unwrap(), slow);

        // Nesting the decoder refuses still builds, entry by entry.
        let mut deep = Value::Null;
        for _ in 0..70 {
            deep = Value::Array(vec![deep]);
        }
        let mut entries: Vec<(Value, Value)> = (0..100)
            .map(|i| (Value::from(format!("k{i}")), Value::from(i)))
            .collect();
        entries.push(("deep".into(), deep.clone()));
        assert_eq!(build_map(entries).unwrap().get("deep"), Some(&deep));

        struct Repeats;
        impl Serialize for Repeats {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use ser::SerializeMap as _;
                let mut map = s.serialize_map(None)?;
                for i in 0..100 {
                    map.serialize_entry(&format!("k{i}"), &i)?;
                }
                map.serialize_entry("k42", &0)?;
                map.end()
            }
        }
        assert_eq!(
            to_value(&Repeats),
            Err(EntryError::Encode {
                path: "$.k42".into(),
                message: "duplicate map key".into()
            })
        );
    }

    #[test]
    fn duplicate_keys_are_refused() {
        struct Twice;
        impl Serialize for Twice {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use ser::SerializeMap as _;
                let mut map = s.serialize_map(None)?;
                map.serialize_entry("a", &1)?;
                map.serialize_entry(&'a', &2)?;
                map.end()
            }
        }
        assert_eq!(
            to_value(&Twice),
            Err(EntryError::Encode {
                path: "$.a".into(),
                message: "duplicate map key".into()
            })
        );
    }

    #[test]
    fn widths_follow_the_wire() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Widths {
            a: i8,
            b: u8,
            c: i16,
            d: u16,
            e: i32,
            f: u32,
            g: i64,
            h: u64,
            i: i128,
            j: u128,
            k: f32,
            l: f64,
            m: bool,
            n: char,
        }
        let widths = Widths {
            a: -128,
            b: 255,
            c: -32768,
            d: 65535,
            e: i32::MIN,
            f: u32::MAX,
            g: i64::MIN,
            h: u64::MAX,
            i: -(1i128 << 64),
            j: u128::from(u64::MAX),
            k: 0.1,
            l: 2.0,
            m: true,
            n: 'é',
        };
        let value = to_value(&widths).unwrap();
        assert_eq!(
            value,
            cbor_map! {
                "a" => -128, "b" => 255, "c" => -32768, "d" => 65535,
                "e" => i32::MIN, "f" => u32::MAX, "g" => i64::MIN, "h" => u64::MAX,
                "i" => Value::Int(INT_MIN), "j" => u64::MAX,
                "k" => f64::from(0.1f32), "l" => 2.0, "m" => true, "n" => "é",
            }
        );
        // A whole double is still a double: `l` encodes as 0xFB.
        let bytes = cbor::encode(value.get("l").unwrap());
        assert_eq!(bytes, [0xfb, 0x40, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(from_value::<Widths>(&value).unwrap(), widths);
    }

    #[test]
    fn integers_outside_cbor_are_refused() {
        assert!(matches!(
            to_value(&(INT_MIN - 1)),
            Err(EntryError::Encode { .. })
        ));
        assert!(matches!(
            to_value(&(u128::from(u64::MAX) + 1)),
            Err(EntryError::Encode { .. })
        ));
        assert_eq!(to_value(&INT_MAX).unwrap(), Value::Int(INT_MAX));
    }

    #[test]
    fn numbers_widen_and_narrow_by_the_rules() {
        // An integer reads into a float field.
        assert_eq!(from_value::<f64>(&Value::Int(3)).unwrap(), 3.0);
        assert_eq!(from_value::<f32>(&Value::Int(-2)).unwrap(), -2.0);
        // A whole float reads into an integer field, in range.
        assert_eq!(from_value::<i32>(&Value::Float(3.0)).unwrap(), 3);
        assert_eq!(from_value::<u8>(&Value::Float(255.0)).unwrap(), 255);
        let (path, message) = decode_error::<u8>(&Value::Float(256.0));
        assert_eq!(path, "$");
        assert!(message.contains("out of range for u8"), "{message}");
        let (_, message) = decode_error::<i32>(&Value::Float(2.5));
        assert_eq!(message, "expected i32, found the float 2.5");
        let (_, message) = decode_error::<i64>(&Value::Float(f64::NAN));
        assert!(message.starts_with("expected i64"), "{message}");
        let (_, message) = decode_error::<i64>(&Value::Float(1e300));
        assert!(message.contains("out of range"), "{message}");
        let (_, message) = decode_error::<u32>(&Value::Int(-1));
        assert_eq!(message, "the integer -1 is out of range for u32");
        let (_, message) = decode_error::<i32>(&Value::Text("3".into()));
        assert_eq!(message, "expected i32, found the text \"3\"");
    }

    #[test]
    fn enums_options_and_units() {
        let shapes = vec![
            Shape::Point,
            Shape::Circle(1.5),
            Shape::Pair(1, -2),
            Shape::Rect { w: 3, h: 4 },
        ];
        let value = to_value(&shapes).unwrap();
        assert_eq!(
            value,
            cbor_array![
                "Point",
                cbor_map! { "Circle" => 1.5 },
                cbor_map! { "Pair" => cbor_array![1, -2] },
                cbor_map! { "Rect" => cbor_map! { "w" => 3, "h" => 4 } },
            ]
        );
        assert_eq!(from_value::<Vec<Shape>>(&value).unwrap(), shapes);
        // A unit variant also reads from a one-entry map with null content.
        assert_eq!(
            from_value::<Shape>(&cbor_map! { "Point" => Value::Null }).unwrap(),
            Shape::Point
        );
        let (path, message) =
            decode_error::<Shape>(&cbor_map! { "Rect" => cbor_map! { "w" => 1, "h" => "x" } });
        assert_eq!(path, "$.Rect.h");
        assert_eq!(message, "expected u32, found the text \"x\"");
        let (_, message) = decode_error::<Shape>(&Value::Text("Hexagon".into()));
        assert!(message.contains("unknown variant `Hexagon`"), "{message}");
        let (_, message) = decode_error::<Shape>(&Value::Text("Circle".into()));
        assert!(message.contains("carries a value"), "{message}");

        assert_eq!(to_value(&None::<i32>).unwrap(), Value::Null);
        assert_eq!(to_value(&Some(4)).unwrap(), Value::Int(4));
        assert_eq!(to_value(&()).unwrap(), Value::Null);
        assert_eq!(from_value::<Option<i32>>(&Value::Null).unwrap(), None);
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Unit;
        assert_eq!(to_value(&Unit).unwrap(), Value::Null);
        assert_eq!(from_value::<Unit>(&cbor_map! {}).unwrap(), Unit);
    }

    #[test]
    fn unknown_keys_are_ignored_and_missing_options_are_none() {
        let value = cbor_map! {
            "orderId" => "o-1",
            "addedLater" => cbor_map! { "deep" => cbor_array![1, 2] },
            "kind" => "EXPRESS",
            "lines" => cbor_array![cbor_map! { "sku" => "fig", "quantity" => 2, "price" => 0.5, "extra" => true }],
        };
        assert_eq!(from_value::<Order>(&value).unwrap(), order());
    }

    #[test]
    fn mismatches_name_the_field_path() {
        let value = cbor_map! {
            "orderId" => "o-1",
            "kind" => "EXPRESS",
            "lines" => cbor_array![
                cbor_map! { "sku" => "fig", "quantity" => 2, "price" => 0.5 },
                cbor_map! { "sku" => "pear", "quantity" => "two", "price" => 0.5 },
            ],
            "note" => Value::Null,
        };
        let error = from_value::<Order>(&value).unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot decode $.lines[1].quantity: expected i32, found the text \"two\""
        );
        let (path, message) = decode_error::<Order>(&cbor_map! { "kind" => "EXPRESS" });
        assert_eq!(path, "$");
        assert_eq!(message, "missing field `orderId`");
        let (path, message) = decode_error::<Order>(
            &cbor_map! { "orderId" => "o", "kind" => "RUSH", "lines" => cbor_array![] },
        );
        assert_eq!(path, "$.kind");
        assert!(message.contains("unknown variant `RUSH`"), "{message}");
        let (path, message) = decode_error::<Order>(&Value::Text("o-1".into()));
        assert_eq!(
            (path.as_str(), message.as_str()),
            ("$", "expected a map, found the text \"o-1\"")
        );
        let (path, _) = decode_error::<HashMap<String, i32>>(&cbor_map! { "a b" => "x" });
        assert_eq!(path, "$[\"a b\"]");
        let (path, _) = decode_error::<HashMap<i32, i32>>(&cbor_map! { "x" => 1 });
        assert_eq!(path, "$.x");
        let (path, message) = decode_error::<(i32, i32)>(&cbor_array![1, 2, 3]);
        assert_eq!(
            (path.as_str(), message.as_str()),
            ("$", "expected an array of 2 items, found 3")
        );
        let (path, message) = decode_error::<Line>(
            &cbor_map! { "sku" => Value::Null, "quantity" => 1, "price" => 1 },
        );
        assert_eq!(
            (path.as_str(), message.as_str()),
            ("$.sku", "expected text, found null")
        );
    }

    #[test]
    fn bytes_need_serde_bytes_to_be_bytes() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Blob {
            #[serde(with = "serde_bytes")]
            digest: Vec<u8>,
            plain: Vec<u8>,
            buf: serde_bytes::ByteBuf,
        }
        let blob = Blob {
            digest: vec![0, 1, 0xff],
            plain: vec![7],
            buf: serde_bytes::ByteBuf::from(vec![9]),
        };
        let value = to_value(&blob).unwrap();
        assert_eq!(
            value,
            cbor_map! { "digest" => vec![0u8, 1, 0xff], "plain" => cbor_array![7], "buf" => vec![9u8] }
        );
        assert_eq!(from_value::<Blob>(&value).unwrap(), blob);
        // Java's byte[] reads into a plain Vec<u8>, and an array of small integers into bytes.
        let java = cbor_map! { "digest" => cbor_array![0, 1, 255], "plain" => vec![7u8], "buf" => vec![9u8] };
        assert_eq!(from_value::<Blob>(&java).unwrap(), blob);
        let (path, message) = decode_error::<Blob>(
            &cbor_map! { "digest" => "AAH/", "plain" => vec![7u8], "buf" => vec![9u8] },
        );
        assert_eq!(
            (path.as_str(), message.as_str()),
            ("$.digest", "expected bytes, found the text \"AAH/\"")
        );
    }

    #[test]
    fn round_trips_through_bytes() {
        let value = to_value(&order()).unwrap();
        assert_eq!(keys(&value), ["orderId", "kind", "lines", "note"]);
        let bytes = cbor::encode(&value);
        let decoded = cbor::decode(&bytes).unwrap();
        assert_eq!(from_value::<Order>(&decoded).unwrap(), order());
        assert_eq!(order().to_payload().unwrap(), value);
        assert_eq!(Order::from_payload(&value).unwrap(), order());
    }

    #[test]
    fn untagged_and_internally_tagged_enums_read() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "type")]
        enum Event {
            Started { at: i64 },
            Stopped { at: i64, reason: String },
        }
        let event = Event::Stopped {
            at: 5,
            reason: "done".into(),
        };
        let value = to_value(&event).unwrap();
        assert_eq!(
            value,
            cbor_map! { "type" => "Stopped", "at" => 5, "reason" => "done" }
        );
        assert_eq!(from_value::<Event>(&value).unwrap(), event);

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(untagged)]
        enum Loose {
            Number(i64),
            Words(Vec<String>),
        }
        assert_eq!(
            from_value::<Loose>(&Value::Int(4)).unwrap(),
            Loose::Number(4)
        );
        assert_eq!(
            from_value::<Loose>(&cbor_array!["a"]).unwrap(),
            Loose::Words(vec!["a".into()])
        );
    }

    #[test]
    fn registry_types_known_schemas_and_keeps_unknown_ones() {
        let mut registry = Registry::new();
        registry
            .register::<Order>()
            .unwrap()
            .register::<Order>()
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.contains("shop.Order#v1"));
        assert_eq!(registry.schemas(), ["shop.Order#v1"]);
        assert!(
            registry
                .type_name("shop.Order#v1")
                .unwrap()
                .ends_with("Order")
        );

        let payload = to_value(&order()).unwrap();
        let typed = registry.decode(Order::SCHEMA, &payload).unwrap();
        assert!(typed.is_typed());
        assert_eq!(typed.schema(), "shop.Order#v1");
        assert_eq!(typed.downcast_ref::<Order>(), Some(&order()));
        assert_eq!(typed.to_payload().unwrap(), payload);
        assert_eq!(typed.downcast::<Order>().unwrap(), order());

        let unknown = registry.decode("shop.Refund#v1", &payload).unwrap();
        assert!(!unknown.is_typed());
        assert_eq!(unknown.downcast_ref::<Order>(), None);
        match unknown {
            EntryValue::Unknown { schema, value } => {
                assert_eq!(schema, "shop.Refund#v1");
                assert_eq!(value, payload);
            }
            EntryValue::Typed(_) => panic!("not registered"),
        }

        let error = registry.decode(Order::SCHEMA, &cbor_map! {}).unwrap_err();
        assert!(matches!(error, EntryError::Decode { .. }));

        #[derive(Debug, Serialize, Deserialize)]
        struct Impostor;
        impl Entry for Impostor {
            const SCHEMA: &'static str = "shop.Order#v1";
        }
        match registry.register::<Impostor>() {
            Err(EntryError::SchemaTaken { schema, .. }) => assert_eq!(schema, "shop.Order#v1"),
            other => panic!("expected SchemaTaken, got {other:?}"),
        }
        // A downcast to another type hands the entry back intact.
        let typed = registry.decode(Order::SCHEMA, &payload).unwrap();
        let typed = typed.downcast::<Impostor>().unwrap_err();
        assert_eq!(typed.schema(), Order::SCHEMA);
        assert_eq!(typed.downcast::<Order>().unwrap(), order());
        assert!(format!("{registry:?}").contains("shop.Order#v1"));
    }

    #[test]
    fn decode_entry_checks_the_schema() {
        let payload = to_value(&order()).unwrap();
        assert_eq!(
            decode_entry::<Order>("shop.Order#v1", &payload).unwrap(),
            order()
        );
        assert_eq!(
            decode_entry::<Order>("shop.Refund#v1", &payload).unwrap_err(),
            EntryError::WrongSchema {
                expected: "shop.Order#v1",
                found: "shop.Refund#v1".into()
            }
        );
    }

    #[test]
    fn paths_quote_names_that_are_not_plain() {
        assert_eq!(Segment::Field("orderId").to_string(), ".orderId");
        assert_eq!(Segment::Field("a b").to_string(), "[\"a b\"]");
        assert_eq!(Segment::Field("9lives").to_string(), "[\"9lives\"]");
        assert_eq!(Segment::Index(3).to_string(), "[3]");
        assert_eq!(Segment::Key(&Value::Int(4)).to_string(), "[4]");
        assert_eq!(Segment::Key(&Value::Bytes(vec![1])).to_string(), "[h'01']");
    }
}
