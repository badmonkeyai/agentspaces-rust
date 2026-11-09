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

//! CBOR (RFC 8949) encoded byte for byte as the Java codec's Jackson CBOR encodes it, a port of
//! `agentspaces-python/agentspaces/cbor.py`. Signatures and hashes cover the encoded bytes, so
//! matching Jackson exactly is the point; the golden vectors in `tests/golden.json` prove it.
//! The rules are Java's wire encoding, `WellFormedCbor` rules S1 to S12: one encoding per value,
//! which every implementation writes.
//!
//! # Encoding rules ([`encode`])
//!
//! - Maps are indefinite-length (`0xBF` ... `0xFF`) with entries in insertion order: a [`Map`]
//!   stands for a Java record (declared component order) as often as for a `java.util.Map`, so the
//!   encoder never sorts. A map-valued field a signature covers (tags, costHints, parameters, ...)
//!   is put in RFC 8949 order with [`canonical_map`] where it is built (wire v3).
//! - Arrays are definite-length with a minimal head (wire v2).
//! - Byte strings are definite with minimal heads.
//! - A text of at most [`TEXT_CHUNK_UNITS`] (3996) UTF-16 code units is definite with a minimal
//!   head. A longer text is written as Jackson writes it (Java `WellFormedCbor` rule S6): an
//!   indefinite-length text (`0x7F`), definite text chunks with minimal heads, and a break
//!   (`0xFF`). While more than 3996 units remain the next chunk takes 3996 units, or 3995 when
//!   its last unit would be a high surrogate (a chunk never splits a surrogate pair, so never a
//!   UTF-8 sequence), and the rest, never empty, forms the last chunk. Units are counted in
//!   UTF-16, as Java's `String.length()` counts them: a character outside the Basic Multilingual
//!   Plane is two. Map keys follow the same rule, since Jackson writes a `java.util.Map` key the
//!   way it writes a text value. `tests/jackson-text-vectors.json`, written by real Jackson
//!   (`interop/jackson-vectors`), proves the boundaries in every context.
//! - An integer inside Java's `long` range uses the minimal width; negatives are major type 1
//!   (rule S4). One outside it, a [`Value::Int`] past 64 bits signed or a [`Value::BigInt`], is
//!   a bignum as Jackson writes a `BigInteger` (rule S9): tag 2 for a positive value and tag 3
//!   for a negative one, over the magnitude in `BigInteger.toByteArray()` form (see [`BigInt`];
//!   Jackson's tag 3 holds the magnitude itself, not RFC 8949's one less).
//! - A [`Value::Decimal`] is tag 4 over `[exponent, mantissa]`, normalized (rule S9, see
//!   [`Decimal`]).
//! - `false`, `true`, `null` are `0xF4`, `0xF5`, `0xF6`.
//! - Every float is a 64-bit double (`0xFB`, big-endian), whatever its value, and every NaN is
//!   the one NaN Java's `Double.NaN` writes, `7FF8000000000000` (rule S10).
//! - `tests/jackson-wire-vectors.json`, written by real Jackson (`interop/jackson-vectors`),
//!   proves the numbers both ways, and the verdict of every rule below against Java's.
//!
//! # Decoding rules ([`decode`], [`decode_lenient`])
//!
//! [`decode`] reads a document from the network: exactly one item in the wire encoding, rules S1
//! to S12 as Java's `WellFormedCbor.checkCanonical` applies them before every network read
//! (`CborCodec.fromWire`, `fromDocument`), so this peer accepts exactly the
//! documents Java, Python, TypeScript, and Ruby accept, and a signature it checks over a
//! re-encoding covers the bytes that arrived:
//!
//! - one item and no trailing byte (S1); at most [`MAX_CBOR_DEPTH`] nested containers,
//!   the two-element array of a decimal counted as one, as Jackson counts it (S2);
//! - every head in its shortest form (S3), a float's excepted;
//! - a plain integer inside Java's `long` (S4), and a bignum only outside it, its magnitude in
//!   minimal form (S9);
//! - definite byte strings (S5) and arrays (S7); indefinite maps whose keys are distinct text
//!   strings (S8);
//! - a text definite up to [`TEXT_CHUNK_UNITS`] units and past that in exactly Jackson's chunks
//!   (S6): a chunked text of 3996 units or fewer (so a chunked stamp, as SPEC §9 rules), a
//!   definite text past them, other chunk boundaries, and an empty chunk are each refused;
//! - tags 2 and 3 over a definite byte string and tag 4 over `[exponent, mantissa]` in their one
//!   form, never as a map key, and no other tag (S9); a bignum of more than
//!   [`MAX_BIGNUM_BYTES`] bytes, which Jackson's number-length constraint refuses, is refused;
//! - float32 and float64 with only Java's NaN of each width, no half float (S10); `false`,
//!   `true`, and `null` as the only simple values (S11); a break only where it ends an
//!   indefinite map or text (S12).
//!
//! [`decode_lenient`] reads what this crate or an older peer wrote before the wire encoding
//! (Java `CborCodec.fromBytes`): heads of any width, definite or indefinite arrays and maps,
//! text, integer, and byte-string keys, plain integers to ±2^64, any text chunking and definite
//! texts of any length, half floats, any NaN, and `undefined` (as [`Value::Null`]). Its tags are
//! those of [`decode`], in the same forms.
//!
//! Both refuse, never panicking: input longer than [`MAX_FRAME_BYTES`], more than
//! [`MAX_CBOR_DEPTH`] nested containers, a length head larger than the bytes that remain (checked
//! before anything is allocated), invalid UTF-8 in text, duplicate map keys, a map key that is
//! not text, an integer, or a byte string (an array, map, tag, simple value, or float key:
//! Jackson reads none of them, and a container key nested in keys would make the duplicate check
//! hash its subtree once per level, so an 8 MiB frame cost seconds), a break byte outside an
//! indefinite container, indefinite byte strings (Jackson never writes one; rule S5), other tags,
//! other simple values, and reserved additional-information values.
//!
//! An indefinite-length text decodes to its chunks joined. Each chunk must be a definite text
//! string (a byte string, a nested indefinite string, or any other item is
//! [`CborError::InvalidChunk`]) that is valid UTF-8 on its own (a chunk that splits a UTF-8
//! sequence is [`CborError::InvalidUtf8`]), and a break must end the text
//! ([`CborError::Truncated`] otherwise). Decoding is linear in the input: each chunk is read and
//! appended once, and [`decode`] refuses a chunk that follows one shorter than Jackson's as soon
//! as it is read, so even a text of one-byte chunks filling the frame cap costs one pass.
//!
//! # JSON
//!
//! The conversion between [`Value`] and JSON that the CLI and the MCP gateway need lives in the
//! peer crate's `agentspaces::json` module, not here.

#![warn(missing_docs)]

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FusedIterator;

use crate::limits::{MAX_CBOR_DEPTH, MAX_FRAME_BYTES};

mod big;

pub use big::{
    BigInt, Decimal, DecimalError, MAX_BIGNUM_BYTES, MAX_DECIMAL_EXPONENT, parse_integer,
};

/// The smallest [`Value::Int`]: -2^64, the smallest integer CBOR carries without a tag (major
/// type 1, argument `u64::MAX`). The wire writes one below -2^63 as a bignum (rule S9).
pub const INT_MIN: i128 = -(1i128 << 64);

/// The largest [`Value::Int`]: 2^64 - 1, the largest integer CBOR carries without a tag (major
/// type 0, argument `u64::MAX`). The wire writes one above 2^63 - 1 as a bignum (rule S9).
pub const INT_MAX: i128 = u64::MAX as i128;

/// The bits of the one NaN this wire writes, Java's `Double.NaN` (rule S10).
const CANONICAL_NAN: u64 = 0x7FF8_0000_0000_0000;

/// The bits of the one float32 NaN [`decode`] reads, Java's `Float.NaN` (rule S10).
const CANONICAL_NAN32: u32 = 0x7FC0_0000;

/// Maps up to this size check for duplicate keys pairwise; larger ones hash, so a hostile map of
/// many keys costs linear time, not quadratic.
const PAIRWISE_DUPLICATE_CHECK: usize = 16;

/// The most container slots preallocated from a definite length head. Beyond it the vector grows
/// as items actually decode, so a head can never make the decoder reserve memory out of
/// proportion to the bytes that back it.
const PREALLOCATION_LIMIT: usize = 1024;

const BREAK: u8 = 0xFF;

/// The initial byte of an indefinite-length text string.
const INDEFINITE_TEXT: u8 = 0x7F;

/// The most UTF-16 code units a text is written with as one definite string, and the length of
/// every chunk but the last of a longer one (one fewer where the chunk would end on a high
/// surrogate): Jackson's `CBORGenerator.MAX_LONG_STRING_CHARS`, Java `WellFormedCbor.TEXT_CHUNK`
/// (rule S6). See the module rules.
pub const TEXT_CHUNK_UNITS: usize = 3996;

// ---------------------------------------------------------------------------------------------
// Value

/// One CBOR data item as this wire uses it.
///
/// Equality is equality of encodings: two values are equal exactly when [`encode`] writes the same
/// bytes for both. Floats therefore compare by their bits (every NaN equals every other, since all
/// encode as the one NaN, and `0.0 != -0.0`), maps compare in order, and `Int(1) != Float(1.0)`.
/// This makes `Value` [`Eq`] and [`Hash`], so it can key a [`Map`] or a `HashSet`.
#[derive(Clone, Default)]
pub enum Value {
    /// CBOR null (`0xF6`); also what simple values 22 (null) and 23 (undefined) decode to.
    #[default]
    Null,
    /// A boolean (`0xF4` / `0xF5`).
    Bool(bool),
    /// An integer. The range is [`INT_MIN`]`..=`[`INT_MAX`]; [`decode`] never produces anything
    /// outside it, and [`encode`] clamps a hand-built value outside it (see [`try_encode`] to
    /// refuse instead). Inside Java's `long` range it is major type 0 or 1; outside, a tag 2 or 3
    /// bignum.
    Int(i128),
    /// An integer outside [`INT_MIN`]`..=`[`INT_MAX`], a tag 2 or 3 bignum (a Java `BigInteger`).
    BigInt(BigInt),
    /// A decimal fraction, tag 4 (a Java `BigDecimal`).
    Decimal(Decimal),
    /// A floating-point number; always encoded as a 64-bit double, a NaN as Java's `Double.NaN`.
    Float(f64),
    /// A byte string (major type 2).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (major type 3), encoded definite up to [`TEXT_CHUNK_UNITS`] UTF-16
    /// units and in Jackson's chunks beyond.
    Text(String),
    /// An array (major type 4), encoded definite-length.
    Array(Vec<Value>),
    /// A map (major type 5), encoded indefinite-length in insertion order.
    Map(Map),
}

impl Value {
    /// The text of a [`Value::Text`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The bytes of a [`Value::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// A [`Value::Int`] that fits an `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        self.as_i128().and_then(|n| i64::try_from(n).ok())
    }

    /// A [`Value::Int`] that fits a `u64` (so not negative).
    pub fn as_u64(&self) -> Option<u64> {
        self.as_i128().and_then(|n| u64::try_from(n).ok())
    }

    /// A [`Value::Int`] that fits a `usize` (so not negative).
    pub fn as_usize(&self) -> Option<usize> {
        self.as_i128().and_then(|n| usize::try_from(n).ok())
    }

    /// The integer of a [`Value::Int`].
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// A [`Value::Float`], or a [`Value::Int`] converted to the nearest `f64` (Jackson reads an
    /// integer into a `double` field the same way).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(x) => Some(*x),
            // Rounds to the nearest double, which is the documented intent.
            Value::Int(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// The boolean of a [`Value::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The map of a [`Value::Map`].
    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The map of a [`Value::Map`], mutably.
    pub fn as_map_mut(&mut self) -> Option<&mut Map> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The items of a [`Value::Array`].
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The items of a [`Value::Array`], mutably.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Whether this is [`Value::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The value under a text key, when this is a map that has one; `None` for any other value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map().and_then(|map| map.get(key))
    }

    /// The value under a text key, mutably, when this is a map that has one.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.as_map_mut().and_then(|map| map.get_mut(key))
    }

    /// The text of a [`Value::Text`], taken by value.
    pub fn into_text(self) -> Option<String> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The bytes of a [`Value::Bytes`], taken by value.
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The items of a [`Value::Array`], taken by value.
    pub fn into_array(self) -> Option<Vec<Value>> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The map of a [`Value::Map`], taken by value.
    pub fn into_map(self) -> Option<Map> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The decimal of a [`Value::Decimal`].
    pub fn as_decimal(&self) -> Option<&Decimal> {
        match self {
            Value::Decimal(decimal) => Some(decimal),
            _ => None,
        }
    }

    /// The bignum of a [`Value::BigInt`].
    pub fn as_big_int(&self) -> Option<&BigInt> {
        match self {
            Value::BigInt(big) => Some(big),
            _ => None,
        }
    }

    /// The CBOR type name of this value ("null", "bool", "int", "bignum", "decimal", "float",
    /// "bytes", "text", "array", "map"), for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::BigInt(_) => "bignum",
            Value::Decimal(_) => "decimal",
            Value::Float(_) => "float",
            Value::Bytes(_) => "bytes",
            Value::Text(_) => "text",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::BigInt(a), Value::BigInt(b)) => a == b,
            (Value::Decimal(a), Value::Decimal(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => float_bits(*a) == float_bits(*b),
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Text(a), Value::Text(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Null => {}
            Value::Bool(b) => b.hash(state),
            Value::Int(n) => n.hash(state),
            Value::BigInt(big) => big.hash(state),
            Value::Decimal(decimal) => decimal.hash(state),
            Value::Float(x) => float_bits(*x).hash(state),
            Value::Bytes(bytes) => bytes.hash(state),
            Value::Text(text) => text.hash(state),
            Value::Array(items) => items.hash(state),
            Value::Map(map) => map.hash(state),
        }
    }
}

/// The bits a float is written with: its own, or the one NaN's (rule S10).
fn float_bits(x: f64) -> u64 {
    if x.is_nan() {
        CANONICAL_NAN
    } else {
        x.to_bits()
    }
}

/// CBOR diagnostic notation (RFC 8949 §8): `null`, `true`, `42`, `1.5`, `h'00ff'`, `"text"`,
/// `[...]`, `{k: v, ...}`, a bignum as its digits, a decimal as `4([exponent, mantissa])`. The
/// alternate form (`{:#?}`) spreads containers over lines.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(n) => write!(f, "{n}"),
            Value::BigInt(big) => write!(f, "{big}"),
            Value::Decimal(decimal) => write!(f, "{decimal:?}"),
            Value::Float(x) => write!(f, "{x:?}"),
            Value::Bytes(bytes) => {
                f.write_str("h'")?;
                for byte in bytes {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str("'")
            }
            Value::Text(text) => write!(f, "{text:?}"),
            Value::Array(items) => f.debug_list().entries(items).finish(),
            Value::Map(map) => fmt::Debug::fmt(map, f),
        }
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Value::Text(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Value::Text(text)
    }
}

impl From<&String> for Value {
    fn from(text: &String) -> Self {
        Value::Text(text.clone())
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

macro_rules! from_integer {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(n: $t) -> Self {
                Value::Int(i128::from(n))
            }
        }
    )*};
}

from_integer!(i8, i16, i32, i64, i128, u8, u16, u32, u64);

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        // usize is at most 64 bits on every supported target, so this never saturates.
        Value::Int(i128::try_from(n).unwrap_or(i128::MAX))
    }
}

impl From<isize> for Value {
    fn from(n: isize) -> Self {
        // isize is at most 64 bits on every supported target, so this never saturates.
        Value::Int(i128::try_from(n).unwrap_or(i128::MAX))
    }
}

impl From<f64> for Value {
    fn from(x: f64) -> Self {
        Value::Float(x)
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Value::Bytes(bytes)
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Value::Bytes(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(bytes: [u8; N]) -> Self {
        Value::Bytes(bytes.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(bytes: &[u8; N]) -> Self {
        Value::Bytes(bytes.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Value::Array(items)
    }
}

impl From<Map> for Value {
    fn from(map: Map) -> Self {
        Value::Map(map)
    }
}

impl From<BigInt> for Value {
    fn from(big: BigInt) -> Self {
        Value::BigInt(big)
    }
}

impl From<Decimal> for Value {
    fn from(decimal: Decimal) -> Self {
        Value::Decimal(decimal)
    }
}

/// `None` becomes [`Value::Null`], the way Jackson writes an absent record component.
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(option: Option<T>) -> Self {
        option.map_or(Value::Null, Into::into)
    }
}

// ---------------------------------------------------------------------------------------------
// Map

/// An insertion-ordered map of [`Value`] keys to [`Value`] values: the shape of a Python `dict`,
/// and of a Java record or map as Jackson streams it.
///
/// Keys are unique: [`Map::insert`] replaces the value of an existing key in place, keeping its
/// position. Lookups are linear scans, which suits the small maps of this wire (records of a few
/// dozen fields); iterate rather than look up when a decoded map may be large. Equality is
/// order-sensitive, like the encoded bytes.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Map {
    entries: Vec<(Value, Value)>,
}

impl Map {
    /// An empty map.
    pub fn new() -> Self {
        Map {
            entries: Vec::new(),
        }
    }

    /// An empty map with room for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Map {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sets `key` to `value`. An existing key keeps its position and its old value is returned;
    /// a new key is appended and `None` is returned.
    pub fn insert(&mut self, key: impl Into<Value>, value: impl Into<Value>) -> Option<Value> {
        let key = key.into();
        let value = value.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => Some(std::mem::replace(&mut slot.1, value)),
            None => {
                self.entries.push((key, value));
                None
            }
        }
    }

    /// The value under a text key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.position(key).map(|i| &self.entries[i].1)
    }

    /// The value under a text key, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.position(key).map(|i| &mut self.entries[i].1)
    }

    /// The value under any key.
    pub fn get_value(&self, key: &Value) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Whether the map has a text key.
    pub fn contains_key(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// Removes a text key and returns its value; the remaining entries keep their order.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.position(key).map(|i| self.entries.remove(i).1)
    }

    /// Removes any key and returns its value; the remaining entries keep their order.
    pub fn remove_value(&mut self, key: &Value) -> Option<Value> {
        let index = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(index).1)
    }

    /// Keeps only the entries the predicate accepts, in order.
    pub fn retain(&mut self, mut keep: impl FnMut(&Value, &mut Value) -> bool) {
        self.entries.retain_mut(|(k, v)| keep(k, v));
    }

    /// The entries in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.entries.iter())
    }

    /// The entries in order, with mutable values.
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut(self.entries.iter_mut())
    }

    /// The keys in order.
    pub fn keys(&self) -> Keys<'_> {
        Keys(self.entries.iter())
    }

    /// The values in order.
    pub fn values(&self) -> Values<'_> {
        Values(self.entries.iter())
    }

    /// The values in order, mutably.
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut(self.entries.iter_mut())
    }

    /// The entries as a slice of `(key, value)` pairs, in order.
    pub fn as_slice(&self) -> &[(Value, Value)] {
        &self.entries
    }

    /// Reorders the entries canonically, in place; see [`canonical_map`] for the order.
    pub fn sort_canonical(&mut self) {
        self.entries
            .sort_by(|(a, _), (b, _)| canonical_key_order(a, b));
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|(k, _)| matches!(k, Value::Text(text) if text == key))
    }
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// Collects with [`Map::insert`] semantics: a repeated key keeps its first position and takes the
/// last value.
impl<K: Into<Value>, V: Into<Value>> FromIterator<(K, V)> for Map {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Map::new();
        map.extend(iter);
        map
    }
}

/// Extends with [`Map::insert`] semantics.
impl<K: Into<Value>, V: Into<Value>> Extend<(K, V)> for Map {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, value) in iter {
            self.insert(key, value);
        }
    }
}

impl IntoIterator for Map {
    type Item = (Value, Value);
    type IntoIter = IntoIter;

    fn into_iter(self) -> IntoIter {
        IntoIter(self.entries.into_iter())
    }
}

impl<'a> IntoIterator for &'a Map {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Map {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = IterMut<'a>;

    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

macro_rules! map_iterator {
    ($(#[$doc:meta])* $name:ident<$lt:lifetime>, $inner:ty, $item:ty, |$entry:ident| $project:expr) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name<$lt>($inner);

        impl<$lt> Iterator for $name<$lt> {
            type Item = $item;

            fn next(&mut self) -> Option<$item> {
                self.0.next().map(|$entry| $project)
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }
        }

        impl<$lt> DoubleEndedIterator for $name<$lt> {
            fn next_back(&mut self) -> Option<$item> {
                self.0.next_back().map(|$entry| $project)
            }
        }

        impl<$lt> ExactSizeIterator for $name<$lt> {}

        impl<$lt> FusedIterator for $name<$lt> {}
    };
}

map_iterator!(
    /// The entries of a [`Map`] in order; see [`Map::iter`].
    Iter<'a>, std::slice::Iter<'a, (Value, Value)>, (&'a Value, &'a Value), |e| (&e.0, &e.1)
);
map_iterator!(
    /// The entries of a [`Map`] in order, with mutable values; see [`Map::iter_mut`].
    IterMut<'a>, std::slice::IterMut<'a, (Value, Value)>, (&'a Value, &'a mut Value),
    |e| (&e.0, &mut e.1)
);
map_iterator!(
    /// The keys of a [`Map`] in order; see [`Map::keys`].
    Keys<'a>, std::slice::Iter<'a, (Value, Value)>, &'a Value, |e| &e.0
);
map_iterator!(
    /// The values of a [`Map`] in order; see [`Map::values`].
    Values<'a>, std::slice::Iter<'a, (Value, Value)>, &'a Value, |e| &e.1
);
map_iterator!(
    /// The values of a [`Map`] in order, mutably; see [`Map::values_mut`].
    ValuesMut<'a>, std::slice::IterMut<'a, (Value, Value)>, &'a mut Value, |e| &mut e.1
);

/// The entries of a [`Map`] in order, by value; see [`Map::into_iter`](IntoIterator::into_iter).
#[derive(Debug)]
pub struct IntoIter(std::vec::IntoIter<(Value, Value)>);

impl Iterator for IntoIter {
    type Item = (Value, Value);

    fn next(&mut self) -> Option<(Value, Value)> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for IntoIter {
    fn next_back(&mut self) -> Option<(Value, Value)> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for IntoIter {}

impl FusedIterator for IntoIter {}

// ---------------------------------------------------------------------------------------------
// Builders

/// Builds a [`Value::Map`] with its entries in the written order; keys and values are anything
/// that converts [`Into`] a [`Value`]. A repeated key keeps its first position and takes the last
/// value ([`Map::insert`]).
///
/// ```
/// use agentspaces_wire::{cbor, cbor_map};
///
/// let group = "zGroup";
/// let envelope = cbor_map! { "ver" => 3, "group" => group, "to" => None::<String> };
/// assert_eq!(
///     cbor::encode(&envelope),
///     b"\xbf\x63ver\x03\x65group\x66zGroup\x62to\xf6\xff".to_vec()
/// );
/// ```
#[macro_export]
macro_rules! cbor_map {
    (@unit $key:expr) => {
        ()
    };
    () => {
        $crate::cbor::Value::Map($crate::cbor::Map::new())
    };
    ($($key:expr => $value:expr),+ $(,)?) => {{
        let mut map = $crate::cbor::Map::with_capacity(
            <[()]>::len(&[$($crate::cbor_map!(@unit $key)),+]),
        );
        $( map.insert($key, $value); )+
        $crate::cbor::Value::Map(map)
    }};
}

/// Builds a [`Value::Array`] of the given items, each converted [`Into`] a [`Value`].
///
/// ```
/// use agentspaces_wire::{cbor, cbor_array};
///
/// let items = cbor_array![1, "two", None::<i64>];
/// assert_eq!(cbor::encode(&items), b"\x83\x01\x63two\xf6".to_vec());
/// ```
#[macro_export]
macro_rules! cbor_array {
    ($($item:expr),* $(,)?) => {
        $crate::cbor::Value::Array(::std::vec![$($crate::cbor::Value::from($item)),*])
    };
}

// ---------------------------------------------------------------------------------------------
// Canonical order

/// A copy of a map with its entries in canonical order: text keys first, shorter UTF-8 encoding
/// first and bytewise between equal lengths (RFC 8949 §4.2.1 as `cbor.py`'s `_key_order` applies
/// it, the order the Java codec writes every `java.util.Map` in as of wire v3). Keys that are not
/// text (this wire never writes any) follow every text key, ordered by the same rule applied to
/// their encoded bytes: shorter encoding first, then bytewise. A decoded map never holds a
/// container key ([`decode`] refuses one), so encoding such a key here costs only a hand-built
/// map.
///
/// Apply it to map-valued fields a signature covers (tags, costHints, spaceBindings,
/// resourceHints, parameters, access), never to a map that stands for a record. It does not
/// recurse into nested maps.
pub fn canonical_map(map: &Map) -> Map {
    let mut copy = map.clone();
    copy.sort_canonical();
    copy
}

fn canonical_key_order(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Text(x), Value::Text(y)) => x
            .len()
            .cmp(&y.len())
            .then_with(|| x.as_bytes().cmp(y.as_bytes())),
        (Value::Text(_), _) => Ordering::Less,
        (_, Value::Text(_)) => Ordering::Greater,
        _ => {
            let (x, y) = (encode(a), encode(b));
            x.len().cmp(&y.len()).then_with(|| x.cmp(&y))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Errors

/// Why bytes did not decode, or (for [`try_encode`]) why a value did not encode. Offsets are byte
/// positions in the input where the offending item starts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// The input ended inside an item.
    #[error("truncated CBOR item at offset {offset}")]
    Truncated {
        /// Where more bytes were needed.
        offset: usize,
    },
    /// Bytes remain after the one item the input must hold.
    #[error("trailing bytes after the CBOR item, from offset {offset}")]
    TrailingBytes {
        /// Where the trailing bytes start.
        offset: usize,
    },
    /// Containers nest deeper than [`MAX_CBOR_DEPTH`].
    #[error("CBOR nesting deeper than {limit} at offset {offset}")]
    TooDeep {
        /// The container that went over the limit.
        offset: usize,
        /// The limit, [`MAX_CBOR_DEPTH`].
        limit: usize,
    },
    /// A length head claims more bytes (or items) than the input has left; refused before
    /// anything is allocated.
    #[error("CBOR length {length} at offset {offset} exceeds the {remaining} bytes that remain")]
    LengthExceedsInput {
        /// The item with the hostile or corrupt head.
        offset: usize,
        /// The claimed length (bytes for strings, items for arrays, entries for maps).
        length: u64,
        /// The bytes left after the head.
        remaining: usize,
    },
    /// The input is longer than [`MAX_FRAME_BYTES`], the frame cap every decoder input is held
    /// to; refused before any byte is read.
    #[error("CBOR input of {length} bytes exceeds the {limit}-byte frame cap")]
    TooLarge {
        /// The input length.
        length: usize,
        /// The cap, [`MAX_FRAME_BYTES`].
        limit: usize,
    },
    /// A text string, or one chunk of an indefinite-length text taken on its own, is not valid
    /// UTF-8 (a chunk that splits a UTF-8 sequence is one).
    #[error("invalid UTF-8 in the CBOR text string at offset {offset}")]
    InvalidUtf8 {
        /// The text string, or the head of the chunk.
        offset: usize,
    },
    /// A chunk of an indefinite-length text string that is not a definite-length text string: a
    /// byte string, a nested indefinite string, or any other item (RFC 8949 §3.2.3).
    #[error(
        "CBOR item 0x{byte:02x} at offset {offset} inside an indefinite-length text: chunks are definite text strings"
    )]
    InvalidChunk {
        /// The offending chunk.
        offset: usize,
        /// Its initial byte.
        byte: u8,
    },
    /// A map has the same key twice.
    #[error("duplicate key in the CBOR map at offset {offset}")]
    DuplicateKey {
        /// The map.
        offset: usize,
    },
    /// A break byte (`0xFF`) where no indefinite container is open.
    #[error("unexpected CBOR break byte at offset {offset}")]
    UnexpectedBreak {
        /// The break byte.
        offset: usize,
    },
    /// A simple value other than false, true, null, undefined, or a float.
    #[error("unsupported CBOR simple value 0x{byte:02x} at offset {offset}")]
    UnsupportedSimple {
        /// The item.
        offset: usize,
        /// Its initial byte.
        byte: u8,
    },
    /// A tag (major type 6) this wire does not use: any but the big-number tags 2, 3, and 4, a
    /// tag where a map key belongs, or a big-number tag over an item Jackson never writes under
    /// it (tag 2 or 3 over anything but a definite byte string; tag 4 over anything but a
    /// two-element array of a plain integer and a plain integer or bignum), as SPEC §9 rules for
    /// CBOR outside a stamp.
    #[error(
        "CBOR tag at offset {offset}: only tags 2, 3, and 4 over their own items are used on this wire"
    )]
    Tag {
        /// The tag, or the item inside a big-number tag that it never encloses.
        offset: usize,
    },
    /// An indefinite-length byte string: Jackson writes every byte string definite (Java
    /// `WellFormedCbor` rule S5). An indefinite-length text decodes (see the module rules).
    #[error("indefinite-length CBOR byte string at offset {offset}: not used on this wire")]
    IndefiniteString {
        /// The string.
        offset: usize,
    },
    /// A reserved additional-information value (28 to 30), or an indefinite length on an
    /// integer.
    #[error("malformed CBOR head 0x{byte:02x} at offset {offset}")]
    MalformedHead {
        /// The item.
        offset: usize,
        /// Its initial byte.
        byte: u8,
    },
    /// A map key that is an array, a map, a boolean, null, undefined, or a float: Jackson, the
    /// Java codec, reads only text, integer, and byte-string keys. Refused before the key is
    /// decoded, so a container key is never built.
    #[error(
        "unsupported CBOR map key 0x{byte:02x} at offset {offset}: keys are text, integers, or bytes"
    )]
    UnsupportedKey {
        /// The key.
        offset: usize,
        /// Its initial byte.
        byte: u8,
    },
    /// [`try_encode`] met an integer outside [`INT_MIN`]`..=`[`INT_MAX`].
    #[error("integer {value} is outside the CBOR integer range")]
    IntegerOutOfRange {
        /// The integer.
        value: i128,
    },
    /// An item [`decode_lenient`] reads but [`decode`] refuses: it breaks a rule of the wire
    /// encoding (Java `WellFormedCbor` rules S1 to S12), so Java,
    /// Python, TypeScript, and Ruby refuse the document that holds it.
    #[error("CBOR item at offset {offset} is not in the wire encoding: {rule}")]
    NotWireEncoding {
        /// The item.
        offset: usize,
        /// The rule it breaks.
        rule: WireRule,
    },
    /// A bignum (tag 2 or 3, alone or as a decimal's mantissa) whose byte string is longer than
    /// [`MAX_BIGNUM_BYTES`], which Jackson's number-length constraint refuses in every Java read.
    #[error(
        "CBOR bignum of {length} bytes at offset {offset} exceeds the {limit} bytes Java reads"
    )]
    BignumTooLong {
        /// The bignum's tag.
        offset: usize,
        /// Its byte length.
        length: usize,
        /// The limit, [`MAX_BIGNUM_BYTES`].
        limit: usize,
    },
}

/// The rule of the wire encoding an item breaks ([`CborError::NotWireEncoding`]), as Java's
/// `WellFormedCbor` numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WireRule {
    /// S3: a head wider than its argument needs (a float's head excepted).
    ShortestHead,
    /// S4: a plain integer outside Java's `long` range, which is written as a bignum.
    LongRange,
    /// S6: a definite text past [`TEXT_CHUNK_UNITS`] UTF-16 units.
    LongText,
    /// S6: an indefinite-length text other than Jackson's chunks of a text past
    /// [`TEXT_CHUNK_UNITS`] units: a text of that many units or fewer (one chunk or several),
    /// other chunk boundaries, or an empty chunk.
    TextChunks,
    /// S7: an indefinite-length array.
    DefiniteArray,
    /// S8: a definite-length map.
    IndefiniteMap,
    /// S8: a map key that is not a text string.
    TextKey,
    /// S9: a bignum whose bytes are not the minimal magnitude of a value outside Java's `long`.
    Bignum,
    /// S9: a decimal with a trailing zero in its mantissa (or a zero whose exponent is not 0), or
    /// whose exponent lies outside ±[`MAX_DECIMAL_EXPONENT`].
    Decimal,
    /// S10: a half float, or a NaN other than Java's `Double.NaN` or `Float.NaN`.
    Float,
    /// S11: `undefined`, a simple value other than `false`, `true`, and `null`.
    SimpleValue,
}

impl fmt::Display for WireRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WireRule::ShortestHead => "a head wider than its argument needs (S3)",
            WireRule::LongRange => "an integer outside a Java long is a bignum (S4)",
            WireRule::LongText => "a text past 3996 UTF-16 units is chunked (S6)",
            WireRule::TextChunks => "a text chunked other than as Jackson chunks it (S6)",
            WireRule::DefiniteArray => "an array is definite-length (S7)",
            WireRule::IndefiniteMap => "a map is indefinite-length (S8)",
            WireRule::TextKey => "a map key is a text string (S8)",
            WireRule::Bignum => {
                "a bignum holds the minimal magnitude of a value outside a long (S9)"
            }
            WireRule::Decimal => "a decimal is normalized, its exponent inside an int (S9)",
            WireRule::Float => "a float is float32 or float64 with Java's one NaN (S10)",
            WireRule::SimpleValue => "the simple values are false, true and null (S11)",
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Encoding

/// Encodes a value the way the Java codec encodes its equivalent (see the module rules).
///
/// Infallible: an [`Value::Int`] outside [`INT_MIN`]`..=`[`INT_MAX`] (which only hand-built
/// values can hold) is clamped to the nearest end of the range. Use [`try_encode`] to refuse it.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Appends the encoding of a value to `out`; [`encode`] without the allocation.
pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    // The out-of-range report is what try_encode uses; encode clamps by contract.
    let _ = write(value, out);
}

/// Encodes a value, refusing an integer outside [`INT_MIN`]`..=`[`INT_MAX`] instead of clamping
/// it. Otherwise identical to [`encode`].
pub fn try_encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    match write(value, &mut out) {
        None => Ok(out),
        Some(value) => Err(CborError::IntegerOutOfRange { value }),
    }
}

/// Writes `value` and returns the first out-of-range integer it clamped, if any.
fn write(value: &Value, out: &mut Vec<u8>) -> Option<i128> {
    match value {
        Value::Null => out.push(0xF6),
        Value::Bool(false) => out.push(0xF4),
        Value::Bool(true) => out.push(0xF5),
        Value::Int(n) => {
            let clamped = (*n).clamp(INT_MIN, INT_MAX);
            write_integer(clamped, out);
            if clamped != *n {
                return Some(*n);
            }
        }
        Value::BigInt(big) => write_bignum(big.is_negative(), &big.content(), out),
        Value::Decimal(decimal) => {
            out.extend_from_slice(&[0xC4, 0x82]);
            write_integer(i128::from(decimal.exponent()), out);
            match decimal.mantissa() {
                Value::BigInt(big) => write_bignum(big.is_negative(), &big.content(), out),
                // A decimal's mantissa is an Int or a BigInt, within the Int range.
                mantissa => write_integer(mantissa.as_i128().unwrap_or(0), out),
            }
        }
        Value::Float(x) => {
            out.push(0xFB);
            out.extend_from_slice(&float_bits(*x).to_be_bytes());
        }
        Value::Bytes(bytes) => {
            head(2, length(bytes.len()), out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => write_text(text, out),
        Value::Array(items) => {
            head(4, length(items.len()), out);
            let mut clamped = None;
            for item in items {
                let item_clamped = write(item, out);
                clamped = clamped.or(item_clamped);
            }
            return clamped;
        }
        Value::Map(map) => {
            out.push(0xBF);
            let mut clamped = None;
            for (key, item) in map {
                let key_clamped = write(key, out);
                let item_clamped = write(item, out);
                clamped = clamped.or(key_clamped).or(item_clamped);
            }
            out.push(BREAK);
            return clamped;
        }
    }
    None
}

/// An integer as Java writes it (rules S4 and S9): a plain integer inside the `long` range, else
/// a bignum, tag 2 over the magnitude of a positive value and tag 3 over the magnitude of a
/// negative one (Jackson's tag 3, not RFC 8949's: -2^63 - 1 is `C3 49 00 80 .. 01`).
fn write_integer(n: i128, out: &mut Vec<u8>) {
    match i64::try_from(n) {
        Ok(small) if small >= 0 => head(0, small.unsigned_abs(), out),
        // -1 - small >= 0 for a negative small; unsigned_abs keeps it exact at i64::MIN.
        Ok(small) => head(1, (small + 1).unsigned_abs(), out),
        Err(_) => write_bignum(
            n < 0,
            &big::content_of(&big::magnitude_of(n.unsigned_abs())),
            out,
        ),
    }
}

/// A bignum: tag 2 (positive) or 3 (negative) over a definite byte string of `content`.
fn write_bignum(negative: bool, content: &[u8], out: &mut Vec<u8>) {
    out.push(if negative { 0xC3 } else { 0xC2 });
    head(2, length(content.len()), out);
    out.extend_from_slice(content);
}

/// A text as Jackson writes it: definite up to [`TEXT_CHUNK_UNITS`] UTF-16 units, else chunked
/// (Jackson `CBORGenerator._writeChunkedString`; see the module rules).
fn write_text(text: &str, out: &mut Vec<u8>) {
    // A text has at most as many UTF-16 units as UTF-8 bytes, so a short one is never counted.
    let mut remaining = if text.len() <= TEXT_CHUNK_UNITS {
        0
    } else {
        utf16_units(text)
    };
    if remaining <= TEXT_CHUNK_UNITS {
        definite_text(text, out);
        return;
    }
    out.push(INDEFINITE_TEXT);
    let mut rest = text;
    while remaining > TEXT_CHUNK_UNITS {
        let (end, units) = chunk_end(rest);
        let (chunk, tail) = rest.split_at(end);
        definite_text(chunk, out);
        rest = tail;
        remaining -= units;
    }
    definite_text(rest, out);
    out.push(BREAK);
}

fn definite_text(text: &str, out: &mut Vec<u8>) {
    head(3, length(text.len()), out);
    out.extend_from_slice(text.as_bytes());
}

/// The UTF-16 length of a text, Java's `String.length()`: one unit per UTF-8 lead byte, and one
/// more for each four-byte sequence (a surrogate pair in UTF-16).
fn utf16_units(text: &str) -> usize {
    text.bytes()
        .map(|byte| usize::from(byte & 0xC0 != 0x80) + usize::from(byte >= 0xF0))
        .sum()
}

/// The next chunk of a text longer than [`TEXT_CHUNK_UNITS`] units: its byte length and its
/// UTF-16 length. It takes whole characters while they fit in [`TEXT_CHUNK_UNITS`] units, which
/// is Jackson's rule: [`TEXT_CHUNK_UNITS`] units, or one fewer when a surrogate pair would
/// straddle the end (its high surrogate the chunk's last unit).
fn chunk_end(text: &str) -> (usize, usize) {
    let mut units = 0;
    for (index, character) in text.char_indices() {
        let width = character.len_utf16();
        if units + width > TEXT_CHUNK_UNITS {
            return (index, units);
        }
        units += width;
    }
    (text.len(), units)
}

fn length(len: usize) -> u64 {
    // usize is at most 64 bits on every supported target, so this never saturates.
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// A minimal-width head: the major type and its argument.
fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if let Ok(small) = u8::try_from(argument) {
        if small < 24 {
            out.push(major | small);
        } else {
            out.extend_from_slice(&[major | 24, small]);
        }
    } else if let Ok(short) = u16::try_from(argument) {
        out.push(major | 25);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(argument) {
        out.push(major | 26);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding

/// Decodes exactly one CBOR item in the wire encoding, as a document from the network must be
/// (rules S1 to S12, see the module rules): the reader of every frame, record, claim, card, and
/// payload. Never panics; every malformed, hostile, or unsupported input is a [`CborError`], and
/// an input [`decode_lenient`] would read but the wire encoding refuses is
/// [`CborError::NotWireEncoding`]. Input longer than [`MAX_FRAME_BYTES`] is refused outright
/// ([`CborError::TooLarge`]), so the decoded tree is bounded by a fixed multiple of the frame cap
/// whoever the caller is. [`encode`] of what this returns gives back the input, a float32
/// excepted (it decodes to a [`Value::Float`], which encodes as a double).
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    decode_with(bytes, true)
}

/// Decodes exactly one CBOR item leniently, as Java's `CborCodec.fromBytes` reads what a node
/// persisted before the wire encoding (see the module rules): for bytes this process or an older
/// peer wrote and stored, never for bytes from the network, which [`decode`] reads. Its limits
/// and refusals are [`decode`]'s, less the rules of the wire encoding.
pub fn decode_lenient(bytes: &[u8]) -> Result<Value, CborError> {
    decode_with(bytes, false)
}

fn decode_with(bytes: &[u8], strict: bool) -> Result<Value, CborError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(CborError::TooLarge {
            length: bytes.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    let mut decoder = Decoder {
        input: bytes,
        pos: 0,
        strict,
    };
    let value = decoder.item(0)?;
    if decoder.pos != bytes.len() {
        return Err(CborError::TrailingBytes {
            offset: decoder.pos,
        });
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    /// Whether the rules of the wire encoding apply ([`decode`]) or not ([`decode_lenient`]).
    strict: bool,
}

/// A head's argument: a definite count or value, or the indefinite marker.
enum Argument {
    Definite(u64),
    Indefinite,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CborError> {
        let truncated = CborError::Truncated { offset: self.pos };
        let end = self.pos.checked_add(count).ok_or(truncated.clone())?;
        let bytes = self.input.get(self.pos..end).ok_or(truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let offset = self.pos;
        let bytes = self.take(N)?;
        <[u8; N]>::try_from(bytes).map_err(|_| CborError::Truncated { offset })
    }

    /// Refuses the item at `offset` under `rule` when the wire encoding applies.
    fn rule(&self, broken: bool, offset: usize, rule: WireRule) -> Result<(), CborError> {
        if self.strict && broken {
            return Err(CborError::NotWireEncoding { offset, rule });
        }
        Ok(())
    }

    /// The argument of the head whose initial byte, at `start`, was just read; the wire encoding
    /// takes it in its shortest form only (S3).
    fn argument(&mut self, start: usize, initial: u8) -> Result<Argument, CborError> {
        let (argument, least) = match initial & 0x1F {
            info @ 0..=23 => (u64::from(info), 0),
            24 => (u64::from(self.fixed::<1>()?[0]), 24),
            25 => (u64::from(u16::from_be_bytes(self.fixed()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.fixed()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.fixed()?), 0x1_0000_0000),
            31 => return Ok(Argument::Indefinite),
            _ => {
                return Err(CborError::MalformedHead {
                    offset: start,
                    byte: initial,
                });
            }
        };
        self.rule(argument < least, start, WireRule::ShortestHead)?;
        Ok(Argument::Definite(argument))
    }

    /// A definite length that the remaining input can back at `unit` bytes per element.
    fn backed_length(&self, start: usize, length: u64, unit: usize) -> Result<usize, CborError> {
        let remaining = self.remaining();
        let capacity = (remaining / unit) as u64;
        if length > capacity {
            return Err(CborError::LengthExceedsInput {
                offset: start,
                length,
                remaining,
            });
        }
        // length <= remaining / unit, which is a usize.
        usize::try_from(length).map_err(|_| CborError::LengthExceedsInput {
            offset: start,
            length,
            remaining,
        })
    }

    /// Decodes the item at the cursor; `depth` counts the containers that enclose it.
    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        let start = self.pos;
        let initial = self.peek().ok_or(CborError::Truncated { offset: start })?;
        self.pos += 1;
        let major = initial >> 5;
        match major {
            7 => return self.simple(start, initial),
            4 | 5 if depth >= MAX_CBOR_DEPTH => {
                return Err(CborError::TooDeep {
                    offset: start,
                    limit: MAX_CBOR_DEPTH,
                });
            }
            _ => {}
        }
        let argument = self.argument(start, initial)?;
        match (major, argument) {
            (0, Argument::Definite(n)) => {
                self.rule(n > i64::MAX as u64, start, WireRule::LongRange)?;
                Ok(Value::Int(i128::from(n)))
            }
            (1, Argument::Definite(n)) => {
                self.rule(n > i64::MAX as u64, start, WireRule::LongRange)?;
                Ok(Value::Int(-1 - i128::from(n)))
            }
            (2, Argument::Indefinite) => Err(CborError::IndefiniteString { offset: start }),
            (3, Argument::Indefinite) => self.chunked_text(start),
            (2, Argument::Definite(n)) => {
                let len = self.backed_length(start, n, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            (3, Argument::Definite(n)) => {
                let len = self.backed_length(start, n, 1)?;
                let text = std::str::from_utf8(self.take(len)?)
                    .map_err(|_| CborError::InvalidUtf8 { offset: start })?;
                // A text has at most as many UTF-16 units as UTF-8 bytes.
                let long =
                    self.strict && len > TEXT_CHUNK_UNITS && utf16_units(text) > TEXT_CHUNK_UNITS;
                self.rule(long, start, WireRule::LongText)?;
                Ok(Value::Text(text.to_owned()))
            }
            (4, Argument::Definite(n)) => {
                let count = self.backed_length(start, n, 1)?;
                let mut items = Vec::with_capacity(count.min(PREALLOCATION_LIMIT));
                for _ in 0..count {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            (4, Argument::Indefinite) => {
                self.rule(true, start, WireRule::DefiniteArray)?;
                let mut items = Vec::new();
                while !self.at_break()? {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            (5, Argument::Definite(n)) => {
                self.rule(true, start, WireRule::IndefiniteMap)?;
                // Every entry takes at least two bytes: a key and a value.
                let count = self.backed_length(start, n, 2)?;
                let mut entries = Vec::with_capacity(count.min(PREALLOCATION_LIMIT));
                for _ in 0..count {
                    entries.push(self.entry(depth)?);
                }
                map_of(entries, start)
            }
            (5, Argument::Indefinite) => {
                let mut entries = Vec::new();
                while !self.at_break()? {
                    entries.push(self.entry(depth)?);
                }
                map_of(entries, start)
            }
            (6, Argument::Definite(tag)) => self.tagged(start, tag, depth),
            // Majors 0, 1, and 6 with an indefinite length; major 7 returned above.
            _ => Err(CborError::MalformedHead {
                offset: start,
                byte: initial,
            }),
        }
    }

    /// The chunks of an indefinite-length text whose `0x7F` at `start` was just read, joined, up
    /// to and including its break. Linear in the input: each chunk is read and appended once.
    /// The wire encoding takes only Jackson's chunks (S6): a chunk after one of fewer than
    /// [`TEXT_CHUNK_UNITS`] - 1 units is refused as soon as it is read, and the boundaries are
    /// checked against Jackson's once the break is reached.
    fn chunked_text(&mut self, start: usize) -> Result<Value, CborError> {
        let mut text = String::new();
        // The byte length of each chunk, and the UTF-16 length of the last, when strict.
        let mut lengths = Vec::new();
        let mut last_units = None;
        while !self.at_break()? {
            let chunk = self.pos;
            let initial = self.peek().ok_or(CborError::Truncated { offset: chunk })?;
            let invalid = CborError::InvalidChunk {
                offset: chunk,
                byte: initial,
            };
            if initial >> 5 != 3 || initial & 0x1F == 31 {
                return Err(invalid);
            }
            self.pos += 1;
            let Argument::Definite(n) = self.argument(chunk, initial)? else {
                return Err(invalid);
            };
            let len = self.backed_length(chunk, n, 1)?;
            let piece = std::str::from_utf8(self.take(len)?)
                .map_err(|_| CborError::InvalidUtf8 { offset: chunk })?;
            if self.strict {
                // Only the last chunk is shorter than TEXT_CHUNK_UNITS - 1 units.
                let short = last_units.is_some_and(|units| units + 1 < TEXT_CHUNK_UNITS);
                self.rule(short, start, WireRule::TextChunks)?;
                last_units = Some(utf16_units(piece));
                lengths.push(len);
            }
            text.push_str(piece);
        }
        if self.strict && !jackson_chunks(&text, &lengths) {
            return Err(CborError::NotWireEncoding {
                offset: start,
                rule: WireRule::TextChunks,
            });
        }
        Ok(Value::Text(text))
    }

    fn entry(&mut self, depth: usize) -> Result<(Value, Value), CborError> {
        // Jackson reads only text, integer, and byte-string keys (it refuses arrays, maps,
        // and simple values and floats as "Unsupported major type"), and no encoder writes a
        // tagged key (Java refuses one, the big-number tags included). Refused before the key
        // is decoded, so a container key is never built, and every key that is built is a
        // scalar: the duplicate check stays linear in the input rather than in input times
        // depth. A break and a simple value this wire never carries keep their own errors. The
        // wire encoding takes text keys alone (S8), so it refuses the integer and byte-string
        // keys that a lenient read takes.
        let offset = self.pos;
        if let Some(byte) = self.peek() {
            if matches!(byte >> 5, 4 | 5) || matches!(byte, 0xF4..=0xF7 | 0xF9..=0xFB) {
                return Err(CborError::UnsupportedKey { offset, byte });
            }
            if byte >> 5 == 6 {
                return Err(CborError::Tag { offset });
            }
            self.rule(byte >> 5 <= 2, offset, WireRule::TextKey)?;
        }
        let key = self.item(depth + 1)?;
        let value = self.item(depth + 1)?;
        Ok((key, value))
    }

    /// Inside an indefinite container: consumes the break byte and returns true when it is next.
    fn at_break(&mut self) -> Result<bool, CborError> {
        match self.peek() {
            None => Err(CborError::Truncated { offset: self.pos }),
            Some(BREAK) => {
                self.pos += 1;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    /// Major type 7: simple values and floats, which carry no length head. The wire encoding
    /// takes `false`, `true`, `null` (S11), and float32 and float64 with Java's NaNs (S10).
    fn simple(&mut self, start: usize, initial: u8) -> Result<Value, CborError> {
        match initial & 0x1F {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => {
                self.rule(true, start, WireRule::SimpleValue)?;
                Ok(Value::Null)
            }
            25 => {
                self.rule(true, start, WireRule::Float)?;
                Ok(Value::Float(half_to_f64(u16::from_be_bytes(self.fixed()?))))
            }
            26 => {
                let bits = u32::from_be_bytes(self.fixed()?);
                let single = f32::from_bits(bits);
                self.rule(
                    single.is_nan() && bits != CANONICAL_NAN32,
                    start,
                    WireRule::Float,
                )?;
                Ok(Value::Float(f64::from(single)))
            }
            27 => {
                let bits = u64::from_be_bytes(self.fixed()?);
                let double = f64::from_bits(bits);
                self.rule(
                    double.is_nan() && bits != CANONICAL_NAN,
                    start,
                    WireRule::Float,
                )?;
                Ok(Value::Float(double))
            }
            31 => Err(CborError::UnexpectedBreak { offset: start }),
            _ => Err(CborError::UnsupportedSimple {
                offset: start,
                byte: initial,
            }),
        }
    }

    /// A tag whose head at `start` was just read (SPEC §9, CBOR outside a stamp): a
    /// bignum (tag 2 or 3) or a decimal (tag 4), each in its one form (S9); any other tag is
    /// refused.
    fn tagged(&mut self, start: usize, tag: u64, depth: usize) -> Result<Value, CborError> {
        match tag {
            2 | 3 => self.bignum(start, tag == 3),
            4 => self.decimal(start, depth),
            _ => Err(CborError::Tag { offset: start }),
        }
    }

    /// The content of the bignum whose tag at `start` was just read: a definite byte string
    /// holding the minimal magnitude of a value outside Java's `long` (S9), in both modes, since
    /// no encoder of this wire ever wrote another, and at most [`MAX_BIGNUM_BYTES`] long.
    fn bignum(&mut self, start: usize, negative: bool) -> Result<Value, CborError> {
        let at = self.pos;
        let initial = self.peek().ok_or(CborError::Truncated { offset: at })?;
        if initial >> 5 != 2 || initial & 0x1F == 31 {
            return Err(CborError::Tag { offset: start });
        }
        self.pos += 1;
        let Argument::Definite(n) = self.argument(at, initial)? else {
            return Err(CborError::Tag { offset: start });
        };
        let len = self.backed_length(at, n, 1)?;
        if len > MAX_BIGNUM_BYTES {
            return Err(CborError::BignumTooLong {
                offset: start,
                length: len,
                limit: MAX_BIGNUM_BYTES,
            });
        }
        let content = self.take(len)?;
        let not_minimal = match content {
            [] => true,
            [first, ..] if *first >= 0x80 => true,
            [0, second, ..] => *second < 0x80,
            _ => false,
        };
        let magnitude = content.strip_prefix(&[0]).unwrap_or(content);
        // Above 2^63 - 1 under tag 2; above 2^63 (Jackson's tag 3 holds the magnitude) under 3.
        let floor = if negative {
            1u128 << 63
        } else {
            (1u128 << 63) - 1
        };
        let inside_long = magnitude.len() <= 8 && {
            let mut word = [0u8; 16];
            word[16 - magnitude.len()..].copy_from_slice(magnitude);
            u128::from_be_bytes(word) <= floor
        };
        if not_minimal || inside_long {
            return Err(CborError::NotWireEncoding {
                offset: start,
                rule: WireRule::Bignum,
            });
        }
        Ok(big::integer_value(negative, magnitude))
    }

    /// The content of the decimal whose tag at `start` was just read: a two-element array, a
    /// nesting level as Jackson counts it (S2), of a plain integer exponent within
    /// ±[`MAX_DECIMAL_EXPONENT`] and a plain integer or bignum mantissa, normalized (S9).
    fn decimal(&mut self, start: usize, depth: usize) -> Result<Value, CborError> {
        if self
            .peek()
            .ok_or(CborError::Truncated { offset: self.pos })?
            != 0x82
        {
            return Err(CborError::Tag { offset: start });
        }
        if depth >= MAX_CBOR_DEPTH {
            return Err(CborError::TooDeep {
                offset: start,
                limit: MAX_CBOR_DEPTH,
            });
        }
        self.pos += 1;
        let exponent_at = self.pos;
        let exponent = self
            .peek()
            .ok_or(CborError::Truncated { offset: self.pos })?;
        if exponent >> 5 > 1 {
            return Err(CborError::Tag {
                offset: exponent_at,
            });
        }
        let exponent = self.item(depth + 1)?.as_i128().unwrap_or(i128::MAX);
        let mantissa_at = self.pos;
        let mantissa = self
            .peek()
            .ok_or(CborError::Truncated { offset: self.pos })?;
        if mantissa >> 5 > 1 && mantissa != 0xC2 && mantissa != 0xC3 {
            return Err(CborError::Tag {
                offset: mantissa_at,
            });
        }
        let mantissa = self.item(depth + 1)?;
        let exponent = i32::try_from(exponent)
            .ok()
            .filter(|e| i64::from(*e).abs() <= MAX_DECIMAL_EXPONENT);
        let normalized = match &mantissa {
            Value::Int(0) => exponent == Some(0),
            Value::Int(n) => n % 10 != 0,
            Value::BigInt(big) => !big::divisible_by_ten(big.magnitude()),
            _ => false,
        };
        match exponent {
            Some(exponent) if normalized => {
                Ok(Value::Decimal(Decimal::checked(exponent, mantissa)))
            }
            _ => Err(CborError::NotWireEncoding {
                offset: start,
                rule: WireRule::Decimal,
            }),
        }
    }
}

/// Whether chunks of these byte lengths are Jackson's chunks of `text` (S6): only a text past
/// [`TEXT_CHUNK_UNITS`] UTF-16 units is chunked; while more than that remain the next chunk
/// takes [`TEXT_CHUNK_UNITS`] units, or one fewer when its last unit would be a high surrogate,
/// and the rest forms the last chunk (Java `WellFormedCbor.chunking`).
fn jackson_chunks(text: &str, lengths: &[usize]) -> bool {
    let mut remaining = utf16_units(text);
    if remaining <= TEXT_CHUNK_UNITS {
        return false;
    }
    let mut rest = text;
    for (index, &length) in lengths.iter().enumerate() {
        let last = index + 1 == lengths.len();
        let (end, units) = if remaining > TEXT_CHUNK_UNITS {
            chunk_end(rest)
        } else {
            (rest.len(), remaining)
        };
        if length != end || last != (remaining == units) {
            return false;
        }
        rest = &rest[end..];
        remaining -= units;
    }
    true
}

fn map_of(entries: Vec<(Value, Value)>, start: usize) -> Result<Value, CborError> {
    let duplicate = if entries.len() <= PAIRWISE_DUPLICATE_CHECK {
        entries
            .iter()
            .enumerate()
            .any(|(i, (key, _))| entries[..i].iter().any(|(earlier, _)| earlier == key))
    } else {
        let mut seen = HashSet::with_capacity(entries.len());
        entries.iter().any(|(key, _)| !seen.insert(key))
    };
    if duplicate {
        return Err(CborError::DuplicateKey { offset: start });
    }
    Ok(Value::Map(Map { entries }))
}

/// IEEE 754 binary16 to binary64, exactly (every half is representable as a double).
fn half_to_f64(bits: u16) -> f64 {
    let negative = bits & 0x8000 != 0;
    let exponent = (bits >> 10) & 0x1F;
    let mantissa = u64::from(bits & 0x03FF);
    let magnitude = match exponent {
        // Zero and subnormals: mantissa * 2^-24.
        0 => mantissa as f64 * f64::powi(2.0, -24),
        // Infinity and NaN, keeping the NaN payload in the top mantissa bits.
        0x1F => f64::from_bits(0x7FF0_0000_0000_0000 | (mantissa << 42)),
        // Normal: (1024 + mantissa) * 2^(exponent - 25).
        _ => (1024 + mantissa) as f64 * f64::powi(2.0, i32::from(exponent) - 25),
    };
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Half floats are outside the wire encoding (S10): the lenient read widens them exactly.
    #[test]
    fn halves_decode_exactly() {
        for (bits, expected) in [
            ("f90000", 0.0),
            ("f98000", -0.0),
            ("f93c00", 1.0),
            ("f93e00", 1.5),
            ("f97bff", 65504.0),
            ("f90001", 5.960_464_477_539_063e-8),
            ("f90400", 6.103_515_625e-5),
            ("f9c400", -4.0),
            ("f97c00", f64::INFINITY),
            ("f9fc00", f64::NEG_INFINITY),
        ] {
            assert_eq!(
                decode_lenient(&hex(bits)),
                Ok(Value::Float(expected)),
                "{bits}"
            );
            assert_eq!(
                decode(&hex(bits)),
                Err(CborError::NotWireEncoding {
                    offset: 0,
                    rule: WireRule::Float
                }),
                "{bits}"
            );
        }
        assert!(
            decode_lenient(&hex("f97e00"))
                .unwrap()
                .as_f64()
                .unwrap()
                .is_nan()
        );
    }

    #[test]
    fn singles_widen_exactly() {
        // 0x40490fdb is the single nearest pi; widening keeps its value, not the double nearest pi.
        let widened = decode(&hex("fa40490fdb")).unwrap().as_f64().unwrap();
        assert_eq!(widened, f64::from(std::f32::consts::PI));
        assert_eq!(widened.to_bits(), 0x4009_21FB_6000_0000);
        assert_eq!(
            decode(&hex("fa3dcccccd")),
            Ok(Value::Float(0.100_000_001_490_116_12))
        );
    }

    #[test]
    fn input_beyond_the_frame_cap_is_refused() {
        // A byte string that fills the cap exactly decodes; one byte more is refused unread.
        let content = MAX_FRAME_BYTES - 5;
        let mut at_cap = vec![0x5A];
        at_cap.extend_from_slice(&u32::try_from(content).unwrap().to_be_bytes());
        at_cap.resize(MAX_FRAME_BYTES, 0);
        assert_eq!(
            decode(&at_cap).map(|value| value.as_bytes().map(<[u8]>::len)),
            Ok(Some(content))
        );
        let mut over = at_cap;
        over.push(0);
        assert_eq!(
            decode(&over),
            Err(CborError::TooLarge {
                length: MAX_FRAME_BYTES + 1,
                limit: MAX_FRAME_BYTES
            })
        );
    }

    /// Only the keys Jackson reads (text, integers, byte strings) decode leniently;
    /// arrays, maps, and simple values or floats as keys are refused before they are built. The
    /// wire encoding takes indefinite maps of text keys alone (S8).
    #[test]
    fn map_keys_are_text_integers_or_bytes() {
        for (input, offset, byte) in [
            ("a1810000", 1, 0x81),
            ("a1a1000000", 1, 0xA1),
            ("bf9f00ff00ff", 1, 0x9F),
            ("a1f500", 1, 0xF5),
            ("a1f600", 1, 0xF6),
            ("a1f93c0000", 1, 0xF9),
            ("a1fb3ff000000000000000", 1, 0xFB),
            ("a26161008100", 4, 0x81),
        ] {
            assert_eq!(
                decode_lenient(&hex(input)),
                Err(CborError::UnsupportedKey { offset, byte }),
                "{input}"
            );
            // A definite map is refused first on the wire; an indefinite one at its key.
            let expected = if input.starts_with("bf") {
                CborError::UnsupportedKey { offset, byte }
            } else {
                CborError::NotWireEncoding {
                    offset: 0,
                    rule: WireRule::IndefiniteMap,
                }
            };
            assert_eq!(decode(&hex(input)), Err(expected), "{input}");
            let indefinite = format!("bf{}ff", &input[2..]);
            if input.starts_with("a1") {
                assert_eq!(
                    decode(&hex(&indefinite)),
                    Err(CborError::UnsupportedKey { offset, byte }),
                    "{indefinite}"
                );
            }
        }
        // A map past the pairwise duplicate check whose 17th key is a map.
        let mut wide = vec![0xBF];
        for k in 0..16u8 {
            wide.extend_from_slice(&[0x61, b'a' + k, 0x00]);
        }
        wide.extend_from_slice(&hex("a1000000ff"));
        for read in [decode, decode_lenient] {
            assert_eq!(
                read(&wide),
                Err(CborError::UnsupportedKey {
                    offset: 49,
                    byte: 0xA1
                })
            );
        }
        // Byte-string, negative, and positive integer keys still decode leniently; a break
        // where a definite map's key belongs is still an unexpected break.
        assert_eq!(
            decode_lenient(&hex("a1410000")),
            Ok(Value::Map(
                [(Value::from(b"\x00".as_slice()), Value::Int(0))]
                    .into_iter()
                    .collect()
            ))
        );
        assert!(decode_lenient(&hex("a12000")).is_ok());
        assert!(decode_lenient(&hex("a10000")).is_ok());
        assert_eq!(
            decode_lenient(&hex("a1ff00")),
            Err(CborError::UnexpectedBreak { offset: 1 })
        );
        // On the wire each of those keys is refused (S8), and a tag is no key in either read.
        for input in ["bf410000ff", "bf2000ff", "bf0000ff"] {
            assert!(decode_lenient(&hex(input)).is_ok(), "{input}");
            assert_eq!(
                decode(&hex(input)),
                Err(CborError::NotWireEncoding {
                    offset: 1,
                    rule: WireRule::TextKey
                }),
                "{input}"
            );
        }
        for read in [decode, decode_lenient] {
            assert_eq!(
                read(&hex("bfc24901000000000000000000ff")),
                Err(CborError::Tag { offset: 1 })
            );
        }
    }

    #[test]
    fn units_and_chunk_ends_count_utf16_as_java_does() {
        for text in [
            "",
            "a",
            "\u{e9}",
            "\u{4e2d}",
            "\u{1f600}",
            "a\u{e9}\u{4e2d}\u{1f600}z",
        ] {
            assert_eq!(utf16_units(text), text.encode_utf16().count(), "{text}");
        }
        let aligned = "a".repeat(TEXT_CHUNK_UNITS + 5);
        assert_eq!(chunk_end(&aligned), (TEXT_CHUNK_UNITS, TEXT_CHUNK_UNITS));
        // A pair whose high surrogate would be the chunk's last unit starts the next chunk.
        let straddling = format!("{}\u{1f600}b", "a".repeat(TEXT_CHUNK_UNITS - 1));
        assert_eq!(
            chunk_end(&straddling),
            (TEXT_CHUNK_UNITS - 1, TEXT_CHUNK_UNITS - 1)
        );
        let fitting = format!("{}\u{1f600}b", "a".repeat(TEXT_CHUNK_UNITS - 2));
        assert_eq!(
            chunk_end(&fitting),
            (TEXT_CHUNK_UNITS + 2, TEXT_CHUNK_UNITS)
        );
        // 3997 units: a chunk of 3996 and one of 1, never an empty one.
        let mut out = Vec::new();
        write_text(&"a".repeat(TEXT_CHUNK_UNITS + 1), &mut out);
        assert_eq!(&out[..4], &[0x7F, 0x79, 0x0F, 0x9C]);
        assert_eq!(&out[out.len() - 3..], &[0x61, b'a', 0xFF]);
    }

    /// The stamp items alone, as the documents `stamp row 1` to `stamp row 11` of
    /// `tests/jackson-wire-vectors.json` send them: rows 10 and 11 (a stamp in one chunk and in
    /// two) are refused under S6 as Java, Python, TypeScript, and Ruby refuse them (SPEC §9: a
    /// stamp is definite text), and rows 5 to 9 (a head wider than the length needs) under S3.
    #[test]
    fn stamp_items_decode_as_java_reads_them() {
        let row2 = "1762560000000:65536:zPeer";
        let row2_hex: String = row2.bytes().map(|b| format!("{b:02x}")).collect();
        let rows: [(&str, Option<WireRule>); 11] = [
            ("65353a303a6e", None),
            (&format!("7819{row2_hex}"), None),
            ("66353a303ac3b1", None),
            ("68353a303af09f9880", None),
            ("7805353a303a6e", Some(WireRule::ShortestHead)),
            ("790005353a303a6e", Some(WireRule::ShortestHead)),
            ("7a00000005353a303a6e", Some(WireRule::ShortestHead)),
            ("7b0000000000000005353a303a6e", Some(WireRule::ShortestHead)),
            (&format!("790019{row2_hex}"), Some(WireRule::ShortestHead)),
            ("7f65353a303a6eff", Some(WireRule::TextChunks)),
            ("7f62353a63303a6eff", Some(WireRule::TextChunks)),
        ];
        for (index, (input, refused)) in rows.iter().enumerate() {
            let row = index + 1;
            let lenient = decode_lenient(&hex(input)).expect("the lenient read takes rows 1 to 11");
            match refused {
                None => assert_eq!(decode(&hex(input)), Ok(lenient), "row {row}"),
                Some(rule) => assert_eq!(
                    decode(&hex(input)),
                    Err(CborError::NotWireEncoding {
                        offset: 0,
                        rule: *rule
                    }),
                    "row {row}"
                ),
            }
        }
        assert_eq!(
            decode_lenient(&hex("7f62353a63303a6eff")),
            Ok(Value::from("5:0:n"))
        );
        // Rows 12 to 14 (tags), 15 to 20 (UTF-8) stay refused in both reads.
        for input in [
            "c065353a303a6e",
            "d82065353a303a6e",
            "d9d9f765353a303a6e",
            "66353a303ac1ae",
            "67353a303ae081ae",
            "6635c0ba303a6e",
            "67353a303aeda080",
            "65353a303aff",
            "66353a303a6e80",
        ] {
            assert!(decode(&hex(input)).is_err(), "{input}");
            assert!(decode_lenient(&hex(input)).is_err(), "{input}");
        }
    }

    /// The forms of a text rule S6 refuses, and the other rules a lenient read does not hold an
    /// input to, each with the rule it breaks.
    #[test]
    fn the_wire_encoding_refuses_what_the_lenient_read_takes() {
        let long = "61".repeat(TEXT_CHUNK_UNITS + 1);
        let chunk = "61".repeat(TEXT_CHUNK_UNITS);
        for (input, offset, rule) in [
            ("1817", 0, WireRule::ShortestHead),
            ("5801aa", 0, WireRule::ShortestHead),
            ("980101", 0, WireRule::ShortestHead),
            ("d80249010000000000000000", 0, WireRule::ShortestHead),
            ("1b8000000000000000", 0, WireRule::LongRange),
            ("3bffffffffffffffff", 0, WireRule::LongRange),
            (&format!("790f9d{long}"), 0, WireRule::LongText),
            (&format!("7f790f9d{long}ff"), 0, WireRule::TextChunks),
            (&format!("7f790f9c{chunk}616160ff"), 0, WireRule::TextChunks),
            (&format!("7f790f9c{chunk}ff"), 0, WireRule::TextChunks),
            ("7fff", 0, WireRule::TextChunks),
            ("7f6060ff", 0, WireRule::TextChunks),
            ("817f6161ff", 1, WireRule::TextChunks),
            ("9f01ff", 0, WireRule::DefiniteArray),
            ("a0", 0, WireRule::IndefiniteMap),
            ("bf0101ff", 1, WireRule::TextKey),
            ("f97e00", 0, WireRule::Float),
            ("fa7fc00001", 0, WireRule::Float),
            ("fbfff8000000000000", 0, WireRule::Float),
            ("f7", 0, WireRule::SimpleValue),
        ] {
            assert_eq!(
                decode(&hex(input)),
                Err(CborError::NotWireEncoding { offset, rule }),
                "{}",
                &input[..input.len().min(24)]
            );
            assert!(decode_lenient(&hex(input)).is_ok(), "{input}");
        }
    }

    /// An integer outside Java's `long` is a bignum both ways, Jackson's tag 3
    /// holding the magnitude (the bytes are `CborCodec`'s, `tests/jackson-wire-vectors.json`).
    #[test]
    fn integers_outside_a_long_are_bignums() {
        let two_63 = 1i128 << 63;
        for (n, bytes) in [
            (two_63 - 1, "1b7fffffffffffffff"),
            (-two_63, "3b7fffffffffffffff"),
            (two_63, "c249008000000000000000"),
            (-two_63 - 1, "c349008000000000000001"),
            (INT_MAX, "c24900ffffffffffffffff"),
            (INT_MIN, "c349010000000000000000"),
        ] {
            assert_eq!(encode(&Value::Int(n)), hex(bytes), "{n}");
            assert_eq!(decode(&hex(bytes)), Ok(Value::Int(n)), "{n}");
        }
        let big = decode(&hex("c249010000000000000000")).expect("2^64");
        assert_eq!(big.type_name(), "bignum");
        assert_eq!(format!("{big:?}"), "18446744073709551616");
        assert_eq!(encode(&big), hex("c249010000000000000000"));
        let below = decode(&hex("c349010000000000000001")).expect("-2^64 - 1");
        assert_eq!(below.as_big_int().map(BigInt::is_negative), Some(true));
        assert_eq!(encode(&below), hex("c349010000000000000001"));
        // The bignum forms S9 refuses, and Jackson's 1000-byte limit.
        for (input, rule) in [
            ("c2487fffffffffffffff", WireRule::Bignum),
            ("c349008000000000000000", WireRule::Bignum),
            ("c24180", WireRule::Bignum),
            ("c240", WireRule::Bignum),
            ("c243000080", WireRule::Bignum),
        ] {
            assert_eq!(
                decode(&hex(input)),
                Err(CborError::NotWireEncoding { offset: 0, rule }),
                "{input}"
            );
        }
        let mut oversized = hex("c25903e9");
        oversized.push(0x7F);
        oversized.resize(oversized.len() + MAX_BIGNUM_BYTES, 0xFF);
        assert_eq!(
            decode(&oversized),
            Err(CborError::BignumTooLong {
                offset: 0,
                length: MAX_BIGNUM_BYTES + 1,
                limit: MAX_BIGNUM_BYTES
            })
        );
        for input in ["c201", "c2c24101", "c25f4101ff", "c0 6161", "dfff"] {
            let input: String = input.split_whitespace().collect();
            assert!(
                matches!(
                    decode(&hex(&input)),
                    Err(CborError::Tag { .. } | CborError::MalformedHead { .. })
                ),
                "{input}"
            );
        }
        assert_eq!(
            try_encode(&Value::Int(INT_MAX)),
            Ok(hex("c24900ffffffffffffffff"))
        );
    }

    /// A decimal is tag 4 over `[exponent, mantissa]`, normalized, its
    /// exponent inside ±(2^31 - 1), and the array a nesting level.
    #[test]
    fn decimals_are_tag_four_normalized() {
        for (input, text) in [
            ("c48221187d", "1.25"),
            ("c4820000", "0"),
            ("c4820301", "1E+3"),
            ("c48220387c", "-12.5"),
            ("c48224c249400000000000000000", "11805916207174113.03424"),
            ("c4823a7ffffffe01", "1E-2147483647"),
        ] {
            let value = decode(&hex(input)).expect(input);
            let decimal = value.as_decimal().expect("a decimal");
            assert_eq!(decimal.to_string(), text, "{input}");
            assert_eq!(encode(&value), hex(input), "{input}");
            assert_eq!(text.parse::<Decimal>().as_ref(), Ok(decimal), "{text}");
        }
        for input in [
            "c4820100",
            "c482000a",
            "c4823a7fffffff01",
            "c4821b000000010000000001",
        ] {
            assert_eq!(
                decode(&hex(input)),
                Err(CborError::NotWireEncoding {
                    offset: 0,
                    rule: WireRule::Decimal
                }),
                "{input}"
            );
        }
        for input in [
            "c483200101",
            "c48200f93c00",
            "c482006131",
            "c49f2001ff",
            "c482c2410101",
        ] {
            assert!(
                matches!(decode(&hex(input)), Err(CborError::Tag { .. })),
                "{input}"
            );
        }
        let nested = |arrays: usize| {
            let mut input = vec![0x81; arrays];
            input.extend_from_slice(&hex("c4820001"));
            input
        };
        assert!(decode(&nested(MAX_CBOR_DEPTH - 1)).is_ok());
        assert!(matches!(
            decode(&nested(MAX_CBOR_DEPTH)),
            Err(CborError::TooDeep { .. })
        ));
    }

    /// Every NaN is written, and equal, as Java's `Double.NaN` (S10); the wire reads only it.
    #[test]
    fn every_nan_is_javas() {
        let quiet_negative = f64::from_bits(0xFFF8_0000_0000_0000);
        let payload = f64::from_bits(0x7FF8_0000_0000_0001);
        for nan in [f64::NAN, quiet_negative, payload] {
            assert_eq!(encode(&Value::Float(nan)), hex("fb7ff8000000000000"));
            assert_eq!(Value::Float(nan), Value::Float(f64::NAN));
        }
        assert!(decode(&hex("fb7ff8000000000000")).is_ok());
        assert!(decode(&hex("fa7fc00000")).is_ok());
        assert!(decode_lenient(&hex("fbfff8000000000000")).is_ok());
    }

    #[test]
    fn value_equality_is_encoding_equality() {
        assert_eq!(Value::Float(f64::NAN), Value::Float(f64::NAN));
        assert_ne!(Value::Float(0.0), Value::Float(-0.0));
        assert_ne!(Value::Int(1), Value::Float(1.0));
        assert_ne!(Value::from("a"), Value::from(b"a"));
    }

    #[test]
    fn debug_is_diagnostic_notation() {
        let value =
            crate::cbor_map! { "a" => b"\x00\xff", "b" => cbor_array![1, 1.5, None::<i64>, true] };
        assert_eq!(
            format!("{value:?}"),
            r#"{"a": h'00ff', "b": [1, 1.5, null, true]}"#
        );
    }

    #[test]
    fn accessors_check_types_and_ranges() {
        assert_eq!(Value::Int(-1).as_u64(), None);
        assert_eq!(Value::Int(-1).as_i64(), Some(-1));
        assert_eq!(Value::Int(INT_MAX).as_i64(), None);
        assert_eq!(Value::Int(INT_MAX).as_u64(), Some(u64::MAX));
        assert_eq!(Value::Int(3).as_f64(), Some(3.0));
        assert_eq!(Value::from("x").as_i64(), None);
        assert_eq!(Value::Null.get("x"), None);
        assert!(Value::from(None::<String>).is_null());
        assert_eq!(Value::from(Some("x")).as_str(), Some("x"));
    }
}
