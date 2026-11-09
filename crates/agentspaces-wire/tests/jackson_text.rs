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

//! Long texts as Jackson writes them: an indefinite-length text of definite chunks past 3996
//! UTF-16 units (Java `WellFormedCbor` rule S6), byte for byte in both directions.
//!
//! `jackson-text-vectors.json` is written by real Jackson through `CborCodec.defaultCodec()`
//! (`interop/jackson-vectors`, see its README): each case is a text recipe, a context (the text
//! alone, a record field, beside a byte string, a map value, a map key, an array element, a nested
//! record), and the exact bytes Java wrote. Every case must encode here to those bytes and decode
//! from them to its value. Beyond the vectors: deterministic random texts around every multiple of
//! 3996 units keep Jackson's boundaries and round trip; malformed chunked texts are refused without
//! a panic; every other form of a text (a definite long text, other boundaries, empty chunks, a
//! chunked short text) is refused by the wire decoder as Java refuses it (rule S6) and read by the
//! lenient one, which re-encodes it in the Jackson form; and a text of one-byte chunks filling the
//! frame cap is refused at once by the one and decoded in linear time by the other.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use agentspaces_wire::cbor::{self, CborError, Map, TEXT_CHUNK_UNITS, Value, WireRule};
use agentspaces_wire::identity::Identity;
use agentspaces_wire::limits::MAX_FRAME_BYTES;
use agentspaces_wire::records::{EntryWrite, entry_state, sign_view_of, verify_record};
use agentspaces_wire::{cbor_array, cbor_map};
use serde_json::Value as Json;

/// The vector file, read once.
fn vectors() -> &'static Json {
    static VECTORS: OnceLock<Json> = OnceLock::new();
    VECTORS.get_or_init(|| {
        serde_json::from_str(include_str!("jackson-text-vectors.json"))
            .expect("jackson-text-vectors.json parses")
    })
}

/// One case of the vector file.
struct Case {
    name: String,
    context: String,
    text: String,
    units: usize,
    utf8: usize,
    chunks: Vec<usize>,
    bytes: Vec<u8>,
}

fn cases() -> Vec<Case> {
    vectors()["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            let text = case["text"]
                .as_array()
                .expect("a recipe")
                .iter()
                .map(|piece| {
                    let count = piece[1].as_u64().expect("a count");
                    piece[0]
                        .as_str()
                        .expect("a piece")
                        .repeat(usize::try_from(count).expect("a count"))
                })
                .collect::<String>();
            let number = |field: &str| {
                usize::try_from(case[field].as_u64().expect(field)).expect("a length")
            };
            Case {
                name: case["name"].as_str().expect("a name").to_owned(),
                context: case["context"].as_str().expect("a context").to_owned(),
                text,
                units: number("units"),
                utf8: number("utf8"),
                chunks: case["chunks"]
                    .as_array()
                    .expect("chunks")
                    .iter()
                    .map(|n| usize::try_from(n.as_u64().expect("a chunk")).expect("a chunk"))
                    .collect(),
                bytes: hex::decode(case["hex"].as_str().expect("hex")).expect("hex decodes"),
            }
        })
        .collect()
}

/// The value the Java generator wrapped a text in for `context` (`TextVectors.wrap`).
fn wrap(context: &str, text: &str) -> Value {
    let data: Vec<u8> = (0..64).collect();
    match context {
        "value" => Value::from(text),
        "field" => cbor_map! { "text" => text },
        "bytesField" => cbor_map! { "text" => text, "data" => data },
        "mapValue" => cbor_map! { "k" => text },
        "mapKey" => cbor_map! { text => "v" },
        "arrayElement" => cbor_map! { "items" => cbor_array!["a", text, "z"] },
        "nested" => cbor_map! { "id" => "o", "inner" => cbor_map! { "text" => text }, "n" => 7 },
        other => panic!("an unknown context {other}"),
    }
}

/// The UTF-16 length of each chunk of an encoded text item, by walking its bytes independently
/// of the decoder; empty for a definite text.
fn chunk_units(bytes: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    if bytes.first() != Some(&0x7F) {
        return lengths;
    }
    let mut at = 1;
    while bytes[at] != 0xFF {
        let head = bytes[at];
        assert_eq!(head >> 5, 3, "a chunk is a text string");
        let (length, width) = match head & 0x1F {
            info @ 0..=23 => (usize::from(info), 0),
            24 => (usize::from(bytes[at + 1]), 1),
            25 => (
                usize::from(u16::from_be_bytes([bytes[at + 1], bytes[at + 2]])),
                2,
            ),
            other => panic!("a chunk head of additional information {other}"),
        };
        let minimal = match width {
            0 => length < 24,
            1 => (24..256).contains(&length),
            _ => length >= 256,
        };
        assert!(minimal, "a chunk head is minimal");
        let from = at + 1 + width;
        let chunk = std::str::from_utf8(&bytes[from..from + length]).expect("a chunk is UTF-8");
        lengths.push(chunk.encode_utf16().count());
        at = from + length;
    }
    assert_eq!(at, bytes.len() - 1, "the break ends the text");
    lengths
}

/// The chunk lengths of Java's rule, computed over UTF-16 units as Java holds the text
/// (`WellFormedCbor.chunking`, `TextVectors.expectedChunks`).
fn rule_chunks(text: &str) -> Vec<usize> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut lengths = Vec::new();
    let mut remaining = units.len();
    if remaining <= TEXT_CHUNK_UNITS {
        return lengths;
    }
    let mut offset = 0;
    while remaining > TEXT_CHUNK_UNITS {
        let last = units[offset + TEXT_CHUNK_UNITS - 1];
        let take = if (0xD800..=0xDBFF).contains(&last) {
            TEXT_CHUNK_UNITS - 1
        } else {
            TEXT_CHUNK_UNITS
        };
        lengths.push(take);
        offset += take;
        remaining -= take;
    }
    lengths.push(remaining);
    lengths
}

// ---------------------------------------------------------------------------------- vectors

#[test]
fn the_vectors_are_real_jackson_and_cover_every_context() {
    let file = vectors();
    assert_eq!(file["textChunk"], 3996);
    assert_eq!(TEXT_CHUNK_UNITS, 3996);
    assert_eq!(
        file["codecAgreesWithPlainMapper"], true,
        "CborCodec writes text as a plain CBORMapper does"
    );
    assert_eq!(
        file["emptyChunkSeen"], false,
        "Jackson never writes an empty chunk"
    );
    assert_eq!(
        file["mapKeysChunked"], true,
        "Jackson chunks a long map key as it chunks a value"
    );
    let cases = cases();
    assert!(cases.len() >= 80, "{} cases", cases.len());
    for context in [
        "value",
        "field",
        "bytesField",
        "mapValue",
        "mapKey",
        "arrayElement",
        "nested",
    ] {
        let chunked = cases
            .iter()
            .filter(|case| case.context == context && !case.chunks.is_empty())
            .count();
        assert!(chunked >= 5, "{context}: {chunked} chunked cases");
    }
    // A chunk that ends one unit early, at every boundary of a text.
    assert!(
        cases
            .iter()
            .any(|case| case.chunks == [3995, 3995, 3995, 102])
    );
}

#[test]
fn every_jackson_vector_encodes_byte_for_byte() {
    for case in cases() {
        let label = format!("{} in {}", case.name, case.context);
        assert_eq!(case.text.encode_utf16().count(), case.units, "{label}");
        assert_eq!(case.text.len(), case.utf8, "{label}");
        let encoded = cbor::encode(&wrap(&case.context, &case.text));
        assert!(
            encoded == case.bytes,
            "{label}: Rust wrote {} bytes, Java {}; first difference at {:?}",
            encoded.len(),
            case.bytes.len(),
            encoded.iter().zip(&case.bytes).position(|(a, b)| a != b)
        );
        // The text's own encoding is the same in every context, and chunked as Java says.
        let alone = cbor::encode(&Value::from(case.text.as_str()));
        assert_eq!(chunk_units(&alone), case.chunks, "{label}");
        assert_eq!(rule_chunks(&case.text), case.chunks, "{label}");
        assert!(
            case.bytes
                .windows(alone.len())
                .any(|window| window == alone),
            "{label}: the text's encoding appears as is"
        );
    }
}

#[test]
fn every_jackson_vector_decodes_to_its_value() {
    for case in cases() {
        let label = format!("{} in {}", case.name, case.context);
        let decoded = cbor::decode(&case.bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(
            decoded == wrap(&case.context, &case.text),
            "{label}: decodes to its value"
        );
        assert_eq!(cbor::encode(&decoded), case.bytes, "{label}: re-encodes");
    }
}

// ---------------------------------------------------------------------------------- round trips

/// SplitMix64: a deterministic generator, so every run tests the same texts.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// A character of a UTF-8 width the mix picks, from ranges that hold only scalar values.
    fn character(&mut self, mix: u64) -> char {
        let pick = self.below(100);
        let code = if pick < mix {
            0x1_0000 + self.below(0x10_0000) // four bytes, a surrogate pair in UTF-16
        } else if pick < mix + (100 - mix) / 3 {
            0x80 + self.below(0x780) // two bytes
        } else if pick < mix + 2 * (100 - mix) / 3 {
            0xE000 + self.below(0x2000) // three bytes, past the surrogates
        } else {
            0x20 + self.below(0x5F) // ASCII
        };
        char::from_u32(u32::try_from(code).expect("a code point")).expect("a scalar value")
    }

    /// A text of exactly `units` UTF-16 units: random characters, a one-unit one where a pair
    /// would overshoot.
    fn text(&mut self, units: usize, mix: u64) -> String {
        let mut text = String::new();
        let mut have = 0;
        while have < units {
            let mut character = self.character(mix);
            if have + character.len_utf16() > units {
                character = 'z';
            }
            have += character.len_utf16();
            text.push(character);
        }
        text
    }
}

#[test]
fn random_texts_round_trip_in_jackson_chunks() {
    let mut random = Random(0x5EED_3996);
    let mut texts = 0;
    let mut early = 0;
    for multiple in 1..=4 {
        for delta in -4i64..=4 {
            let units =
                usize::try_from(i64::try_from(multiple * TEXT_CHUNK_UNITS).unwrap() + delta)
                    .expect("a length");
            for mix in [0, 10, 50, 90, 100] {
                let text = random.text(units, mix);
                assert_eq!(text.encode_utf16().count(), units);
                let encoded = cbor::encode(&Value::from(text.as_str()));
                let chunks = chunk_units(&encoded);
                assert_eq!(chunks, rule_chunks(&text), "{units} units, mix {mix}");
                assert_eq!(chunks.is_empty(), units <= TEXT_CHUNK_UNITS);
                assert!(chunks.iter().all(|&n| n > 0), "no empty chunk");
                early += chunks
                    .iter()
                    .rev()
                    .skip(1)
                    .filter(|&&n| n == TEXT_CHUNK_UNITS - 1)
                    .count();
                assert_eq!(
                    cbor::decode(&encoded),
                    Ok(Value::Text(text.clone())),
                    "{units} units, mix {mix}"
                );
                // As a map key and inside a record, too.
                let record = cbor_map! { text.as_str() => text.as_str(), "n" => 1 };
                assert_eq!(cbor::decode(&cbor::encode(&record)), Ok(record));
                texts += 1;
            }
        }
    }
    assert_eq!(texts, 4 * 9 * 5);
    assert!(early > 20, "pairs straddled {early} boundaries");
}

#[test]
fn a_pair_at_every_offset_of_the_first_boundary_keeps_the_rule() {
    for before in 3980..4010 {
        let text = format!("{}\u{1F600}{}", "a".repeat(before), "b".repeat(50));
        let encoded = cbor::encode(&Value::from(text.as_str()));
        assert_eq!(chunk_units(&encoded), rule_chunks(&text), "{before}");
        assert_eq!(cbor::decode(&encoded), Ok(Value::Text(text)));
    }
}

#[test]
fn short_texts_keep_their_definite_bytes() {
    for (text, expected) in [
        ("", "60"),
        ("a", "6161"),
        ("\u{1F600}", "64f09f9880"),
        ("\u{e9}", "62c3a9"),
    ] {
        assert_eq!(hex::encode(cbor::encode(&Value::from(text))), expected);
    }
    // 1998 surrogate pairs are 3996 units and 7992 bytes: one definite text.
    let pairs = "\u{1F600}".repeat(1998);
    let encoded = cbor::encode(&Value::from(pairs.as_str()));
    assert_eq!(&encoded[..3], &[0x79, 0x1F, 0x38]);
    assert_eq!(encoded.len(), 3 + 7992);
}

// ---------------------------------------------------------------------------------- malformed

#[test]
fn malformed_chunked_texts_are_refused_without_a_panic() {
    let refused = |input: &str| cbor::decode(&hex::decode(input).expect("hex"));
    for (input, expected) in [
        // A byte string, a nested indefinite text, and other items as chunks.
        (
            "7f4161ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0x41,
            },
        ),
        (
            "7f7f6161ffff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0x7F,
            },
        ),
        (
            "7f01ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0x01,
            },
        ),
        (
            "7f80ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0x80,
            },
        ),
        (
            "7fa0ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0xA0,
            },
        ),
        (
            "7fc06161ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0xC0,
            },
        ),
        (
            "7ff6ff",
            CborError::InvalidChunk {
                offset: 1,
                byte: 0xF6,
            },
        ),
        (
            "7f61617f",
            CborError::InvalidChunk {
                offset: 3,
                byte: 0x7F,
            },
        ),
        // Invalid UTF-8 in a chunk, and chunks that split a UTF-8 sequence.
        ("7f61ffff", CborError::InvalidUtf8 { offset: 1 }),
        ("7f6161 61c3 61a9ff", CborError::InvalidUtf8 { offset: 3 }),
        ("7f62f09f6298 80ff", CborError::InvalidUtf8 { offset: 1 }),
        ("7f63eda080ff", CborError::InvalidUtf8 { offset: 1 }),
        // A missing break, an empty tail, a chunk longer than the input, a reserved head.
        ("7f", CborError::Truncated { offset: 1 }),
        ("7f6161", CborError::Truncated { offset: 3 }),
        (
            "7f62",
            CborError::LengthExceedsInput {
                offset: 1,
                length: 2,
                remaining: 0,
            },
        ),
        (
            "7f7affffffffff",
            CborError::LengthExceedsInput {
                offset: 1,
                length: 0xFFFF_FFFF,
                remaining: 1,
            },
        ),
        (
            "7f7cff",
            CborError::MalformedHead {
                offset: 1,
                byte: 0x7C,
            },
        ),
        // Indefinite byte strings stay refused, inside a text's place or anywhere.
        ("5f4100ff", CborError::IndefiniteString { offset: 0 }),
        (
            "817f5f4100ffff",
            CborError::InvalidChunk {
                offset: 2,
                byte: 0x5F,
            },
        ),
    ] {
        let input: String = input.split_whitespace().collect();
        assert_eq!(refused(&input), Err(expected.clone()), "{input}");
        assert_eq!(
            cbor::decode_lenient(&hex::decode(&input).expect("hex")),
            Err(expected),
            "{input}"
        );
    }
    // A chunked key equal to a definite one is a duplicate where a short chunked key reads (the
    // lenient read); on the wire the chunked short key is refused first (S6), and two keys in
    // Jackson's chunks that are equal are a duplicate.
    let duplicate = hex::decode("bf7f6161ff01616102ff").expect("hex");
    assert_eq!(
        cbor::decode_lenient(&duplicate),
        Err(CborError::DuplicateKey { offset: 0 })
    );
    assert_eq!(
        cbor::decode(&duplicate),
        Err(CborError::NotWireEncoding {
            offset: 1,
            rule: WireRule::TextChunks
        })
    );
    let long_key = cbor::encode(&Value::from("k".repeat(TEXT_CHUNK_UNITS + 1)));
    let twice = [&[0xBF][..], &long_key, &[0x01], &long_key, &[0x02, 0xFF]].concat();
    assert_eq!(
        cbor::decode(&twice),
        Err(CborError::DuplicateKey { offset: 0 })
    );
}

// ---------------------------------------------------------------------------------- other forms

/// Every form of a text but Jackson's is refused on the wire (rule S6), as Java's
/// `checkCanonical`, Python, TypeScript, and Ruby refuse it, so a relay cannot re-chunk or pad a
/// signed item that Rust would verify over its re-encoding while every other implementation
/// drops it. The lenient read (for bytes this process stored) still reads each
/// form and re-encodes it as Jackson writes it.
#[test]
fn other_text_forms_are_refused_on_the_wire_and_re_encode_as_jackson_writes() {
    let chunks = |input: &[u8]| cbor::decode(input);
    let s6 = |offset| {
        Err(CborError::NotWireEncoding {
            offset,
            rule: WireRule::TextChunks,
        })
    };
    // A definite text past the chunk length, as older Rust, Python, and Ruby peers wrote it.
    let long = "\u{e9}".repeat(5000);
    let mut definite = vec![0x79];
    definite.extend_from_slice(&u16::try_from(long.len()).unwrap().to_be_bytes());
    definite.extend_from_slice(long.as_bytes());
    assert_eq!(
        cbor::decode(&definite),
        Err(CborError::NotWireEncoding {
            offset: 0,
            rule: WireRule::LongText
        })
    );
    let decoded = cbor::decode_lenient(&definite).expect("a definite long text decodes leniently");
    assert_eq!(decoded, Value::Text(long.clone()));
    let jackson = cbor::encode(&decoded);
    assert_eq!(chunk_units(&jackson), [3996, 1004]);
    assert_ne!(jackson, definite);
    assert_eq!(cbor::decode(&jackson), Ok(Value::Text(long.clone())));

    // Chunks of a thousand units each: the same text, re-encoded in Jackson's chunks.
    let mut thousands = vec![0x7F];
    for chunk in long.as_bytes().chunks(2000) {
        thousands.push(0x79);
        thousands.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
        thousands.extend_from_slice(chunk);
    }
    thousands.push(0xFF);
    assert_eq!(chunks(&thousands), s6(0));
    assert_eq!(
        cbor::decode_lenient(&thousands),
        Ok(Value::Text(long.clone()))
    );
    assert_eq!(
        cbor::encode(&cbor::decode_lenient(&thousands).unwrap()),
        jackson
    );

    // Jackson's chunks with an empty chunk added, at the end or in between; one oversized chunk.
    let mut padded = jackson.clone();
    padded.insert(padded.len() - 1, 0x60);
    assert_eq!(chunks(&padded), s6(0));
    let mut between = vec![0x7F];
    between.extend_from_slice(&jackson[1..jackson.len() - 1]);
    let second = 1 + 3 + 3996 * 2;
    between.insert(second, 0x60);
    between.push(0xFF);
    assert_eq!(chunks(&between), s6(0));
    let mut whole = vec![0x7F];
    whole.extend_from_slice(&definite);
    whole.push(0xFF);
    assert_eq!(chunks(&whole), s6(0));
    for input in [&padded, &between, &whole] {
        assert_eq!(cbor::decode_lenient(input), Ok(Value::Text(long.clone())));
    }

    // Empty chunks, no chunks, and a chunked short text (among them a stamp in chunks, the
    // documents `stamp row 10` and `stamp row 11`): refused on the wire, each re-encodes definite
    // when read leniently.
    for (input, text, again) in [
        ("7f6060ff", "", "60"),
        ("7fff", "", "60"),
        ("7f616160ff", "a", "6161"),
        ("7f61616162ff", "ab", "626162"),
        ("7f65353a303a6eff", "5:0:n", "65353a303a6e"),
        ("7f62353a63303a6eff", "5:0:n", "65353a303a6e"),
    ] {
        let bytes = hex::decode(input).unwrap();
        assert_eq!(chunks(&bytes), s6(0), "{input}");
        let decoded = cbor::decode_lenient(&bytes).expect(input);
        assert_eq!(decoded, Value::from(text), "{input}");
        assert_eq!(hex::encode(cbor::encode(&decoded)), again, "{input}");
    }

    // A chunked short text as a map key and inside an indefinite array: refused on the wire.
    let key = hex::decode("bf7f61616162ff01ff").unwrap();
    assert_eq!(chunks(&key), s6(1));
    let mut map = Map::new();
    map.insert("ab", Value::Int(1));
    assert_eq!(cbor::decode_lenient(&key), Ok(Value::Map(map)));
    let array = hex::decode("9f7f6178ffff").unwrap();
    assert!(chunks(&array).is_err());
    assert_eq!(cbor::decode_lenient(&array), Ok(cbor_array!["x"]));
    assert_eq!(chunks(&hex::decode("817f6178ffff").unwrap()), s6(1));
}

// ---------------------------------------------------------------------------------- signatures

/// The definite encoding of a text, as Rust, Python, and Ruby peers wrote every text before.
fn definite(text: &str) -> Vec<u8> {
    let mut out = vec![0x7A];
    out.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

/// `bytes` with the first occurrence of `from` replaced by `to`.
fn replaced(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("the bytes hold the text");
    [&bytes[..at], to, &bytes[at + from.len()..]].concat()
}

/// A signature over a re-encoding covers the long texts in Jackson's chunks: a record whose tag
/// and payload hold long texts signs and, once received (decoded from its encoding), verifies,
/// its sign view holding the tag chunked; a record signed over the definite form of the same view
/// (an older peer's) does not verify here, as Java refuses it.
#[test]
fn a_record_with_long_texts_signs_and_verifies_over_jackson_chunks() {
    let identity = Identity::from_seed(&[7; 32]);
    let issued = format!("1735689600000:0:{}", identity.peer_id());
    let mut random = Random(0x7A65);
    let note = random.text(5_000, 50);
    let topic = random.text(9_000, 30);
    let mut tags = Map::new();
    tags.insert("note", note.as_str());
    let payload = cbor::encode(&cbor_map! { "topic" => topic.as_str(), "priority" => 1 });
    let write = EntryWrite {
        entry_id: "11111111-2222-3333-4444-555555555555",
        space_id: "z2zifgVUFH2KJqQSoZxoEsBTmVtcgYqDuemnhq9NS7L3a",
        type_name: "Task#v1",
        payload: Some(&payload),
        payload_ref: None,
        tags: Some(&tags),
        key_epoch: None,
        issued: &issued,
        expires_at_millis: 1_735_693_200_000,
        counter: 1,
    };
    let state = entry_state(&write, &identity, "rust", None).expect("a signed write");
    let received = cbor::decode(&cbor::encode(&Value::Map(state))).expect("the state decodes");
    let mut record = received
        .get("record")
        .and_then(Value::as_map)
        .expect("a record")
        .clone();
    assert_eq!(
        record.get("tags"),
        Some(&cbor_map! { "note" => note.as_str() })
    );
    let view = cbor::encode(&Value::Map(sign_view_of(&record).expect("a sign view")));
    let chunked = cbor::encode(&Value::from(note.as_str()));
    assert_eq!(chunked[0], 0x7F);
    assert!(view.windows(chunked.len()).any(|window| window == chunked));
    let now = 1_735_689_600_000;
    assert!(verify_record(&record, identity.public_raw(), None, now));

    // Signed over the definite form of the same view: refused.
    let old_view = replaced(&view, &chunked, &definite(&note));
    record.insert("sig", identity.sign(&old_view).to_vec());
    assert!(!verify_record(&record, identity.public_raw(), None, now));
    record.insert("sig", identity.sign(&view).to_vec());
    assert!(verify_record(&record, identity.public_raw(), None, now));
}

// ---------------------------------------------------------------------------------- floods

/// One-byte chunks (`61 61`, two input bytes each) and empty ones (`60`, one byte each), filling
/// the frame cap: millions of chunks. The wire decoder refuses each flood at its second chunk
/// (no chunk follows one shorter than Jackson's); the lenient one decodes it in one pass.
#[test]
fn a_flood_of_tiny_chunks_is_refused_at_once_and_decodes_leniently_in_linear_time() {
    let pairs = (MAX_FRAME_BYTES - 2) / 2;
    let mut ones = Vec::with_capacity(MAX_FRAME_BYTES);
    ones.push(0x7F);
    for _ in 0..pairs {
        ones.extend_from_slice(&[0x61, b'a']);
    }
    ones.push(0xFF);
    let mut empties = vec![0x60; MAX_FRAME_BYTES];
    empties[0] = 0x7F;
    empties[MAX_FRAME_BYTES - 1] = 0xFF;

    let started = Instant::now();
    for flood in [&ones, &empties] {
        assert_eq!(
            cbor::decode(flood),
            Err(CborError::NotWireEncoding {
                offset: 0,
                rule: WireRule::TextChunks
            })
        );
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "refused at the second chunk, not after the flood: {:?}",
        started.elapsed()
    );
    let started = Instant::now();
    let text = cbor::decode_lenient(&ones).expect("one-byte chunks decode leniently");
    assert_eq!(text.as_str().map(str::len), Some(pairs));
    assert_eq!(cbor::decode_lenient(&empties), Ok(Value::from("")));
    // Linear work is well under a second even unoptimized; a quadratic join would take hours.
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );

    // Past the cap the input is refused unread, chunked or not.
    ones.push(0x00);
    for read in [cbor::decode, cbor::decode_lenient] {
        assert!(matches!(read(&ones), Err(CborError::TooLarge { .. })));
    }
}
