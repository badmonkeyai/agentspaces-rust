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

//! CIDs of tree nodes (annex H, nodes and CIDs): `"b"` + base32lower(`0x01`, codec, `0x12`,
//! `0x20`, sha2-256 of the bytes), with codec `dag-cbor` (0x71) for a structured node and `raw`
//! (0x55) for a blob chunk. The binary form is the 36 bytes after the multibase prefix; a CID's
//! text is always 59 characters. A codec or multihash this module does not know is refused by
//! name. A BLAKE3 identity (multihash 0x1e, PDT 2) parses through [`identity_digest`] only and is
//! never a node link.

use super::{NodeError, sha256};

/// The `dag-cbor` codec of a structured node.
pub const DAG_CBOR: u8 = 0x71;
/// The `raw` codec of a blob chunk.
pub const RAW: u8 = 0x55;
/// The sha2-256 multihash code.
pub const SHA2_256: u8 = 0x12;
/// The BLAKE3 multihash code of a blob identity (PDT 2).
pub const BLAKE3: u8 = 0x1E;
/// The bytes of a digest.
pub const DIGEST_LENGTH: usize = 32;
/// The bytes of a binary CID.
pub const BINARY_LENGTH: usize = 4 + DIGEST_LENGTH;
/// The characters of a CID's text.
pub const TEXT_LENGTH: usize = 59;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A parsed CID: its codec and its sha2-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    /// [`DAG_CBOR`] or [`RAW`].
    pub codec: u8,
    /// The sha2-256 digest.
    pub digest: [u8; 32],
}

/// RFC 4648 base32, lower case, unpadded.
pub fn base32_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 0x1F) as usize] as char);
            bits -= 5;
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

/// The bytes of lower-case unpadded base32, or `None` for a character outside the alphabet or
/// pad bits that are not zero.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    if buffer != 0 {
        return None;
    }
    Some(out)
}

/// The CID of `data` under `codec` ([`DAG_CBOR`] or [`RAW`]).
pub fn of(data: &[u8], codec: u8) -> String {
    of_digest(&sha256(data), codec)
}

/// The CID of a sha2-256 digest under `codec`.
pub fn of_digest(digest: &[u8; 32], codec: u8) -> String {
    let mut binary = [0u8; BINARY_LENGTH];
    binary[..4].copy_from_slice(&[0x01, codec, SHA2_256, DIGEST_LENGTH as u8]);
    binary[4..].copy_from_slice(digest);
    format!("b{}", base32_lower(&binary))
}

/// The codec and digest of a CID; refuses anything outside the pinned form by name.
pub fn parse(cid: &str) -> Result<Parsed, NodeError> {
    let refuse = |why: &str| NodeError::new(format!("{why}: {cid:?}"));
    if cid.len() != TEXT_LENGTH || !cid.starts_with('b') {
        return Err(refuse("not a base32 CIDv1 of a sha2-256 digest"));
    }
    let raw = base32_decode(&cid[1..]).ok_or_else(|| refuse("not base32 text"))?;
    parse_binary(&raw).map_err(|e| NodeError::new(format!("{} in {cid}", e.rule)))
}

/// The codec and digest of a 36-byte binary CID.
pub fn parse_binary(raw: &[u8]) -> Result<Parsed, NodeError> {
    if raw.len() != BINARY_LENGTH || raw[0] != 0x01 {
        return Err(NodeError::new("not a CIDv1"));
    }
    if raw[1] != DAG_CBOR && raw[1] != RAW {
        return Err(NodeError::new(format!("unknown codec 0x{:02x}", raw[1])));
    }
    if raw[2] != SHA2_256 {
        return Err(NodeError::new(format!(
            "unknown multihash 0x{:02x}; sha2-256 (0x12) is the one a node link carries",
            raw[2]
        )));
    }
    if usize::from(raw[3]) != DIGEST_LENGTH {
        return Err(NodeError::new(format!(
            "digest length {}; sha2-256 digests are 32 bytes",
            raw[3]
        )));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&raw[4..]);
    Ok(Parsed {
        codec: raw[1],
        digest,
    })
}

/// The 36 binary bytes of a CID.
pub fn binary(cid: &str) -> Result<Vec<u8>, NodeError> {
    parse(cid)?;
    base32_decode(&cid[1..]).ok_or_else(|| NodeError::new("not base32 text"))
}

/// The text of a binary CID, validated.
pub fn from_binary(raw: &[u8]) -> Result<String, NodeError> {
    parse_binary(raw)?;
    Ok(format!("b{}", base32_lower(raw)))
}

/// Whether `text` is a CID in the pinned form.
pub fn is_cid(text: &str) -> bool {
    parse(text).is_ok()
}

/// The codec of a CID, or `None` when it is no CID.
pub fn codec_of(cid: &str) -> Option<u8> {
    parse(cid).ok().map(|p| p.codec)
}

/// Whether `data` hashes to `cid` (every node is verified against its CID before any use).
pub fn verifies(cid: &str, data: &[u8]) -> bool {
    parse(cid).is_ok_and(|p| p.digest == sha256(data))
}

/// The identity CID of a blob's 32-byte BLAKE3 hash (PDT 2): codec raw, multihash 0x1e.
pub fn identity(digest: &[u8; 32]) -> String {
    let mut binary = [0u8; BINARY_LENGTH];
    binary[..4].copy_from_slice(&[0x01, RAW, BLAKE3, DIGEST_LENGTH as u8]);
    binary[4..].copy_from_slice(digest);
    format!("b{}", base32_lower(&binary))
}

/// The BLAKE3 hash an identity names, or `None` when `text` is no identity in canonical form.
pub fn identity_digest(text: &str) -> Option<[u8; 32]> {
    if text.len() != TEXT_LENGTH || !text.starts_with('b') {
        return None;
    }
    let raw = base32_decode(&text[1..])?;
    if raw.len() != BINARY_LENGTH || raw[..4] != [0x01, RAW, BLAKE3, DIGEST_LENGTH as u8] {
        return None;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&raw[4..]);
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_codecs() {
        for codec in [DAG_CBOR, RAW] {
            let cid = of(b"hello", codec);
            assert_eq!(cid.len(), TEXT_LENGTH);
            let parsed = parse(&cid).unwrap();
            assert_eq!(parsed.codec, codec);
            assert_eq!(from_binary(&binary(&cid).unwrap()).unwrap(), cid);
            assert!(verifies(&cid, b"hello"));
            assert!(!verifies(&cid, b"hellp"));
        }
        assert!(of(&[], RAW).starts_with("bafkrei"));
        assert!(of(&[0xa0], DAG_CBOR).starts_with("bafyrei"));
    }

    #[test]
    fn refuses_other_forms() {
        assert!(parse("Bafkrei").is_err());
        let blake = identity(&[7; 32]);
        assert!(parse(&blake).is_err(), "a BLAKE3 identity is never a node link");
        assert_eq!(identity_digest(&blake), Some([7; 32]));
        assert_eq!(identity_digest(&of(b"x", RAW)), None);
    }
}
