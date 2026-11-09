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

//! Base58btc (the Bitcoin alphabet) and its multibase form, `z` + base58btc, the encoding of every
//! PeerID, GroupID, and SpaceID (`identity.py`'s `base58btc` and `multibase`; Java `Multibase`).
//!
//! Leading zero bytes encode as leading `1`s and decode back, so the round trip is exact for any
//! input. Both directions cost time quadratic in the input length; ids are under 50 characters,
//! and callers bound any other untrusted input before decoding it.
#![warn(missing_docs)]

/// The Bitcoin base58 alphabet: digits and letters without `0`, `O`, `I`, and `l`.
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The multibase prefix of base58btc.
pub const MULTIBASE_PREFIX: char = 'z';

const INVALID: u8 = 0xFF;

/// ASCII byte to base58 digit, [`INVALID`] where the byte is not in the alphabet.
const DIGITS: [u8; 128] = {
    let mut table = [INVALID; 128];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Why a string did not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Base58Error {
    /// A character outside the base58btc alphabet.
    #[error("invalid base58btc character {character:?} at byte {index}")]
    InvalidCharacter {
        /// The byte position of the character in the input.
        index: usize,
        /// The character.
        character: char,
    },
    /// A multibase string that does not start with `z` (base58btc).
    #[error("not multibase base58btc: the string does not start with 'z'")]
    MissingMultibasePrefix,
}

/// Base58btc of `data`, with each leading zero byte as a leading `1`.
pub fn encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&byte| byte == 0).count();
    let rest = data.get(zeros..).unwrap_or_default();
    // Base-58 digits, least significant first. log(256) / log(58) < 1.366.
    let mut digits: Vec<u8> = Vec::with_capacity(rest.len() * 1366 / 1000 + 1);
    for &byte in rest {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut text = String::with_capacity(zeros + digits.len());
    text.extend(std::iter::repeat_n('1', zeros));
    // Every digit is below 58, so it indexes the alphabet.
    text.extend(
        digits
            .iter()
            .rev()
            .map(|&digit| char::from(ALPHABET[usize::from(digit)])),
    );
    text
}

/// The bytes of a base58btc string; each leading `1` is a leading zero byte. The empty string
/// decodes to no bytes.
pub fn decode(text: &str) -> Result<Vec<u8>, Base58Error> {
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    // Bytes, least significant first. log(58) / log(256) < 0.733.
    let mut bytes: Vec<u8> = Vec::with_capacity((text.len() - zeros) * 733 / 1000 + 1);
    for (index, character) in text.char_indices().skip(zeros) {
        let digit = u8::try_from(character)
            .ok()
            .and_then(|ascii| DIGITS.get(usize::from(ascii)).copied())
            .filter(|&digit| digit != INVALID)
            .ok_or(Base58Error::InvalidCharacter { index, character })?;
        let mut carry = u32::from(digit);
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// The multibase form the Java side uses: `z` + base58btc of `data`.
pub fn multibase(data: &[u8]) -> String {
    let mut text = String::with_capacity(1 + data.len() * 1366 / 1000 + 1);
    text.push(MULTIBASE_PREFIX);
    text.push_str(&encode(data));
    text
}

/// The bytes of a multibase base58btc string; refuses any other multibase prefix.
pub fn multibase_decode(text: &str) -> Result<Vec<u8>, Base58Error> {
    let rest = text
        .strip_prefix(MULTIBASE_PREFIX)
        .ok_or(Base58Error::MissingMultibasePrefix)?;
    decode(rest).map_err(|error| match error {
        // Report positions in the caller's string, prefix included.
        Base58Error::InvalidCharacter { index, character } => Base58Error::InvalidCharacter {
            index: index + MULTIBASE_PREFIX.len_utf8(),
            character,
        },
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // draft-msporny-base58 test vectors.
        assert_eq!(encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(
            encode(b"The quick brown fox jumps over the lazy dog."),
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
        );
        assert_eq!(encode(&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
        assert_eq!(
            decode("11233QC4"),
            Ok(vec![0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd])
        );
        assert_eq!(encode(&[]), "");
        assert_eq!(decode(""), Ok(vec![]));
        assert_eq!(encode(&[0]), "1");
        assert_eq!(encode(&[0, 0, 0]), "111");
        assert_eq!(decode("111"), Ok(vec![0, 0, 0]));
    }

    #[test]
    fn refuses_characters_outside_the_alphabet() {
        for (text, index, character) in [
            ("0", 0, '0'),
            ("1O", 1, 'O'),
            ("2I", 1, 'I'),
            ("abl", 2, 'l'),
            ("aé", 1, 'é'),
        ] {
            assert_eq!(
                decode(text),
                Err(Base58Error::InvalidCharacter { index, character }),
                "{text}"
            );
        }
        assert_eq!(
            multibase_decode("z0"),
            Err(Base58Error::InvalidCharacter {
                index: 1,
                character: '0'
            })
        );
    }
}
