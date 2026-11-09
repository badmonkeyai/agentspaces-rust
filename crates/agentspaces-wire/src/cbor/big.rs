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

//! Big numbers: a Java `BigInteger` past the 64 bits a [`Value::Int`] holds, and a Java
//! `BigDecimal`, the values CBOR tags 2, 3, and 4 carry on this wire (Java `WellFormedCbor`
//! rule S9).
//!
//! Jackson's tags differ from RFC 8949 §3.4.3 in one point, and the encoding follows Java, the
//! peer that writes them: tag 3 holds the magnitude of a negative value, not one less than it
//! (Jackson writes -2^63 - 1 as `C3 49 00 80 00 00 00 00 00 00 01`). Either tag holds its
//! magnitude as `BigInteger.toByteArray()` writes a non-negative value: big-endian, as few bytes
//! as hold it with the top bit of the first clear (so a leading `00` only before a byte of
//! `80` or more).

use std::fmt;
use std::str::FromStr;

use super::{INT_MAX, INT_MIN, Value};

/// The most bytes the byte string of a bignum (tag 2 or 3, alone or as a decimal's mantissa)
/// holds: Jackson's `StreamReadConstraints.maxNumberLength` default, which every Java read
/// (`CborCodec.fromWire`, `fromDocument`) applies to that byte length. Java refuses a longer
/// one, so [`decode`](super::decode) refuses it too, and nothing longer is ever built here, which
/// also bounds the cost of printing one in decimal (at most 2,409 digits).
pub const MAX_BIGNUM_BYTES: usize = 1000;

/// The largest magnitude of a decimal's exponent: 2^31 - 1. A `BigDecimal`'s exponent is its
/// negated `int` scale, and Java refuses -2^31, which it cannot negate (rule S9).
pub const MAX_DECIMAL_EXPONENT: i64 = i32::MAX as i64;

/// The most decimal digits a text of an integer may hold to read as one ([`parse_integer`],
/// [`Decimal::from_str`]): enough for every magnitude of [`MAX_BIGNUM_BYTES`] (2^7999 has 2,408
/// digits), and a bound on the quadratic work of reading them.
const MAX_DECIMAL_DIGITS: usize = 2_409;

/// An integer outside [`INT_MIN`]`..=`[`INT_MAX`]: a Java `BigInteger` that needs more than 64
/// bits of magnitude, written as a tag 2 (positive) or tag 3 (negative) bignum. Every integer
/// inside that range is a [`Value::Int`] instead, so each integer has one [`Value`] and one
/// encoding. Build one with [`Value::integer`] or [`parse_integer`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigInt {
    negative: bool,
    /// Big-endian, no leading zero byte; more than 2^64 - 1 (positive) or 2^64 (negative).
    magnitude: Vec<u8>,
}

impl BigInt {
    /// Whether the integer is below zero.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The magnitude (absolute value), big-endian, without leading zero bytes.
    pub fn magnitude(&self) -> &[u8] {
        &self.magnitude
    }

    /// The bytes of its bignum: the magnitude with a `00` before a first byte of `80` or more.
    pub(super) fn content(&self) -> Vec<u8> {
        content_of(&self.magnitude)
    }
}

/// Decimal digits, with a leading `-` when negative.
impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        f.write_str(&decimal_digits(&self.magnitude))
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A decimal fraction, `mantissa × 10^exponent`: a Java `BigDecimal`, written as tag 4 over
/// `[exponent, mantissa]` (RFC 8949 §3.4.4). It is held as Java's encoder writes it (rule S9):
/// normalized, so the mantissa has no trailing decimal zero and zero is `[0, 0]`; the exponent
/// within ±[`MAX_DECIMAL_EXPONENT`]; the mantissa a [`Value::Int`] or a [`Value::BigInt`]. So
/// each decimal value has one [`Decimal`] and one encoding (1.50 and 1.5 are the same one).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Decimal {
    exponent: i32,
    /// A `Value::Int` or a `Value::BigInt`, never a multiple of ten unless zero.
    mantissa: Box<Value>,
}

impl Decimal {
    /// The decimal `mantissa × 10^exponent`, normalized as Java writes it (trailing zeros of the
    /// mantissa moved into the exponent, zero as `[0, 0]`). `None` when the mantissa is not a
    /// [`Value::Int`] or [`Value::BigInt`], or the normalized exponent lies outside
    /// ±[`MAX_DECIMAL_EXPONENT`]. A [`Value::Int`] outside [`INT_MIN`]`..=`[`INT_MAX`] (only a
    /// hand-built one) is refused too.
    pub fn new(exponent: i64, mantissa: Value) -> Option<Decimal> {
        let (mut negative, mut magnitude) = match mantissa {
            Value::Int(n) if (INT_MIN..=INT_MAX).contains(&n) => {
                (n < 0, magnitude_of(n.unsigned_abs()))
            }
            Value::BigInt(big) => (big.negative, big.magnitude),
            _ => return None,
        };
        let mut exponent = i128::from(exponent);
        if magnitude.is_empty() {
            (negative, exponent) = (false, 0);
        }
        while !magnitude.is_empty() && remainder(&magnitude, 10) == 0 {
            magnitude = quotient(&magnitude, 10);
            exponent += 1;
        }
        let exponent = i32::try_from(exponent)
            .ok()
            .filter(|e| i64::from(*e).abs() <= MAX_DECIMAL_EXPONENT)?;
        Some(Decimal {
            exponent,
            mantissa: Box::new(integer_value(negative, &magnitude)),
        })
    }

    /// Builds a decimal whose parts the decoder already checked against rule S9.
    pub(super) fn checked(exponent: i32, mantissa: Value) -> Decimal {
        Decimal {
            exponent,
            mantissa: Box::new(mantissa),
        }
    }

    /// The power of ten, within ±[`MAX_DECIMAL_EXPONENT`].
    pub fn exponent(&self) -> i32 {
        self.exponent
    }

    /// The mantissa, a [`Value::Int`] or a [`Value::BigInt`].
    pub fn mantissa(&self) -> &Value {
        &self.mantissa
    }
}

/// Java's `BigDecimal.toString()`: plain digits when the exponent is 0, a decimal point when the
/// exponent is negative and the number not far below one (`1.25`, `0.000125`), and otherwise
/// scientific notation (`1E+3`, `1.25E-8`).
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (negative, digits) = match self.mantissa.as_ref() {
            Value::Int(n) => (*n < 0, n.unsigned_abs().to_string()),
            Value::BigInt(big) => (big.negative, decimal_digits(&big.magnitude)),
            _ => (false, String::from("0")),
        };
        if negative {
            f.write_str("-")?;
        }
        let exponent = i64::from(self.exponent);
        // digits is never empty and at most a few thousand characters long.
        let length = i64::try_from(digits.len()).unwrap_or(i64::MAX);
        let adjusted = exponent + length - 1;
        if exponent == 0 {
            f.write_str(&digits)
        } else if exponent < 0 && adjusted >= -6 {
            // The point falls inside the digits or at most five zeros before them.
            let point = length + exponent;
            if point > 0 {
                let (whole, fraction) = digits.split_at(usize::try_from(point).unwrap_or(0));
                write!(f, "{whole}.{fraction}")
            } else {
                let zeros = usize::try_from(-point).unwrap_or(0);
                write!(f, "0.{}{digits}", "0".repeat(zeros))
            }
        } else {
            let (first, rest) = digits.split_at(1);
            f.write_str(first)?;
            if !rest.is_empty() {
                write!(f, ".{rest}")?;
            }
            write!(f, "E{}{adjusted}", if adjusted >= 0 { "+" } else { "" })
        }
    }
}

impl fmt::Debug for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "4([{}, {:?}])", self.exponent, self.mantissa)
    }
}

/// Why a text did not read as a [`Decimal`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a decimal of this wire: {0:?}")]
pub struct DecimalError(String);

/// Reads the forms Java's `new BigDecimal(String)` reads: an optional sign, digits with an
/// optional decimal point (at least one digit), and an optional exponent (`e` or `E`, an
/// optional sign, digits): `1.25`, `-12.5`, `1E+3`, `.5`, `7.`. The value is normalized
/// ([`Decimal::new`]). Refused: any other text, more than 2,409 significant digits, and an
/// exponent outside ±[`MAX_DECIMAL_EXPONENT`] once normalized.
impl FromStr for Decimal {
    type Err = DecimalError;

    fn from_str(text: &str) -> Result<Decimal, DecimalError> {
        let refused = || DecimalError(text.chars().take(64).collect());
        let (negative, unsigned) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        let (significand, exponent) = match unsigned.find(['e', 'E']) {
            Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
            None => (unsigned, None),
        };
        let (whole, fraction) = significand.split_once('.').unwrap_or((significand, ""));
        let all_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
        if whole.len() + fraction.len() == 0 || !all_digits(whole) || !all_digits(fraction) {
            return Err(refused());
        }
        let mut power = match exponent {
            None => 0i128,
            Some(exponent) => {
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                // More than 18 digits is far outside every exponent a decimal holds.
                if digits.is_empty() || digits.len() > 18 || !all_digits(digits) {
                    return Err(refused());
                }
                exponent.parse::<i128>().map_err(|_| refused())?
            }
        };
        power -= i128::try_from(fraction.len()).map_err(|_| refused())?;
        let joined = format!("{whole}{fraction}");
        let significant = joined.trim_start_matches('0');
        let trimmed = significant.trim_end_matches('0');
        if trimmed.is_empty() {
            return Ok(Decimal::checked(0, Value::Int(0)));
        }
        power += i128::try_from(significant.len() - trimmed.len()).map_err(|_| refused())?;
        if trimmed.len() > MAX_DECIMAL_DIGITS {
            return Err(refused());
        }
        let exponent = i64::try_from(power)
            .ok()
            .filter(|e| e.abs() <= MAX_DECIMAL_EXPONENT)
            .ok_or_else(refused)?;
        let mantissa = integer_value(negative, &magnitude_from_digits(trimmed));
        Decimal::new(exponent, mantissa).ok_or_else(refused)
    }
}

/// The integer a decimal text holds (an optional `-` or `+`, then digits): a [`Value::Int`]
/// inside [`INT_MIN`]`..=`[`INT_MAX`] and a [`Value::BigInt`] beyond. `None` for any other text,
/// for more than 2,409 significant digits, and for a magnitude whose bignum would hold more than
/// [`MAX_BIGNUM_BYTES`] bytes.
pub fn parse_integer(text: &str) -> Option<Value> {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let significant = digits.trim_start_matches('0');
    if significant.len() > MAX_DECIMAL_DIGITS {
        return None;
    }
    let magnitude = magnitude_from_digits(significant);
    (content_of(&magnitude).len() <= MAX_BIGNUM_BYTES).then(|| integer_value(negative, &magnitude))
}

impl Value {
    /// The integer of a sign and a big-endian magnitude (leading zero bytes allowed): a
    /// [`Value::Int`] inside [`INT_MIN`]`..=`[`INT_MAX`] and a [`Value::BigInt`] beyond, so an
    /// integer always has the one form. Zero is `Int(0)` whatever the sign. `None` when the
    /// magnitude's bignum would hold more than [`MAX_BIGNUM_BYTES`] bytes, which Java refuses.
    pub fn integer(negative: bool, magnitude: &[u8]) -> Option<Value> {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let magnitude = &magnitude[start..];
        (content_of(magnitude).len() <= MAX_BIGNUM_BYTES)
            .then(|| integer_value(negative, magnitude))
    }
}

/// The integer of a sign and a magnitude without leading zeros, with no length bound.
pub(super) fn integer_value(negative: bool, magnitude: &[u8]) -> Value {
    if magnitude.len() <= 16 {
        let mut word = [0u8; 16];
        word[16 - magnitude.len()..].copy_from_slice(magnitude);
        let unsigned = u128::from_be_bytes(word);
        // INT_MAX and -INT_MIN are 2^64 - 1 and 2^64, which fit an i128.
        let value = if negative {
            i128::try_from(unsigned).ok().map(|n| -n)
        } else {
            i128::try_from(unsigned).ok()
        };
        if let Some(value) = value.filter(|n| (INT_MIN..=INT_MAX).contains(n)) {
            return Value::Int(value);
        }
    }
    Value::BigInt(BigInt {
        negative,
        magnitude: magnitude.to_vec(),
    })
}

/// The minimal big-endian bytes of an unsigned magnitude (empty for zero).
pub(super) fn magnitude_of(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// A bignum's bytes for a magnitude without leading zeros (`BigInteger.toByteArray()` of a
/// non-negative value): a `00` before a first byte of `80` or more; zero is one `00`.
pub(super) fn content_of(magnitude: &[u8]) -> Vec<u8> {
    match magnitude.first() {
        Some(&first) if first < 0x80 => magnitude.to_vec(),
        _ => {
            let mut content = Vec::with_capacity(magnitude.len() + 1);
            content.push(0);
            content.extend_from_slice(magnitude);
            content
        }
    }
}

/// Whether a magnitude is a multiple of ten (zero included).
pub(super) fn divisible_by_ten(magnitude: &[u8]) -> bool {
    remainder(magnitude, 10) == 0
}

/// `magnitude mod divisor`.
fn remainder(magnitude: &[u8], divisor: u32) -> u32 {
    magnitude.iter().fold(0u32, |rest, &byte| {
        // rest < divisor <= u32::MAX, so rest * 256 + byte fits a u64.
        u32::try_from(((u64::from(rest) << 8) | u64::from(byte)) % u64::from(divisor)).unwrap_or(0)
    })
}

/// `magnitude / divisor`, without leading zeros.
fn quotient(magnitude: &[u8], divisor: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(magnitude.len());
    let mut rest = 0u64;
    for &byte in magnitude {
        let current = (rest << 8) | u64::from(byte);
        // current < divisor * 256, so the quotient digit fits a byte.
        out.push(u8::try_from(current / u64::from(divisor)).unwrap_or(u8::MAX));
        rest = current % u64::from(divisor);
    }
    let start = out.iter().position(|&b| b != 0).unwrap_or(out.len());
    out.split_off(start)
}

/// The decimal digits of a magnitude ("0" for an empty one): nine digits per pass of a long
/// division, quadratic in the length, which [`MAX_BIGNUM_BYTES`] bounds wherever the magnitude
/// came from.
fn decimal_digits(magnitude: &[u8]) -> String {
    const NINE_DIGITS: u32 = 1_000_000_000;
    let mut groups = Vec::new();
    let mut rest = magnitude.to_vec();
    while !rest.is_empty() {
        groups.push(remainder(&rest, NINE_DIGITS));
        rest = quotient(&rest, NINE_DIGITS);
    }
    let mut digits = groups
        .pop()
        .map_or_else(|| String::from("0"), |g| g.to_string());
    for group in groups.iter().rev() {
        digits.push_str(&format!("{group:09}"));
    }
    digits
}

/// The magnitude of a text of ASCII digits, without leading zeros: quadratic in the length,
/// which its callers bound.
fn magnitude_from_digits(digits: &str) -> Vec<u8> {
    let mut magnitude: Vec<u8> = Vec::new();
    for digit in digits.bytes() {
        let mut carry = u32::from(digit - b'0');
        for byte in magnitude.iter_mut().rev() {
            let current = u32::from(*byte) * 10 + carry;
            *byte = (current & 0xFF) as u8;
            carry = current >> 8;
        }
        while carry > 0 {
            magnitude.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    magnitude
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_and_magnitudes_convert_both_ways() {
        for text in [
            "1",
            "255",
            "256",
            "18446744073709551615",
            "18446744073709551616",
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
            "1000000000000000000000000000000000000000000000001",
        ] {
            let magnitude = magnitude_from_digits(text);
            assert_eq!(decimal_digits(&magnitude), text);
        }
        assert_eq!(decimal_digits(&[]), "0");
        assert_eq!(magnitude_from_digits(""), Vec::<u8>::new());
        assert_eq!(remainder(&magnitude_from_digits("1234567"), 10), 7);
        assert_eq!(
            quotient(&magnitude_from_digits("1234567"), 10),
            magnitude_from_digits("123456")
        );
    }

    #[test]
    fn integers_take_the_one_form_of_their_value() {
        assert_eq!(Value::integer(false, &[]), Some(Value::Int(0)));
        assert_eq!(Value::integer(true, &[0, 0]), Some(Value::Int(0)));
        assert_eq!(Value::integer(false, &[0xFF; 8]), Some(Value::Int(INT_MAX)));
        let two_64 = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(Value::integer(true, &two_64), Some(Value::Int(INT_MIN)));
        let Some(Value::BigInt(big)) = Value::integer(false, &two_64) else {
            panic!("2^64 is a BigInt");
        };
        assert_eq!(big.to_string(), "18446744073709551616");
        assert_eq!(big.content(), two_64);
        let Some(Value::BigInt(below)) = Value::integer(true, &[1, 0, 0, 0, 0, 0, 0, 0, 1]) else {
            panic!("-2^64 - 1 is a BigInt");
        };
        assert_eq!(below.to_string(), "-18446744073709551617");
        assert_eq!(content_of(&[0x80]), [0, 0x80]);
        // The longest magnitude Java reads, and one byte more.
        let mut longest = vec![0x7F];
        longest.resize(MAX_BIGNUM_BYTES, 0xFF);
        assert!(Value::integer(false, &longest).is_some());
        assert_eq!(Value::integer(false, &[0xFF; MAX_BIGNUM_BYTES]), None);
        let digits = Value::integer(false, &longest).map(|v| match v {
            Value::BigInt(big) => big.to_string(),
            _ => String::new(),
        });
        let digits = digits.unwrap_or_default();
        assert_eq!(digits.len(), 2_408);
        assert!(parse_integer(&digits).is_some());
        assert_eq!(parse_integer(&format!("{digits}0")), None);
    }

    #[test]
    fn decimals_print_and_read_as_java_does() {
        for (exponent, mantissa, text) in [
            (-2, 125, "1.25"),
            (-1, -125, "-12.5"),
            (0, 0, "0"),
            (3, 1, "1E+3"),
            (-3, 1, "0.001"),
            (-7, 125, "0.0000125"),
            (-9, 125, "1.25E-7"),
            (2, 17, "1.7E+3"),
            (-3, 2_147_483_648, "2147483.648"),
        ] {
            let decimal = Decimal::new(exponent, Value::Int(mantissa)).expect("a decimal");
            assert_eq!(decimal.to_string(), text, "{exponent} {mantissa}");
            assert_eq!(text.parse::<Decimal>(), Ok(decimal), "{text}");
        }
        assert_eq!(
            Decimal::new(-2, Value::Int(150)),
            Decimal::new(-1, Value::Int(15))
        );
        assert_eq!("1.50".parse().ok(), Decimal::new(-1, Value::Int(15)));
        assert_eq!(
            "0.00".parse::<Decimal>().map(|d| d.to_string()),
            Ok("0".into())
        );
        assert_eq!(
            "1E+2147483647".parse::<Decimal>().map(|d| d.exponent()),
            Ok(i32::MAX)
        );
        for refused in [
            "",
            "-",
            ".",
            "1e",
            "1e+",
            "1.2.3",
            "1,5",
            "NaN",
            "0x10",
            " 1",
            "1E+2147483648",
            "1E-2147483648",
        ] {
            assert!(refused.parse::<Decimal>().is_err(), "{refused:?}");
        }
        // 10E+2147483646 normalizes to 1E+2147483647; one more power is out of range.
        assert!("10E+2147483646".parse::<Decimal>().is_ok());
        assert!("100E+2147483646".parse::<Decimal>().is_err());
        assert_eq!(Decimal::new(0, Value::Float(1.0)), None);
    }
}
