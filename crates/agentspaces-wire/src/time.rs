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

//! ISO-8601 instants and durations exactly as `java.time` prints them on this wire, and as
//! `identity.py`'s `parse_instant_millis`, `parse_duration_millis`, and `instant_iso` accept and
//! write them. Civil dates are pure integer arithmetic on the proleptic Gregorian calendar (no
//! clock, no time-zone database, no dependency).
//!
//! # Grammar
//!
//! - Instant: `YYYY-MM-DDTHH:MM:SS[.f]Z` with ASCII digits, a four-digit year from 0001 to 9999,
//!   a real calendar date, hours 00 to 23, minutes and seconds 00 to 59 (no leap second), an
//!   optional fraction of one to nine digits (truncated to milliseconds), and an upper-case `Z`.
//! - Duration: `PT[nH][nM][n[.f]S]` with at least one part, the parts in that order, ASCII
//!   digits of any count, and a seconds fraction of one to nine digits (truncated to
//!   milliseconds). No days (`P1D`), no signs, no lower case: Java prints `PT24H`.
//!
//! Deliberate differences from `identity.py`, each a refusal where Python accepts, and each as
//! `java.time` itself parses:
//! - Python's `$` also matches before a final newline, so it accepts `"2026-01-01T00:00:00Z\n"`
//!   and `"PT1H\n"`; this module refuses both.
//! - Python's `\d` matches any Unicode decimal digit (`"PT١H"` is an hour there); this module
//!   reads ASCII digits only, as `java.time` does.
//! - Python's integers are unbounded; a duration beyond `i64` milliseconds is
//!   [`TimeError::Overflow`] here, as it is an `ArithmeticException` in Java.
#![warn(missing_docs)]

/// Why text is not an instant or a duration of this wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeError {
    /// Not a `java.time.Instant` string this wire carries.
    #[error("not an ISO-8601 instant as java.time.Instant prints it: {reason}")]
    InvalidInstant {
        /// What was wrong.
        reason: &'static str,
    },
    /// Not a `java.time.Duration` string this wire carries.
    #[error("not an ISO-8601 duration as java.time.Duration prints it: {reason}")]
    InvalidDuration {
        /// What was wrong.
        reason: &'static str,
    },
    /// A well-formed duration too long for 64-bit milliseconds.
    #[error("the duration does not fit in 64-bit milliseconds")]
    Overflow,
}

const MILLIS_PER_SECOND: i64 = 1000;
const SECONDS_PER_DAY: i64 = 86_400;

/// Epoch milliseconds of `java.time.Instant` text: `"2026-01-01T00:00:00Z"` is
/// `1_767_225_600_000`, and `"2024-02-29T12:34:56.7Z"` is `1_709_210_096_700`. See the module
/// grammar; anything else is refused.
pub fn parse_instant_millis(text: &str) -> Result<i64, TimeError> {
    let invalid = |reason| TimeError::InvalidInstant { reason };
    let mut cursor = Cursor::new(text);
    let year = cursor.fixed_digits(4).ok_or(invalid("year"))?;
    cursor.expect(b'-').ok_or(invalid("date separator"))?;
    let month = cursor.fixed_digits(2).ok_or(invalid("month"))?;
    cursor.expect(b'-').ok_or(invalid("date separator"))?;
    let day = cursor.fixed_digits(2).ok_or(invalid("day"))?;
    cursor
        .expect(b'T')
        .ok_or(invalid("date and time separator"))?;
    let hour = cursor.fixed_digits(2).ok_or(invalid("hour"))?;
    cursor.expect(b':').ok_or(invalid("time separator"))?;
    let minute = cursor.fixed_digits(2).ok_or(invalid("minute"))?;
    cursor.expect(b':').ok_or(invalid("time separator"))?;
    let second = cursor.fixed_digits(2).ok_or(invalid("second"))?;
    let millis = if cursor.expect(b'.').is_some() {
        cursor.fraction_millis().ok_or(invalid("fraction"))?
    } else {
        0
    };
    cursor
        .expect(b'Z')
        .ok_or(invalid("zone, which must be Z"))?;
    if !cursor.at_end() {
        return Err(invalid("trailing characters"));
    }

    let year = i64::from(year);
    if year < 1 {
        return Err(invalid("year 0000"));
    }
    if !(1..=12).contains(&month) {
        return Err(invalid("month out of range"));
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(invalid("day out of range"));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(invalid("time out of range"));
    }
    let seconds = days_from_civil(year, month, day) * SECONDS_PER_DAY
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    // Years 1 to 9999 keep this within +/- 2.6e14, far inside i64.
    Ok(seconds * MILLIS_PER_SECOND + millis)
}

/// Milliseconds of `java.time.Duration` text: `"PT24H"` is `86_400_000`, `"PT1H30M"` is
/// `5_400_000`, `"PT0.5S"` is `500`. See the module grammar; anything else is refused, and a
/// duration beyond `i64` milliseconds is [`TimeError::Overflow`].
pub fn parse_duration_millis(text: &str) -> Result<i64, TimeError> {
    let invalid = |reason| TimeError::InvalidDuration { reason };
    let body = text
        .strip_prefix("PT")
        .ok_or(invalid("must start with PT"))?;
    if body.is_empty() {
        return Err(invalid("no hours, minutes, or seconds"));
    }
    let mut cursor = Cursor::new(body);
    // Units still allowed, in order: hours, minutes, seconds.
    let mut next_unit = 0;
    let mut total: i64 = 0;
    while !cursor.at_end() {
        let whole = cursor.number().ok_or(invalid("expected digits"))??;
        let (unit, millis) = match cursor.next() {
            Some(b'H') => (0, whole.checked_mul(3_600_000)),
            Some(b'M') => (1, whole.checked_mul(60_000)),
            Some(b'S') => (2, whole.checked_mul(MILLIS_PER_SECOND)),
            Some(b'.') => {
                let fraction = cursor.fraction_millis().ok_or(invalid("fraction"))?;
                cursor
                    .expect(b'S')
                    .ok_or(invalid("a fraction belongs to seconds"))?;
                let millis = whole
                    .checked_mul(MILLIS_PER_SECOND)
                    .and_then(|m| m.checked_add(fraction));
                (2, millis)
            }
            _ => return Err(invalid("expected H, M, or S after digits")),
        };
        if unit < next_unit {
            return Err(invalid("units out of order or repeated"));
        }
        next_unit = unit + 1;
        total = millis
            .and_then(|m| total.checked_add(m))
            .ok_or(TimeError::Overflow)?;
    }
    Ok(total)
}

/// Epoch milliseconds as `java.time.Instant.toString` prints them: whole seconds bare, otherwise
/// three fraction digits (`"2026-01-01T00:00:00Z"`, `"2026-01-01T00:00:00.250Z"`). Years 0 to
/// 9999 print as four digits, later years with a `+` and earlier ones with a `-` (`"+10000-…"`,
/// `"-0001-…"`), as Java prints them; [`parse_instant_millis`] reads back years 1 to 9999.
pub fn instant_iso(millis: i64) -> String {
    let seconds = millis.div_euclid(MILLIS_PER_SECOND);
    let fraction = millis.rem_euclid(MILLIS_PER_SECOND);
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (of_day / 3600, of_day / 60 % 60, of_day % 60);
    let year = if year > 9999 {
        format!("+{year}")
    } else if year < 0 {
        format!("-{:04}", year.unsigned_abs())
    } else {
        format!("{year:04}")
    };
    if fraction == 0 {
        format!("{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!("{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:03}Z")
    }
}

/// Whether `text` is an instant exactly as Java writes the instant it denotes back
/// (`Instant.toString`, `DateTimeFormatter.ISO_INSTANT`, which Jackson's `InstantSerializer` uses
/// on this wire): [`parse_instant_millis`] accepts it, and its fraction, when there is one, is the
/// nanoseconds in groups of three digits with trailing zero groups dropped (`.100`, `.123456`,
/// `.000000001`; never `.1`, `.000`, or `.120000`). Java prints no fraction for a whole second.
///
/// Java decodes a signed instant into an `Instant` and verifies the signature over its
/// re-encoding, so a verifier that judges received text must accept only this form for both to
/// verify the same bytes. Sub-millisecond fractions are canonical (Java's `Instant.now()` carries
/// them), though [`parse_instant_millis`] reads only the milliseconds.
pub fn is_canonical_instant(text: &str) -> bool {
    if parse_instant_millis(text).is_err() {
        return false;
    }
    // Parsed, so the text is ASCII `YYYY-MM-DDTHH:MM:SS[.f]Z`.
    match text.strip_suffix('Z').and_then(|body| body.split_once('.')) {
        None => true,
        Some((_, fraction)) => matches!(fraction.len(), 3 | 6 | 9) && !fraction.ends_with("000"),
    }
}

/// Whether `text` is a duration exactly as Java writes the duration it denotes back
/// (`Duration.toString`, which Jackson's `DurationSerializer` uses on this wire):
/// [`parse_duration_millis`] accepts it, and it is `PT` then the whole hours (`H`, omitted when
/// zero), the minutes below an hour (`M`, omitted when zero), and the seconds below a minute with
/// the nanoseconds as a fraction stripped of trailing zeros (`S`, omitted when both are zero and
/// an hour or minute was written), each number without leading zeros. `PT24H`, `PT1H30M`,
/// `PT0.5S`, and `PT0S` are canonical; `PT1440M`, `PT01H`, `PT0H1M`, `PT1M0S`, and `PT0.50S` are
/// not.
///
/// Java decodes a signed duration into a `Duration` and verifies the signature over its
/// re-encoding, so a verifier that judges received text must accept only this form.
pub fn is_canonical_duration(text: &str) -> bool {
    if parse_duration_millis(text).is_err() {
        return false;
    }
    // Parsed: `PT`, then `digits H`, `digits M`, and `digits[.digits]S`, each at most once and
    // in that order, the value within i64 milliseconds.
    let Some(mut rest) = text.strip_prefix("PT") else {
        return false;
    };
    let mut part = |unit: char| -> Option<&str> {
        let (number, after) = rest.split_once(unit)?;
        rest = after;
        Some(number)
    };
    let hours = part('H');
    let minutes = part('M');
    let seconds = part('S');
    let number =
        |digits: Option<&str>| -> Option<u128> { digits.map_or(Some(0), |d| d.parse().ok()) };
    let (whole_seconds, fraction) = match seconds {
        Some(seconds) => match seconds.split_once('.') {
            Some((whole, fraction)) => (Some(whole), fraction),
            None => (Some(seconds), ""),
        },
        None => (None, ""),
    };
    let (Some(hours), Some(minutes), Some(whole_seconds)) =
        (number(hours), number(minutes), number(whole_seconds))
    else {
        return false;
    };
    let total = hours * 3600 + minutes * 60 + whole_seconds;
    let nanos: u32 = if fraction.is_empty() {
        0
    } else {
        // At most nine digits (the grammar's bound), right-padded to nanoseconds.
        format!("{fraction:0<9}").parse().unwrap_or(u32::MAX)
    };
    java_duration_text(total, nanos) == text
}

/// Java `Duration.toString` of a non-negative duration of `seconds` and `nanos`.
fn java_duration_text(seconds: u128, nanos: u32) -> String {
    let (hours, minutes, secs) = (seconds / 3600, seconds % 3600 / 60, seconds % 60);
    let mut out = String::from("PT");
    if hours != 0 {
        out.push_str(&format!("{hours}H"));
    }
    if minutes != 0 {
        out.push_str(&format!("{minutes}M"));
    }
    if secs == 0 && nanos == 0 && out.len() > 2 {
        return out;
    }
    out.push_str(&secs.to_string());
    if nanos > 0 {
        let fraction = format!("{nanos:09}");
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    out.push('S');
    out
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Hinnant's `civil_from_days`).
/// Exact over the whole `i64` millisecond range.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    // Both are small and positive by construction: day 1..=31, month 1..=12.
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = (if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    }) as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// A forward reader over ASCII text.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Cursor {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.pos).copied()?;
        self.pos += 1;
        Some(byte)
    }

    fn expect(&mut self, wanted: u8) -> Option<()> {
        (self.bytes.get(self.pos) == Some(&wanted)).then(|| self.pos += 1)
    }

    /// The run of ASCII digits at the cursor, possibly empty.
    fn digits(&mut self) -> &'a [u8] {
        let start = self.pos;
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        self.bytes.get(start..self.pos).unwrap_or_default()
    }

    /// Exactly `count` ASCII digits as a number; `count` is at most 4 here.
    fn fixed_digits(&mut self, count: usize) -> Option<u32> {
        let digits = self.bytes.get(self.pos..self.pos.checked_add(count)?)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.pos += count;
        Some(digits.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0')))
    }

    /// A run of one or more digits: `None` when there is none, `Some(Err)` when it overflows.
    fn number(&mut self) -> Option<Result<i64, TimeError>> {
        let digits = self.digits();
        if digits.is_empty() {
            return None;
        }
        Some(digits.iter().try_fold(0i64, |n, d| {
            n.checked_mul(10)
                .and_then(|n| n.checked_add(i64::from(d - b'0')))
                .ok_or(TimeError::Overflow)
        }))
    }

    /// One to nine fraction digits as whole milliseconds (the first three, zero-padded).
    fn fraction_millis(&mut self) -> Option<i64> {
        let digits = self.digits();
        if digits.is_empty() || digits.len() > 9 {
            return None;
        }
        Some(
            (0..3)
                .map(|i| digits.get(i).map_or(0, |d| i64::from(d - b'0')))
                .fold(0, |n, d| n * 10 + d),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expected value below was printed by agentspaces-python's identity.py.

    #[test]
    fn instants_parse_like_identity_py() {
        for (text, millis) in [
            ("2026-01-01T00:00:00Z", 1_767_225_600_000),
            ("2025-01-01T00:00:00Z", 1_735_689_600_000),
            ("1970-01-01T00:00:00Z", 0),
            ("2024-02-29T12:34:56.789Z", 1_709_210_096_789),
            ("2024-02-29T12:34:56.7Z", 1_709_210_096_700),
            ("2024-02-29T12:34:56.123456789Z", 1_709_210_096_123),
            ("0001-01-01T00:00:00Z", -62_135_596_800_000),
            ("9999-12-31T23:59:59.999Z", 253_402_300_799_999),
            ("1969-12-31T23:59:59.999Z", -1),
            ("2000-03-01T00:00:00Z", 951_868_800_000),
            ("1900-03-01T00:00:00Z", -2_203_891_200_000),
            ("2025-01-02T00:30:00Z", 1_735_777_800_000),
        ] {
            assert_eq!(parse_instant_millis(text), Ok(millis), "{text}");
        }
    }

    #[test]
    fn malformed_instants_are_refused() {
        for text in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "0000-01-01T00:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00.1234567890Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01 00:00:00Z",
            "2026-1-01T00:00:00Z",
            "+2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00z",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00Z\n",
            "2026-01-01T00:00:00ZZ",
            " 2026-01-01T00:00:00Z",
            // ARABIC-INDIC DIGIT TWO: Python's \d matches it; ASCII digits only here.
            "\u{0662}026-01-01T00:00:00Z",
            "",
        ] {
            assert!(
                matches!(
                    parse_instant_millis(text),
                    Err(TimeError::InvalidInstant { .. })
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn durations_parse_like_identity_py() {
        for (text, millis) in [
            ("PT24H", 86_400_000),
            ("PT15M", 900_000),
            ("PT1S", 1_000),
            ("PT0.5S", 500),
            ("PT1H30M", 5_400_000),
            ("PT720H", 2_592_000_000),
            ("PT0S", 0),
            ("PT1.123456789S", 1_123),
            ("PT1.9999S", 1_999),
            ("PT01H", 3_600_000),
            ("PT1H2M3.004S", 3_723_004),
            ("PT10M0.5S", 600_500),
        ] {
            assert_eq!(parse_duration_millis(text), Ok(millis), "{text}");
        }
    }

    #[test]
    fn malformed_durations_are_refused() {
        for text in [
            "P1D",
            "PT",
            "PTH",
            "PT1H1H",
            "PT1M1H",
            "PT1S1M",
            "PT.5S",
            "PT1.S",
            "PT1.1234567890S",
            "-PT1H",
            "PT-1H",
            "pt1h",
            "PT1h",
            "P1DT1H",
            "PT1.5H",
            "PT1H ",
            "",
            "PT1",
            "PT1HM",
            // Python accepts both: `$` before a final newline, `\d` for ARABIC-INDIC DIGIT ONE.
            "PT1H\n",
            "PT\u{0661}H",
        ] {
            assert!(
                matches!(
                    parse_duration_millis(text),
                    Err(TimeError::InvalidDuration { .. })
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn huge_durations_overflow_instead_of_wrapping() {
        assert_eq!(
            parse_duration_millis("PT99999999999999999999H"),
            Err(TimeError::Overflow)
        );
        // i64::MAX / 3_600_000 = 2_562_047_788_015.
        assert_eq!(
            parse_duration_millis("PT2562047788016H"),
            Err(TimeError::Overflow)
        );
        assert_eq!(
            parse_duration_millis("PT2562047788015H"),
            Ok(2_562_047_788_015 * 3_600_000)
        );
        assert_eq!(
            parse_duration_millis("PT2562047788015H59M"),
            Err(TimeError::Overflow)
        );
        assert_eq!(
            parse_duration_millis("PT0000000000000000000000001S"),
            Ok(1_000)
        );
    }

    #[test]
    fn instants_format_like_identity_py() {
        for (millis, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_767_225_600_000, "2026-01-01T00:00:00Z"),
            (1_767_225_600_250, "2026-01-01T00:00:00.250Z"),
            (1_767_225_600_001, "2026-01-01T00:00:00.001Z"),
            (-1, "1969-12-31T23:59:59.999Z"),
            (-1_000, "1969-12-31T23:59:59Z"),
            (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
            (-62_135_596_800_000, "0001-01-01T00:00:00Z"),
            (951_782_400_000, "2000-02-29T00:00:00Z"),
            (1_735_693_200_000, "2025-01-01T01:00:00Z"),
            (1_709_210_096_789, "2024-02-29T12:34:56.789Z"),
        ] {
            assert_eq!(instant_iso(millis), text, "{millis}");
        }
    }

    #[test]
    fn instants_round_trip_through_text() {
        let first = parse_instant_millis("0001-01-01T00:00:00Z").unwrap();
        let last = parse_instant_millis("9999-12-31T23:59:59.999Z").unwrap();
        let step = (last - first) / 100_003;
        let mut millis = first;
        while millis <= last {
            assert_eq!(
                parse_instant_millis(&instant_iso(millis)),
                Ok(millis),
                "{millis}"
            );
            millis += step;
        }
        assert_eq!(parse_instant_millis(&instant_iso(last)), Ok(last));
    }

    #[test]
    fn civil_days_round_trip_across_eras() {
        for days in (-1_000_000..1_000_000).step_by(997) {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days, "{days}");
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn extreme_millis_format_without_overflow() {
        assert_eq!(instant_iso(i64::MAX), "+292278994-08-17T07:12:55.807Z");
        assert_eq!(instant_iso(i64::MIN), "-292275055-05-16T16:47:04.192Z");
        assert_eq!(instant_iso(253_402_300_800_000), "+10000-01-01T00:00:00Z");
        assert_eq!(instant_iso(-62_167_219_200_000), "0000-01-01T00:00:00Z");
        assert_eq!(
            instant_iso(-62_167_219_200_001),
            "-0001-12-31T23:59:59.999Z"
        );
    }

    /// Java's `Instant.toString` and `Duration.toString` of each input, as JDK 25 printed them:
    /// an input is canonical exactly when Java writes it back unchanged.
    #[test]
    fn canonical_text_is_what_java_writes_back() {
        for (text, java) in [
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.100Z"),
            ("2026-01-01T00:00:00.100Z", "2026-01-01T00:00:00.100Z"),
            ("2026-01-01T00:00:00.120000Z", "2026-01-01T00:00:00.120Z"),
            ("2026-01-01T00:00:00.000001Z", "2026-01-01T00:00:00.000001Z"),
            (
                "2026-01-01T00:00:00.123456789Z",
                "2026-01-01T00:00:00.123456789Z",
            ),
            (
                "2026-01-01T00:00:00.123456780Z",
                "2026-01-01T00:00:00.123456780Z",
            ),
        ] {
            assert_eq!(is_canonical_instant(text), text == java, "{text}");
        }
        assert!(!is_canonical_instant("2026-01-01T00:00:00.000000000Z"));
        assert!(!is_canonical_instant("not an instant"));
        for (text, java) in [
            ("PT24H", "PT24H"),
            ("PT1440M", "PT24H"),
            ("PT01H", "PT1H"),
            ("PT0H1M", "PT1M"),
            ("PT1M0S", "PT1M"),
            ("PT0.50S", "PT0.5S"),
            ("PT0.5S", "PT0.5S"),
            ("PT0S", "PT0S"),
            ("PT1H30M", "PT1H30M"),
            ("PT90M", "PT1H30M"),
            ("PT3600S", "PT1H"),
            ("PT0.000000001S", "PT0.000000001S"),
            ("PT1.000S", "PT1S"),
            ("PT59.999999999S", "PT59.999999999S"),
            ("PT1H0.5S", "PT1H0.5S"),
            ("PT0000000000000000000000001S", "PT1S"),
        ] {
            assert_eq!(is_canonical_duration(text), text == java, "{text}");
        }
        assert!(!is_canonical_duration("P1D"));
        assert!(!is_canonical_duration("PT"));
        assert_eq!(java_duration_text(0, 0), "PT0S");
        assert_eq!(java_duration_text(86_400, 0), "PT24H");
    }
}
