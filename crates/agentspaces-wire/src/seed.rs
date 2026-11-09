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

//! Seed endpoints (SPEC §5.5), a port of `seed.py`: a scheme, a host, and a port to dial. A seed
//! written without a scheme dials the caller's default (`tcp`, as it always has for the Python
//! client); `tls` dials TLS 1.3 with a channel certificate (SPEC §5.6). The beacon's
//! [`crate::beacon::seeds_of`] answers the same [`Seed`]s.
//!
//! [`parse_seed`] reads `scheme://host:port`, `host:port`, `[v6]:port`, and `scheme://[v6]:port`,
//! and refuses what `seed.py` refuses: an address with no host, no port, or a port that is not
//! digits ([`SeedError::NotAnAddress`]), and any `/` after the scheme, since no scheme this wire
//! dials takes a path ([`SeedError::Path`]). The port must also fit a `u16`, and its digits must
//! be ASCII: `seed.py` would accept `h:70000` (and Unicode decimal digits) and fail only when it
//! dials. Never panics.
#![warn(missing_docs)]

use std::fmt;
use std::str::FromStr;

/// The scheme a seed written without one dials (`seed.py`'s `parse_seed` default).
pub const DEFAULT_SCHEME: &str = "tcp";

/// One seed to dial: a host (bare, an IPv6 address without its brackets), a port, and a transport
/// scheme (lower case when parsed: `tcp`, `tls`, ...). Python `seed.Seed`.
///
/// Its [`Display`](fmt::Display) form is `scheme://host:port`, an IPv6 host in brackets, which
/// [`parse_seed`] reads back to the same seed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    /// The host name or address, without IPv6 brackets.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The transport scheme.
    pub scheme: String,
}

impl Seed {
    /// A seed of `scheme` at `host:port`, taken as given.
    pub fn new(host: impl Into<String>, port: u16, scheme: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            scheme: scheme.into(),
        }
    }

    /// `host:port`, an IPv6 host (any host holding a `:`) in brackets (`seed.py`'s `address`).
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// `scheme://host:port`, an IPv6 host in brackets.
impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.address())
    }
}

/// [`parse_seed`] with [`DEFAULT_SCHEME`].
impl FromStr for Seed {
    type Err = SeedError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_seed(text, DEFAULT_SCHEME)
    }
}

/// Why a seed was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SeedError {
    /// Not `host:port` (`[v6]:port`): no host, no port, a port that is not ASCII digits, or a
    /// port beyond 65535. Carries the address as given.
    #[error("not a seed address: {0:?}")]
    NotAnAddress(String),
    /// A `/` after the scheme: no scheme this wire dials takes a path. Carries the seed as given.
    #[error("a {scheme} seed takes no path: {seed:?}")]
    Path {
        /// The scheme the seed would have dialed.
        scheme: String,
        /// The seed text.
        seed: String,
    },
}

/// `seed.py`'s `seed_address`: `host:port` (`[v6]:port`) as `(host, port)`, after trimming
/// surrounding space. A bracketed host ends at the first `]`, and every `:` after it is skipped;
/// otherwise the port follows the last `:`, so `a:b:7` is the host `a:b`.
pub fn seed_address(address: &str) -> Result<(String, u16), SeedError> {
    let text = address.trim_matches(python_space);
    let (host, port) = match text.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, rest.trim_start_matches(':'))
        }
        None => text.rsplit_once(':').unwrap_or(("", text)),
    };
    let refused = || SeedError::NotAnAddress(address.to_owned());
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    let port = port.parse().map_err(|_| refused())?;
    Ok((host.to_owned(), port))
}

/// `seed.py`'s `parse_seed` of a text: `scheme://host:port` (the scheme compared and kept in
/// lower case), or `host:port` dialing `default_scheme` (kept as given). Surrounding space is
/// trimmed first. A `/` anywhere after the scheme is refused ([`SeedError::Path`]), as is an
/// address [`seed_address`] refuses.
///
/// A scheme is a letter, then letters, digits, `+`, `.`, and `-`; text that does not open with
/// one and `://` is all address (so `1tcp://h:1` is refused for its `/`).
pub fn parse_seed(text: &str, default_scheme: &str) -> Result<Seed, SeedError> {
    let trimmed = text.trim_matches(python_space);
    let (scheme, rest) = match split_scheme(trimmed) {
        Some((scheme, rest)) => (scheme.to_lowercase(), rest),
        None => (default_scheme.to_owned(), trimmed),
    };
    if rest.contains('/') {
        return Err(SeedError::Path {
            scheme,
            seed: text.to_owned(),
        });
    }
    let (host, port) = seed_address(rest)?;
    Ok(Seed { host, port, scheme })
}

/// `seed.py`'s `_SCHEME` (`^([a-z][a-z0-9+.-]*)://(.+)$`, case-insensitive): the scheme and the
/// rest, which is non-empty and holds no line feed (the pattern's `.` stops at one).
fn split_scheme(text: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = text.split_once("://")?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    let well_formed = scheme_letter(first)
        && chars.all(|c| scheme_letter(c) || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'));
    (well_formed && !rest.is_empty() && !rest.contains('\n')).then_some((scheme, rest))
}

/// A letter `[a-z]` matches under Python's Unicode case-insensitive matching: the 52 ASCII
/// letters and the four that case-fold onto them (`İ`, `ı`, `ſ`, and the Kelvin sign).
fn scheme_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c, '\u{130}' | '\u{131}' | '\u{17F}' | '\u{212A}')
}

/// The space Python's `str.strip()` removes: Rust's [`char::is_whitespace`] and the four
/// separators `U+001C..=U+001F`.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1C}'..='\u{1F}').contains(&c)
}
