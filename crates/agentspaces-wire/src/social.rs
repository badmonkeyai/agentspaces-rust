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

//! The invite key and the delegated credential (SPEC §5.1, TECH-SPEC §10.0a), a port of
//! `social.py` with Java `GroupSecret`, `InviteKey`, `Base32Crockford`, and `JoinCredentials` as
//! the authority on bytes.
//!
//! - One 128-bit [`GroupSecret`] yields, by HKDF-SHA-256 under the salt [`SALT`], the invite
//!   signing key (`invite-sign`), the group's content key (`content-key`), and the one-way lookup
//!   code (`lookup`, 80 bits, 16 Crockford base32 characters).
//! - An [`InviteKey`] is that secret with the social beacon's host and, optionally, the founder's
//!   delegation, rendered compact (`aspace-inv1-<code>-<secret>[-<delegation>][@host]`) for a
//!   text message or as a URL (`https://<host>/j/<code>#<secret>[.<delegation>]`) for a phone.
//! - The founder signs a [`Delegation`] of the invite public key once ([`delegate`]); a holder
//!   of the secret then signs its own PeerID under it ([`issue_delegated`]) and presents the
//!   result as the [`HINT_KEY`] resource hint ([`hints_for`]). Members judge it with public data
//!   alone ([`judge_delegated_credential`]).
//!
//! Every derivation and CBOR shape is bit-identical to the Java side, which
//! `tests/social-golden.json` pins. Secrets (the group secret, the invite seed, the content key,
//! and every rendering that carries the secret) are held in [`Zeroizing`] buffers and never
//! printed by [`fmt::Debug`]. Decoding untrusted text returns `Result` or a verdict, never
//! panics. The module also carries the standard base64 codec ([`base64_encode`],
//! [`base64_decode`]) with Java's basic-decoder rules, which [`crate::beacon`] shares.
#![warn(missing_docs)]

use std::fmt;

use crate::cbor::{self, Map, Value};
use crate::crypto::{self, CryptoError, KEY_LENGTH, Zeroizing};
use crate::identity::Identity;
use crate::ids;
use crate::util::encode_map;

/// The HKDF salt, also the key format's version tag.
pub const SALT: &[u8] = b"aspace-inv1";
/// The length of a group secret in bytes (128 bits).
pub const SECRET_LENGTH: usize = 16;
/// The length of the lookup code's derivation in bytes (80 bits, 16 base32 characters).
pub const CODE_LENGTH: usize = 10;
/// The built-in default social beacon, omitted from compact keys.
pub const DEFAULT_HOST: &str = "s.agentspaces.dev";
/// The prefix of a compact invite key.
pub const PREFIX: &str = "aspace-inv1-";
/// The resource-hint key a candidate carries its join credential under.
pub const HINT_KEY: &str = "aspace:join";
/// The prefix of a delegated credential string (Java `JoinCredentials.DELEGATED_PREFIX`).
pub const DELEGATED_PREFIX: &str = "d1:";
/// The clock skew a delegation's expiry is judged with, as advertisements allow (ten minutes).
pub const EXPIRY_SKEW_MILLIS: i64 = 10 * 60 * 1000;

/// Why an invite key, a delegation, or a credential could not be read or made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SocialError {
    /// A group secret of the wrong length.
    #[error("not an invite key: the secret is {0} bytes, not {SECRET_LENGTH}")]
    SecretLength(usize),
    /// A character outside the Crockford base32 alphabet (after its O/I/L readings).
    #[error("not a Crockford base32 character: {0:?}")]
    Base32(char),
    /// Text that is not standard base64 as Java's basic decoder reads it.
    #[error("not base64")]
    Base64,
    /// Text that is not a compact invite key.
    #[error("not an invite key: {0}")]
    NotInviteKey(&'static str),
    /// Text that is not an invite link.
    #[error("not an invite link: {0}")]
    NotInviteLink(&'static str),
    /// A delegation string that does not decode to a delegation.
    #[error("not a delegation string")]
    NotDelegation,
    /// A credential string that does not decode to a delegated credential.
    #[error("not a delegated credential")]
    NotDelegatedCredential,
    /// The crypto port failed to derive a key or draw a secret.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

// ---------------------------------------------------------------------------------------------
// Base64 (java.util.Base64 basic)

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 §4) with padding, as Java `Base64.getEncoder()` writes it.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let byte = |i: usize| chunk.get(i).copied().map_or(0, u32::from);
        let bits = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        let sextet = |shift: u32| char::from(BASE64_ALPHABET[((bits >> shift) & 63) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

fn base64_value(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Standard base64 decoded exactly as Java `Base64.getDecoder()` decodes it: every character
/// must be in the alphabet (no whitespace), padding is optional but must be complete when
/// present, nothing may follow it, a dangling single character is refused, and unused trailing
/// bits are ignored. `None` when the text is not base64.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    // `shift` is where the next sextet goes in the 24-bit unit: 18, 12, 6, or 0.
    let (mut bits, mut shift, mut at) = (0u32, 18i32, 0usize);
    while at < bytes.len() {
        let byte = bytes[at];
        at += 1;
        if byte == b'=' {
            // "=" opening a unit, "x=" (caught below), or "xx=" without a second "=" is wrong.
            if shift == 18 || (shift == 6 && bytes.get(at) != Some(&b'=')) {
                return None;
            }
            if shift == 6 {
                at += 1;
            }
            // Java stops at the padding; anything after it is refused.
            if at < bytes.len() {
                return None;
            }
            break;
        }
        bits |= base64_value(byte)? << shift;
        shift -= 6;
        if shift < 0 {
            out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            bits = 0;
            shift = 18;
        }
    }
    match shift {
        6 => out.push((bits >> 16) as u8),
        0 => out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8]),
        // A dangling single character does not carry a whole byte.
        12 => return None,
        _ => {}
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Crockford base32

const BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32, no padding: no I, L, O, or U, so a key read aloud survives.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(char::from(
                BASE32_ALPHABET[((buffer >> (bits - 5)) & 31) as usize],
            ));
            bits -= 5;
        }
        // Keep only the bits not yet written, so the buffer never overflows.
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            BASE32_ALPHABET[((buffer << (5 - bits)) & 31) as usize],
        ));
    }
    out
}

fn base32_value(c: char) -> Option<u32> {
    let value = match c {
        'O' => 0,
        'I' | 'L' => 1,
        _ => BASE32_ALPHABET.iter().position(|&a| char::from(a) == c)?,
    };
    u32::try_from(value).ok()
}

/// Crockford base32 decoded as Java `Base32Crockford.decode` does: case-insensitive (Unicode
/// upper-casing, as Java's `toUpperCase(Locale.ROOT)`), dashes and spaces ignored, `O` read as
/// `0` and `I` and `L` as `1`; any other character is refused. Leftover bits are dropped.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, SocialError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().flat_map(char::to_uppercase) {
        if c == '-' || c == ' ' {
            continue;
        }
        let value = base32_value(c).ok_or(SocialError::Base32(c))?;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// The group secret

fn derive<const N: usize>(secret: &[u8], info: &str) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let okm = crypto::port().hkdf_sha256(secret, SALT, info.as_bytes(), N)?;
    // A conforming port returns exactly N bytes; one that does not is refused, not trusted.
    if okm.len() != N {
        return Err(CryptoError::HkdfLength { requested: N });
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&okm);
    Ok(out)
}

/// The 128 bits a group's creator draws and every holder of an invite key derives from (Java
/// `GroupSecret`). Every derivation is computed once, at construction, through the installed
/// [`crypto::port`]. Equality is constant-time over the secret; [`fmt::Debug`] shows the lookup
/// code only. The secret and its derived keys are wiped on drop.
#[derive(Clone)]
pub struct GroupSecret {
    secret: Zeroizing<[u8; SECRET_LENGTH]>,
    invite_seed: Zeroizing<[u8; KEY_LENGTH]>,
    invite_public: [u8; KEY_LENGTH],
    content_key: Zeroizing<[u8; KEY_LENGTH]>,
    code: String,
}

impl GroupSecret {
    /// The secret of 16 bytes, with its derivations.
    pub fn new(secret: [u8; SECRET_LENGTH]) -> Result<Self, CryptoError> {
        Self::derived(Zeroizing::new(secret))
    }

    /// The secret of a byte slice, refused unless it is exactly [`SECRET_LENGTH`] bytes.
    pub fn from_slice(secret: &[u8]) -> Result<Self, SocialError> {
        if secret.len() != SECRET_LENGTH {
            return Err(SocialError::SecretLength(secret.len()));
        }
        let mut bytes = Zeroizing::new([0u8; SECRET_LENGTH]);
        bytes.copy_from_slice(secret);
        Ok(Self::derived(bytes)?)
    }

    /// A fresh secret from the installed crypto port's random source.
    pub fn random() -> Result<Self, CryptoError> {
        let mut secret = Zeroizing::new([0u8; SECRET_LENGTH]);
        crypto::port().fill_random(&mut *secret)?;
        Self::derived(secret)
    }

    fn derived(secret: Zeroizing<[u8; SECRET_LENGTH]>) -> Result<Self, CryptoError> {
        let invite_seed = derive::<KEY_LENGTH>(&*secret, "invite-sign")?;
        let content_key = derive::<KEY_LENGTH>(&*secret, "content-key")?;
        let lookup = derive::<CODE_LENGTH>(&*secret, "lookup")?;
        let invite_public = crypto::port().ed25519_public_key(&invite_seed);
        Ok(GroupSecret {
            secret,
            invite_seed,
            invite_public,
            content_key,
            code: base32_encode(&*lookup),
        })
    }

    /// The 16 secret bytes.
    pub fn as_bytes(&self) -> &[u8; SECRET_LENGTH] {
        &self.secret
    }

    /// The invite signing key's 32-byte Ed25519 seed (RFC 8032 private key): HKDF `invite-sign`.
    pub fn invite_private_seed(&self) -> Zeroizing<[u8; KEY_LENGTH]> {
        self.invite_seed.clone()
    }

    /// The invite signing key pair.
    pub fn invite_key(&self) -> Identity {
        Identity::from_seed(&self.invite_seed)
    }

    /// The raw 32-byte public half of the invite signing key.
    pub fn invite_public_key(&self) -> [u8; KEY_LENGTH] {
        self.invite_public
    }

    /// The group's content key, epoch 0, 32 bytes: HKDF `content-key`.
    pub fn content_key(&self) -> Zeroizing<[u8; KEY_LENGTH]> {
        self.content_key.clone()
    }

    /// The content key in standard base64.
    pub fn content_key_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(base64_encode(&*self.content_key))
    }

    /// The lookup code: 80 bits of the one-way derivation `lookup`, 16 Crockford characters. It
    /// names the group at the social beacon (`/j/<code>`) and reveals nothing of the secret.
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl PartialEq for GroupSecret {
    fn eq(&self, other: &Self) -> bool {
        crypto::port().ct_eq(&*self.secret, &*other.secret)
    }
}

impl Eq for GroupSecret {}

impl fmt::Debug for GroupSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupSecret[{}]", self.code)
    }
}

// ---------------------------------------------------------------------------------------------
// The invite key

/// Java `String.trim` widened to Unicode whitespace (Python's `strip`): what a pasted key is
/// forgiven around it.
fn trim_pasted(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ' || c.is_whitespace())
}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// One invite key, two renderings (Java `InviteKey`). Compact, for a text message:
/// `aspace-inv1-<code>-<secret>[-<delegation>][@host[:port]]`, the host present only when the
/// beacon is not [`DEFAULT_HOST`]. URL, for a phone:
/// `https://<host>/j/<code>#<secret>[.<delegation>]`; the server receives the path only. The
/// delegation (public data) is optional: without it the beacon document's `invite` field
/// carries it.
///
/// Both renderings carry the secret, so they are returned in [`Zeroizing`] strings, and
/// [`fmt::Debug`] shows the code and host only.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteKey {
    host: String,
    code: String,
    secret: GroupSecret,
    delegation: Option<Vec<u8>>,
}

impl InviteKey {
    /// A key from its parts, without a delegation: the host is trimmed and lower-cased, the code
    /// trimmed and upper-cased (Java's compact constructor). The code is not checked against
    /// the secret here; [`InviteKey::parse`] checks it.
    pub fn new(host: &str, code: &str, secret: GroupSecret) -> Self {
        InviteKey {
            host: trim_pasted(host).to_lowercase(),
            code: trim_pasted(code).to_uppercase(),
            secret,
            delegation: None,
        }
    }

    /// The key of a secret at the default beacon, its code derived from the secret.
    pub fn of(secret: GroupSecret) -> Self {
        let code = secret.code().to_owned();
        Self::new(DEFAULT_HOST, &code, secret)
    }

    /// The beacon host, lower case, with a port when it is not the default.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The lookup code, upper case.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The group secret.
    pub fn secret(&self) -> &GroupSecret {
        &self.secret
    }

    /// The delegation as its base64 string, if the key carries one.
    pub fn delegation(&self) -> Option<String> {
        self.delegation.as_deref().map(base64_encode)
    }

    /// The delegation's decoded bytes, if the key carries one.
    pub fn delegation_bytes(&self) -> Option<&[u8]> {
        self.delegation.as_deref()
    }

    /// Room for a rendering, so the secret-bearing string never reallocates (a reallocation
    /// would leave an unwiped copy behind).
    fn rendering_capacity(&self) -> usize {
        64 + self.host.len() + self.code.len() + self.delegation.as_ref().map_or(0, |d| d.len() * 2)
    }

    /// The compact rendering: `aspace-inv1-<code>-<secret>[-<delegation>][@host]`.
    pub fn compact(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(self.rendering_capacity()));
        out.push_str(PREFIX);
        out.push_str(&self.code);
        out.push('-');
        out.push_str(&Zeroizing::new(base32_encode(&*self.secret.secret)));
        if let Some(delegation) = &self.delegation {
            out.push('-');
            out.push_str(&base32_encode(delegation));
        }
        if self.host != DEFAULT_HOST {
            out.push('@');
            out.push_str(&self.host);
        }
        out
    }

    /// The URL rendering: `https://<host>/j/<code>#<secret>[.<delegation>]`.
    pub fn url(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(self.rendering_capacity()));
        out.push_str("https://");
        out.push_str(&self.host);
        out.push_str("/j/");
        out.push_str(&self.code);
        out.push('#');
        out.push_str(&Zeroizing::new(base32_encode(&*self.secret.secret)));
        if let Some(delegation) = &self.delegation {
            out.push('.');
            out.push_str(&base32_encode(delegation));
        }
        out
    }

    /// The beacon's base URL under `scheme` (`https` in production).
    pub fn beacon(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.host)
    }

    /// The document URL at the beacon, `<scheme>://<host>/j/<code>`: public, no secret.
    pub fn document_url(&self, scheme: &str) -> String {
        format!("{scheme}://{}/j/{}", self.host, self.code)
    }

    /// The same key carrying `delegation` (a base64 delegation string), or none. Refused when the
    /// text is not base64; its content is not judged here.
    pub fn with_delegation(&self, delegation: Option<&str>) -> Result<InviteKey, SocialError> {
        let delegation = match delegation {
            Some(text) => Some(base64_decode(trim_pasted(text)).ok_or(SocialError::Base64)?),
            None => None,
        };
        Ok(InviteKey {
            delegation,
            ..self.clone()
        })
    }

    /// The same key at another beacon host (trimmed and lower-cased).
    pub fn with_host(&self, host: &str) -> InviteKey {
        InviteKey {
            host: trim_pasted(host).to_lowercase(),
            ..self.clone()
        }
    }

    /// Parses either rendering; case, surrounding whitespace, and spaces, tabs, or line breaks
    /// inside the compact form are forgiven. Refused when the text is not an invite key or the
    /// code does not belong to the secret.
    ///
    /// Trailing empty segments of the compact form are dropped as Java's `String.split` drops
    /// them (`<code>-<secret>-` carries no delegation); Python keeps an empty one.
    pub fn parse(text: &str) -> Result<InviteKey, SocialError> {
        let t = trim_pasted(text);
        if starts_with_ignore_case(t, "https://") || starts_with_ignore_case(t, "http://") {
            return Self::parse_url(t);
        }
        let mut compact = Zeroizing::new(String::with_capacity(t.len()));
        compact.extend(t.chars().filter(|c| !matches!(c, ' ' | '\n' | '\t')));
        if !starts_with_ignore_case(&compact, PREFIX) {
            return Err(SocialError::NotInviteKey(
                "it does not start with aspace-inv1-",
            ));
        }
        let rest = &compact[PREFIX.len()..];
        let (rest, host) = match rest.rfind('@') {
            Some(at) => (&rest[..at], trim_pasted(&rest[at + 1..])),
            None => (rest, DEFAULT_HOST),
        };
        let mut segments: Vec<&str> = rest.split('-').collect();
        while segments.last().is_some_and(|s| s.is_empty()) {
            segments.pop();
        }
        if !(2..=3).contains(&segments.len()) {
            return Err(SocialError::NotInviteKey(
                "expected code-secret[-delegation]",
            ));
        }
        let secret = Self::secret_of(segments[1])?;
        let code = segments[0].to_uppercase();
        if code != secret.code() {
            return Err(SocialError::NotInviteKey(
                "the code does not belong to the secret",
            ));
        }
        let delegation = segments.get(2).map(|s| base32_decode(s)).transpose()?;
        Ok(InviteKey {
            delegation,
            ..InviteKey::new(host, &code, secret)
        })
    }

    fn parse_url(text: &str) -> Result<InviteKey, SocialError> {
        // urlsplit drops tabs and line breaks; the Python and Java parsers drop spaces.
        let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
        cleaned.extend(
            text.chars()
                .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n')),
        );
        let url = split_url(&cleaned).ok_or(SocialError::NotInviteLink("not a URL"))?;
        let shape = "expected https://host/j/<code>#<secret>";
        let j = url
            .path
            .find("/j/")
            .ok_or(SocialError::NotInviteLink(shape))?;
        if url.fragment.trim().is_empty() {
            return Err(SocialError::NotInviteLink(shape));
        }
        let code = url.path[j + 3..].split('/').next().unwrap_or_default();
        let (secret_text, delegation_text) = match url.fragment.split_once('.') {
            Some((secret, delegation)) => (secret, Some(delegation)),
            None => (url.fragment, None),
        };
        let secret = Self::secret_of(secret_text)?;
        if code.to_uppercase() != secret.code() {
            return Err(SocialError::NotInviteLink(
                "the code does not belong to the secret",
            ));
        }
        let delegation = delegation_text.map(base32_decode).transpose()?;
        let (hostname, port) = url_host_port(url.netloc)?;
        if hostname.is_empty() {
            return Err(SocialError::NotInviteLink("no host"));
        }
        let mut host = if hostname.contains(':') {
            format!("[{hostname}]")
        } else {
            hostname
        };
        if let Some(port) = port.filter(|&p| p != 0 && p != 443) {
            host.push(':');
            host.push_str(&port.to_string());
        }
        Ok(InviteKey {
            delegation,
            ..InviteKey::new(&host, code, secret)
        })
    }

    fn secret_of(segment: &str) -> Result<GroupSecret, SocialError> {
        let decoded = Zeroizing::new(base32_decode(segment)?);
        GroupSecret::from_slice(&decoded)
    }
}

impl fmt::Debug for InviteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}-...", self.code)?;
        if self.host != DEFAULT_HOST {
            write!(f, "@{}", self.host)?;
        }
        Ok(())
    }
}

/// The parts of a URL `urllib.parse.urlsplit` yields that an invite link uses.
struct SplitUrl<'a> {
    netloc: &'a str,
    path: &'a str,
    fragment: &'a str,
}

/// `scheme://netloc/path?query#fragment`, split as `urlsplit` splits it (the caller has checked
/// the scheme is http or https). The netloc ends at the first `/`, `?`, or `#`.
fn split_url(text: &str) -> Option<SplitUrl<'_>> {
    let (_, rest) = text.split_once("://")?;
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (rest, _query) = rest.split_once('?').unwrap_or((rest, ""));
    let (netloc, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    Some(SplitUrl {
        netloc,
        path,
        fragment,
    })
}

/// `urlsplit`'s `hostname` (lower case, brackets removed) and `port` of a netloc: unbalanced
/// brackets are refused, a port that is not a decimal number in 0..=65535 is refused, and an
/// empty one is absent.
fn url_host_port(netloc: &str) -> Result<(String, Option<u16>), SocialError> {
    if netloc.contains('[') != netloc.contains(']') {
        return Err(SocialError::NotInviteLink("invalid IPv6 URL"));
    }
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (host, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (host, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, after.split_once(':').map_or("", |(_, port)| port))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let port = if port.is_empty() {
        None
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        Some(
            port.parse::<u16>()
                .map_err(|_| SocialError::NotInviteLink("port out of range 0-65535"))?,
        )
    } else {
        return Err(SocialError::NotInviteLink("the port is not a number"));
    };
    Ok((host.to_lowercase(), port))
}

// ---------------------------------------------------------------------------------------------
// Delegations and credentials (CBOR)

/// Java `JoinCredentials.DelegationView`: the bytes a founder signs when delegating, as a map in
/// declared field order (`inviteKey`, `group`, `notAfterMillis`, `label`).
pub fn delegation_view(invite_key: &[u8], group: &str, not_after_millis: i64, label: &str) -> Map {
    let mut view = Map::with_capacity(4);
    view.insert("inviteKey", invite_key);
    view.insert("group", group);
    view.insert("notAfterMillis", not_after_millis);
    view.insert("label", label);
    view
}

/// Java `JoinCredentials.CredentialView`: the bytes the invite key (or a founder) signs per
/// candidate, `{candidate, group}`.
pub fn credential_view(candidate: &str, group: &str) -> Map {
    let mut view = Map::with_capacity(2);
    view.insert("candidate", candidate);
    view.insert("group", group);
    view
}

/// Java `JoinCredentials.Delegation`: the founder's signature binding an invite public key to a
/// group with an expiry and a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The founder's raw Ed25519 public key (32 bytes in a well-formed delegation).
    pub founder_key: Vec<u8>,
    /// The invite signing key's raw Ed25519 public key (32 bytes in a well-formed delegation).
    pub invite_key: Vec<u8>,
    /// The GroupID delegated to.
    pub group: String,
    /// The expiry in epoch milliseconds.
    pub not_after_millis: i64,
    /// The founder's label for it (empty when none).
    pub label: String,
    /// The founder's signature over the [`delegation_view`].
    pub signature: Vec<u8>,
}

impl Delegation {
    /// The record as a CBOR map in Java's declared field order (`founderKey`, `inviteKey`,
    /// `group`, `notAfterMillis`, `label`, `signature`).
    pub fn to_map(&self) -> Map {
        let mut map = Map::with_capacity(6);
        map.insert("founderKey", self.founder_key.as_slice());
        map.insert("inviteKey", self.invite_key.as_slice());
        map.insert("group", self.group.as_str());
        map.insert("notAfterMillis", self.not_after_millis);
        map.insert("label", self.label.as_str());
        map.insert("signature", self.signature.as_slice());
        map
    }

    /// The record's CBOR bytes, which [`delegation_hash`] hashes.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_map(&self.to_map())
    }

    /// The base64 delegation string.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_cbor())
    }

    /// The record a decoded map carries: `founderKey`, `inviteKey`, and `signature` byte
    /// strings, `group` text, and `notAfterMillis` an integer in the `long` range; a `label` that
    /// is absent or not text reads as empty (as `social.py`). `None` when the shape is wrong.
    pub fn from_map(map: &Map) -> Option<Delegation> {
        let bytes = |key: &str| map.get(key).and_then(Value::as_bytes).map(<[u8]>::to_vec);
        Some(Delegation {
            founder_key: bytes("founderKey")?,
            invite_key: bytes("inviteKey")?,
            group: map.get("group")?.as_str()?.to_owned(),
            not_after_millis: map.get("notAfterMillis")?.as_i64()?,
            label: map
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            signature: bytes("signature")?,
        })
    }
}

/// Java `JoinCredentials.DelegatedCredential`: a delegation and the invite key's signature over
/// the candidate's [`credential_view`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedCredential {
    /// The founder's delegation.
    pub delegation: Delegation,
    /// The invite key's signature over `(candidate, group)`.
    pub signature: Vec<u8>,
}

impl DelegatedCredential {
    /// The record as a CBOR map in Java's declared field order (`delegation`, `signature`).
    pub fn to_map(&self) -> Map {
        let mut map = Map::with_capacity(2);
        map.insert("delegation", self.delegation.to_map());
        map.insert("signature", self.signature.as_slice());
        map
    }

    /// The `d1:` credential string.
    pub fn to_credential_string(&self) -> String {
        format!(
            "{DELEGATED_PREFIX}{}",
            base64_encode(&encode_map(&self.to_map()))
        )
    }
}

/// What Java `JoinCredentials.describe` reads from a delegation string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationInfo {
    /// The founder's PeerID (the founder key's derived id).
    pub founder: String,
    /// The invite signing key's raw public key.
    pub invite_key: Vec<u8>,
    /// The GroupID delegated to.
    pub group: String,
    /// The expiry in epoch milliseconds.
    pub not_after_millis: i64,
    /// The founder's label.
    pub label: String,
}

/// Java `JoinCredentials.delegate`: the founder signs the invite key bound to the group with an
/// expiry and a label (`None` is the empty label); returns the base64 delegation string.
pub fn delegate(
    founder: &Identity,
    group: &str,
    invite_public_key: &[u8; KEY_LENGTH],
    not_after_millis: i64,
    label: Option<&str>,
) -> String {
    let label = label.unwrap_or_default();
    let view = encode_map(&delegation_view(
        invite_public_key,
        group,
        not_after_millis,
        label,
    ));
    Delegation {
        founder_key: founder.public_raw().to_vec(),
        invite_key: invite_public_key.to_vec(),
        group: group.to_owned(),
        not_after_millis,
        label: label.to_owned(),
        signature: founder.sign(&view).to_vec(),
    }
    .to_base64()
}

/// The [`Delegation`] a delegation string carries (trimmed, base64, CBOR).
pub fn decode_delegation(delegation: &str) -> Result<Delegation, SocialError> {
    let bytes = base64_decode(trim_pasted(delegation)).ok_or(SocialError::NotDelegation)?;
    let value = cbor::decode(&bytes).map_err(|_| SocialError::NotDelegation)?;
    value
        .as_map()
        .and_then(Delegation::from_map)
        .ok_or(SocialError::NotDelegation)
}

/// Java `JoinCredentials.describe`: the founder's PeerID, the invite key, the group, the expiry,
/// and the label of a delegation string.
pub fn delegation_info(delegation: &str) -> Result<DelegationInfo, SocialError> {
    let d = decode_delegation(delegation)?;
    Ok(DelegationInfo {
        founder: ids::derive_id(&d.founder_key),
        invite_key: d.invite_key,
        group: d.group,
        not_after_millis: d.not_after_millis,
        label: d.label,
    })
}

/// The GroupID a delegation string names.
pub fn delegation_group(delegation: &str) -> Result<String, SocialError> {
    Ok(decode_delegation(delegation)?.group)
}

/// Java `JoinCredentials.issueDelegated`: the invite key's signature over `(candidate, group)`
/// under the delegation, as the `d1:` credential string. `invite_signing_key` is the invite
/// [`Identity`] ([`GroupSecret::invite_key`], or [`Identity::from_seed`] of its seed).
pub fn issue_delegated(
    delegation: &str,
    invite_signing_key: &Identity,
    candidate: &str,
) -> Result<String, SocialError> {
    let delegation = decode_delegation(delegation)?;
    let view = encode_map(&credential_view(candidate, &delegation.group));
    Ok(DelegatedCredential {
        signature: invite_signing_key.sign(&view).to_vec(),
        delegation,
    }
    .to_credential_string())
}

fn strip_prefix(encoded: &str) -> &str {
    encoded.strip_prefix(DELEGATED_PREFIX).unwrap_or(encoded)
}

/// The [`DelegatedCredential`] of a `d1:` credential string (surrounding whitespace forgiven).
pub fn decode_delegated(credential: &str) -> Result<DelegatedCredential, SocialError> {
    let encoded = trim_pasted(credential)
        .strip_prefix(DELEGATED_PREFIX)
        .ok_or(SocialError::NotDelegatedCredential)?;
    let value = base64_decode(encoded)
        .and_then(|bytes| cbor::decode(&bytes).ok())
        .ok_or(SocialError::NotDelegatedCredential)?;
    let map = value.as_map().ok_or(SocialError::NotDelegatedCredential)?;
    let (Some(delegation), Some(signature)) = (
        map.get("delegation").and_then(Value::as_map),
        map.get("signature").and_then(Value::as_bytes),
    ) else {
        return Err(SocialError::NotDelegatedCredential);
    };
    Ok(DelegatedCredential {
        delegation: Delegation::from_map(delegation).ok_or(SocialError::NotDelegation)?,
        signature: signature.to_vec(),
    })
}

/// Java `JoinCredentials.hash`: SHA-256 of a credential's decoded bytes (the `d1:` prefix
/// dropped), which a `JOIN_CREDENTIAL` revocation names to refuse one holder. Refused only when
/// the text is not base64; the bytes are not otherwise judged.
pub fn credential_hash(credential: &str) -> Result<[u8; 32], SocialError> {
    let bytes = base64_decode(strip_prefix(trim_pasted(credential))).ok_or(SocialError::Base64)?;
    Ok(crypto::port().sha256(&bytes))
}

/// Java `JoinCredentials.delegationHash`: SHA-256 of the delegation's bytes, from a delegation
/// string or a delegated credential; revoking it refuses every credential issued under it.
pub fn delegation_hash(delegation_or_credential: &str) -> Result<[u8; 32], SocialError> {
    let text = trim_pasted(delegation_or_credential);
    let delegation = if text.starts_with(DELEGATED_PREFIX) {
        decode_delegated(text)?.delegation
    } else {
        decode_delegation(text)?
    };
    Ok(crypto::port().sha256(&delegation.to_cbor()))
}

/// The delegation half of Java `JoinCredentials.verify`: both keys are 32 bytes, the founder key
/// hashes to the founding's issuer, the delegation names the group, it has not expired at
/// `now_ms` ([`EXPIRY_SKEW_MILLIS`] of skew allowed), and the founder's signature verifies over
/// the [`delegation_view`].
pub fn delegation_verifies(
    delegation: &Delegation,
    group_ad_issuer: &str,
    group_id: &str,
    now_ms: i64,
) -> bool {
    if delegation.founder_key.len() != KEY_LENGTH
        || delegation.invite_key.len() != KEY_LENGTH
        || ids::derive_id(&delegation.founder_key) != group_ad_issuer
        || delegation.group != group_id
        || now_ms.saturating_sub(EXPIRY_SKEW_MILLIS) > delegation.not_after_millis
    {
        return false;
    }
    let view = encode_map(&delegation_view(
        &delegation.invite_key,
        &delegation.group,
        delegation.not_after_millis,
        &delegation.label,
    ));
    Identity::verify(&delegation.founder_key, &view, &delegation.signature)
}

/// Java `JoinCredentials.admits` for the delegated shape, with public data only: the delegation
/// verifies against the founding's issuer and group at `now_ms`, and the invite key's signature
/// verifies over `(candidate, group)`. Revocation is the caller's (the peer's registry).
pub fn delegated_credential_admits(
    credential: &str,
    candidate: &str,
    group_ad_issuer: &str,
    group_id: &str,
    now_ms: i64,
) -> bool {
    judge_delegated_credential(credential, candidate, group_ad_issuer, group_id, now_ms)
        == JoinVerdict::Valid
}

/// What a verifier concludes about a delegated credential (Java `JoinCredentials.Verdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoinVerdict {
    /// The credential admits the candidate now.
    Valid,
    /// Every check passed but the delegation's expiry.
    Expired,
    /// Malformed, wrong founder, wrong group, wrong candidate, or a bad signature.
    Invalid,
}

impl JoinVerdict {
    /// The verdict as `social.py` writes it: `"valid"`, `"expired"`, or `"invalid"`.
    pub fn as_str(self) -> &'static str {
        match self {
            JoinVerdict::Valid => "valid",
            JoinVerdict::Expired => "expired",
            JoinVerdict::Invalid => "invalid",
        }
    }
}

/// Java `JoinCredentials.judge` for the delegated shape: [`JoinVerdict::Expired`] only when every
/// check but the expiry passes. A member admitted while the delegation was valid is re-admitted
/// under the same credential after it expires (SPEC §5.1, v0.1.20), so expiry alone is not a
/// refusal for a peer that joined in time.
pub fn judge_delegated_credential(
    credential: &str,
    candidate: &str,
    group_ad_issuer: &str,
    group_id: &str,
    now_ms: i64,
) -> JoinVerdict {
    let Ok(parsed) = decode_delegated(credential) else {
        return JoinVerdict::Invalid;
    };
    let delegation = &parsed.delegation;
    // Everything but the expiry is judged by asking at an instant inside the window.
    if !delegation_verifies(
        delegation,
        group_ad_issuer,
        group_id,
        delegation.not_after_millis,
    ) {
        return JoinVerdict::Invalid;
    }
    let view = encode_map(&credential_view(candidate, group_id));
    if !Identity::verify(&delegation.invite_key, &view, &parsed.signature) {
        return JoinVerdict::Invalid;
    }
    if now_ms.saturating_sub(EXPIRY_SKEW_MILLIS) > delegation.not_after_millis {
        JoinVerdict::Expired
    } else {
        JoinVerdict::Valid
    }
}

/// Java `SocialGroups.hintsFor`: the resource hints a holder of `key` presents, the delegated
/// credential for `self_peer_id` under [`HINT_KEY`].
pub fn hints_for(
    key: &InviteKey,
    delegation: &str,
    self_peer_id: &str,
) -> Result<Map, SocialError> {
    let credential = issue_delegated(delegation, &key.secret().invite_key(), self_peer_id)?;
    let mut hints = Map::with_capacity(1);
    hints.insert(HINT_KEY, credential);
    Ok(hints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_reads_as_java_does() {
        for len in 0..10u8 {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(37).wrapping_add(5))
                .collect();
            let text = base64_encode(&data);
            assert_eq!(base64_decode(&text).as_deref(), Some(data.as_slice()));
            // Padding is optional for Java's basic decoder.
            assert_eq!(
                base64_decode(text.trim_end_matches('=')).as_deref(),
                Some(data.as_slice())
            );
        }
        assert_eq!(base64_encode(b"ab?"), "YWI/");
        assert_eq!(base64_decode("QQ==").as_deref(), Some(&b"A"[..]));
        assert_eq!(base64_decode("QUI=").as_deref(), Some(&b"AB"[..]));
        assert_eq!(
            base64_decode("QR==").as_deref(),
            Some(&b"A"[..]),
            "trailing bits ignored"
        );
        for bad in [
            "QQ=", "Q", "Q===", "=", "QQ==QQ==", "QQ== ", " QQ==", "QQ\n==", "Q@==", "é", "QUI=A",
        ] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn base32_round_trips() {
        for len in 0..12u8 {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(91).wrapping_add(7))
                .collect();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
        assert_eq!(base32_encode(&[0xFF; 5]), "ZZZZZZZZ");
        assert_eq!(base32_decode("u"), Err(SocialError::Base32('U')));
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let secret = GroupSecret::new([7; SECRET_LENGTH]).unwrap();
        let key = InviteKey::of(secret.clone()).with_host("Beacon.Example");
        let shown = format!("{secret:?} {key:?}");
        assert!(shown.contains(secret.code()));
        assert!(shown.contains("@beacon.example"));
        assert!(!shown.contains(&base32_encode(&[7; SECRET_LENGTH])));
    }

    #[test]
    fn url_hosts_follow_urlsplit() {
        assert_eq!(
            url_host_port("Host:8443").unwrap(),
            ("host".into(), Some(8443))
        );
        assert_eq!(url_host_port("u@[::1]:7").unwrap(), ("::1".into(), Some(7)));
        assert_eq!(url_host_port("host:").unwrap(), ("host".into(), None));
        assert!(url_host_port("host:99999").is_err());
        assert!(url_host_port("host:x").is_err());
        assert!(url_host_port("[::1").is_err());
    }
}
