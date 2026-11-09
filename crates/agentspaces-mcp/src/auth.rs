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

//! Bearer token verification for the HTTP gateway: the [`TokenVerifier`] seam, and
//! [`StaticTokens`], fixed tokens each naming a principal and its scopes. [`crate::jwt`] holds
//! the JWT verifier.
//!
//! # Static tokens
//!
//! A token file is YAML or JSON: a list of records, bare or under `tokens:`. Each record names
//! the token itself (`token`) or the hex SHA-256 of it (`sha256`, so the file need not hold the
//! secret), the principal it stands for, and its scopes:
//!
//! ```yaml
//! tokens:
//!   - token: "a-long-random-secret"
//!     principal: ana
//!     scopes: [orders:write]
//!   - sha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
//!     principal: ci
//!     scopes: [reports]
//! ```
//!
//! - The file is refused when its group or others have any access to it (`mode & 0o077`, as
//!   the keystore judges a private key): `chmod 600` it. On other systems than
//!   Unix the operating system's access control is trusted.
//! - Every token is kept only as its SHA-256. A presented token is hashed and compared with
//!   every known digest in constant time ([`subtle`]), so neither the comparison nor which
//!   record matched shows in the time a refusal takes.
//! - No token, digest, or record value is ever logged or put in an error message: errors name
//!   the file, the record's index, and the field.

use std::fmt;
use std::future::Future;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use agentspaces::catalog::Principal;
use agentspaces::wire::crypto;
use serde_json::Value as Json;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The largest token file read.
pub const MAX_TOKEN_FILE: u64 = 1024 * 1024;

/// The longest bearer token judged; a longer one is refused unread.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The most scopes one principal carries.
pub const MAX_SCOPES: usize = 256;

/// What a verifier answers: the caller a valid token names.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<Principal, AuthError>> + Send + 'a>>;

/// Verifies bearer tokens: [`StaticTokens`], [`JwtVerifier`](crate::JwtVerifier), or
/// a host's own.
pub trait TokenVerifier: Send + Sync + 'static {
    /// The caller `token` names, or why it is refused. The token is a secret: an implementation
    /// never logs it nor puts it in the error.
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a>;
}

/// Why a token was refused: a reason safe to show the caller (it never carries the token).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct AuthError {
    reason: String,
    unsafe_file: bool,
}

impl AuthError {
    /// A refusal for `reason`.
    pub fn new(reason: impl Into<String>) -> AuthError {
        AuthError {
            reason: reason.into(),
            unsafe_file: false,
        }
    }

    /// A refusal of a file that decides who may be verified (a key set) because others may
    /// change it, for `reason`.
    pub fn unsafe_file(reason: impl Into<String>) -> AuthError {
        AuthError {
            reason: reason.into(),
            unsafe_file: true,
        }
    }

    /// Why.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Whether a file was refused because its group or others may write it
    /// ([`AuthError::unsafe_file`]).
    pub fn is_unsafe_file(&self) -> bool {
        self.unsafe_file
    }
}

/// Why a token file or record was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenFileError {
    /// The file could not be read.
    #[error("cannot read the token file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// Its group or others have access to it.
    #[error(
        "the token file {path} is readable by group or others (mode {mode:03o}, any group or \
         other bit counts); run `chmod 600 {path}`"
    )]
    Readable {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// It is larger than [`MAX_TOKEN_FILE`].
    #[error("the token file {path} is larger than {MAX_TOKEN_FILE} bytes")]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// It is not YAML or JSON.
    #[error("the token file {path} is not YAML or JSON: {reason}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// Where it went wrong (no content of the file).
        reason: String,
    },
    /// A record is not a valid token record.
    #[error("{0}")]
    Invalid(String),
}

#[derive(Clone)]
struct TokenEntry {
    digest: [u8; 32],
    principal: String,
    scopes: Vec<String>,
}

/// Fixed bearer tokens, each standing for a principal with its scopes; see the [module
/// docs](self).
///
/// ```
/// use agentspaces_mcp::StaticTokens;
///
/// let tokens = StaticTokens::new()
///     .token("a-long-random-secret", "ana", ["orders:write"])?
///     .token("another-secret", "ci", ["reports"])?;
/// assert_eq!(tokens.len(), 2);
/// # Ok::<(), agentspaces_mcp::TokenFileError>(())
/// ```
#[derive(Clone, Default)]
pub struct StaticTokens {
    entries: Vec<TokenEntry>,
}

impl fmt::Debug for StaticTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticTokens")
            .field("principals", &self.principals())
            .finish_non_exhaustive()
    }
}

impl StaticTokens {
    /// No tokens yet.
    pub fn new() -> StaticTokens {
        StaticTokens::default()
    }

    /// Adds `token`, standing for `principal` with `scopes`.
    ///
    /// # Errors
    ///
    /// [`TokenFileError::Invalid`] for a blank token or principal, a token longer than
    /// [`MAX_TOKEN_BYTES`], more than [`MAX_SCOPES`] scopes, or a token already known.
    pub fn token<S: Into<String>>(
        self,
        token: &str,
        principal: impl Into<String>,
        scopes: impl IntoIterator<Item = S>,
    ) -> Result<StaticTokens, TokenFileError> {
        if token.trim().is_empty() {
            return Err(TokenFileError::Invalid(
                "a token may not be blank".to_owned(),
            ));
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenFileError::Invalid(format!(
                "a token may hold at most {MAX_TOKEN_BYTES} bytes"
            )));
        }
        self.digest(sha256(token.as_bytes()), principal, scopes)
    }

    /// Adds the token whose SHA-256 is `hex_digest` (64 hex digits), standing for `principal`
    /// with `scopes`.
    ///
    /// # Errors
    ///
    /// [`TokenFileError::Invalid`] for a digest that is not 64 hex digits, and as
    /// [`StaticTokens::token`].
    pub fn sha256<S: Into<String>>(
        self,
        hex_digest: &str,
        principal: impl Into<String>,
        scopes: impl IntoIterator<Item = S>,
    ) -> Result<StaticTokens, TokenFileError> {
        let digest = parse_digest(hex_digest).ok_or_else(|| {
            TokenFileError::Invalid("a sha256 is 64 hexadecimal digits".to_owned())
        })?;
        self.digest(digest, principal, scopes)
    }

    fn digest<S: Into<String>>(
        mut self,
        digest: [u8; 32],
        principal: impl Into<String>,
        scopes: impl IntoIterator<Item = S>,
    ) -> Result<StaticTokens, TokenFileError> {
        let principal = principal.into();
        if principal.trim().is_empty() {
            return Err(TokenFileError::Invalid(
                "a token's principal may not be blank".to_owned(),
            ));
        }
        let scopes: Vec<String> = scopes.into_iter().map(Into::into).collect();
        if scopes.len() > MAX_SCOPES {
            return Err(TokenFileError::Invalid(format!(
                "a token carries at most {MAX_SCOPES} scopes"
            )));
        }
        if self.find_digest(&digest).is_some() {
            return Err(TokenFileError::Invalid(format!(
                "a token for {principal} is already known (two records hold the same token)"
            )));
        }
        self.entries.push(TokenEntry {
            digest,
            principal,
            scopes,
        });
        Ok(self)
    }

    /// The tokens of a YAML or JSON token file; see the [module docs](self).
    ///
    /// # Errors
    ///
    /// [`TokenFileError::Readable`] when its group or others have access (Unix),
    /// [`TokenFileError::Io`], [`TokenFileError::TooLarge`], [`TokenFileError::Parse`], and
    /// [`TokenFileError::Invalid`] for a record that is not `{token or sha256, principal,
    /// scopes}`, a duplicate, or a file with no token.
    pub fn load(path: impl AsRef<Path>) -> Result<StaticTokens, TokenFileError> {
        let path = path.as_ref();
        let io = |source: std::io::Error| TokenFileError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = std::fs::File::open(path).map_err(io)?;
        // The opened file's own metadata: what is judged is what is read.
        let metadata = file.metadata().map_err(io)?;
        if !metadata.is_file() {
            return Err(TokenFileError::Invalid(format!(
                "the token file {} is not a regular file",
                path.display()
            )));
        }
        check_mode(path, &metadata)?;
        if metadata.len() > MAX_TOKEN_FILE {
            return Err(TokenFileError::TooLarge {
                path: path.to_path_buf(),
            });
        }
        let mut text = String::new();
        file.take(MAX_TOKEN_FILE + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        if text.len() as u64 > MAX_TOKEN_FILE {
            return Err(TokenFileError::TooLarge {
                path: path.to_path_buf(),
            });
        }
        let tree = parse_tree(&text, path)?;
        let records = match &tree {
            Json::Array(records) => records.as_slice(),
            Json::Object(object) => match object.get("tokens") {
                Some(Json::Array(records)) if object.len() == 1 => records.as_slice(),
                _ => {
                    return Err(TokenFileError::Invalid(format!(
                        "the token file {} is a list of token records, bare or under `tokens:`",
                        path.display()
                    )));
                }
            },
            _ => {
                return Err(TokenFileError::Invalid(format!(
                    "the token file {} is a list of token records, bare or under `tokens:`",
                    path.display()
                )));
            }
        };
        let mut tokens = StaticTokens::new();
        for (index, record) in records.iter().enumerate() {
            tokens = tokens.record(record).map_err(|reason| {
                TokenFileError::Invalid(format!(
                    "the token file {}, record {index}: {reason}",
                    path.display()
                ))
            })?;
        }
        if tokens.is_empty() {
            return Err(TokenFileError::Invalid(format!(
                "the token file {} holds no token",
                path.display()
            )));
        }
        Ok(tokens)
    }

    /// Adds one record of a token file; the error names fields, never values.
    fn record(self, record: &Json) -> Result<StaticTokens, String> {
        let Json::Object(fields) = record else {
            return Err("a record is {token or sha256, principal, scopes}".to_owned());
        };
        let mut token = None;
        let mut digest = None;
        let mut principal = None;
        let mut scopes = Vec::new();
        for (key, value) in fields {
            match (key.as_str(), value) {
                ("token", Json::String(text)) => token = Some(text.as_str()),
                ("sha256", Json::String(text)) => digest = Some(text.as_str()),
                ("principal", Json::String(text)) => principal = Some(text.clone()),
                ("scopes", Json::Array(items)) => {
                    for item in items {
                        match item {
                            Json::String(scope) => scopes.push(scope.clone()),
                            _ => return Err("scopes is a list of strings".to_owned()),
                        }
                    }
                }
                ("scopes", Json::Null) => {}
                ("token" | "sha256" | "principal", _) => {
                    return Err(format!("{key} is a string"));
                }
                ("scopes", _) => return Err("scopes is a list of strings".to_owned()),
                (other, _) => {
                    let shown: String = other.chars().take(40).collect();
                    return Err(format!(
                        "unknown field {shown:?} (a record is {{token or sha256, principal, \
                         scopes}})"
                    ));
                }
            }
        }
        let principal = principal.ok_or("a record names its principal")?;
        let added = match (token, digest) {
            (Some(token), None) => self.token(token, principal, scopes),
            (None, Some(digest)) => self.sha256(digest, principal, scopes),
            (Some(_), Some(_)) => {
                return Err("a record holds a token or a sha256, not both".to_owned());
            }
            (None, None) => return Err("a record holds a token or its sha256".to_owned()),
        };
        added.map_err(|error| error.to_string())
    }

    /// How many tokens are known.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The principals the tokens stand for, in order.
    pub fn principals(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.principal.as_str())
            .collect()
    }

    /// The caller `token` names, if any: compared with every known digest in constant time.
    pub fn lookup(&self, token: &str) -> Option<Principal> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return None;
        }
        self.find_digest(&sha256(token.as_bytes()))
            .map(|entry| Principal::token(entry.principal.clone(), entry.scopes.iter().cloned()))
    }

    /// The entry whose digest is `presented`: every entry is compared, in constant time, and
    /// the matching index is selected without a branch.
    fn find_digest(&self, presented: &[u8; 32]) -> Option<&TokenEntry> {
        let mut matched = Choice::from(0);
        let mut index = 0u64;
        for (at, entry) in self.entries.iter().enumerate() {
            let equal = digest_eq(&entry.digest, presented);
            index.conditional_assign(&(at as u64), equal);
            matched |= equal;
        }
        if bool::from(matched) {
            usize::try_from(index)
                .ok()
                .and_then(|index| self.entries.get(index))
        } else {
            None
        }
    }
}

impl TokenVerifier for StaticTokens {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        let found = self.lookup(token);
        Box::pin(async move { found.ok_or_else(|| AuthError::new("the token is not known")) })
    }
}

impl<T: TokenVerifier + ?Sized> TokenVerifier for std::sync::Arc<T> {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        (**self).verify(token)
    }
}

/// Two digests compared in constant time.
fn digest_eq(known: &[u8; 32], presented: &[u8; 32]) -> Choice {
    #[cfg(test)]
    tests::COMPARISONS.with(|count| count.set(count.get() + 1));
    known.ct_eq(presented)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    crypto::port().sha256(data)
}

fn parse_digest(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0u8; 32];
    for (at, byte) in digest.iter_mut().enumerate() {
        let pair = hex.get(at * 2..at * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(digest)
}

#[cfg(unix)]
fn check_mode(path: &Path, metadata: &std::fs::Metadata) -> Result<(), TokenFileError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TokenFileError::Readable {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), TokenFileError> {
    Ok(())
}

/// The file as a JSON tree: JSON when it looks like JSON, else YAML within the bounds the fleet
/// file is read with. Errors carry a location, never the file's content.
fn parse_tree(text: &str, path: &Path) -> Result<Json, TokenFileError> {
    parse_document(text, MAX_TOKEN_FILE as usize).map_err(|reason| TokenFileError::Parse {
        path: path.to_path_buf(),
        reason,
    })
}

/// A YAML or JSON document of at most `max_bytes` as a JSON tree: JSON when it looks like
/// JSON, else YAML within the bounds the fleet file is read with (no aliases or anchors, one
/// document, depth 16). The error carries a location, never the document's content.
pub(crate) fn parse_document(text: &str, max_bytes: usize) -> Result<Json, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if matches!(text.trim_start().chars().next(), Some('{' | '[')) {
        return serde_json::from_str::<Json>(text)
            .map_err(|error| format!("line {}, column {}", error.line(), error.column()));
    }
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(max_bytes),
            max_events: 200_000,
            max_aliases: 0,
            max_anchors: 0,
            max_depth: 16,
            max_documents: 1,
            max_nodes: 100_000,
            max_total_scalar_bytes: max_bytes,
            max_merge_keys: 0,
        },
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options::<Json>(text, options).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        /// How many digest comparisons ran on this thread.
        pub(super) static COMPARISONS: Cell<usize> = const { Cell::new(0) };
    }

    fn comparisons() -> usize {
        COMPARISONS.with(Cell::get)
    }

    fn tokens() -> StaticTokens {
        StaticTokens::new()
            .token("first-secret", "ana", ["a"])
            .and_then(|tokens| tokens.token("second-secret", "bob", ["b"]))
            .and_then(|tokens| tokens.token("third-secret", "cy", Vec::<String>::new()))
            .expect("tokens")
    }

    /// Every lookup compares the presented digest with every known one, in constant time,
    /// whichever record matches or none: no early exit shows which record matched.
    #[test]
    fn every_lookup_compares_every_digest_in_constant_time() {
        let tokens = tokens();
        for presented in ["first-secret", "third-secret", "nope", "first-secreT"] {
            let before = comparisons();
            let _ = tokens.lookup(presented);
            assert_eq!(comparisons() - before, 3, "{presented}");
        }
        assert_eq!(
            tokens.lookup("second-secret"),
            Some(Principal::token("bob", ["b"]))
        );
        assert_eq!(
            tokens.lookup("first-secret").and_then(|p| p.subject),
            Some("ana".into())
        );
        assert!(tokens.lookup("second-secre").is_none());
        assert!(tokens.lookup("").is_none());
        assert!(tokens.lookup(&"x".repeat(MAX_TOKEN_BYTES + 1)).is_none());
    }

    #[test]
    fn records_are_checked_without_showing_values() {
        assert!(StaticTokens::new().token("  ", "ana", ["a"]).is_err());
        assert!(StaticTokens::new().token("t", " ", ["a"]).is_err());
        assert!(tokens().token("first-secret", "eve", ["a"]).is_err());
        assert!(StaticTokens::new().sha256("zz", "ana", ["a"]).is_err());
        let hex = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        let by_digest = StaticTokens::new()
            .sha256(hex, "ana", ["a"])
            .expect("digest");
        assert_eq!(
            by_digest.lookup("password").and_then(|p| p.subject),
            Some("ana".into())
        );
        let error = StaticTokens::new()
            .record(&serde_json::json!({"token": 12345, "principal": "x"}))
            .expect_err("refused");
        assert!(!error.contains("12345"), "{error}");
        let error = StaticTokens::new()
            .record(&serde_json::json!({"token": "s3cret", "principal": "x", "scope": ["a"]}))
            .expect_err("refused");
        assert!(error.contains("unknown field \"scope\""), "{error}");
        assert!(!error.contains("s3cret"), "{error}");
        assert!(!format!("{:?}", tokens()).contains("secret"));
    }
}
