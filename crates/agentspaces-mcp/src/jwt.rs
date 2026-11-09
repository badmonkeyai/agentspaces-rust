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

//! JWT bearer tokens: [`JwtVerifier`] checks a token's signature against the issuer's
//! JSON Web Key Set, its issuer, audience, expiry, and not-before time, and answers the principal
//! it names with the scopes it carries.
//!
//! ```no_run
//! # fn run() -> Result<(), agentspaces_mcp::AuthError> {
//! use agentspaces_mcp::{JwksSource, JwtOptions, JwtVerifier};
//!
//! let verifier = JwtVerifier::new(
//!     JwtOptions::new(
//!         "https://auth.example.com/",
//!         "https://mcp.example.com/mcp",
//!         JwksSource::Url("https://auth.example.com/.well-known/jwks.json".into()),
//!     )
//!     .algorithms(["RS256", "ES256"])?,
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! - **Keys.** The key set comes from a URL (HTTPS, or HTTP to a loopback address only), a
//!   file, or text. It is cached; a token naming a key id (`kid`) the cache does not hold
//!   reloads the set, at most once per [`JwtOptions::refresh_cooldown`] (30 s by default), so a
//!   flood of made-up key ids cannot make the gateway hammer the issuer; the set is also
//!   reloaded on use once it is older than [`JwtOptions::max_cache_age`] (1 hour). One reload
//!   runs at a time, and the cache is never locked while it fetches: a token whose key is
//!   cached is judged at once, whatever reload a made-up key id started or however slow the
//!   issuer answers; only tokens waiting for the reload's keys wait for it. A token without a
//!   key id is judged by the one key of its algorithm's family when the set holds exactly one.
//!   A key marked for encryption (`use: enc`) or for another algorithm (`alg`) is never used.
//! - **Key files.** A key set file decides who may sign tokens, so, like a policy file, it is
//!   refused when its group or others may write it (`chmod go-w`), or when it is not a regular
//!   file; it is judged and read through one open handle, at most 1 MiB.
//! - **Algorithms.** Only those [`JwtOptions::algorithms`] names are accepted (by default
//!   `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, and `EdDSA`; the
//!   HMAC algorithms only when named), and the key's family must match the token's algorithm.
//! - **Claims.** `iss` must be the issuer, `aud` one of the audiences, and `exp` present and in
//!   the future, all within [`JwtOptions::leeway`] (60 s); `nbf`, when present, in the past. The
//!   principal is `sub` (else `azp`, else `client_id`); the scopes are the space-separated
//!   `scope` claim and the `scp` claim (a list, or a space-separated string).

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agentspaces::catalog::Principal;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header};
use serde_json::{Map as JsonMap, Value as Json};
use tokio::time::Instant;

use crate::auth::{AuthError, MAX_SCOPES, MAX_TOKEN_BYTES, TokenVerifier, VerifyFuture};

/// The largest key set read.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// The most keys of a set kept.
pub const MAX_JWKS_KEYS: usize = 64;

/// The algorithms accepted by default: every asymmetric one.
pub const DEFAULT_ALGORITHMS: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// Where a key set comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwksSource {
    /// Fetched over HTTPS (or HTTP to a loopback address), as an issuer publishes it.
    Url(String),
    /// Read from a file.
    File(PathBuf),
    /// The set's JSON text itself.
    Inline(String),
}

/// What a [`JwtVerifier`] accepts; see the [module docs](self).
#[derive(Debug, Clone)]
pub struct JwtOptions {
    issuer: String,
    audiences: Vec<String>,
    jwks: JwksSource,
    algorithms: Vec<Algorithm>,
    leeway: Duration,
    refresh_cooldown: Duration,
    max_cache_age: Duration,
    http_timeout: Duration,
}

impl JwtOptions {
    /// Tokens of `issuer` for `audience`, signed by a key of `jwks`.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: JwksSource) -> Self {
        JwtOptions {
            issuer: issuer.into(),
            audiences: vec![audience.into()],
            jwks,
            algorithms: DEFAULT_ALGORITHMS
                .iter()
                .filter_map(|name| Algorithm::from_str(name).ok())
                .collect(),
            leeway: Duration::from_secs(60),
            refresh_cooldown: Duration::from_secs(30),
            max_cache_age: Duration::from_secs(3600),
            http_timeout: Duration::from_secs(10),
        }
    }

    /// Also accepts tokens for `audience`.
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Accepts only the algorithms named (`RS256`, `ES256`, `EdDSA`, ...).
    ///
    /// # Errors
    ///
    /// [`AuthError`] for a name that is no JWS algorithm, or for none at all.
    pub fn algorithms<S: AsRef<str>>(
        mut self,
        names: impl IntoIterator<Item = S>,
    ) -> Result<Self, AuthError> {
        let mut algorithms = Vec::new();
        for name in names {
            let name = name.as_ref();
            let algorithm = Algorithm::from_str(name)
                .map_err(|_| AuthError::new(format!("{name:?} is not a JWS algorithm")))?;
            if !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
        if algorithms.is_empty() {
            return Err(AuthError::new(
                "a JWT verifier accepts at least one algorithm",
            ));
        }
        self.algorithms = algorithms;
        Ok(self)
    }

    /// The clock skew allowed for `exp` and `nbf` (60 s by default).
    #[must_use]
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The least time between two reloads of the key set for an unknown key id (30 s).
    #[must_use]
    pub fn refresh_cooldown(mut self, cooldown: Duration) -> Self {
        self.refresh_cooldown = cooldown;
        self
    }

    /// How old the cached key set may grow before a use reloads it (1 hour).
    #[must_use]
    pub fn max_cache_age(mut self, age: Duration) -> Self {
        self.max_cache_age = age;
        self
    }

    /// How long fetching the key set may take (10 s).
    #[must_use]
    pub fn http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }
}

#[derive(Clone)]
struct CachedKey {
    kid: Option<String>,
    algorithm: Option<Algorithm>,
    key: DecodingKey,
}

#[derive(Default)]
struct KeyCache {
    keys: Arc<Vec<CachedKey>>,
    loaded: Option<Instant>,
}

/// Verifies JWT bearer tokens against an issuer's key set; see the [module docs](self).
pub struct JwtVerifier {
    options: JwtOptions,
    client: Option<reqwest::Client>,
    /// The keys held and when they were (last asked to be) loaded; never locked across I/O.
    cache: Mutex<KeyCache>,
    /// Held by the one reload running.
    reloading: tokio::sync::Mutex<()>,
    loads: AtomicU64,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("options", &self.options)
            .field("loads", &self.jwks_loads())
            .finish_non_exhaustive()
    }
}

impl JwtVerifier {
    /// A verifier under `options`. A file or inline key set is read now; a URL is fetched at the
    /// first token.
    ///
    /// # Errors
    ///
    /// [`AuthError`] for a URL that is neither HTTPS nor HTTP to a loopback address, a key set
    /// that cannot be read or holds no usable key, or an HTTP client that cannot be built.
    pub fn new(options: JwtOptions) -> Result<JwtVerifier, AuthError> {
        if options
            .audiences
            .iter()
            .all(|audience| audience.trim().is_empty())
        {
            return Err(AuthError::new("a JWT verifier names its audience"));
        }
        if options.issuer.trim().is_empty() {
            return Err(AuthError::new("a JWT verifier names its issuer"));
        }
        let client = match &options.jwks {
            JwksSource::Url(url) => {
                check_url(url)?;
                Some(
                    reqwest::Client::builder()
                        .timeout(options.http_timeout)
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .map_err(|error| {
                            AuthError::new(format!("cannot build the JWKS client: {error}"))
                        })?,
                )
            }
            JwksSource::File(_) | JwksSource::Inline(_) => None,
        };
        let cache = match &options.jwks {
            JwksSource::Url(_) => KeyCache::default(),
            local => KeyCache {
                keys: Arc::new(read_local(local)?),
                loaded: Some(Instant::now()),
            },
        };
        let loads = u64::from(cache.loaded.is_some());
        Ok(JwtVerifier {
            options,
            client,
            cache: Mutex::new(cache),
            reloading: tokio::sync::Mutex::new(()),
            loads: AtomicU64::new(loads),
        })
    }

    /// The keys held and when they were loaded, read under the cache lock and nothing else.
    fn held(&self) -> (Arc<Vec<CachedKey>>, Option<Instant>) {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        (Arc::clone(&cache.keys), cache.loaded)
    }

    fn is_stale(&self, loaded: Option<Instant>) -> bool {
        loaded.is_none_or(|loaded| loaded.elapsed() >= self.options.max_cache_age)
    }

    /// How many times the key set was loaded (read or fetched) successfully.
    pub fn jwks_loads(&self) -> u64 {
        self.loads.load(Ordering::Relaxed)
    }

    /// The caller `token` names; see the [module docs](self).
    ///
    /// # Errors
    ///
    /// [`AuthError`] with the reason the token is refused.
    pub async fn verify_token(&self, token: &str) -> Result<Principal, AuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::new("the token is not a JWT"));
        }
        let header = decode_header(token).map_err(|_| AuthError::new("the token is not a JWT"))?;
        let algorithm = header.alg;
        if !self.options.algorithms.contains(&algorithm) {
            return Err(AuthError::new("the token's algorithm is not accepted"));
        }
        let key = self.key_for(header.kid.as_deref(), algorithm).await?;
        let mut validation = Validation::new(algorithm);
        validation.algorithms = vec![algorithm];
        validation.set_issuer(&[self.options.issuer.as_str()]);
        validation.set_audience(&self.options.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = self.options.leeway.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        let data = decode::<JsonMap<String, Json>>(token, &key, &validation)
            .map_err(|error| AuthError::new(refusal(error.kind())))?;
        principal_of(&data.claims)
    }

    /// The key that judges a token of `algorithm` naming `kid`: from the cache, reloaded when
    /// stale, or (once per cooldown) when the key id is unknown. A key the cache holds is
    /// answered without waiting for any reload ([module docs](self)).
    async fn key_for(
        &self,
        kid: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<DecodingKey, AuthError> {
        let not_held = || AuthError::new("the token's signing key is not in the issuer's key set");
        let (keys, loaded) = self.held();
        let known = pick(&keys, kid, algorithm);
        if !self.is_stale(loaded)
            && let Some(key) = known
        {
            return Ok(key);
        }
        if let Some(key) = known {
            // A stale set still holds this key: one caller reloads it, the others go on.
            let Ok(_reloading) = self.reloading.try_lock() else {
                return Ok(key);
            };
            if self.is_stale(self.held().1) {
                self.reload().await;
            }
            let (keys, _) = self.held();
            return pick(&keys, kid, algorithm).ok_or_else(not_held);
        }
        // An unknown key (or none loaded yet): wait for the reload running, if any, then look
        // again before asking the issuer.
        let _reloading = self.reloading.lock().await;
        let (keys, loaded) = self.held();
        let stale = self.is_stale(loaded);
        if !stale && let Some(key) = pick(&keys, kid, algorithm) {
            return Ok(key);
        }
        let cooled = loaded.is_none_or(|loaded| loaded.elapsed() >= self.options.refresh_cooldown);
        if stale || ((kid.is_some() || keys.is_empty()) && cooled) {
            self.reload().await;
            let (keys, _) = self.held();
            if let Some(key) = pick(&keys, kid, algorithm) {
                return Ok(key);
            }
        }
        Err(not_held())
    }

    /// Loads the key set into the cache, the cache lock held only to stamp and to swap; on
    /// failure keeps the keys it had (logged, never the token). The caller holds `reloading`.
    async fn reload(&self) {
        // Stamped first: a load in flight counts against the cooldown and the cache's age, so
        // tokens arriving meanwhile neither queue more loads nor wait for a stale set.
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .loaded = Some(Instant::now());
        let loaded = match &self.options.jwks {
            JwksSource::Url(url) => self.fetch(url).await,
            local => read_local(local),
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        // A failed load counts against the cooldown too: an unreachable issuer is not retried
        // for every token.
        cache.loaded = Some(Instant::now());
        match loaded {
            Ok(keys) => {
                cache.keys = Arc::new(keys);
                self.loads.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                tracing::warn!(%error, "the JWT key set could not be loaded; keeping the keys held");
            }
        }
    }

    async fn fetch(&self, url: &str) -> Result<Vec<CachedKey>, AuthError> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AuthError::new("no HTTP client for the key set"))?;
        let mut response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| AuthError::new(format!("cannot fetch the key set: {error}")))?;
        if !response.status().is_success() {
            return Err(AuthError::new(format!(
                "the key set answered HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(AuthError::new("the key set is too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| AuthError::new(format!("cannot read the key set: {error}")))?
        {
            if body.len() + chunk.len() > MAX_JWKS_BYTES {
                return Err(AuthError::new("the key set is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        parse_jwks(&body)
    }
}

impl TokenVerifier for JwtVerifier {
    fn verify<'a>(&'a self, token: &'a str) -> VerifyFuture<'a> {
        Box::pin(self.verify_token(token))
    }
}

/// The keys of a file or inline key set.
fn read_local(source: &JwksSource) -> Result<Vec<CachedKey>, AuthError> {
    let text = match source {
        JwksSource::Inline(text) => text.clone(),
        JwksSource::File(path) => read_key_file(path)?,
        JwksSource::Url(url) => {
            return Err(AuthError::new(format!("{url} is fetched, not read")));
        }
    };
    parse_jwks(text.as_bytes())
}

/// A key set file's text: opened once, judged by the opened file's own metadata (a regular file
/// its group and others may not write, at most [`MAX_JWKS_BYTES`]), and read through the same
/// handle, so the file judged is the file read. Whoever may write the file may add a key and
/// sign tokens for any subject and scope, as `Policy::load` judges a policy file.
fn read_key_file(path: &Path) -> Result<String, AuthError> {
    let unreadable = |error: std::io::Error| {
        AuthError::new(format!(
            "cannot read the key set {}: {error}",
            path.display()
        ))
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(AuthError::new(format!(
            "the key set {} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(AuthError::unsafe_file(format!(
                "the key set {} is writable by group or others (mode {mode:03o}), so they could \
                 add a key and sign tokens for anyone; run `chmod go-w {}`",
                path.display(),
                path.display()
            )));
        }
    }
    let too_large = || {
        AuthError::new(format!(
            "the key set {} is larger than {MAX_JWKS_BYTES} bytes",
            path.display()
        ))
    };
    if metadata.len() > MAX_JWKS_BYTES as u64 {
        return Err(too_large());
    }
    let mut text = String::new();
    file.take(MAX_JWKS_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    if text.len() > MAX_JWKS_BYTES {
        return Err(too_large());
    }
    Ok(text)
}

/// A URL a key set may be fetched from: HTTPS, or HTTP to a loopback address.
fn check_url(url: &str) -> Result<(), AuthError> {
    let parsed: http::Uri = url
        .parse()
        .map_err(|_| AuthError::new(format!("the key set URL {url:?} is not a URL")))?;
    let host = parsed
        .host()
        .ok_or_else(|| AuthError::new(format!("the key set URL {url:?} names no host")))?;
    match parsed.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if is_loopback_host(host) => Ok(()),
        _ => Err(AuthError::new(format!(
            "the key set URL {url:?} is not HTTPS (plain HTTP only to a loopback address)"
        ))),
    }
}

/// Whether `host` (a URL's host, IPv6 in brackets) is the loopback interface.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The usable signature keys of a key set's JSON; keys this verifier cannot use are passed over.
fn parse_jwks(bytes: &[u8]) -> Result<Vec<CachedKey>, AuthError> {
    let set: Json =
        serde_json::from_slice(bytes).map_err(|_| AuthError::new("the key set is not JSON"))?;
    let Some(Json::Array(keys)) = set.get("keys") else {
        return Err(AuthError::new("the key set has no \"keys\" list"));
    };
    let mut usable = Vec::new();
    for raw in keys.iter().take(MAX_JWKS_KEYS) {
        let Ok(jwk) = serde_json::from_value::<Jwk>(raw.clone()) else {
            continue;
        };
        if matches!(
            jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        ) {
            continue;
        }
        let algorithm = match jwk.common.key_algorithm {
            Some(declared) => match Algorithm::try_from(declared) {
                Ok(algorithm) => Some(algorithm),
                Err(_) => continue,
            },
            None => None,
        };
        let Ok(key) = DecodingKey::from_jwk(&jwk) else {
            continue;
        };
        usable.push(CachedKey {
            kid: jwk.common.key_id.clone(),
            algorithm,
            key,
        });
    }
    if usable.is_empty() {
        return Err(AuthError::new("the key set holds no usable signature key"));
    }
    Ok(usable)
}

/// The key of `keys` for a token of `algorithm` naming `kid`: the key with that id whose family
/// (and declared algorithm, if any) fits; without an id, the one key that fits.
fn pick(keys: &[CachedKey], kid: Option<&str>, algorithm: Algorithm) -> Option<DecodingKey> {
    let family: AlgorithmFamily = algorithm.family();
    let fits = |key: &&CachedKey| {
        key.key.family() == family && key.algorithm.is_none_or(|declared| declared == algorithm)
    };
    match kid {
        Some(kid) => keys
            .iter()
            .filter(fits)
            .find(|key| key.kid.as_deref() == Some(kid))
            .map(|key| key.key.clone()),
        None => {
            let mut fitting = keys.iter().filter(fits);
            match (fitting.next(), fitting.next()) {
                (Some(only), None) => Some(only.key.clone()),
                _ => None,
            }
        }
    }
}

/// A refusal's reason, for the caller (no detail of the token).
fn refusal(kind: &ErrorKind) -> &'static str {
    match kind {
        ErrorKind::ExpiredSignature => "the token has expired",
        ErrorKind::ImmatureSignature => "the token is not valid yet",
        ErrorKind::InvalidIssuer => "the token is not from the accepted issuer",
        ErrorKind::InvalidAudience => "the token is not for this server",
        ErrorKind::InvalidSignature => "the token's signature does not verify",
        ErrorKind::MissingRequiredClaim(_) => "the token lacks a required claim (exp, iss, aud)",
        ErrorKind::InvalidAlgorithm | ErrorKind::MissingAlgorithm => {
            "the token's algorithm does not fit its key"
        }
        _ => "the token is not a valid JWT",
    }
}

/// The principal and scopes a verified token's claims name.
fn principal_of(claims: &JsonMap<String, Json>) -> Result<Principal, AuthError> {
    let subject = ["sub", "azp", "client_id"]
        .iter()
        .find_map(|claim| claims.get(*claim).and_then(Json::as_str))
        .filter(|subject| !subject.trim().is_empty())
        .ok_or_else(|| AuthError::new("the token names no subject (sub, azp, or client_id)"))?;
    let mut scopes: Vec<String> = Vec::new();
    let mut add = |scope: &str| {
        if !scope.is_empty()
            && !scopes.iter().any(|known| known == scope)
            && scopes.len() < MAX_SCOPES
        {
            scopes.push(scope.to_owned());
        }
    };
    if let Some(Json::String(scope)) = claims.get("scope") {
        scope.split_whitespace().for_each(&mut add);
    }
    match claims.get("scp") {
        Some(Json::String(scope)) => scope.split_whitespace().for_each(&mut add),
        Some(Json::Array(items)) => items.iter().filter_map(Json::as_str).for_each(&mut add),
        _ => {}
    }
    Ok(Principal::token(subject, scopes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_set_urls_are_https_or_loopback() {
        assert!(check_url("https://auth.example.com/jwks.json").is_ok());
        assert!(check_url("http://127.0.0.1:9000/jwks.json").is_ok());
        assert!(check_url("http://[::1]:9000/jwks.json").is_ok());
        assert!(check_url("http://localhost/jwks.json").is_ok());
        assert!(check_url("http://auth.example.com/jwks.json").is_err());
        assert!(check_url("file:///etc/jwks.json").is_err());
        assert!(check_url("not a url").is_err());
    }

    #[test]
    fn scopes_come_from_scope_and_scp() {
        let claims = serde_json::json!({"sub": "ana", "scope": "a b", "scp": ["b", "c"]});
        let principal = principal_of(claims.as_object().expect("claims")).expect("a principal");
        assert_eq!(principal.subject.as_deref(), Some("ana"));
        assert_eq!(principal.scopes, ["a", "b", "c"]);
        let claims = serde_json::json!({"client_id": "svc", "scp": "x y"});
        let principal = principal_of(claims.as_object().expect("claims")).expect("a principal");
        assert_eq!(principal.subject.as_deref(), Some("svc"));
        assert_eq!(principal.scopes, ["x", "y"]);
        assert!(
            principal_of(
                serde_json::json!({"scope": "a"})
                    .as_object()
                    .expect("claims")
            )
            .is_err()
        );
    }

    const SET: &str = r#"{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "sig", "alg": "EdDSA"}]}"#;

    /// A key set file its group or others may write is refused (it decides who
    /// may sign tokens), as is a path that is not a regular file; an owner-written one loads.
    #[cfg(unix)]
    #[test]
    fn key_set_files_others_may_write_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("asrs-jwks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("jwks.json");
        std::fs::write(&path, SET).expect("write");
        let source = JwksSource::File(path.clone());
        for mode in [0o666, 0o664, 0o646, 0o620] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let refused = read_local(&source).err().map(|error| error.to_string());
            assert!(
                refused
                    .as_deref()
                    .is_some_and(|error| error.contains("writable by group or others")),
                "{mode:o}: {refused:?}"
            );
            assert!(
                JwtVerifier::new(JwtOptions::new("iss", "aud", source.clone()))
                    .is_err_and(|error| error.is_unsafe_file()),
                "{mode:o}"
            );
        }
        for mode in [0o644, 0o600, 0o444] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(
                read_local(&source).map(|keys| keys.len()).ok(),
                Some(1),
                "{mode:o}"
            );
        }
        let directory = read_local(&JwksSource::File(dir.clone()))
            .err()
            .map(|error| error.to_string());
        assert!(
            directory
                .as_deref()
                .is_some_and(|error| error.contains("not a regular file")),
            "{directory:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unusable_keys_are_passed_over() {
        assert!(parse_jwks(b"{}").is_err());
        assert!(parse_jwks(b"not json").is_err());
        assert!(parse_jwks(br#"{"keys": [{"kty": "nope"}]}"#).is_err());
        let set = br#"{"keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "enc", "use": "enc"},
            {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "sig", "alg": "EdDSA"}
        ]}"#;
        let keys = parse_jwks(set).expect("one key");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_deref(), Some("sig"));
        assert!(pick(&keys, Some("sig"), Algorithm::EdDSA).is_some());
        assert!(pick(&keys, None, Algorithm::EdDSA).is_some());
        assert!(pick(&keys, Some("enc"), Algorithm::EdDSA).is_none());
        assert!(pick(&keys, Some("sig"), Algorithm::RS256).is_none());
    }
}
