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

//! The exit codes of `aspace` and the failure every command answers.
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | an error: no seed accepted the connection, an I/O failure, the peer closed |
//! | 2 | refused or not found: a configuration or argument refused, nothing matched, an entry not held |
//! | 3 | a timeout: the join, every seed's dial, a wait for an entry, a confirmation |
//! | 4 | authentication or authorization: a revoked identity, a readable private key, another writer's entry, a founding that does not verify, a seed that is not attested, a daemon socket or directory not this user's, an MCP token file others may read or policy or key set file others may write |

use std::fmt;

use agentspaces::catalog::CatalogError;
use agentspaces::config::ConfigError;
use agentspaces::json::JsonError;
use agentspaces::keystore::KeystoreError;
use agentspaces::peer::PeerError;
use agentspaces::space::SpaceError;
use agentspaces_mcp::{AuthError, PolicyFileError, ServeError, TokenFileError};

/// Success.
pub const SUCCESS: u8 = 0;
/// An error.
pub const ERROR: u8 = 1;
/// Refused or not found.
pub const REFUSED: u8 = 2;
/// A timeout.
pub const TIMEOUT: u8 = 3;
/// Authentication or authorization.
pub const AUTH: u8 = 4;

/// Why a command did not succeed: an exit code and the message for standard error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The exit code.
    pub code: u8,
    /// What went wrong, and the fix when there is one.
    pub message: String,
}

impl Failure {
    /// An error (exit 1).
    pub fn error(message: impl Into<String>) -> Self {
        Self::with(ERROR, message)
    }

    /// A refusal or a miss (exit 2).
    pub fn refused(message: impl Into<String>) -> Self {
        Self::with(REFUSED, message)
    }

    /// A timeout (exit 3).
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::with(TIMEOUT, message)
    }

    /// An authentication or authorization failure (exit 4).
    pub fn auth(message: impl Into<String>) -> Self {
        Self::with(AUTH, message)
    }

    fn with(code: u8, message: impl Into<String>) -> Self {
        Failure {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<ConfigError> for Failure {
    fn from(error: ConfigError) -> Self {
        Failure::refused(error.to_string())
    }
}

impl From<JsonError> for Failure {
    fn from(error: JsonError) -> Self {
        Failure::refused(error.to_string())
    }
}

impl From<KeystoreError> for Failure {
    fn from(error: KeystoreError) -> Self {
        match error {
            KeystoreError::Readable { .. } => Failure::auth(error.to_string()),
            KeystoreError::UnsafeName { .. } => Failure::refused(error.to_string()),
            other => Failure::error(other.to_string()),
        }
    }
}

impl From<PeerError> for Failure {
    fn from(error: PeerError) -> Self {
        let message = error.to_string();
        match error {
            PeerError::JoinTimeout { .. } | PeerError::DialTimedOut(_) => Failure::timeout(message),
            PeerError::Revoked(_)
            | PeerError::ForeignAgent(_)
            | PeerError::InvalidFounding
            | PeerError::SeedNotAttested(_) => Failure::auth(message),
            PeerError::Config(config) => config.into(),
            PeerError::Keystore(keystore) => keystore.into(),
            PeerError::InvalidGroup(_)
            | PeerError::InvalidArgument(_)
            | PeerError::Refused { .. }
            | PeerError::FrameTooLarge(_) => Failure::refused(message),
            _ => Failure::error(message),
        }
    }
}

impl From<SpaceError> for Failure {
    fn from(error: SpaceError) -> Self {
        let message = error.to_string();
        match error {
            SpaceError::Peer(peer) => peer.into(),
            SpaceError::NotIssuer { .. } => Failure::auth(message),
            SpaceError::InvalidLease(_)
            | SpaceError::Filter(_)
            | SpaceError::Entry(_)
            | SpaceError::UnknownEntry(_)
            | SpaceError::NotHeld(_)
            | SpaceError::LeaseLapsed(_)
            | SpaceError::Refused { .. } => Failure::refused(message),
            _ => Failure::error(message),
        }
    }
}

impl From<CatalogError> for Failure {
    fn from(error: CatalogError) -> Self {
        let message = error.to_string();
        match error {
            CatalogError::Space(space) => space.into(),
            CatalogError::Unauthorized(_) => Failure::auth(message),
            CatalogError::NotFound(_)
            | CatalogError::Ambiguous { .. }
            | CatalogError::NoLongerOffered(_) => Failure::refused(format!(
                "{message}; `aspace cards` lists what the fleet offers"
            )),
            _ => Failure::error(message),
        }
    }
}

impl From<TokenFileError> for Failure {
    /// A token file its group or others may read exits 4, as a readable private key does;
    /// any other refusal of it exits 2.
    fn from(error: TokenFileError) -> Self {
        match error {
            TokenFileError::Readable { .. } => Failure::auth(error.to_string()),
            TokenFileError::Io { .. } => Failure::error(error.to_string()),
            other => Failure::refused(other.to_string()),
        }
    }
}

impl From<PolicyFileError> for Failure {
    /// A policy file its group or others may write exits 4; any other refusal of it exits 2.
    fn from(error: PolicyFileError) -> Self {
        match error {
            PolicyFileError::Writable { .. } => Failure::auth(error.to_string()),
            PolicyFileError::Io { .. } => Failure::error(error.to_string()),
            other => Failure::refused(other.to_string()),
        }
    }
}

impl From<AuthError> for Failure {
    /// A JWT verifier that cannot be built (an issuer, audience, or key set it cannot use); a
    /// key set file its group or others may write is an authorization failure (exit 4), as a
    /// policy file they may write is.
    fn from(error: AuthError) -> Self {
        if error.is_unsafe_file() {
            Failure::auth(format!("the JWT verifier: {error}"))
        } else {
            Failure::refused(format!("the JWT verifier: {error}"))
        }
    }
}

impl From<ServeError> for Failure {
    fn from(error: ServeError) -> Self {
        let message = error.to_string();
        match error {
            ServeError::NoVerifier { .. } => Failure::refused(format!(
                "{message} (aspace mcp --tokens FILE, or --jwt-issuer, --jwt-audience, and \
                 --jwks; --allow-unauthenticated only behind a proxy that authenticates)"
            )),
            ServeError::Options(_) => Failure::refused(message),
            _ => Failure::error(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn errors_map_to_the_contract_codes() {
        assert_eq!(
            Failure::from(PeerError::JoinTimeout {
                group: "z".into(),
                timeout: Duration::from_secs(1)
            })
            .code,
            TIMEOUT
        );
        assert_eq!(Failure::from(PeerError::Revoked("p".into())).code, AUTH);
        assert_eq!(Failure::from(PeerError::NoSeeds).code, ERROR);
        // Every seed's dial timing out is a timeout, and a seed that is not attested an
        // authentication failure, however many seeds there are; a refusal stays an error.
        assert_eq!(
            Failure::from(PeerError::DialTimedOut("tls://h:1: timed out".into())).code,
            TIMEOUT
        );
        assert_eq!(
            Failure::from(PeerError::SeedNotAttested("tls://h:1".into())).code,
            AUTH
        );
        assert_eq!(
            Failure::from(PeerError::NoSeedAccepted("tcp://h:1: refused".into())).code,
            ERROR
        );
        assert_eq!(Failure::from(ConfigError::NoGroup).code, REFUSED);
        assert_eq!(Failure::from(SpaceError::NotHeld("e".into())).code, REFUSED);
        assert_eq!(
            Failure::from(SpaceError::Peer(PeerError::Closed)).code,
            ERROR
        );
        assert_eq!(
            Failure::from(PeerError::Config(ConfigError::NoGroup)).code,
            REFUSED
        );
        assert_eq!(
            Failure::from(CatalogError::NotFound("x".into())).code,
            REFUSED
        );
        assert_eq!(
            Failure::from(CatalogError::Ambiguous {
                query: "s#v1".into(),
                candidates: vec!["a".into(), "b".into()]
            })
            .code,
            REFUSED
        );
        assert_eq!(
            Failure::from(CatalogError::Unauthorized("x".into())).code,
            AUTH
        );
        assert_eq!(
            Failure::from(CatalogError::Space(SpaceError::Peer(PeerError::Closed))).code,
            ERROR
        );
    }
}
