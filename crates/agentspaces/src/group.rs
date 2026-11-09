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

//! How a peer names the group it joins, and the security profile it runs.

use agentspaces_wire::ids;

/// The group a peer joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSpec {
    /// A group founded from a text, as the Java demos and `founding:` configuration found them.
    /// The GroupID is `multibase(sha-256(text))`. Such a group has no signed founding, so it can
    /// only be joined this way, never by id (a seed holding only the text answers no GROUP_AD).
    FoundingText(String),
    /// Join by GroupID (`aspace://<id>` or the bare id): the peer asks the seed for the signed
    /// founding advertisement (GROUP_AD_WANT, GROUP_AD) and verifies it with the four checks of
    /// SPEC §5.1 before it introduces itself.
    Join(String),
    /// A signed founding advertisement the caller holds (its CBOR bytes), verified locally.
    FoundingDocument(Vec<u8>),
}

impl GroupSpec {
    /// The GroupID when it is known without asking the network: derived from a founding text,
    /// parsed from a join URI, or `None` for a document not yet verified.
    pub fn group_id(&self) -> Option<String> {
        match self {
            Self::FoundingText(text) => Some(ids::group_id_from_founding(text.as_bytes())),
            Self::Join(uri) => ids::parse_group_id(uri).map(str::to_owned),
            Self::FoundingDocument(_) => None,
        }
    }
}

/// The security profile: what the peer requires of its links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Signed frames over any transport, plaintext `tcp` allowed. Never on a shared network.
    DevLocal,
    /// TLS 1.3 with attested channel certificates; a plaintext seed outside loopback is refused.
    #[default]
    Mtls,
}

impl Profile {
    /// Parses `dev-local` or `mtls` (case-insensitive).
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "dev-local" => Some(Self::DevLocal),
            "mtls" => Some(Self::Mtls),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_ids_come_from_text_or_uri() {
        let text = GroupSpec::FoundingText("research-fleet-demo-v1".into());
        let id = text.group_id().expect("derived");
        assert_eq!(
            GroupSpec::Join(format!("aspace://{id}"))
                .group_id()
                .as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            GroupSpec::Join(id.clone()).group_id().as_deref(),
            Some(id.as_str())
        );
        assert_eq!(GroupSpec::FoundingDocument(vec![]).group_id(), None);
        assert_eq!(Profile::parse("DEV-LOCAL"), Some(Profile::DevLocal));
        assert_eq!(Profile::parse("nope"), None);
    }
}
