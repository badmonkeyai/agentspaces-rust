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

//! The self-certifying names (SPEC §4): a PeerID, GroupID, or SpaceID is multibase base58btc of
//! SHA-256 over its material, so every implementation derives identical names from identical
//! bytes. Ports `identity.py`'s `derive_id`, `group_id_from_founding`, and `space_id_local`, and
//! Java `GroupId.ofUri` for the join URI.
#![warn(missing_docs)]

use crate::base58;
use crate::crypto;

/// The URI scheme prefix of a group's id (`aspace://<groupID>`, SPEC §4.4); a founding
/// advertisement's `id` carries it.
pub const URI_PREFIX: &str = "aspace://";

/// `multibase(sha-256(material))`: PeerIDs (over the raw 32-byte Ed25519 public key), GroupIDs,
/// and SpaceIDs alike. Hashes through the installed [`crypto::port`].
pub fn derive_id(material: &[u8]) -> String {
    base58::multibase(&crypto::port().sha256(material))
}

/// The GroupID of founding bytes (Java `GroupId.fromFounding`): the founding string's UTF-8 for a
/// `founding:` group, or the canonical CBOR of the founding document for a self-certifying one
/// (SPEC §4.4). The same derivation as [`derive_id`]; the name records what the material is.
pub fn group_id_from_founding(founding: &[u8]) -> String {
    derive_id(founding)
}

/// The SpaceID of a local space name (Java `SpaceId.local`): the hash of `"local:" + name`. A
/// group's space is conventionally named `<groupID>/<space>`.
pub fn space_id_local(name: &str) -> String {
    let mut material = Vec::with_capacity("local:".len() + name.len());
    material.extend_from_slice(b"local:");
    material.extend_from_slice(name.as_bytes());
    derive_id(&material)
}

/// The `(peer, local name)` of an agent id, as Java `AgentId.parse` and its constructor accept
/// it: `<peerId>/<localName>` split at the first `/`, with a non-empty peer id and a non-empty
/// local name that holds no further `/`. `None` otherwise (`peer/`, `/name`, `peer/a/b`, no `/`).
///
/// The text of an id this accepts is exactly what Java writes the id back as
/// (`AgentId.encoded`), so a signature over it means the same bytes to Java. The peer id is not
/// checked to be well-formed multibase.
pub fn parse_agent_id(agent: &str) -> Option<(&str, &str)> {
    let (peer, local) = agent.split_once('/')?;
    (!peer.is_empty() && !local.is_empty() && !local.contains('/')).then_some((peer, local))
}

/// The bare GroupID of a join URI, as Java `GroupId.ofUri` parses it: surrounding whitespace and
/// control characters trimmed, an `aspace://` prefix (any letter case) removed, and anything from
/// the first `/` on (a space name) dropped. Accepts `aspace://<id>`, `aspace://<id>/<space>`, or a
/// bare id; `None` when no id remains. The id is not checked to be well-formed multibase.
///
/// The Python and Ruby `parse_group_id` are narrower than Java and this function: they match
/// the scheme in lower case only, keep a `/<space>` suffix, trim Unicode whitespace rather than
/// control characters, and return an empty id for a bare `aspace://`. They agree with this
/// function on a lower-case `aspace://<id>` or a bare id, trimmed of ASCII whitespace.
pub fn parse_group_id(text: &str) -> Option<&str> {
    // Java's String.trim: every code point up to U+0020.
    let text = text.trim_matches(|c: char| c <= ' ');
    let split = URI_PREFIX.len();
    let id = match (text.get(..split), text.get(split..)) {
        (Some(scheme), Some(rest)) if scheme.eq_ignore_ascii_case(URI_PREFIX) => rest,
        _ => text,
    };
    let id = id.split('/').next().unwrap_or_default();
    (!id.is_empty()).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_join_uris_like_java() {
        assert_eq!(parse_group_id("zAbc"), Some("zAbc"));
        assert_eq!(parse_group_id("aspace://zAbc"), Some("zAbc"));
        assert_eq!(parse_group_id("  aspace://zAbc/tasks \n"), Some("zAbc"));
        assert_eq!(parse_group_id("ASPACE://zAbc"), Some("zAbc"));
        assert_eq!(parse_group_id("aspace://"), None);
        assert_eq!(parse_group_id("aspace:///tasks"), None);
        assert_eq!(parse_group_id("   "), None);
        assert_eq!(parse_group_id(""), None);
        // A multi-byte character where the scheme would end must not split a code point.
        assert_eq!(parse_group_id("aspace:/é"), Some("aspace:"));
        assert_eq!(parse_group_id("ééééé"), Some("ééééé"));
    }

    #[test]
    fn agent_ids_parse_as_java_parses_them() {
        assert_eq!(parse_agent_id("zP/a"), Some(("zP", "a")));
        assert_eq!(parse_agent_id("zP/a.b-c"), Some(("zP", "a.b-c")));
        for bad in ["zP/", "/a", "zP/a/b", "zP", "", "/", "zP//a"] {
            assert_eq!(parse_agent_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn derived_ids_are_multibase_sha256() {
        // sha-256("") = e3b0c442...; its base58btc is fixed.
        let id = derive_id(b"");
        assert!(id.starts_with('z'));
        assert_eq!(
            base58::multibase_decode(&id).unwrap(),
            crypto::port().sha256(b"").to_vec()
        );
        assert_eq!(group_id_from_founding(b"x"), derive_id(b"x"));
        assert_eq!(space_id_local("g/tasks"), derive_id(b"local:g/tasks"));
    }
}
