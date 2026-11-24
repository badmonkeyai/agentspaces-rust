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

//! The TTL floor (SPEC v0.1.36 §9.5, *TTLs*; the reference implementation's `TtlFloor`). A
//! short TTL makes a noisy group, since every renewal is a frame, so a TTL that
//! something renews should be about 1.5 times the cycle that renews it, and a TTL, lease, or
//! expiry a deployment configures under [`FLOOR`] needs a stated reason. Where this crate takes
//! a configured TTL (an agent's card TTL, the content swarm's holding lease, a persistent value's
//! head lease) it asks [`check`]: under the floor it logs a warning, or, under a strict policy,
//! refuses; a TTL the policy's overrides name passes either way (the expert's stated reason).
//!
//! The policy comes from the environment by default ([`TtlPolicy::from_env`]):
//! `AGENTSPACES_TTL_STRICT=true` refuses, and `AGENTSPACES_TTL_OVERRIDES` lists the names (comma
//! separated) an expert has judged; the names are those [`check`] is given, such as
//! `agent.card-ttl`.

use std::time::Duration;

/// The floor under which a configured TTL needs a reason (60 s).
pub const FLOOR: Duration = Duration::from_secs(60);

/// How a configured TTL under the floor is treated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Refuse rather than warn.
    pub strict: bool,
    /// The names of TTLs an expert has judged; these pass under the floor.
    pub overrides: Vec<String>,
}

impl TtlPolicy {
    /// The policy of the environment: `AGENTSPACES_TTL_STRICT` (`true` or `1` refuses) and
    /// `AGENTSPACES_TTL_OVERRIDES` (comma-separated names).
    pub fn from_env() -> Self {
        let strict = std::env::var("AGENTSPACES_TTL_STRICT")
            .is_ok_and(|value| matches!(value.trim(), "true" | "1" | "TRUE" | "True"));
        let overrides = std::env::var("AGENTSPACES_TTL_OVERRIDES")
            .map(|list| {
                list.split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Self { strict, overrides }
    }
}

/// A configured TTL under the floor that a strict policy refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the configured {name} of {ttl:?} is under the {floor:?} TTL floor (SPEC 9.5): give it a \
     longer value, or name it in AGENTSPACES_TTL_OVERRIDES with a stated reason",
    floor = FLOOR
)]
pub struct UnderFloor {
    /// The TTL's name.
    pub name: String,
    /// The value configured.
    pub ttl: Duration,
}

/// What [`check`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At or above the floor.
    Fine,
    /// Under the floor and named in the overrides.
    Overridden,
    /// Under the floor: warned.
    Warned,
}

/// Judges the configured TTL `name` of `ttl` under `policy`: [`Verdict::Fine`] at or above the
/// floor, [`Verdict::Overridden`] under it when the policy names it, otherwise a warning logged
/// ([`Verdict::Warned`]) or, under a strict policy, [`UnderFloor`].
pub fn check(name: &str, ttl: Duration, policy: &TtlPolicy) -> Result<Verdict, UnderFloor> {
    if ttl >= FLOOR {
        return Ok(Verdict::Fine);
    }
    if policy.overrides.iter().any(|named| named == name) {
        return Ok(Verdict::Overridden);
    }
    if policy.strict {
        return Err(UnderFloor {
            name: name.to_owned(),
            ttl,
        });
    }
    tracing::warn!(
        ttl = name,
        configured_ms = ttl.as_millis(),
        floor_ms = FLOOR.as_millis(),
        "agentspaces: a configured TTL is under the 60 s floor; a short TTL makes a noisy group \
         (name it in AGENTSPACES_TTL_OVERRIDES with a reason, or set AGENTSPACES_TTL_STRICT=true \
         to refuse)"
    );
    Ok(Verdict::Warned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ttl_under_the_floor_warns_refuses_when_strict_and_passes_when_named() {
        let lax = TtlPolicy::default();
        assert_eq!(check("agent.card-ttl", FLOOR, &lax), Ok(Verdict::Fine));
        assert_eq!(
            check("agent.card-ttl", Duration::from_secs(59), &lax),
            Ok(Verdict::Warned)
        );
        let strict = TtlPolicy {
            strict: true,
            overrides: vec!["content.holding-lease".to_owned()],
        };
        let refused = check("agent.card-ttl", Duration::from_secs(10), &strict);
        assert!(matches!(&refused, Err(error) if error.name == "agent.card-ttl"));
        assert!(refused.unwrap_err().to_string().contains("TTL floor"));
        assert_eq!(
            check("content.holding-lease", Duration::from_secs(10), &strict),
            Ok(Verdict::Overridden)
        );
        assert_eq!(
            check("agent.card-ttl", Duration::from_secs(600), &strict),
            Ok(Verdict::Fine)
        );
    }
}
