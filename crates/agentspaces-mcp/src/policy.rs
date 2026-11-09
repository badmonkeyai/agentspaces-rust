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

//! Who may invoke what: a [`Policy`] maps token scopes to the offerings a caller may
//! invoke, and the `only` patterns that limit what is offered at all.
//!
//! ```
//! use agentspaces_mcp::{Policy, Principal};
//!
//! let policy = Policy::scoped()
//!     .allow("orders:write", ["shop.*", "refund"])
//!     .allow("reports", ["report_*"]);
//! assert!(policy.allows(&Principal::token("ana", ["orders:write"]), "shop.order"));
//! assert!(!policy.allows(&Principal::token("ana", ["orders:write"]), "report_daily"));
//! assert!(policy.allows(&Principal::local(), "report_daily"), "the local user may call anything");
//! assert_eq!(policy.scopes_for("report_daily"), ["reports"]);
//! ```
//!
//! # Policy files
//!
//! [`Policy::load`] reads the same policy from a YAML or JSON file (`aspace mcp --policy`): each
//! scope with the offering globs it allows, and optionally what a caller without a token may
//! invoke (`local`, everything when absent):
//!
//! ```yaml
//! scopes:
//!   orders:write: ["shop.*", refund]
//!   reports: [report_*]
//!   "*": [ping]          # any verified token, whatever its scopes
//! local: ["*"]           # standard input and the same process
//! ```
//!
//! A policy file is not a secret, but whoever may change it may widen what callers invoke: it is
//! refused when its group or others may write it (`chmod go-w`).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use agentspaces::catalog::{FleetCatalog, Principal, glob};
use serde_json::Value as Json;

/// The largest policy file read.
pub const MAX_POLICY_FILE: u64 = 1024 * 1024;

/// Why a policy file was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyFileError {
    /// The file could not be read.
    #[error("cannot read the policy file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// Its group or others may write it.
    #[error(
        "the policy file {path} is writable by group or others (mode {mode:03o}), so they could \
         widen what callers may invoke; run `chmod go-w {path}`"
    )]
    Writable {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// It is larger than [`MAX_POLICY_FILE`].
    #[error("the policy file {path} is larger than {MAX_POLICY_FILE} bytes")]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// It is not YAML or JSON.
    #[error("the policy file {path} is not YAML or JSON: {reason}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// Where it went wrong.
        reason: String,
    },
    /// It is YAML or JSON, but not a policy.
    #[error("the policy file {path}: {reason}")]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
}

/// The scope rule that any caller with a verified token matches, whatever its scopes.
pub const ANY_SCOPE: &str = "*";

/// One scope's offerings.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    scope: String,
    offerings: Vec<String>,
}

/// What a caller may invoke, judged at every call ([`Policy::allows`]).
///
/// - [`Policy::open`] (the default): every caller may invoke every offering the gateway lists,
///   the posture of a local stdio server and of Ruby's gateway without `authorize`.
/// - [`Policy::scoped`]: a caller with a token may invoke an offering when one of its scopes has
///   a rule ([`Policy::allow`]) with a glob (`*` any run of characters, `?` one) matching the
///   offering's name; a rule for [`ANY_SCOPE`] matches every token. A local caller (no token:
///   standard input, the same process) may invoke what [`Policy::local`] names, everything by
///   default.
///
/// An HTTP caller always carries a token principal; with
/// [`HttpOptions::allow_unauthenticated`](crate::HttpOptions::allow_unauthenticated) and no
/// verifier it is the scopeless [`crate::http::ANONYMOUS`], which a scoped policy refuses unless
/// an [`ANY_SCOPE`] rule names the offering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    open: bool,
    rules: Vec<Rule>,
    /// What a local caller may invoke; `None`: everything.
    local: Option<Vec<String>>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy::open()
    }
}

impl Policy {
    /// Every caller may invoke every offering.
    pub fn open() -> Policy {
        Policy {
            open: true,
            rules: Vec::new(),
            local: None,
        }
    }

    /// Callers with a token may invoke only what their scopes' rules allow (nothing until
    /// [`Policy::allow`]); a local caller everything until [`Policy::local`] narrows it.
    pub fn scoped() -> Policy {
        Policy {
            open: false,
            ..Policy::open()
        }
    }

    /// Lets a token carrying `scope` invoke the offerings `offerings` (globs over offering names)
    /// match; adds to the rules given, and makes the policy scoped.
    #[must_use]
    pub fn allow<S: Into<String>>(
        mut self,
        scope: impl Into<String>,
        offerings: impl IntoIterator<Item = S>,
    ) -> Policy {
        self.open = false;
        self.rules.push(Rule {
            scope: scope.into(),
            offerings: offerings.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Lets a local caller (no token) invoke only the offerings `offerings` match (none for an
    /// empty list); makes the policy scoped.
    #[must_use]
    pub fn local<S: Into<String>>(mut self, offerings: impl IntoIterator<Item = S>) -> Policy {
        self.open = false;
        self.local = Some(offerings.into_iter().map(Into::into).collect());
        self
    }

    /// Whether every caller may invoke everything.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Whether `principal` may invoke the offering named `offering`.
    pub fn allows(&self, principal: &Principal, offering: &str) -> bool {
        if self.open {
            return true;
        }
        if principal.is_local() {
            return self
                .local
                .as_ref()
                .is_none_or(|globs| matches_any(globs, offering));
        }
        self.rules.iter().any(|rule| {
            (rule.scope == ANY_SCOPE || principal.has_scope(&rule.scope))
                && matches_any(&rule.offerings, offering)
        })
    }

    /// The scopes that have rules, in rule order, without duplicates.
    pub fn scopes(&self) -> Vec<&str> {
        let mut scopes: Vec<&str> = Vec::new();
        for rule in &self.rules {
            if !scopes.contains(&rule.scope.as_str()) {
                scopes.push(&rule.scope);
            }
        }
        scopes
    }

    /// What a local caller may invoke: `None` for everything, else the globs of
    /// [`Policy::local`].
    pub fn local_globs(&self) -> Option<&[String]> {
        self.local.as_deref()
    }

    /// The scoped policy of a YAML or JSON policy file; see the [module docs](self#policy-files).
    ///
    /// # Errors
    ///
    /// [`PolicyFileError::Writable`] when its group or others may write it (Unix),
    /// [`PolicyFileError::Io`], [`PolicyFileError::TooLarge`], [`PolicyFileError::Parse`], and
    /// [`PolicyFileError::Invalid`] for a document that is not `{scopes: {scope: [glob, ...]},
    /// local: [glob, ...]}`.
    pub fn load(path: impl AsRef<Path>) -> Result<Policy, PolicyFileError> {
        let path = path.as_ref();
        let io = |source: std::io::Error| PolicyFileError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = std::fs::File::open(path).map_err(io)?;
        // The opened file's own metadata: what is judged is what is read.
        let metadata = file.metadata().map_err(io)?;
        let invalid = |reason: String| PolicyFileError::Invalid {
            path: path.to_path_buf(),
            reason,
        };
        if !metadata.is_file() {
            return Err(invalid("not a regular file".to_owned()));
        }
        check_writable(path, &metadata)?;
        let too_large = || PolicyFileError::TooLarge {
            path: path.to_path_buf(),
        };
        if metadata.len() > MAX_POLICY_FILE {
            return Err(too_large());
        }
        let mut text = String::new();
        file.take(MAX_POLICY_FILE + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        if text.len() as u64 > MAX_POLICY_FILE {
            return Err(too_large());
        }
        let tree =
            crate::auth::parse_document(&text, MAX_POLICY_FILE as usize).map_err(|reason| {
                PolicyFileError::Parse {
                    path: path.to_path_buf(),
                    reason,
                }
            })?;
        Policy::from_document(&tree).map_err(invalid)
    }

    /// The policy of a parsed policy document; the error names keys, never globs.
    fn from_document(tree: &Json) -> Result<Policy, String> {
        const SHAPE: &str = "a policy is {scopes: {<scope>: [<offering glob>, ...]}, local: [<offering glob>, ...]}";
        let Json::Object(fields) = tree else {
            return Err(SHAPE.to_owned());
        };
        let mut policy = Policy::scoped();
        for (key, value) in fields {
            match (key.as_str(), value) {
                ("scopes", Json::Object(scopes)) => {
                    for (scope, globs) in scopes {
                        if scope.trim().is_empty() {
                            return Err("a scope name may not be blank".to_owned());
                        }
                        let globs = globs_of(globs).ok_or_else(|| {
                            format!(
                                "scope {:?} names its offerings as a glob or a list of globs",
                                crate::text::clean(scope, 64)
                            )
                        })?;
                        policy = policy.allow(scope.clone(), globs);
                    }
                }
                ("scopes", Json::Null) => {}
                ("scopes", _) => {
                    return Err("scopes maps each scope to its offering globs".to_owned());
                }
                ("local", value) => {
                    let globs = globs_of(value).ok_or_else(|| {
                        "local is a glob or a list of globs (an empty list: nothing)".to_owned()
                    })?;
                    policy = policy.local(globs);
                }
                (other, _) => {
                    return Err(format!(
                        "unknown key {:?} ({SHAPE})",
                        crate::text::clean(other, 40)
                    ));
                }
            }
        }
        Ok(policy)
    }

    /// The scopes whose rules allow `offering` (what an `insufficient_scope` challenge names),
    /// without duplicates, in rule order.
    pub fn scopes_for(&self, offering: &str) -> Vec<String> {
        let mut scopes: Vec<String> = Vec::new();
        for rule in &self.rules {
            if matches_any(&rule.offerings, offering) && !scopes.contains(&rule.scope) {
                scopes.push(rule.scope.clone());
            }
        }
        scopes
    }
}

/// A glob or a list of globs; `None` for anything else.
fn globs_of(value: &Json) -> Option<Vec<String>> {
    match value {
        Json::String(glob) => Some(vec![glob.clone()]),
        Json::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    }
}

#[cfg(unix)]
fn check_writable(path: &Path, metadata: &std::fs::Metadata) -> Result<(), PolicyFileError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(PolicyFileError::Writable {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_writable(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), PolicyFileError> {
    Ok(())
}

fn matches_any(globs: &[String], name: &str) -> bool {
    globs.iter().any(|pattern| glob(pattern, name))
}

/// The prefix of an `only` pattern that matches an action's space rather than its name or
/// schemas: `space:orders*`.
pub const SPACE_PREFIX: &str = "space:";

/// Applies `only` patterns to `catalog`, as the catalogue applies its own: before the
/// actions are folded and named, so a tool keeps the name the Ruby gateway gives it under the
/// same filter.
///
/// - A bare pattern is [`FleetCatalog::only`]'s: a glob against the action's name, its consumed
///   schema, or its produced schema.
/// - A `space:<glob>` pattern matches the space the action's input is written into.
///
/// Patterns of one kind are alternatives; when both kinds are given an action must match one of
/// each (`shop.*` and `space:orders` offer the shop actions taking from `orders`). Space
/// patterns are installed with [`FleetCatalog::only_if`], which replaces a predicate the
/// catalogue had.
pub fn apply_only(catalog: FleetCatalog, patterns: &[String]) -> FleetCatalog {
    let mut names = Vec::new();
    let mut spaces = Vec::new();
    for pattern in patterns {
        match pattern.strip_prefix(SPACE_PREFIX) {
            Some(space) => spaces.push(space.to_owned()),
            None => names.push(pattern.clone()),
        }
    }
    let catalog = if names.is_empty() {
        catalog
    } else {
        catalog.only(names)
    };
    if spaces.is_empty() {
        catalog
    } else {
        catalog.only_if(move |action| matches_any(&spaces, action.space()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_policies_allow_everyone() {
        let policy = Policy::default();
        assert!(policy.is_open());
        assert!(policy.allows(&Principal::local(), "x"));
        assert!(policy.allows(&Principal::token("t", Vec::<String>::new()), "x"));
    }

    #[test]
    fn scoped_policies_map_scopes_to_offerings() {
        let policy = Policy::scoped()
            .allow("a", ["research*"])
            .allow("b", ["research_?"])
            .allow(ANY_SCOPE, ["ping"]);
        let a = Principal::token("ana", ["a"]);
        let none = Principal::token("nobody", Vec::<String>::new());
        assert!(policy.allows(&a, "research_854bb186"));
        assert!(!policy.allows(&a, "summarize"));
        assert!(policy.allows(&none, "ping"));
        assert!(!policy.allows(&none, "research"));
        assert_eq!(
            policy.scopes_for("research_x"),
            ["a".to_owned(), "b".to_owned()]
        );
        assert!(policy.scopes_for("summarize").is_empty());
        assert!(policy.allows(&Principal::local(), "summarize"));
        let narrowed = policy.local(["ping"]);
        assert!(!narrowed.allows(&Principal::local(), "summarize"));
        assert!(narrowed.allows(&Principal::local(), "ping"));
        assert!(
            !Policy::scoped()
                .local(Vec::<String>::new())
                .allows(&Principal::local(), "x")
        );
    }

    /// The policy files (their modes are Unix permission bits).
    #[cfg(unix)]
    mod files {
        use super::*;

        /// A scratch file of this test process, removed on drop.
        struct Scratch(PathBuf);

        impl Scratch {
            fn write(name: &str, text: &str, mode: u32) -> Scratch {
                use std::os::unix::fs::PermissionsExt as _;
                let path = std::env::temp_dir()
                    .join(format!("asrs-policy-{name}-{}.yaml", std::process::id()));
                std::fs::write(&path, text).expect("written");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .expect("chmod");
                Scratch(path)
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        #[test]
        fn policy_files_map_scopes_to_offerings() {
            let file = Scratch::write(
                "good",
                "scopes:\n  orders:write: [\"shop.*\", refund]\n  reports: report_*\n  \"*\": [ping]\n\
                 local: [ping]\n",
                0o644,
            );
            let policy = Policy::load(&file.0).expect("a policy");
            assert_eq!(
                policy,
                Policy::scoped()
                    .allow("orders:write", ["shop.*", "refund"])
                    .allow("reports", ["report_*"])
                    .allow(ANY_SCOPE, ["ping"])
                    .local(["ping"])
            );
            assert_eq!(policy.scopes(), ["orders:write", "reports", "*"]);
            assert_eq!(policy.local_globs(), Some(&["ping".to_owned()][..]));
            assert!(!policy.allows(&Principal::local(), "refund"));
            let json = Scratch::write("json", r#"{"scopes": {"a": ["x*"]}}"#, 0o600);
            let policy = Policy::load(&json.0).expect("a JSON policy");
            assert!(policy.allows(&Principal::token("t", ["a"]), "xy"));
            assert!(
                policy.allows(&Principal::local(), "anything"),
                "local: everything"
            );
            assert!(!policy.is_open(), "a policy file is always scoped");
        }

        #[test]
        fn policy_files_others_may_write_or_that_are_not_policies_are_refused() {
            let writable = Scratch::write("writable", "scopes: {a: [x]}\n", 0o666);
            let error = Policy::load(&writable.0).expect_err("writable by others");
            assert!(matches!(error, PolicyFileError::Writable { .. }), "{error}");
            assert!(error.to_string().contains("chmod go-w"), "{error}");
            for (name, text, mentions) in [
                ("list", "- a\n- b\n", "a policy is"),
                ("unknown", "scope: {a: [x]}\n", "unknown key \"scope\""),
                ("number", "scopes: {a: 3}\n", "scope \"a\""),
                ("nested", "scopes: {a: [[x]]}\n", "scope \"a\""),
                ("local", "local: {a: b}\n", "local is"),
                ("blank", "scopes: {\" \": [x]}\n", "blank"),
            ] {
                let file = Scratch::write(name, text, 0o600);
                let error = Policy::load(&file.0).expect_err(name);
                assert!(
                    matches!(error, PolicyFileError::Invalid { .. }),
                    "{name}: {error}"
                );
                assert!(error.to_string().contains(mentions), "{name}: {error}");
            }
            let broken = Scratch::write("broken", "scopes: [\n", 0o600);
            assert!(matches!(
                Policy::load(&broken.0),
                Err(PolicyFileError::Parse { .. })
            ));
            assert!(matches!(
                Policy::load("/nonexistent/asrs-policy.yaml"),
                Err(PolicyFileError::Io { .. })
            ));
        }
    }
}
