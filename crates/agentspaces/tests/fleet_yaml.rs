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

//! The shared fleet YAML ([`agentspaces::config::FleetFile`], [`agentspaces::config::Config`]): the
//! `agentspaces:` subtree every host reads, its precedence under `ASPACE_*` variables and
//! command-line flags, its join paths, the refusals that name the key, variable, or flag they read,
//! and the bounds on the file (size, aliases, depth).
//!
//! `the_file_ruby_reads_reads_the_same_here` loads one file with the Ruby `Config.load` (the
//! `agentspaces-rb` gem next to this workspace) and compares; it says why and passes when `ruby`
//! or the gem is not there, unless `ASPACE_RUBY_REQUIRED=1` is set.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces::config::{
    self, Config, ConfigError, FleetFile, MAX_FLEET_FILE_BYTES, Origin, Overrides,
};
use agentspaces::group::{GroupSpec, Profile};
use agentspaces::wire::cbor::{self, Value};
use agentspaces::wire::founding;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::seed::Seed;
use base64::Engine as _;

// ---------------------------------------------------------------------------------------------
// Helpers

/// A fresh directory under Cargo's per-target scratch space, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "fleet-yaml-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Writes `text` to `name` in the scratch directory and answers its path.
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).expect("write the fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn no_vars(_: &str) -> Option<String> {
    None
}

fn parse(path: &Path, text: &str) -> Result<FleetFile, ConfigError> {
    FleetFile::parse(text, path, &vars(&[("HOME", "/home/ada")]))
}

fn assert_mentions(error: &ConfigError, parts: &[&str]) {
    let message = error.to_string();
    for part in parts {
        assert!(message.contains(part), "{part:?} missing from: {message}");
    }
}

fn group_id(founding: &str) -> String {
    ids::group_id_from_founding(founding.as_bytes())
}

/// A join URI of a well-formed GroupID.
fn join_uri(founding: &str) -> String {
    format!("aspace://{}", group_id(founding))
}

/// The CBOR of a signed founding advertisement and its GroupID.
fn signed_founding() -> (Vec<u8>, String) {
    let founder = Identity::from_seed(&[7; 32]);
    let signed = founding::found_group(
        &founder,
        "yaml-fleet",
        "OPEN",
        "LEASE_RACE",
        3,
        "PT1S",
        "2026-01-01T00:00:00Z",
        "PT24H",
    )
    .expect("found a group");
    let bytes = cbor::encode(&Value::Map(signed));
    let id = founding::verify_signed_group_ad(&cbor::decode(&bytes).expect("decodes"))
        .expect("verifies");
    (bytes, id)
}

/// A full fleet file, as every host reads it, with a second group and keys this peer does not use.
fn full_fleet_file(join: &str) -> String {
    format!(
        r#"# The shared fleet file, as every host reads it.
spring:
  application:
    name: shop
agentspaces:
  keystore: ~/.config/agentspaces/keys      # peer.key and peer.pub, shared with Java, Python, Ruby
  bind: 0.0.0.0:7500                        # a listener key: ignored by a dial-only peer
  tick-millis: 250
  security:
    profile: mtls
    oidc:
      client-secret: hunter2
  groups:
    - name: research-fleet
      join: {join}
      seeds: [ "tls://fleet.example.com:7500" ]
      spaces: [ {{ name: tasks }}, {{ name: votes, strategy: AUCTION }} ]
      join-timeout-millis: 2500
    - name: partner
      founding: partner-fleet-v1
      seeds: 127.0.0.1:7711, 127.0.0.1:7712
      spaces: results
"#
    )
}

// ---------------------------------------------------------------------------------------------
// Reading the file

#[test]
fn the_full_fleet_file_reads_with_its_groups_and_ignores_what_it_does_not_use() {
    let scratch = Scratch::new("full-fleet");
    let join = join_uri("research-fleet-demo-v1");
    let path = scratch.file("fleet.yaml", &full_fleet_file(&join));
    let file = FleetFile::read(&path, &Origin::Default, &vars(&[])).expect("reads");
    assert_eq!(file.path, path);
    assert_eq!(file.keystore.as_deref(), Some("~/.config/agentspaces/keys"));
    assert_eq!(file.profile.as_deref(), Some("mtls"));
    assert!(!file.allow_plain);
    assert_eq!(file.groups.len(), 2);

    let research = &file.groups[0];
    assert_eq!(research.name, "research-fleet");
    assert_eq!(research.key, "agentspaces.groups[0]");
    assert_eq!(research.spec, GroupSpec::Join(join.clone()));
    assert_eq!(research.spec_key, "agentspaces.groups[0].join");
    assert_eq!(research.group_id, group_id("research-fleet-demo-v1"));
    assert_eq!(
        research.seeds,
        [Seed::new("fleet.example.com", 7500, "tls")]
    );
    assert_eq!(research.spaces, ["tasks", "votes"]);
    assert_eq!(research.join_timeout, Some(Duration::from_millis(2500)));

    let partner = &file.groups[1];
    assert_eq!(
        partner.spec,
        GroupSpec::FoundingText("partner-fleet-v1".into())
    );
    assert_eq!(partner.group_id, group_id("partner-fleet-v1"));
    assert_eq!(
        partner.seeds,
        [
            Seed::new("127.0.0.1", 7711, "tcp"),
            Seed::new("127.0.0.1", 7712, "tcp")
        ],
        "a comma-separated scalar is a list, as the Node host reads it"
    );
    assert_eq!(partner.spaces, ["results"]);
    assert_eq!(partner.join_timeout, None);

    for key in [
        "agentspaces.bind",
        "agentspaces.tick-millis",
        "agentspaces.security.oidc",
    ] {
        assert!(
            file.ignored.iter().any(|k| k == key),
            "{key} in {:?}",
            file.ignored
        );
    }
    assert!(
        !format!("{file:?}").contains("hunter2"),
        "the value of an ignored key is never kept"
    );
}

#[test]
fn keys_read_in_kebab_snake_and_camel_case() {
    let scratch = Scratch::new("case");
    let (document, id) = signed_founding();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&document);
    for spelling in ["founding-document", "founding_document", "foundingDocument"] {
        let text = format!(
            "agentspaces:\n  Peer_Ad_Interval_Millis: 15000\n  groups:\n    - name: g\n      \
             {spelling}: {encoded}\n      seeds: [127.0.0.1:7711]\n      joinTimeoutMillis: 700\n"
        );
        let file = parse(&scratch.path().join("case.yaml"), &text).expect(spelling);
        assert_eq!(
            file.groups[0].spec,
            GroupSpec::FoundingDocument(document.clone()),
            "{spelling}"
        );
        assert_eq!(file.groups[0].group_id, id);
        assert_eq!(
            file.groups[0].join_timeout,
            Some(Duration::from_millis(700))
        );
        assert_eq!(file.peer_ad_interval, Some(Duration::from_secs(15)));
    }

    let text = "agentspaces:\n  groups:\n    - name: g\n      group-id: x\n      groupId: y\n";
    let error = parse(Path::new("/etc/fleet.yaml"), text).expect_err("two spellings");
    assert!(matches!(error, ConfigError::Conflict { .. }), "{error:?}");
    assert_mentions(
        &error,
        &[
            "agentspaces.groups[0].group-id in /etc/fleet.yaml",
            "agentspaces.groups[0].groupId in /etc/fleet.yaml",
            "keep one",
        ],
    );
}

#[test]
fn every_join_path_reads() {
    let scratch = Scratch::new("join-paths");
    let (document, document_id) = signed_founding();
    let raw = scratch.path().join("founding.cbor");
    fs::write(&raw, &document).expect("write the founding");
    let encoded = scratch.path().join("founding.b64");
    fs::write(
        &encoded,
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(&document)
        ),
    )
    .expect("write the founding");
    let id = group_id("research-fleet-demo-v1");
    let text = format!(
        "agentspaces:
  groups:
    - name: by-uri
      join: aspace://{id}
    - name: by-bare-id
      group-id: {id}
    - name: by-both
      join: aspace://{id}
      group-id: {id}
    - name: by-text
      founding: research-fleet-demo-v1
    - name: by-raw-file
      founding-document: {raw}
    - name: by-base64-file
      founding-document: {encoded}
    - name: by-name
    - just-a-name
",
        raw = raw.display(),
        encoded = encoded.display()
    );
    let file = parse(&scratch.path().join("paths.yaml"), &text).expect("reads");
    let specs: Vec<(&str, &GroupSpec, &str)> = file
        .groups
        .iter()
        .map(|g| (g.name.as_str(), &g.spec, g.group_id.as_str()))
        .collect();
    let by_name = group_id("by-name");
    let just = group_id("just-a-name");
    assert_eq!(
        specs,
        [
            (
                "by-uri",
                &GroupSpec::Join(format!("aspace://{id}")),
                id.as_str()
            ),
            ("by-bare-id", &GroupSpec::Join(id.clone()), id.as_str()),
            (
                "by-both",
                &GroupSpec::Join(format!("aspace://{id}")),
                id.as_str()
            ),
            (
                "by-text",
                &GroupSpec::FoundingText("research-fleet-demo-v1".into()),
                id.as_str()
            ),
            (
                "by-raw-file",
                &GroupSpec::FoundingDocument(document.clone()),
                document_id.as_str()
            ),
            (
                "by-base64-file",
                &GroupSpec::FoundingDocument(document.clone()),
                document_id.as_str()
            ),
            (
                "by-name",
                &GroupSpec::FoundingText("by-name".into()),
                by_name.as_str()
            ),
            (
                "just-a-name",
                &GroupSpec::FoundingText("just-a-name".into()),
                just.as_str()
            ),
        ]
    );
    assert_eq!(file.groups[6].spec_key, "agentspaces.groups[6].name");
}

#[test]
fn a_founding_document_under_home_and_a_bad_one() {
    let scratch = Scratch::new("founding-home");
    let (document, _) = signed_founding();
    fs::create_dir_all(scratch.path().join("groups")).expect("dir");
    fs::write(scratch.path().join("groups/fleet.founding"), &document).expect("write");
    let home = scratch.path().display().to_string();
    let text = "agentspaces:\n  groups:\n    - name: g\n      founding-document: ~/groups/fleet.founding\n";
    let file = FleetFile::parse(text, Path::new("/x.yaml"), &vars(&[("HOME", &home)]))
        .expect("reads under HOME");
    assert_eq!(
        file.groups[0].spec,
        GroupSpec::FoundingDocument(document.clone())
    );

    // A document whose signature does not verify.
    let mut tampered = document.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    let path = scratch.path().join("tampered.cbor");
    fs::write(&path, &tampered).expect("write");
    let text = format!(
        "agentspaces:\n  groups:\n    - name: g\n      founding-document: {}\n",
        path.display()
    );
    let error = parse(Path::new("/etc/fleet.yaml"), &text).expect_err("tampered");
    assert_mentions(
        &error,
        &[
            "agentspaces.groups[0].founding-document in /etc/fleet.yaml",
            "not a signed founding advertisement that verifies",
        ],
    );

    let text = "agentspaces:\n  groups:\n    - name: g\n      founding-document: /no/such/file and not base64\n";
    let error = parse(Path::new("/etc/fleet.yaml"), text).expect_err("neither");
    assert_mentions(
        &error,
        &[
            "agentspaces.groups[0].founding-document",
            "neither a readable file nor base64 CBOR",
        ],
    );
}

#[test]
fn group_refusals_name_the_key() {
    let path = Path::new("/etc/agentspaces/fleet.yaml");
    let cases: [(&str, &[&str]); 9] = [
        (
            "agentspaces:\n  groups:\n    - seeds: [a:1]\n",
            &[
                "agentspaces.groups[0].name in /etc/agentspaces/fleet.yaml",
                "needs a name",
            ],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n      join: aspace://nope\n",
            &[
                "agentspaces.groups[0].join",
                "\"aspace://nope\"",
                "not a group id",
            ],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n      join: zabc\n      founding: t\n",
            &[
                "agentspaces.groups[0].join",
                "agentspaces.groups[0].founding",
                "founding-document",
                "keep one",
            ],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n      seeds: [ 'tls://ok:7500', 'tcp://nope' ]\n",
            &[
                "agentspaces.groups[0].seeds[1]",
                "\"tcp://nope\"",
                "not a seed",
            ],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n    - name: g\n",
            &[
                "agentspaces.groups[1].name",
                "agentspaces.groups[0] already names",
            ],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n      spaces: [ { strategy: AUCTION } ]\n",
            &["agentspaces.groups[0].spaces[0]", "has no name"],
        ),
        (
            "agentspaces:\n  groups:\n    - name: g\n      join-timeout-millis: -5\n",
            &[
                "agentspaces.groups[0].join-timeout-millis",
                "positive number of milliseconds",
            ],
        ),
        (
            "agentspaces:\n  keystore: [a, b]\n",
            &["agentspaces.keystore", "not text"],
        ),
        (
            "agentspaces:\n  groups:\n    - [ not, a, group ]\n",
            &["agentspaces.groups[0]", "not a group"],
        ),
    ];
    for (text, parts) in cases {
        let error = parse(path, text).expect_err(text);
        assert_mentions(&error, parts);
    }

    let id = group_id("one");
    let other = group_id("two");
    let text = format!(
        "agentspaces:\n  groups:\n    - name: g\n      join: aspace://{id}\n      group-id: {other}\n"
    );
    let error = parse(path, &text).expect_err("different ids");
    assert_mentions(
        &error,
        &[
            "agentspaces.groups[0].join",
            "agentspaces.groups[0].group-id",
            "different groups",
        ],
    );
}

#[test]
fn a_bare_subtree_and_an_empty_file_read_as_ruby_reads_them() {
    let path = Path::new("/x.yaml");
    let file = parse(path, "groups:\n  - name: g\n    founding: t\n").expect("bare subtree");
    assert_eq!(file.groups[0].spec, GroupSpec::FoundingText("t".into()));

    for empty in ["", "# nothing yet\n", "---\n", "agentspaces:\n"] {
        let file = parse(path, empty).expect("empty");
        assert!(file.groups.is_empty(), "{empty:?}");
    }
    let error = parse(path, "- a\n- b\n").expect_err("a sequence");
    assert_mentions(&error, &["/x.yaml", "not a mapping"]);
    let error = parse(path, "agentspaces: 7\n").expect_err("a scalar subtree");
    assert_mentions(&error, &["agentspaces in /x.yaml", "not a mapping"]);
}

// ---------------------------------------------------------------------------------------------
// Bounds

#[test]
fn an_oversize_file_is_refused_unread() {
    let scratch = Scratch::new("oversize");
    let mut text = String::from("agentspaces:\n  groups:\n    - name: g\n      founding: t\n");
    let filler = format!("# {}\n", "x".repeat(1022));
    while text.len() as u64 <= MAX_FLEET_FILE_BYTES {
        text.push_str(&filler);
    }
    let path = scratch.file("big.yaml", &text);
    let error = FleetFile::read(&path, &Origin::Flag("--config"), &no_vars).expect_err("big");
    assert!(
        matches!(error, ConfigError::FileTooLarge { .. }),
        "{error:?}"
    );
    assert_mentions(&error, &["big.yaml", "larger than 1048576 bytes"]);
    let error = FleetFile::parse(&text, &path, &no_vars).expect_err("big text");
    assert!(
        matches!(error, ConfigError::FileTooLarge { .. }),
        "{error:?}"
    );
}

#[test]
fn an_alias_bomb_is_refused_never_expanded() {
    // The billion laughs: nine levels of ten aliases each would expand to 10^9 nodes.
    let mut text = String::from("a0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n");
    for level in 1..10 {
        let prev = level - 1;
        text.push_str(&format!(
            "a{level}: &a{level} [*a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, \
             *a{prev}, *a{prev}, *a{prev}, *a{prev}]\n"
        ));
    }
    text.push_str("agentspaces:\n  groups:\n    - name: g\n      founding: t\n      seeds: *a9\n");
    let started = std::time::Instant::now();
    let error = parse(Path::new("/bomb.yaml"), &text).expect_err("an alias bomb");
    assert!(matches!(error, ConfigError::Yaml { .. }), "{error:?}");
    assert_mentions(&error, &["/bomb.yaml", "not fleet YAML"]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "refused quickly, not expanded"
    );

    // Too many anchors, and nesting past the bound.
    let mut anchors = String::from("agentspaces:\n  x:\n");
    for index in 0..100 {
        anchors.push_str(&format!("    - &n{index} {index}\n"));
    }
    assert!(parse(Path::new("/anchors.yaml"), &anchors).is_err());
    let deep = format!("agentspaces: {}{}\n", "[".repeat(200), "]".repeat(200));
    assert!(parse(Path::new("/deep.yaml"), &deep).is_err());
    // Two documents are two configurations; one file holds one.
    let two = "agentspaces:\n  groups: [a]\n---\nagentspaces:\n  groups: [b]\n";
    assert!(parse(Path::new("/two.yaml"), two).is_err());
}

#[test]
fn anchors_and_merge_keys_within_the_bounds_read() {
    // The shape of a Rails config/agentspaces.yml, a merge of a shared block.
    let text = "defaults: &defaults
  seeds: [ 'tls://fleet.example.com:7500' ]
  spaces: [ tasks ]
agentspaces:
  groups:
    - <<: *defaults
      name: a
      founding: a-v1
    - <<: *defaults
      name: b
      founding: b-v1
";
    let file = parse(Path::new("/merge.yaml"), text).expect("merge keys");
    for group in &file.groups {
        assert_eq!(group.seeds, [Seed::new("fleet.example.com", 7500, "tls")]);
        assert_eq!(group.spaces, ["tasks"]);
    }
}

#[test]
fn a_file_that_is_not_utf8_or_not_yaml_is_refused_by_name() {
    let scratch = Scratch::new("bad-bytes");
    let path = scratch.path().join("latin1.yaml");
    fs::write(&path, b"agentspaces:\n  keystore: caf\xe9\n").expect("write");
    let error = FleetFile::read(&path, &Origin::Default, &no_vars).expect_err("latin-1");
    assert_mentions(&error, &["latin1.yaml", "not UTF-8"]);

    let path = scratch.file("broken.yaml", "agentspaces:\n  groups: [ unclosed\n");
    let error = FleetFile::read(&path, &Origin::Default, &no_vars).expect_err("broken");
    assert!(matches!(error, ConfigError::Yaml { .. }), "{error:?}");
    assert_mentions(&error, &["broken.yaml"]);

    let path = scratch.file("dup.yaml", "agentspaces:\n  keystore: a\n  keystore: b\n");
    assert!(
        FleetFile::read(&path, &Origin::Default, &no_vars).is_err(),
        "duplicate keys"
    );

    let error = FleetFile::read(scratch.path(), &Origin::Flag("--config"), &no_vars)
        .expect_err("a directory");
    assert_mentions(
        &error,
        &["--config names the fleet file", "not a regular file"],
    );
}

// ---------------------------------------------------------------------------------------------
// Precedence

fn full_fleet_fixture(scratch: &Scratch) -> (PathBuf, String) {
    let join = join_uri("research-fleet-demo-v1");
    (scratch.file("fleet.yaml", &full_fleet_file(&join)), join)
}

#[test]
fn the_file_alone_joins_its_first_group() {
    let scratch = Scratch::new("first");
    let (path, join) = full_fleet_fixture(&scratch);
    let lookup = vars(&[
        ("ASPACE_CONFIG", &path.display().to_string()),
        ("HOME", "/home/ada"),
    ]);
    let config = Config::from_vars(&Overrides::default(), lookup).expect("resolves");
    let settings = &config.settings;
    assert_eq!(settings.group, GroupSpec::Join(join));
    assert_eq!(
        settings.seeds,
        [Seed::new("fleet.example.com", 7500, "tls")]
    );
    assert_eq!(settings.profile, Profile::Mtls);
    assert_eq!(
        settings.keystore.as_deref(),
        Some(Path::new("/home/ada/.config/agentspaces/keys"))
    );
    assert_eq!(settings.spaces, ["tasks", "votes"]);
    assert_eq!(config.group_name.as_deref(), Some("research-fleet"));
    assert_eq!(config.join_timeout, Duration::from_millis(2500));
    assert_eq!(config.file.as_deref(), Some(path.as_path()));
    assert_eq!(
        config.origin("seeds"),
        Some(&Origin::Key {
            file: path.clone(),
            key: "agentspaces.groups[0].seeds".into()
        })
    );
    assert_eq!(
        config.origin("group"),
        Some(&Origin::Key {
            file: path.clone(),
            key: "agentspaces.groups[0].join".into()
        })
    );
    assert_eq!(
        config.origin("keystore"),
        Some(&Origin::Key {
            file: path.clone(),
            key: "agentspaces.keystore".into()
        })
    );
    assert_eq!(config.origin("socket"), None);

    let peer = config
        .peer_config(Identity::from_seed(&[1; 32]))
        .expect("a peer configuration");
    assert_eq!(peer.join_timeout, Duration::from_millis(2500));
    assert_eq!(peer.seeds, config.settings.seeds);

    // Config::load reads the same file, no variables.
    let loaded = Config::load(&path).expect("loads");
    assert_eq!(loaded.settings.group, config.settings.group);
    assert_eq!(loaded.settings.seeds, config.settings.seeds);
}

#[test]
fn variables_override_the_file_and_flags_override_both() {
    let scratch = Scratch::new("layers");
    let (path, _) = full_fleet_fixture(&scratch);
    let config_path = path.display().to_string();

    // ASPACE_GROUP names the file's second group: its founding, seeds, and spaces.
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[
            ("ASPACE_CONFIG", &config_path),
            ("ASPACE_GROUP", "partner"),
            ("ASPACE_KEYSTORE", "/var/keys"),
            ("ASPACE_PROFILE", "dev-local"),
            ("ASPACE_SOCKET", "/run/aspace.sock"),
            ("HOME", "/home/ada"),
        ]),
    )
    .expect("resolves");
    assert_eq!(config.group_name.as_deref(), Some("partner"));
    assert_eq!(
        config.settings.group,
        GroupSpec::FoundingText("partner-fleet-v1".into())
    );
    assert_eq!(config.settings.seeds.len(), 2);
    assert_eq!(config.settings.spaces, ["results"]);
    assert_eq!(
        config.settings.keystore.as_deref(),
        Some(Path::new("/var/keys"))
    );
    assert_eq!(config.settings.profile, Profile::DevLocal);
    assert_eq!(
        config.socket.as_deref(),
        Some(Path::new("/run/aspace.sock"))
    );
    assert_eq!(
        config.origin("group"),
        Some(&Origin::Variable("ASPACE_GROUP"))
    );
    assert_eq!(
        config.origin("keystore"),
        Some(&Origin::Variable("ASPACE_KEYSTORE"))
    );
    assert_eq!(config.join_timeout, config::DEFAULT_JOIN_TIMEOUT);

    // ASPACE_SEEDS and ASPACE_SPACES over the file's group.
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[
            ("ASPACE_CONFIG", &config_path),
            ("ASPACE_SEEDS", "tls://other.example.com:7600"),
            ("ASPACE_SPACES", "alerts, tasks"),
            ("HOME", "/home/ada"),
        ]),
    )
    .expect("resolves");
    assert_eq!(
        config.settings.seeds,
        [Seed::new("other.example.com", 7600, "tls")]
    );
    assert_eq!(config.settings.spaces, ["alerts", "tasks"]);
    assert_eq!(config.group_name.as_deref(), Some("research-fleet"));

    // Flags over variables over the file.
    let overrides = Overrides {
        seeds: Some("127.0.0.1:7999".into()),
        group: Some("adhoc-founding-text".into()),
        keystore: Some("/flag/keys".into()),
        profile: Some("mtls".into()),
        socket: Some("/flag.sock".into()),
        join_timeout: Some(Duration::from_secs(3)),
        ..Overrides::default()
    };
    let config = Config::from_vars(
        &overrides,
        vars(&[
            ("ASPACE_CONFIG", &config_path),
            ("ASPACE_JOIN", &join_uri("ignored-under-the-flag")),
            ("ASPACE_SEEDS", "tls://ignored:1"),
            ("ASPACE_KEYSTORE", "/ignored"),
            ("ASPACE_PROFILE", "dev-local"),
            ("HOME", "/home/ada"),
        ]),
    )
    .expect("resolves");
    assert_eq!(
        config.settings.group,
        GroupSpec::FoundingText("adhoc-founding-text".into()),
        "a --group the file does not name is a founding text"
    );
    assert_eq!(config.group_name, None);
    assert_eq!(config.settings.seeds, [Seed::new("127.0.0.1", 7999, "tcp")]);
    assert_eq!(
        config.settings.keystore.as_deref(),
        Some(Path::new("/flag/keys"))
    );
    assert_eq!(config.settings.profile, Profile::Mtls);
    assert_eq!(config.socket.as_deref(), Some(Path::new("/flag.sock")));
    assert_eq!(config.join_timeout, Duration::from_secs(3));
    assert_eq!(config.settings.spaces, Vec::<String>::new());
    for (field, flag) in [
        ("group", "--group"),
        ("seeds", "--seeds"),
        ("keystore", "--keystore"),
        ("profile", "--profile"),
        ("socket", "--socket"),
        ("join_timeout", "--join-timeout"),
    ] {
        assert_eq!(config.origin(field), Some(&Origin::Flag(flag)), "{field}");
    }

    // --config over ASPACE_CONFIG.
    let other = scratch.file(
        "other.yaml",
        "agentspaces:\n  groups:\n    - name: other\n      seeds: [127.0.0.1:7001]\n",
    );
    let overrides = Overrides {
        config: Some(other.clone()),
        ..Overrides::default()
    };
    let config =
        Config::from_vars(&overrides, vars(&[("ASPACE_CONFIG", &config_path)])).expect("resolves");
    assert_eq!(config.group_name.as_deref(), Some("other"));
    assert_eq!(config.file.as_deref(), Some(other.as_path()));
}

#[test]
fn a_join_by_id_takes_the_seeds_of_the_file_group_of_that_id() {
    let scratch = Scratch::new("join-match");
    let (path, join) = full_fleet_fixture(&scratch);
    let config = Config::from_vars(
        &Overrides {
            join: Some(join.clone()),
            ..Overrides::default()
        },
        vars(&[
            ("ASPACE_CONFIG", &path.display().to_string()),
            ("HOME", "/h"),
        ]),
    )
    .expect("resolves");
    assert_eq!(config.group_name.as_deref(), Some("research-fleet"));
    assert_eq!(
        config.settings.seeds,
        [Seed::new("fleet.example.com", 7500, "tls")]
    );

    // A group named by its founding text finds the file's group too.
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[
            ("ASPACE_CONFIG", &path.display().to_string()),
            ("ASPACE_GROUP", "partner-fleet-v1"),
            ("HOME", "/h"),
        ]),
    )
    .expect("resolves");
    assert_eq!(config.group_name.as_deref(), Some("partner"));
}

#[test]
fn without_a_file_the_variables_resolve_as_peer_settings_do() {
    let lookup = vars(&[
        (
            "ASPACE_SEEDS",
            "127.0.0.1:7711, tls://fleet.example.com:7500",
        ),
        ("ASPACE_GROUP", " my fleet "),
        ("ASPACE_SPACES", "tasks"),
        ("HOME", "/nonexistent-home-for-the-test"),
    ]);
    let config = Config::from_vars(&Overrides::default(), &lookup).expect("resolves");
    let settings = agentspaces::config::PeerSettings::from_vars(&lookup).expect("settings");
    assert_eq!(config.settings, settings);
    assert_eq!(config.file, None);
}

#[test]
fn the_default_path_is_read_only_when_a_file_is_there() {
    let scratch = Scratch::new("default");
    let home = scratch.path().display().to_string();
    let lookup = vars(&[("HOME", &home)]);
    assert_eq!(
        config::default_config_path(&lookup),
        Some(scratch.path().join(".config/agentspaces/fleet.yaml"))
    );
    assert_eq!(
        config::default_keystore(&lookup),
        Some(scratch.path().join(".config/agentspaces/keys"))
    );
    assert_eq!(
        config::default_config_path(&vars(&[("HOME", &home), ("XDG_CONFIG_HOME", "/xdg")])),
        Some(PathBuf::from("/xdg/agentspaces/fleet.yaml"))
    );
    assert_eq!(config::default_config_path(&no_vars), None);

    // No file at the default path: no file, and nothing names a group.
    assert_eq!(
        Config::locate(&Overrides::default(), &lookup).expect("locate"),
        None
    );
    let error = Config::from_vars(&Overrides::default(), &lookup).expect_err("no group");
    assert_mentions(
        &error,
        &[
            "no group to join",
            "--join",
            "ASPACE_GROUP",
            "agentspaces.groups",
        ],
    );

    // A file there is read.
    fs::create_dir_all(scratch.path().join(".config/agentspaces")).expect("dir");
    let path = scratch.path().join(".config/agentspaces/fleet.yaml");
    fs::write(
        &path,
        "agentspaces:\n  groups:\n    - name: home\n      seeds: [localhost:7711]\n",
    )
    .expect("write");
    let config = Config::from_vars(&Overrides::default(), &lookup).expect("resolves");
    assert_eq!(config.group_name.as_deref(), Some("home"));
    assert_eq!(
        Config::locate(&Overrides::default(), &lookup).expect("locate"),
        Some((path, Origin::Default))
    );
}

#[test]
fn keystore_from_vars_reads_only_the_keystore() {
    let scratch = Scratch::new("keystore-only");
    let path = scratch.file(
        "fleet.yaml",
        "agentspaces:\n  keystore: ~/keys\n  groups:\n    - name: g\n",
    );
    let lookup = vars(&[
        ("ASPACE_CONFIG", &path.display().to_string()),
        ("HOME", "/home/ada"),
    ]);
    assert_eq!(
        Config::keystore_from_vars(&Overrides::default(), &lookup).expect("keystore"),
        Some((
            PathBuf::from("/home/ada/keys"),
            Origin::Key {
                file: path.clone(),
                key: "agentspaces.keystore".into()
            }
        ))
    );
    let overrides = Overrides {
        keystore: Some("/flag".into()),
        ..Overrides::default()
    };
    assert_eq!(
        Config::keystore_from_vars(&overrides, &lookup).expect("keystore"),
        Some((PathBuf::from("/flag"), Origin::Flag("--keystore")))
    );
    assert_eq!(
        Config::keystore_from_vars(&Overrides::default(), vars(&[("HOME", "/nowhere-at-all")]))
            .expect("none"),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// Refusals of the layered configuration

#[test]
fn layered_refusals_name_the_flag_variable_or_key() {
    let scratch = Scratch::new("refusals");
    let (path, _) = full_fleet_fixture(&scratch);
    let file_var = path.display().to_string();
    let refused = |overrides: Overrides, pairs: &[(&str, &str)]| {
        let mut pairs = pairs.to_vec();
        pairs.push(("HOME", "/home/ada"));
        Config::from_vars(&overrides, vars(&pairs)).expect_err("refused")
    };

    // Both in one layer.
    let error = refused(
        Overrides {
            group: Some("a".into()),
            join: Some(join_uri("b")),
            ..Overrides::default()
        },
        &[],
    );
    assert_mentions(&error, &["both --group and --join are set"]);
    let error = refused(
        Overrides::default(),
        &[
            ("ASPACE_GROUP", "a"),
            ("ASPACE_JOIN", &join_uri("b")),
            ("ASPACE_SEEDS", "a:1"),
        ],
    );
    assert_mentions(&error, &["ASPACE_GROUP", "ASPACE_JOIN"]);

    // A join that is not a group id.
    let error = refused(
        Overrides {
            join: Some("aspace://not-an-id".into()),
            ..Overrides::default()
        },
        &[("ASPACE_SEEDS", "127.0.0.1:1")],
    );
    assert_mentions(
        &error,
        &["--join", "\"aspace://not-an-id\"", "not a group id"],
    );

    // Seeds that do not parse, by flag and by variable.
    let error = refused(
        Overrides {
            seeds: Some("tls://ok:1, nope".into()),
            group: Some("g".into()),
            ..Overrides::default()
        },
        &[],
    );
    assert_mentions(&error, &["--seeds", "\"nope\"", "not a seed"]);
    let error = refused(
        Overrides::default(),
        &[("ASPACE_SEEDS", "host-without-port"), ("ASPACE_GROUP", "g")],
    );
    assert_mentions(&error, &["ASPACE_SEEDS", "host-without-port"]);

    // No seed anywhere names the group's key in the file.
    let nofile = scratch.file(
        "noseeds.yaml",
        "agentspaces:\n  groups:\n    - name: lonely\n",
    );
    let error = refused(
        Overrides::default(),
        &[("ASPACE_CONFIG", &nofile.display().to_string())],
    );
    assert_mentions(
        &error,
        &[
            "no seed to dial",
            "--seeds",
            "ASPACE_SEEDS",
            "agentspaces.groups[0].seeds in",
        ],
    );

    // A profile that is not one, from the file.
    let badprofile = scratch.file(
        "profile.yaml",
        "agentspaces:\n  security:\n    profile: paranoid\n  groups:\n    - name: g\n      seeds: [tls://a:1]\n",
    );
    let error = refused(
        Overrides::default(),
        &[("ASPACE_CONFIG", &badprofile.display().to_string())],
    );
    assert_mentions(
        &error,
        &[
            "agentspaces.security.profile in",
            "\"paranoid\"",
            "not a profile",
        ],
    );
    let error = refused(
        Overrides {
            profile: Some("open".into()),
            ..Overrides::default()
        },
        &[("ASPACE_CONFIG", &file_var)],
    );
    assert_mentions(&error, &["--profile", "\"open\""]);

    // A missing file named by flag or variable.
    let error = refused(
        Overrides {
            config: Some(PathBuf::from("/no/such/fleet.yaml")),
            ..Overrides::default()
        },
        &[],
    );
    assert!(
        matches!(error, ConfigError::FileUnreadable { .. }),
        "{error:?}"
    );
    assert_mentions(
        &error,
        &["--config names the fleet file /no/such/fleet.yaml"],
    );
    let error = refused(
        Overrides::default(),
        &[("ASPACE_CONFIG", "/no/such/fleet.yaml")],
    );
    assert_mentions(
        &error,
        &["ASPACE_CONFIG names the fleet file /no/such/fleet.yaml"],
    );

    // A ~ path with no HOME.
    let error = Config::from_vars(
        &Overrides::default(),
        vars(&[("ASPACE_CONFIG", "~/fleet.yaml")]),
    )
    .expect_err("no HOME");
    assert_mentions(
        &error,
        &["ASPACE_CONFIG", "\"~/fleet.yaml\"", "HOME is unset"],
    );
    let tilde = scratch.file(
        "tilde.yaml",
        "agentspaces:\n  keystore: ~/keys\n  groups:\n    - name: g\n      seeds: [localhost:1]\n",
    );
    let error = Config::from_vars(
        &Overrides::default(),
        vars(&[("ASPACE_CONFIG", &tilde.display().to_string())]),
    )
    .expect_err("no HOME for the keystore");
    assert_mentions(&error, &["agentspaces.keystore in", "HOME is unset"]);
}

#[test]
fn a_plaintext_seed_outside_loopback_needs_dev_local_and_the_refusal_names_where() {
    let scratch = Scratch::new("plaintext");
    let path = scratch.file(
        "plain.yaml",
        "agentspaces:\n  allow-plain: true\n  groups:\n    - name: g\n      seeds: [ '10.0.0.7:7500' ]\n",
    );
    let file_var = path.display().to_string();
    let error = Config::from_vars(&Overrides::default(), vars(&[("ASPACE_CONFIG", &file_var)]))
        .expect_err("plaintext");
    assert!(
        matches!(error, ConfigError::PlaintextSeedAt { .. }),
        "{error:?}"
    );
    assert_mentions(
        &error,
        &[
            "agentspaces.groups[0].seeds in",
            "tcp://10.0.0.7:7500",
            "not loopback",
            "profile is mtls (the default)",
            "tls://10.0.0.7:7500",
            "dev-local",
            "allow-plain is set, but this peer follows the profile alone",
        ],
    );

    let error = Config::from_vars(
        &Overrides {
            seeds: Some("tcp://fleet.example.com:7500".into()),
            group: Some("g".into()),
            ..Overrides::default()
        },
        vars(&[("ASPACE_PROFILE", "mtls")]),
    )
    .expect_err("plaintext by flag");
    assert_mentions(
        &error,
        &[
            "--seeds holds tcp://fleet.example.com:7500",
            "(ASPACE_PROFILE)",
        ],
    );

    // dev-local from any layer allows it; tls is allowed anywhere.
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[
            ("ASPACE_CONFIG", &file_var),
            ("ASPACE_PROFILE", "dev-local"),
        ]),
    )
    .expect("dev-local");
    assert_eq!(config.settings.profile, Profile::DevLocal);
    let devlocal = scratch.file(
        "devlocal.yaml",
        "agentspaces:\n  security: { profile: DEV-LOCAL }\n  groups:\n    - name: g\n      seeds: [ '10.0.0.7:7500' ]\n",
    );
    Config::from_vars(
        &Overrides::default(),
        vars(&[("ASPACE_CONFIG", &devlocal.display().to_string())]),
    )
    .expect("dev-local from the file");
    Config::from_vars(
        &Overrides {
            seeds: Some("tls://10.0.0.7:7500".into()),
            ..Overrides::default()
        },
        vars(&[("ASPACE_CONFIG", &file_var)]),
    )
    .expect("tls anywhere");
}

#[test]
fn the_java_profiles_run_as_mtls() {
    for name in ["mtls-oidc", "ZERO-TRUST", " mtls "] {
        assert_eq!(
            config::parse_profile_name(name),
            Some(Profile::Mtls),
            "{name}"
        );
    }
    assert_eq!(
        config::parse_profile_name("dev-local"),
        Some(Profile::DevLocal)
    );
    assert_eq!(config::parse_profile_name("none"), None);
}

// ---------------------------------------------------------------------------------------------
// The file the Ruby Config reads

fn ruby_required() -> bool {
    std::env::var("ASPACE_RUBY_REQUIRED").as_deref() == Ok("1")
}

/// The Ruby gem's `lib` directory: `AGENTSPACES_RB_LIB`, or the gem next to this workspace.
fn ruby_lib() -> PathBuf {
    std::env::var_os("AGENTSPACES_RB_LIB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../agentspaces-rb/gems/agentspaces/lib")
        })
}

/// What the Ruby `Config.load` makes of `path`, as JSON; `Err` when it cannot run.
fn ruby_reads(path: &Path) -> Result<serde_json::Value, String> {
    let lib = ruby_lib();
    if !lib.join("agentspaces.rb").is_file() {
        return Err(format!("no Ruby gem at {}", lib.display()));
    }
    let script = r#"
require "agentspaces"
require "json"
c = AgentSpaces::Config.load(ARGV[0])
puts JSON.generate({
  "keystore" => c.keystore, "profile" => c.profile,
  "groups" => c.groups.map { |g|
    { "name" => g.name, "founding" => g.founding, "group_id" => g.group_id,
      "seeds" => g.seeds.map(&:to_s), "spaces" => g.spaces, "join_timeout" => g.join_timeout_millis }
  }
})
"#;
    let output = Command::new("ruby")
        .arg("-I")
        .arg(&lib)
        .arg("-e")
        .arg(script)
        .arg(path)
        .output()
        .map_err(|error| format!("`ruby` does not run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ruby exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("ruby printed no JSON: {error}"))
}

#[test]
fn the_file_ruby_reads_reads_the_same_here() {
    let scratch = Scratch::new("ruby");
    let id = group_id("research-fleet-demo-v1");
    // Keys in the Ruby forms: snake_case, a bare string group, a comma-separated seed scalar.
    let path = scratch.file(
        "fleet.yaml",
        &format!(
            "agentspaces:
  keystore: /var/lib/agentspaces/keys
  bind: 0.0.0.0:7500
  peer_ad_interval_millis: 20000
  security:
    profile: mtls
  groups:
    - name: research-fleet
      founding: research-fleet-demo-v1
      seeds: [ 'tls://fleet.example.com:7500', '127.0.0.1:7711' ]
      spaces: [ {{ name: tasks }}, {{ name: votes }} ]
    - name: partner
      join: aspace://{id}
      join_timeout_millis: 2500
      seeds: tls://partner.example.com:7500
      spaces: [ results ]
"
        ),
    );
    let file = FleetFile::read(&path, &Origin::Default, &no_vars).expect("reads here");
    let ruby = match ruby_reads(&path) {
        Ok(ruby) => ruby,
        Err(why) => {
            assert!(!ruby_required(), "the Ruby Config cannot run: {why}");
            eprintln!("skipping the Ruby comparison: {why}");
            return;
        }
    };
    assert_eq!(ruby["keystore"].as_str(), file.keystore.as_deref());
    assert_eq!(ruby["profile"].as_str(), file.profile.as_deref());
    let groups = ruby["groups"].as_array().expect("groups");
    assert_eq!(groups.len(), file.groups.len());
    for (theirs, ours) in groups.iter().zip(&file.groups) {
        assert_eq!(theirs["name"].as_str(), Some(ours.name.as_str()));
        let their_id = match (theirs["group_id"].as_str(), theirs["founding"].as_str()) {
            (Some(id), _) => id.to_owned(),
            (None, Some(founding)) => group_id(founding),
            (None, None) => panic!("ruby read no group id: {theirs}"),
        };
        assert_eq!(their_id, ours.group_id, "{}", ours.name);
        let seeds: Vec<String> = ours.seeds.iter().map(ToString::to_string).collect();
        let their_seeds: Vec<&str> = theirs["seeds"]
            .as_array()
            .expect("seeds")
            .iter()
            .filter_map(|s| s.as_str())
            .collect();
        assert_eq!(their_seeds, seeds, "{}", ours.name);
        let their_spaces: Vec<&str> = theirs["spaces"]
            .as_array()
            .expect("spaces")
            .iter()
            .filter_map(|s| s.as_str())
            .collect();
        assert_eq!(their_spaces, ours.spaces, "{}", ours.name);
        assert_eq!(
            theirs["join_timeout"].as_u64(),
            Some(
                ours.join_timeout
                    .unwrap_or(config::DEFAULT_JOIN_TIMEOUT)
                    .as_millis() as u64
            )
        );
    }
    // And the configuration the file gives a peer here.
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[("ASPACE_CONFIG", &path.display().to_string())]),
    )
    .expect("resolves");
    assert_eq!(config.settings.peer_ad_interval, Duration::from_secs(20));
    assert_eq!(
        config.settings.group,
        GroupSpec::FoundingText("research-fleet-demo-v1".into())
    );
    assert!(config.ignored.iter().any(|key| key == "agentspaces.bind"));
}
