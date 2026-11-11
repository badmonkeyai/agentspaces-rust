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

//! A listening peer's configuration (SPEC §5.1 to §5.4): the listeners and their
//! advertisements from `--listen`/`--advertise`, `ASPACE_LISTEN`/`ASPACE_ADVERTISE`, and the
//! fleet file's `bind`/`advertise`, layered as every setting is and refused by name; a dial-only
//! configuration never reads them; a group's `membership`; a group the peer founded itself
//! (`--found`); and an invite key (`--invite`, `ASPACE_INVITE`) that names its group and becomes
//! the `aspace:join` credential.

use std::path::{Path, PathBuf};

use agentspaces::config::{
    self, Config, ConfigError, DEFAULT_LISTEN_PORT, Founded, ListenAddress, Origin, Overrides,
};
use agentspaces::group::{self, Charter, GroupSpec, MembershipPolicy};
use agentspaces::wire::cbor;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::social::{self, GroupSecret, InviteKey, JoinVerdict};

/// A scratch directory under the target's temporary space, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("listen-config-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        Self(path)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("written");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

fn listening() -> Overrides {
    Overrides {
        listening: true,
        group: Some("listen-config-v1".to_owned()),
        ..Overrides::default()
    }
}

fn binds(config: &Config) -> Vec<String> {
    config.listen.iter().map(ListenAddress::uri).collect()
}

fn refusal(result: Result<Config, ConfigError>) -> String {
    match result {
        Ok(config) => panic!("resolved: {:?}", config.listen),
        Err(error) => error.to_string(),
    }
}

/// An invite key of a group `founder` founded, and the GroupID.
fn invite(founder: &Identity) -> (String, String) {
    let document = group::found(
        founder,
        &Charter::new("crew", MembershipPolicy::Invite),
        1_767_225_600_000,
    )
    .expect("found");
    let group = group::founding_group_id(&document).expect("verifies");
    let secret = GroupSecret::random().expect("random");
    let delegation = social::delegate(
        founder,
        &group,
        &secret.invite_public_key(),
        4_102_444_800_000,
        Some("tests"),
    );
    let key = InviteKey::of(secret)
        .with_delegation(Some(&delegation))
        .expect("a key");
    (key.compact().to_string(), group)
}

#[test]
fn a_dial_only_configuration_never_reads_the_listeners() {
    let scratch = Scratch::new("dial-only");
    let file = scratch.file(
        "fleet.yaml",
        "agentspaces:\n  bind: [ \"ws://0.0.0.0:1\", {nonsense: 1} ]\n  advertise: 0.0.0.0:1\n  \
         groups:\n    - name: g\n      founding: g-v1\n      membership: maybe\n      \
         seeds: [ \"tls://seed.example.com:7500\" ]\n",
    );
    let path = file.display().to_string();
    let config = Config::from_vars(
        &Overrides::default(),
        vars(&[
            ("ASPACE_CONFIG", &path),
            ("ASPACE_LISTEN", "nonsense"),
            ("ASPACE_ADVERTISE", "nonsense"),
        ]),
    )
    .expect("a visitor resolves whatever the listener keys hold");
    assert!(!config.listening);
    assert!(config.listen.is_empty());
    assert_eq!(config.membership, None);
    assert!(config.ignored.iter().any(|key| key == "agentspaces.bind"));
    assert!(
        config
            .ignored
            .iter()
            .any(|key| key == "agentspaces.advertise")
    );
    let peer = config
        .peer_config(Identity::generate().expect("identity"))
        .expect("a peer configuration");
    assert!(
        !peer.is_listening(),
        "a visitor never binds the file's bind"
    );
}

#[test]
fn a_listener_defaults_to_loopback_7700_and_needs_no_seed() {
    for (profile, scheme) in [("mtls", "tls"), ("dev-local", "tcp")] {
        let config = Config::from_vars(&listening(), vars(&[("ASPACE_PROFILE", profile)]))
            .expect("a first seed needs no seed");
        assert!(config.settings.seeds.is_empty());
        assert_eq!(
            binds(&config),
            [format!("{scheme}://127.0.0.1:{DEFAULT_LISTEN_PORT}")]
        );
        assert_eq!(config.listen[0].origin, Origin::Default);
        let peer = config
            .peer_config(Identity::generate().expect("identity"))
            .expect("a listening peer configuration");
        assert!(peer.is_listening());
        assert!(peer.seeds.is_empty());
    }
    // A dial-only configuration still needs one.
    let error = Config::from_vars(
        &Overrides {
            group: Some("g".to_owned()),
            ..Overrides::default()
        },
        vars(&[]),
    )
    .expect_err("no seed");
    assert!(error.to_string().contains("no seed to dial"), "{error}");
}

#[test]
fn listeners_layer_flags_over_variables_over_the_file() {
    let scratch = Scratch::new("layers");
    let file = scratch.file(
        "fleet.yaml",
        "agentspaces:\n  bind: 127.0.0.1:7500\n  advertise: seed.example.com:7500\n  security:\n    \
         profile: dev-local\n  groups:\n    - name: g\n      founding: g-v1\n      \
         membership: Invite\n",
    );
    let path = file.display().to_string();
    let overrides = Overrides {
        listening: true,
        ..Overrides::default()
    };
    // The file: Java's spelling, the scheme from the profile; its advertisement applies.
    let config = Config::from_vars(&overrides, vars(&[("ASPACE_CONFIG", &path)])).expect("file");
    assert_eq!(binds(&config), ["tcp://127.0.0.1:7500"]);
    assert_eq!(
        config.listen[0].advertise.as_deref(),
        Some("seed.example.com:7500")
    );
    assert_eq!(
        config.origin("listen"),
        Some(&Origin::Key {
            file: file.clone(),
            key: "agentspaces.bind".to_owned()
        })
    );
    let (policy, origin) = config.membership.clone().expect("the group's membership");
    assert_eq!(policy, MembershipPolicy::Invite);
    assert!(
        origin
            .to_string()
            .contains("agentspaces.groups[0].membership")
    );
    // The variable over the file: the file's advertisement is below it and does not apply.
    let config = Config::from_vars(
        &overrides,
        vars(&[
            ("ASPACE_CONFIG", &path),
            ("ASPACE_LISTEN", "tls://0.0.0.0:7600, tcp://127.0.0.1:7601"),
            ("ASPACE_ADVERTISE", "tls://seed.example.com:7600"),
        ]),
    )
    .expect("variables");
    assert_eq!(
        binds(&config),
        ["tls://0.0.0.0:7600", "tcp://127.0.0.1:7601"]
    );
    assert_eq!(
        config.listen[0].advertise.as_deref(),
        Some("seed.example.com:7600")
    );
    assert_eq!(config.listen[1].advertise, None);
    // The flag over both.
    let config = Config::from_vars(
        &Overrides {
            listen: vec!["127.0.0.1:0".to_owned()],
            advertise: vec!["localhost:7999".to_owned()],
            ..overrides.clone()
        },
        vars(&[
            ("ASPACE_CONFIG", &path),
            ("ASPACE_LISTEN", "tls://0.0.0.0:7600"),
        ]),
    )
    .expect("flags");
    assert_eq!(binds(&config), ["tcp://127.0.0.1:0"]);
    assert_eq!(config.listen[0].origin, Origin::Flag(config::FLAG_LISTEN));
    assert_eq!(
        config.listen[0].advertise.as_deref(),
        Some("localhost:7999")
    );
}

#[test]
fn listener_refusals_name_the_flag_variable_or_key() {
    let scratch = Scratch::new("refusals");
    let file = scratch.file(
        "fleet.yaml",
        "agentspaces:\n  bind: 0.0.0.0:7500\n  security:\n    profile: dev-local\n",
    );
    // A plaintext listener outside loopback under mtls is refused, naming the flag.
    let message = refusal(Config::from_vars(
        &Overrides {
            listen: vec!["tcp://0.0.0.0:7500".to_owned()],
            ..listening()
        },
        vars(&[]),
    ));
    assert!(message.starts_with("--listen:"), "{message}");
    assert!(message.contains("dev-local"), "{message}");
    // The file's wildcard bind under dev-local is tcp, and allowed.
    let path = file.display().to_string();
    let config = Config::from_vars(
        &Overrides {
            listening: true,
            group: Some("g".to_owned()),
            ..Overrides::default()
        },
        vars(&[("ASPACE_CONFIG", &path)]),
    )
    .expect("dev-local allows it");
    assert_eq!(binds(&config), ["tcp://0.0.0.0:7500"]);
    for (listen, needle) in [
        ("ws://127.0.0.1:1", "tcp and tls only"),
        ("tcp://127.0.0.1", "not an address to listen on"),
        ("tcp://127.0.0.1:1/path", "not an address to listen on"),
    ] {
        let message = refusal(Config::from_vars(
            &listening(),
            vars(&[("ASPACE_LISTEN", listen)]),
        ));
        assert!(message.starts_with("ASPACE_LISTEN:"), "{message}");
        assert!(message.contains(needle), "{listen}: {message}");
    }
    for (listen, advertise, needle) in [
        (
            "tcp://127.0.0.1:1,tls://127.0.0.1:2",
            "seed.example.com:1",
            "names no scheme",
        ),
        (
            "tcp://127.0.0.1:1",
            "tls://seed.example.com:1",
            "no listener serves it",
        ),
        (
            "tcp://127.0.0.1:1,tcp://127.0.0.1:2",
            "tcp://seed.example.com:1",
            "several listeners serve",
        ),
        ("tcp://127.0.0.1:1", "0.0.0.0:1", "wildcard"),
        (
            "tcp://127.0.0.1:1",
            "a.example.com:1,b.example.com:1",
            "second address",
        ),
        (
            "tcp://127.0.0.1:1",
            "nonsense",
            "not an address to advertise",
        ),
    ] {
        let message = refusal(Config::from_vars(
            &listening(),
            vars(&[
                ("ASPACE_PROFILE", "dev-local"),
                ("ASPACE_LISTEN", listen),
                ("ASPACE_ADVERTISE", advertise),
            ]),
        ));
        assert!(message.starts_with("ASPACE_ADVERTISE:"), "{message}");
        assert!(message.contains(needle), "{advertise}: {message}");
    }
    let bad = scratch.file(
        "bad.yaml",
        "agentspaces:\n  groups:\n    - name: g\n      membership: sometimes\n",
    );
    let message = refusal(Config::from_vars(
        &Overrides {
            listening: true,
            ..Overrides::default()
        },
        vars(&[("ASPACE_CONFIG", &bad.display().to_string())]),
    ));
    assert!(
        message.contains("agentspaces.groups[0].membership") && message.contains("open"),
        "{message}"
    );
}

#[test]
fn a_founded_group_is_the_group_and_excludes_another() {
    let scratch = Scratch::new("founded");
    let founder = Identity::generate().expect("identity");
    let document = group::found(
        &founder,
        &Charter::new("crew", MembershipPolicy::Open),
        1_767_225_600_000,
    )
    .expect("found");
    let id = group::founding_group_id(&document).expect("verifies");
    let file = scratch.file(
        "fleet.yaml",
        "agentspaces:\n  groups:\n    - name: other\n      founding: other-v1\n    - name: crew\n      \
         spaces: [ tasks ]\n",
    );
    let founded = Overrides {
        listening: true,
        founded: Some(Founded {
            name: "crew".to_owned(),
            document: document.clone(),
        }),
        ..Overrides::default()
    };
    let config = Config::from_vars(
        &founded,
        vars(&[("ASPACE_CONFIG", &file.display().to_string())]),
    )
    .expect("resolves");
    assert_eq!(
        config.settings.group,
        GroupSpec::FoundingDocument(document.clone())
    );
    assert_eq!(
        config.origin("group"),
        Some(&Origin::Flag(config::FLAG_FOUND))
    );
    assert_eq!(
        config.group_name.as_deref(),
        Some("crew"),
        "the file's group of that name"
    );
    assert_eq!(config.settings.spaces, ["tasks"]);
    let peer = config.peer_config(founder).expect("a peer configuration");
    assert_eq!(
        group::founding_group_id(&document).as_deref(),
        Some(id.as_str())
    );
    assert!(peer.is_listening());
    let message = refusal(Config::from_vars(
        &Overrides {
            group: Some("g".to_owned()),
            ..founded.clone()
        },
        vars(&[]),
    ));
    assert!(
        message.contains("--found") && message.contains("--group"),
        "{message}"
    );
    let message = refusal(Config::from_vars(
        &Overrides {
            founded: Some(Founded {
                name: "crew".to_owned(),
                document: b"not a founding".to_vec(),
            }),
            ..founded
        },
        vars(&[]),
    ));
    assert!(message.contains("does not verify"), "{message}");
}

#[test]
fn an_invite_names_its_group_and_becomes_the_join_credential() {
    let founder = Identity::generate().expect("identity");
    let (key, group_id) = invite(&founder);
    let seeds = [("ASPACE_SEEDS", "tls://seed.example.com:7500")];

    // No group named: the invite's, joined by id.
    let config = Config::from_vars(
        &Overrides {
            invite: Some(key.clone()),
            ..Overrides::default()
        },
        vars(&seeds),
    )
    .expect("resolves");
    assert_eq!(
        config.settings.group,
        GroupSpec::Join(format!("aspace://{group_id}"))
    );
    assert_eq!(
        config.origin("invite"),
        Some(&Origin::Flag(config::FLAG_INVITE))
    );
    let joiner = Identity::generate().expect("identity");
    let peer = config
        .peer_config(joiner.clone())
        .expect("a peer configuration");
    let credential = peer
        .resource_hints
        .get(social::HINT_KEY)
        .and_then(cbor::Value::as_str)
        .expect("the aspace:join hint")
        .to_owned();
    assert_eq!(
        social::judge_credential(
            &credential,
            joiner.peer_id(),
            founder.peer_id(),
            &group_id,
            1_767_225_600_000
        ),
        JoinVerdict::Valid,
        "the founder's members admit it"
    );
    assert!(
        !format!("{config:?}").contains(&key[30..]),
        "the configuration never shows the secret"
    );

    // From the variable, with the same group named: fine; another group: refused, naming both.
    let config = Config::from_vars(
        &Overrides {
            join: Some(format!("aspace://{group_id}")),
            ..Overrides::default()
        },
        vars(&[seeds[0], ("ASPACE_INVITE", &key)]),
    )
    .expect("the same group");
    assert!(config.invite.is_some());
    let message = refusal(Config::from_vars(
        &Overrides {
            group: Some("someone-else-v1".to_owned()),
            ..Overrides::default()
        },
        vars(&[seeds[0], ("ASPACE_INVITE", &key)]),
    ));
    assert!(
        message.contains("ASPACE_INVITE") && message.contains("--group"),
        "{message}"
    );
    assert!(!message.contains(&key[30..]), "{message}");

    // Not a key, or a key with no delegation: refused, never echoing the text.
    let bare = InviteKey::of(GroupSecret::random().expect("random"))
        .compact()
        .to_string();
    for (text, needle) in [
        ("aspace-inv1-NOPE", "not an invite key"),
        (bare.as_str(), "no delegation"),
    ] {
        let message = refusal(Config::from_vars(
            &Overrides {
                invite: Some(text.to_owned()),
                ..Overrides::default()
            },
            vars(&seeds),
        ));
        assert!(message.starts_with("--invite:"), "{message}");
        assert!(message.contains(needle), "{message}");
        assert!(!message.contains(&text[14..]), "{message}");
    }
}
