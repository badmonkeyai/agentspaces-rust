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

//! The keystore and the configuration: the shared keystore layout (a Java- or Python-written
//! keystore loads to the golden PeerID), its refusals, and every `ASPACE_*` rule and message.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentspaces::config::{self, ConfigError, PeerSettings};
use agentspaces::group::{GroupSpec, Profile};
use agentspaces::keystore::{self, KeystoreError, KeystoreOptions};
use agentspaces::wire::crypto::ED25519_PKCS8_PREFIX;
use agentspaces::wire::identity::Identity;
use agentspaces::wire::ids;
use agentspaces::wire::seed::Seed;

// ---------------------------------------------------------------------------------------------
// Helpers

/// A fresh directory under Cargo's per-target scratch space, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "keystore-{tag}-{}-{}",
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
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn golden() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../agentspaces-wire/tests/golden.json");
    let text = fs::read_to_string(&path).expect("golden.json");
    serde_json::from_str(&text).expect("golden.json parses")
}

fn golden_hex(golden: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(golden[key].as_str().expect(key)).expect("hex")
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Writes the golden Java/Python keystore: the golden PKCS#8 as `peer.key` (0600) and the golden
/// raw public key as `peer.pub`, exactly as `FileKeystore` and `identity.py` lay them out.
fn write_golden_keystore(dir: &Path) -> serde_json::Value {
    let golden = golden();
    fs::create_dir_all(dir).expect("dir");
    let key = dir.join("peer.key");
    fs::write(&key, golden_hex(&golden, "private_key_pkcs8")).expect("peer.key");
    #[cfg(unix)]
    chmod(&key, 0o600);
    fs::write(dir.join("peer.pub"), golden_hex(&golden, "public_key_raw")).expect("peer.pub");
    golden
}

// ---------------------------------------------------------------------------------------------
// Keystore

#[test]
fn create_then_reload_is_the_same_identity_with_the_shared_layout() {
    let scratch = Scratch::new("create");
    let dir = scratch.path().join("missing").join("keys");
    let created = keystore::load_or_create(&dir).expect("created");

    let key = fs::read(dir.join("peer.key")).expect("peer.key");
    let public = fs::read(dir.join("peer.pub")).expect("peer.pub");
    assert_eq!(key.len(), 48, "peer.key is the 48-byte PKCS#8 form");
    assert!(key.starts_with(&ED25519_PKCS8_PREFIX));
    assert_eq!(key.as_slice(), created.pkcs8().as_slice());
    assert_eq!(public.len(), 32, "peer.pub is the raw 32-byte key");
    assert_eq!(public.as_slice(), created.public_raw());
    assert_eq!(created.peer_id(), ids::derive_id(&public));
    // Only the pair: every temporary file was renamed into place.
    assert_eq!(entries(&dir), ["peer.key", "peer.pub"]);

    #[cfg(unix)]
    {
        assert_eq!(mode(&dir.join("peer.key")), 0o600);
        let public_mode = mode(&dir.join("peer.pub"));
        assert_eq!(public_mode & !0o644, 0, "peer.pub mode {public_mode:o}");
        assert_eq!(
            mode(&dir),
            0o700,
            "a missing keystore directory is owner-only"
        );
        assert_eq!(mode(&scratch.path().join("missing")), 0o700);
    }

    let reloaded = keystore::load_or_create(&dir).expect("reloaded");
    assert_eq!(reloaded.peer_id(), created.peer_id());
    assert_eq!(reloaded.public_raw(), created.public_raw());
    assert_eq!(reloaded.pkcs8().as_slice(), created.pkcs8().as_slice());
    // Loading changes nothing on disk.
    assert_eq!(fs::read(dir.join("peer.key")).expect("peer.key"), key);
    assert_eq!(entries(&dir), ["peer.key", "peer.pub"]);

    // The same identity signs the same bytes: it is the same peer.
    assert_eq!(reloaded.sign(b"probe"), created.sign(b"probe"));
}

#[test]
fn an_existing_directory_keeps_its_mode() {
    let scratch = Scratch::new("existing");
    let dir = scratch.path().join("keys");
    fs::create_dir(&dir).expect("dir");
    #[cfg(unix)]
    chmod(&dir, 0o750);
    keystore::load_or_create(&dir).expect("created");
    #[cfg(unix)]
    assert_eq!(mode(&dir), 0o750);
}

#[test]
fn a_java_or_python_written_keystore_loads_to_the_golden_peer_id() {
    let scratch = Scratch::new("golden");
    let golden = write_golden_keystore(scratch.path());
    let identity = keystore::load_or_create(scratch.path()).expect("golden keystore loads");
    assert_eq!(
        identity.peer_id(),
        golden["peer_id"].as_str().expect("peer_id")
    );
    assert_eq!(
        identity.public_raw().as_slice(),
        golden_hex(&golden, "public_key_raw").as_slice()
    );
    assert_eq!(
        identity.pkcs8().as_slice(),
        golden_hex(&golden, "private_key_pkcs8").as_slice()
    );

    // And what this keystore writes for that identity is the bytes Java wrote.
    let copy = scratch.path().join("copy");
    keystore::save_pkcs8(&identity, &copy.join("peer.key")).expect("save_pkcs8");
    keystore::write_key_file(&copy.join("peer.pub"), identity.public_raw(), false)
        .expect("write_key_file");
    assert_eq!(
        fs::read(copy.join("peer.key")).expect("copy"),
        golden_hex(&golden, "private_key_pkcs8")
    );
    let again = keystore::load_or_create(&copy).expect("copy loads");
    assert_eq!(again.peer_id(), identity.peer_id());
}

#[test]
fn a_half_written_pair_is_refused_naming_both_files() {
    let scratch = Scratch::new("half");
    let dir = scratch.path();
    keystore::load_or_create(dir).expect("created");
    let private = dir.join("peer.key");
    let public = dir.join("peer.pub");

    let saved = fs::read(&public).expect("pub");
    fs::remove_file(&public).expect("remove pub");
    let error = keystore::load_or_create(dir).expect_err("private without public");
    assert!(
        matches!(&error, KeystoreError::HalfPair { present, missing }
            if present == &private && missing == &public),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&private.display().to_string()),
        "{message}"
    );
    assert!(message.contains(&public.display().to_string()), "{message}");
    assert!(message.contains("remove both"), "{message}");
    // Nothing was minted in its place.
    assert_eq!(entries(dir), ["peer.key"]);

    fs::write(&public, &saved).expect("restore pub");
    fs::remove_file(&private).expect("remove key");
    let error = keystore::load_or_create(dir).expect_err("public without private");
    assert!(
        matches!(&error, KeystoreError::HalfPair { present, missing }
            if present == &public && missing == &private),
        "{error:?}"
    );
    assert_eq!(entries(dir), ["peer.pub"]);
}

#[test]
fn a_public_key_that_does_not_match_is_refused() {
    let scratch = Scratch::new("mismatch");
    let a = scratch.path().join("a");
    let b = scratch.path().join("b");
    keystore::load_or_create(&a).expect("a");
    keystore::load_or_create(&b).expect("b");
    fs::copy(b.join("peer.pub"), a.join("peer.pub")).expect("copy b's public key over a's");

    let error = keystore::load_or_create(&a).expect_err("mismatched pair");
    assert!(matches!(error, KeystoreError::Mismatch { .. }), "{error:?}");
    let message = error.to_string();
    assert!(
        message.contains(&a.join("peer.key").display().to_string()),
        "{message}"
    );
    assert!(
        message.contains(&a.join("peer.pub").display().to_string()),
        "{message}"
    );
    assert!(message.contains("does not belong to"), "{message}");
}

#[test]
fn malformed_key_files_are_refused_without_printing_them() {
    let scratch = Scratch::new("malformed");
    let dir = scratch.path();
    let identity = keystore::load_or_create(dir).expect("created");

    // A public key of the wrong size.
    fs::write(dir.join("peer.pub"), [7u8; 33]).expect("pub");
    let error = keystore::load_or_create(dir).expect_err("33-byte public key");
    assert!(
        matches!(error, KeystoreError::MalformedPublicKey { length: 33, .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("expected 32"), "{error}");
    fs::write(dir.join("peer.pub"), identity.public_raw()).expect("restore pub");

    // A private key with one byte too many (the RFC 5958 forms are refused the same way).
    let mut key = identity.pkcs8().to_vec();
    key.push(0);
    keystore::write_key_file(&dir.join("peer.key"), &key, true).expect("write key");
    let error = keystore::load_or_create(dir).expect_err("49-byte private key");
    assert!(
        matches!(error, KeystoreError::MalformedPrivateKey { length: 49, .. }),
        "{error:?}"
    );
    let shown = format!("{error} {error:?}");
    let seed_hex = hex::encode(&identity.pkcs8()[16..]);
    assert!(
        !shown.contains(&seed_hex),
        "the key is never printed: {shown}"
    );
    assert!(
        !shown.contains(&format!("{:?}", &identity.pkcs8()[16..20])),
        "{shown}"
    );
    assert!(shown.contains("48-byte PKCS#8"), "{shown}");

    // A private key path that is a directory.
    fs::remove_file(dir.join("peer.key")).expect("remove key");
    fs::create_dir(dir.join("peer.key")).expect("key dir");
    let error = keystore::load_or_create(dir).expect_err("directory as key");
    assert!(matches!(error, KeystoreError::NotAFile { .. }), "{error:?}");
}

#[cfg(unix)]
#[test]
fn a_readable_private_key_is_refused_unless_allowed() {
    let scratch = Scratch::new("readable");
    let dir = scratch.path();
    let created = keystore::load_or_create(dir).expect("created");
    let key = dir.join("peer.key");

    for readable in [0o640, 0o604, 0o644, 0o660] {
        chmod(&key, readable);
        let error = keystore::load_or_create(dir).expect_err("readable key");
        assert!(
            matches!(&error, KeystoreError::Readable { path, mode } if path == &key && *mode == readable),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains(&key.display().to_string()), "{message}");
        assert!(message.contains(&format!("{readable:o}")), "{message}");
        assert!(message.contains("chmod 600"), "{message}");
        assert!(message.contains("allow_readable"), "{message}");

        let allowed = keystore::load_or_create_with(
            dir,
            KeystoreOptions {
                allow_readable: true,
            },
        )
        .expect("allowed");
        assert_eq!(allowed.peer_id(), created.peer_id());
    }

    // Owner-only modes, read-only included, load.
    for private in [0o600, 0o400] {
        chmod(&key, private);
        let loaded = keystore::load_or_create(dir).expect("owner-only");
        assert_eq!(loaded.peer_id(), created.peer_id());
    }
    assert_eq!(
        KeystoreOptions::default(),
        KeystoreOptions {
            allow_readable: false
        }
    );
}

/// The refusal names the file, its mode, the `chmod 600` fix, and every way to accept a readable
/// key; the variable accepts one only for a true value, refuses anything it cannot read as a
/// boolean, and a flag can only widen it.
#[test]
fn the_readable_key_variable_is_a_boolean_and_a_flag_widens_it() {
    let lookup = |value: Option<&'static str>| {
        move |name: &str| {
            assert_eq!(name, keystore::ENV_ALLOW_READABLE_KEY);
            value.map(str::to_owned)
        }
    };
    for (value, allowed) in [
        (None, false),
        (Some(""), false),
        (Some("  "), false),
        (Some("0"), false),
        (Some("false"), false),
        (Some("No"), false),
        (Some("off"), false),
        (Some("1"), true),
        (Some("true"), true),
        (Some(" YES "), true),
        (Some("on"), true),
    ] {
        let options = KeystoreOptions::from_vars(lookup(value)).expect("a boolean");
        assert_eq!(options.allow_readable, allowed, "{value:?}");
    }
    for value in ["maybe", "2", "y", "enabled"] {
        let error = KeystoreOptions::from_vars(lookup(Some(value))).expect_err(value);
        assert!(
            matches!(&error, KeystoreError::InvalidVariable { name, value: held }
                if *name == "ASPACE_ALLOW_READABLE_KEY" && held == value),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&format!("ASPACE_ALLOW_READABLE_KEY={value:?}")),
            "{message}"
        );
        assert!(message.contains("not a boolean"), "{message}");
    }
    let refused = KeystoreOptions::default();
    assert!(!refused.allowing_readable(false).allow_readable);
    assert!(refused.allowing_readable(true).allow_readable);
    let allowed = KeystoreOptions {
        allow_readable: true,
    };
    assert!(
        allowed.allowing_readable(false).allow_readable,
        "a flag left off never narrows the variable"
    );
}

#[cfg(unix)]
#[test]
fn a_readable_key_refusal_names_the_file_the_fix_and_the_ways_to_allow_it() {
    let scratch = Scratch::new("readable-message");
    let dir = scratch.path();
    let created = keystore::load_or_create(dir).expect("created");
    let key = dir.join("peer.key");
    chmod(&key, 0o604);
    let message = keystore::load_or_create(dir)
        .expect_err("readable")
        .to_string();
    let path = key.display().to_string();
    for part in [
        path.as_str(),
        "mode 604",
        &format!("chmod 600 {path}"),
        "--allow-readable-key",
        "ASPACE_ALLOW_READABLE_KEY=1",
        "KeystoreOptions::allow_readable",
    ] {
        assert!(message.contains(part), "{part:?} missing from: {message}");
    }
    // Allowed through the variable's options, the identity is the same; the file is left as
    // it is (loading never rewrites a key).
    let options = KeystoreOptions::from_vars(|_| Some("1".to_owned())).expect("options");
    let loaded = keystore::load_or_create_with(dir, options).expect("allowed");
    assert_eq!(loaded.peer_id(), created.peer_id());
    assert_eq!(mode(&key), 0o604);
}

#[cfg(unix)]
#[test]
fn a_readable_agent_key_is_refused_unless_allowed() {
    let scratch = Scratch::new("readable-agent");
    let dir = scratch.path();
    let peer = keystore::load_or_create(dir).expect("peer");
    let agent = keystore::agent_keys(dir, peer.peer_id(), "worker").expect("agent");
    let key = dir.join(peer.peer_id()).join("worker").join("agent.key");
    chmod(&key, 0o644);
    let error = keystore::agent_keys(dir, peer.peer_id(), "worker").expect_err("readable");
    assert!(
        matches!(&error, KeystoreError::Readable { path, mode: 0o644 } if path == &key),
        "{error:?}"
    );
    let allowed = keystore::agent_keys_with(
        dir,
        peer.peer_id(),
        "worker",
        KeystoreOptions {
            allow_readable: true,
        },
    )
    .expect("allowed");
    assert_eq!(allowed.public_raw(), agent.public_raw());
}

/// Whatever the umask allows, a minted keystore's directories (missing parents included) are 0700
/// and its private key 0600; the public key is never wider than 0644.
#[cfg(unix)]
#[test]
fn a_minted_keystore_is_owner_only_down_to_its_missing_parents() {
    let scratch = Scratch::new("minted");
    let dir = scratch.path().join("a/b/keys");
    let peer = keystore::load_or_create(&dir).expect("minted");
    for created in [
        scratch.path().join("a"),
        scratch.path().join("a/b"),
        dir.clone(),
    ] {
        assert_eq!(mode(&created), 0o700, "{}", created.display());
    }
    assert_eq!(mode(&dir.join("peer.key")), 0o600);
    assert_eq!(mode(&dir.join("peer.pub")) & !0o644, 0);
    keystore::agent_keys(&dir, peer.peer_id(), "a1").expect("agent");
    assert_eq!(mode(&dir.join(peer.peer_id())), 0o700);
    assert_eq!(mode(&dir.join(peer.peer_id()).join("a1")), 0o700);
    assert_eq!(
        mode(&dir.join(peer.peer_id()).join("a1").join("agent.key")),
        0o600
    );
    // No temporary file is left behind.
    let mut expected = vec![
        peer.peer_id().to_owned(),
        "peer.key".to_owned(),
        "peer.pub".to_owned(),
    ];
    expected.sort();
    assert_eq!(entries(&dir), expected);
}

#[cfg(unix)]
#[test]
fn a_secret_replaces_a_readable_file_with_an_owner_only_one() {
    let scratch = Scratch::new("replace");
    let path = scratch.path().join("secret.key");
    fs::write(&path, b"old").expect("old");
    chmod(&path, 0o644);
    keystore::write_key_file(&path, b"new", true).expect("write");
    assert_eq!(fs::read(&path).expect("read"), b"new");
    assert_eq!(mode(&path), 0o600);
    keystore::write_key_file(&scratch.path().join("public.pub"), b"pub", false).expect("pub");
    assert_eq!(mode(&scratch.path().join("public.pub")) & !0o644, 0);
    assert_eq!(entries(scratch.path()), ["public.pub", "secret.key"]);
}

#[test]
fn agent_keys_live_under_the_peer_and_agent_names() {
    let scratch = Scratch::new("agents");
    let dir = scratch.path();
    let peer = keystore::load_or_create(dir).expect("peer");

    let agent = keystore::agent_keys(dir, peer.peer_id(), "triage-1").expect("agent");
    let agent_dir = dir.join(peer.peer_id()).join("triage-1");
    assert_eq!(
        keystore::agent_dir(dir, peer.peer_id(), "triage-1").expect("agent_dir"),
        agent_dir
    );
    assert_eq!(entries(&agent_dir), ["agent.key", "agent.pub"]);
    assert_eq!(
        fs::read(agent_dir.join("agent.key")).expect("key").len(),
        48
    );
    assert_eq!(
        fs::read(agent_dir.join("agent.pub"))
            .expect("pub")
            .as_slice(),
        agent.public_raw()
    );
    assert_ne!(agent.peer_id(), peer.peer_id(), "an agent has its own key");
    #[cfg(unix)]
    {
        assert_eq!(mode(&agent_dir.join("agent.key")), 0o600);
        assert_eq!(mode(&agent_dir), 0o700);
        assert_eq!(mode(&dir.join(peer.peer_id())), 0o700);
    }

    let again = keystore::agent_keys(dir, peer.peer_id(), "triage-1").expect("again");
    assert_eq!(again.public_raw(), agent.public_raw());
    let other = keystore::agent_keys(dir, peer.peer_id(), "triage-2").expect("other");
    assert_ne!(other.public_raw(), agent.public_raw());
    // The peer's own pair is untouched beside the agent directories.
    assert_eq!(
        keystore::load_or_create(dir).expect("peer again").peer_id(),
        peer.peer_id()
    );

    // An agent's pair follows the same refusals.
    fs::remove_file(agent_dir.join("agent.pub")).expect("remove agent.pub");
    let error = keystore::agent_keys(dir, peer.peer_id(), "triage-1").expect_err("half");
    assert!(matches!(error, KeystoreError::HalfPair { .. }), "{error:?}");
    assert!(error.to_string().contains("agent.pub"), "{error}");
}

#[test]
fn agent_and_peer_names_that_could_escape_are_refused() {
    let scratch = Scratch::new("names");
    let dir = scratch.path().join("keys");
    let peer = Identity::from_seed(&[9; 32]);
    let too_long = "a".repeat(65);
    for bad in [
        "",
        ".",
        "..",
        "../x",
        "a/b",
        "a\\b",
        "a b",
        "é",
        too_long.as_str(),
    ] {
        let error = keystore::agent_keys(&dir, peer.peer_id(), bad).expect_err("unsafe agent");
        assert!(
            matches!(&error, KeystoreError::UnsafeName { what: "agent name", name } if name == bad),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("agent name"), "{message}");
        assert!(message.contains(&format!("{bad:?}")), "{message}");
        assert!(message.contains("1 to 64 letters, digits"), "{message}");

        let error = keystore::agent_keys(&dir, bad, "agent").expect_err("unsafe peer");
        assert!(
            matches!(
                &error,
                KeystoreError::UnsafeName {
                    what: "peer id",
                    ..
                }
            ),
            "{error:?}"
        );
    }
    assert!(!dir.exists(), "a refused name creates nothing");
    for good in ["a", "A.b_c-9", "...", "a".repeat(64).as_str()] {
        assert!(keystore::is_safe_name(good), "{good}");
        keystore::agent_dir(&dir, peer.peer_id(), good).expect("safe");
    }
}

#[test]
fn errors_and_identities_never_show_key_bytes() {
    let scratch = Scratch::new("redact");
    let golden = write_golden_keystore(scratch.path());
    let identity = keystore::load_or_create(scratch.path()).expect("golden");
    let seed_hex = hex::encode(&golden_hex(&golden, "private_key_pkcs8")[16..]);
    let shown = format!("{identity:?}");
    assert!(!shown.contains(&seed_hex));
    assert!(shown.contains("<redacted>"));
}

// ---------------------------------------------------------------------------------------------
// Configuration

fn group_id() -> String {
    ids::group_id_from_founding(b"research-fleet-demo-v1")
}

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn refused(pairs: &[(&str, &str)]) -> ConfigError {
    PeerSettings::from_vars(vars(pairs)).expect_err("refused")
}

fn assert_mentions(error: &ConfigError, parts: &[&str]) {
    let message = error.to_string();
    for part in parts {
        assert!(message.contains(part), "{part:?} missing from: {message}");
    }
}

#[test]
fn defaults_match_the_python_peer() {
    let join = format!("aspace://{}", group_id());
    let settings = PeerSettings::from_vars(vars(&[
        ("ASPACE_SEEDS", "tls://fleet.example.com:7500"),
        ("ASPACE_JOIN", &join),
    ]))
    .expect("settings");
    assert_eq!(settings.group, GroupSpec::Join(join.clone()));
    assert_eq!(settings.group.group_id(), Some(group_id()));
    assert_eq!(
        settings.seeds,
        [Seed::new("fleet.example.com", 7500, "tls")]
    );
    assert_eq!(settings.profile, Profile::Mtls);
    assert_eq!(settings.keystore, None);
    assert!(settings.spaces.is_empty());
    assert_eq!(settings.reconnect_interval, Duration::from_secs(5));
    assert_eq!(settings.reconnect_window, Duration::from_secs(600));
    assert_eq!(settings.peer_ad_interval, Duration::from_secs(30));
    assert_eq!(config::DEFAULT_RECONNECT_INTERVAL, Duration::from_secs(5));
    assert_eq!(config::DEFAULT_RECONNECT_WINDOW, Duration::from_secs(600));
    assert_eq!(config::DEFAULT_PEER_AD_INTERVAL, Duration::from_secs(30));

    let built = PeerSettings::new(
        GroupSpec::Join(join),
        vec![Seed::new("fleet.example.com", 7500, "tls")],
    );
    assert_eq!(built, settings);
    built.validate().expect("valid");
}

#[test]
fn every_variable_is_read() {
    let settings = PeerSettings::from_vars(vars(&[
        (
            "ASPACE_SEEDS",
            " 127.0.0.1:7711, tls://Fleet.example.com:7500 ,,tcp://[::1]:7712,127.0.0.1:7711 ",
        ),
        ("ASPACE_GROUP", "research-fleet-demo-v1"),
        ("ASPACE_KEYSTORE", " /var/lib/agentspaces/keys "),
        ("ASPACE_PROFILE", " DEV-LOCAL "),
        ("ASPACE_SPACES", "tasks, votes,,tasks , alerts"),
    ]))
    .expect("settings");
    assert_eq!(
        settings.seeds,
        [
            Seed::new("127.0.0.1", 7711, "tcp"),
            Seed::new("Fleet.example.com", 7500, "tls"),
            Seed::new("::1", 7712, "tcp"),
        ],
        "scheme optional (tcp), trimmed, empty entries skipped, duplicates dropped"
    );
    assert_eq!(
        settings.group,
        GroupSpec::FoundingText("research-fleet-demo-v1".into())
    );
    assert_eq!(settings.group.group_id(), Some(group_id()));
    assert_eq!(
        settings.keystore.as_deref(),
        Some(Path::new("/var/lib/agentspaces/keys"))
    );
    assert_eq!(settings.profile, Profile::DevLocal);
    assert_eq!(settings.spaces, ["tasks", "votes", "alerts"]);
}

#[test]
fn founding_text_is_taken_exactly_and_join_is_trimmed() {
    let settings = PeerSettings::from_vars(vars(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", " my fleet "),
    ]))
    .expect("settings");
    assert_eq!(settings.group, GroupSpec::FoundingText(" my fleet ".into()));

    for join in [
        group_id(),
        format!("  aspace://{}  ", group_id()),
        format!("ASPACE://{}", group_id()),
    ] {
        let settings = PeerSettings::from_vars(vars(&[
            ("ASPACE_SEEDS", "localhost:7711"),
            ("ASPACE_JOIN", &join),
        ]))
        .expect("join");
        assert_eq!(settings.group, GroupSpec::Join(join.trim().to_owned()));
        assert_eq!(settings.group.group_id(), Some(group_id()));
    }
}

#[test]
fn empty_variables_count_as_unset() {
    let join = format!("aspace://{}", group_id());
    let settings = PeerSettings::from_vars(vars(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "  "),
        ("ASPACE_JOIN", &join),
        ("ASPACE_KEYSTORE", ""),
        ("ASPACE_PROFILE", ""),
        ("ASPACE_SPACES", " "),
    ]))
    .expect("settings");
    assert_eq!(settings.group, GroupSpec::Join(join));
    assert_eq!(settings.keystore, None);
    assert_eq!(settings.profile, Profile::Mtls);
    assert!(settings.spaces.is_empty());

    let error = refused(&[("ASPACE_SEEDS", ""), ("ASPACE_GROUP", "g")]);
    assert_eq!(error, ConfigError::NoSeeds { value: None });
}

#[test]
fn the_keystore_expands_home() {
    let base = [("ASPACE_SEEDS", "localhost:7711"), ("ASPACE_GROUP", "g")];
    let with = |keystore: &str, home: Option<&str>| {
        let mut pairs = base.to_vec();
        pairs.push(("ASPACE_KEYSTORE", keystore));
        if let Some(home) = home {
            pairs.push(("HOME", home));
        }
        PeerSettings::from_vars(vars(&pairs))
    };
    let keys = |result: Result<PeerSettings, ConfigError>| result.expect("settings").keystore;
    assert_eq!(
        keys(with("~/.config/agentspaces/keys", Some("/home/ada"))),
        Some(PathBuf::from("/home/ada/.config/agentspaces/keys"))
    );
    assert_eq!(
        keys(with("~", Some("/home/ada"))),
        Some(PathBuf::from("/home/ada"))
    );
    assert_eq!(
        keys(with("~ada/keys", None)),
        Some(PathBuf::from("~ada/keys"))
    );
    assert_eq!(keys(with("keys", None)), Some(PathBuf::from("keys")));

    let error = with("~/keys", None).expect_err("no HOME");
    assert_eq!(
        error,
        ConfigError::KeystoreHome {
            value: "~/keys".into()
        }
    );
    assert_mentions(
        &error,
        &[
            "ASPACE_KEYSTORE",
            "\"~/keys\"",
            "HOME is unset",
            "absolute path",
        ],
    );
}

#[test]
fn no_seeds_is_refused() {
    let error = refused(&[("ASPACE_GROUP", "g")]);
    assert_eq!(error, ConfigError::NoSeeds { value: None });
    assert_mentions(
        &error,
        &[
            "ASPACE_SEEDS",
            "is unset",
            "ASPACE_SEEDS=tls://fleet.example.com:7500",
        ],
    );

    let error = refused(&[("ASPACE_SEEDS", " , ,"), ("ASPACE_GROUP", "g")]);
    assert_eq!(
        error,
        ConfigError::NoSeeds {
            value: Some(" , ,".into())
        }
    );
    assert_mentions(
        &error,
        &["ASPACE_SEEDS=\" , ,\"", "names no seed", "comma-separated"],
    );
}

#[test]
fn a_seed_that_does_not_parse_is_refused() {
    for (value, entry) in [
        ("localhost:7711,fleet:x", "fleet:x"),
        ("tls://fleet.example.com", "tls://fleet.example.com"),
        ("fleet:70000", "fleet:70000"),
        ("tcp://h:1/path", "tcp://h:1/path"),
    ] {
        let error = refused(&[("ASPACE_SEEDS", value), ("ASPACE_GROUP", "g")]);
        assert!(
            matches!(&error, ConfigError::BadSeed { value: v, entry: e, .. } if v == value && e == entry),
            "{error:?}"
        );
        assert_mentions(
            &error,
            &[
                "ASPACE_SEEDS",
                &format!("{value:?}"),
                &format!("{entry:?}"),
                "scheme://host:port",
            ],
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn no_group_and_both_groups_are_refused() {
    let error = refused(&[("ASPACE_SEEDS", "localhost:7711")]);
    assert_eq!(error, ConfigError::NoGroup);
    assert_mentions(
        &error,
        &[
            "ASPACE_GROUP",
            "ASPACE_JOIN",
            "neither",
            "ASPACE_JOIN=aspace://<group-id>",
        ],
    );

    let join = format!("aspace://{}", group_id());
    let error = refused(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "research-fleet-demo-v1"),
        ("ASPACE_JOIN", &join),
    ]);
    assert_eq!(
        error,
        ConfigError::GroupAndJoin {
            group: "research-fleet-demo-v1".into(),
            join: join.clone()
        }
    );
    assert_mentions(
        &error,
        &[
            "ASPACE_GROUP=\"research-fleet-demo-v1\"",
            &format!("ASPACE_JOIN={join:?}"),
            "unset ASPACE_GROUP",
            "unset ASPACE_JOIN",
        ],
    );
}

#[test]
fn a_join_that_is_not_a_group_id_is_refused() {
    let short = format!(
        "aspace://{}",
        agentspaces::wire::base58::multibase(&[1; 16])
    );
    for join in [
        "aspace://",
        "aspace://not-an-id",
        "aspace://zz0OIl",
        "research-fleet",
        short.as_str(),
    ] {
        let error = refused(&[("ASPACE_SEEDS", "localhost:7711"), ("ASPACE_JOIN", join)]);
        assert_eq!(
            error,
            ConfigError::BadJoin {
                value: join.to_owned()
            }
        );
        assert_mentions(
            &error,
            &[
                &format!("ASPACE_JOIN={join:?}"),
                "not a group id",
                "aspace://<group-id>",
            ],
        );
    }
}

#[test]
fn an_unknown_profile_is_refused() {
    let error = refused(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "g"),
        ("ASPACE_PROFILE", "tls"),
    ]);
    assert_eq!(
        error,
        ConfigError::BadProfile {
            value: "tls".into()
        }
    );
    assert_mentions(&error, &["ASPACE_PROFILE=\"tls\"", "mtls", "dev-local"]);
}

#[test]
fn a_plaintext_seed_outside_loopback_needs_dev_local() {
    for seed in [
        "tcp://10.0.0.5:7500",
        "10.0.0.5:7500",
        "TCP://fleet.example.com:7500",
    ] {
        let error = refused(&[("ASPACE_SEEDS", seed), ("ASPACE_GROUP", "g")]);
        let ConfigError::PlaintextSeed {
            seed: refused_seed,
            profile,
        } = &error
        else {
            panic!("{error:?}");
        };
        assert_eq!(*profile, Profile::Mtls);
        assert_eq!(refused_seed.scheme, "tcp");
        assert_mentions(
            &error,
            &[
                "ASPACE_SEEDS",
                &refused_seed.to_string(),
                "not loopback",
                "ASPACE_PROFILE is mtls",
                &format!("tls://{}", refused_seed.address()),
                "ASPACE_PROFILE=dev-local",
            ],
        );

        // Explicitly mtls: refused the same way. Dev-local: allowed.
        let error = refused(&[
            ("ASPACE_SEEDS", seed),
            ("ASPACE_GROUP", "g"),
            ("ASPACE_PROFILE", "mtls"),
        ]);
        assert!(
            matches!(error, ConfigError::PlaintextSeed { .. }),
            "{error:?}"
        );
        let settings = PeerSettings::from_vars(vars(&[
            ("ASPACE_SEEDS", seed),
            ("ASPACE_GROUP", "g"),
            ("ASPACE_PROFILE", "dev-local"),
        ]))
        .expect("dev-local allows plaintext");
        assert_eq!(settings.profile, Profile::DevLocal);
    }

    // The first plaintext seed outside loopback is the one named, wherever it sits.
    let error = refused(&[
        ("ASPACE_SEEDS", "tls://a.example:1,127.0.0.1:2,b.example:3"),
        ("ASPACE_GROUP", "g"),
    ]);
    assert_eq!(
        error,
        ConfigError::PlaintextSeed {
            seed: Seed::new("b.example", 3, "tcp"),
            profile: Profile::Mtls
        }
    );

    // ws and http are plaintext too; tls and other schemes are not judged here.
    for seed in ["ws://h.example:1", "http://h.example:1"] {
        let error = refused(&[("ASPACE_SEEDS", seed), ("ASPACE_GROUP", "g")]);
        assert!(
            matches!(error, ConfigError::PlaintextSeed { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn plaintext_to_loopback_and_tls_anywhere_are_allowed_under_mtls() {
    for seed in [
        "127.0.0.1:7711",
        "tcp://127.8.9.10:7711",
        "localhost:7711",
        "tcp://LOCALHOST:7711",
        "[::1]:7711",
        "tcp://[::ffff:127.0.0.1]:7711",
        "tls://fleet.example.com:7500",
        "tls://10.0.0.5:7500",
    ] {
        let settings =
            PeerSettings::from_vars(vars(&[("ASPACE_SEEDS", seed), ("ASPACE_GROUP", "g")]))
                .unwrap_or_else(|error| panic!("{seed}: {error}"));
        assert_eq!(settings.profile, Profile::Mtls);
    }
}

#[test]
fn loopback_hosts() {
    for host in [
        "localhost",
        "LocalHost",
        "127.0.0.1",
        "127.255.0.1",
        "::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(config::is_loopback_host(host), "{host}");
    }
    for host in [
        "",
        "10.0.0.5",
        "0.0.0.0",
        "::",
        "::ffff:10.0.0.5",
        "localhost.example.com",
        "fleet.example.com",
        "128.0.0.1",
    ] {
        assert!(!config::is_loopback_host(host), "{host}");
    }
    for scheme in ["tcp", "TCP", "ws", "http"] {
        assert!(config::is_plaintext_scheme(scheme), "{scheme}");
    }
    for scheme in ["tls", "wss", "https", "memory"] {
        assert!(!config::is_plaintext_scheme(scheme), "{scheme}");
    }
}

#[test]
fn validate_refuses_settings_built_in_code() {
    let seeds = vec![Seed::new("127.0.0.1", 7711, "tcp")];
    let valid = PeerSettings::new(GroupSpec::FoundingText("g".into()), seeds.clone());
    valid.validate().expect("valid");

    let mut settings = valid.clone();
    settings.seeds.clear();
    let error = settings.validate().expect_err("no seeds");
    assert_eq!(error, ConfigError::NoSeeds { value: None });
    assert_mentions(&error, &["ASPACE_SEEDS", "PeerSettings::seeds"]);

    let settings = PeerSettings::new(GroupSpec::FoundingText(" ".into()), seeds.clone());
    let error = settings.validate().expect_err("blank founding text");
    assert_eq!(error, ConfigError::EmptyFoundingText);
    assert_mentions(
        &error,
        &["ASPACE_GROUP", "PeerSettings::group", "ASPACE_JOIN"],
    );

    let settings = PeerSettings::new(GroupSpec::Join("aspace://".into()), seeds.clone());
    let error = settings.validate().expect_err("join with no id");
    assert_eq!(
        error,
        ConfigError::BadJoin {
            value: "aspace://".into()
        }
    );

    let settings = PeerSettings::new(GroupSpec::FoundingDocument(Vec::new()), seeds.clone());
    let error = settings.validate().expect_err("empty founding document");
    assert_eq!(error, ConfigError::EmptyFoundingDocument);
    assert_mentions(&error, &["PeerSettings::group", "founding document"]);

    let mut settings = valid.clone();
    settings
        .seeds
        .push(Seed::new("fleet.example.com", 7500, "tcp"));
    let error = settings.validate().expect_err("plaintext");
    assert!(
        matches!(error, ConfigError::PlaintextSeed { .. }),
        "{error:?}"
    );
    settings.profile = Profile::DevLocal;
    settings.validate().expect("dev-local");

    let mut settings = valid.clone();
    settings.reconnect_interval = Duration::ZERO;
    let error = settings.validate().expect_err("zero reconnect interval");
    assert_eq!(
        error,
        ConfigError::ZeroInterval {
            field: "reconnect_interval"
        }
    );
    assert_mentions(&error, &["PeerSettings::reconnect_interval", "positive"]);

    let mut settings = valid.clone();
    settings.peer_ad_interval = Duration::ZERO;
    let error = settings.validate().expect_err("zero ad interval");
    assert_eq!(
        error,
        ConfigError::ZeroInterval {
            field: "peer_ad_interval"
        }
    );

    // A zero window is allowed: the peer never redials.
    let mut settings = valid;
    settings.reconnect_window = Duration::ZERO;
    settings.validate().expect("zero window");
}

#[test]
fn the_fleet_yaml_variable_is_not_read_yet() {
    // ASPACE_CONFIG only logs a warning; the variables are the whole configuration.
    let settings = PeerSettings::from_vars(vars(&[
        ("ASPACE_CONFIG", "/etc/agentspaces/fleet.yaml"),
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "g"),
    ]))
    .expect("settings");
    assert_eq!(settings.group, GroupSpec::FoundingText("g".into()));
    assert!(config::VARIABLES.contains(&"ASPACE_CONFIG"));
}

#[test]
fn not_unicode_names_the_variable() {
    let error = ConfigError::NotUnicode {
        variable: "ASPACE_KEYSTORE",
    };
    assert_mentions(&error, &["ASPACE_KEYSTORE", "not UTF-8", "unset it"]);
}

// ---------------------------------------------------------------------------------------------
// The layered configuration over the variables (the fleet file itself: tests/fleet_yaml.rs)

#[test]
fn config_reads_every_variable_as_peer_settings_does_and_the_socket() {
    use agentspaces::config::{Config, Origin, Overrides};
    let pairs = [
        (
            "ASPACE_SEEDS",
            " 127.0.0.1:7711, tls://Fleet.example.com:7500 ,,tcp://[::1]:7712,127.0.0.1:7711 ",
        ),
        ("ASPACE_GROUP", "research-fleet-demo-v1"),
        ("ASPACE_KEYSTORE", " /var/lib/agentspaces/keys "),
        ("ASPACE_PROFILE", " DEV-LOCAL "),
        ("ASPACE_SPACES", "tasks, votes,,tasks , alerts"),
        ("ASPACE_SOCKET", "~/run/aspace.sock"),
        ("HOME", "/nonexistent-home-for-the-test"),
    ];
    let config = Config::from_vars(&Overrides::default(), vars(&pairs)).expect("resolves");
    let settings = PeerSettings::from_vars(vars(&pairs)).expect("settings");
    assert_eq!(config.settings, settings);
    assert_eq!(
        config.socket.as_deref(),
        Some(Path::new("/nonexistent-home-for-the-test/run/aspace.sock"))
    );
    assert_eq!(config.file, None);
    for (field, variable) in [
        ("seeds", "ASPACE_SEEDS"),
        ("group", "ASPACE_GROUP"),
        ("keystore", "ASPACE_KEYSTORE"),
        ("profile", "ASPACE_PROFILE"),
        ("spaces", "ASPACE_SPACES"),
        ("socket", "ASPACE_SOCKET"),
    ] {
        assert_eq!(
            config.origin(field),
            Some(&Origin::Variable(variable)),
            "{field}"
        );
    }
    assert!(config::CONFIG_VARIABLES.contains(&"ASPACE_SOCKET"));
    assert!(config::CONFIG_VARIABLES.contains(&"ASPACE_CONFIG"));
}

#[test]
fn config_refusals_over_the_variables_name_them() {
    use agentspaces::config::{Config, Overrides};
    let refused = |pairs: &[(&str, &str)]| {
        let mut pairs = pairs.to_vec();
        pairs.push(("HOME", "/nonexistent-home-for-the-test"));
        Config::from_vars(&Overrides::default(), vars(&pairs)).expect_err("refused")
    };
    let join = format!("aspace://{}", group_id());
    let error = refused(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "g"),
        ("ASPACE_JOIN", &join),
    ]);
    assert!(
        matches!(error, ConfigError::GroupAndJoin { .. }),
        "{error:?}"
    );
    let error = refused(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_JOIN", "aspace://zz"),
    ]);
    assert_mentions(
        &error,
        &["ASPACE_JOIN", "\"aspace://zz\"", "not a group id"],
    );
    let error = refused(&[("ASPACE_SEEDS", "nope"), ("ASPACE_GROUP", "g")]);
    assert_mentions(&error, &["ASPACE_SEEDS", "\"nope\"", "not a seed"]);
    let error = refused(&[("ASPACE_GROUP", "g")]);
    assert_mentions(&error, &["no seed to dial", "ASPACE_SEEDS"]);
    let error = refused(&[
        ("ASPACE_SEEDS", "localhost:7711"),
        ("ASPACE_GROUP", "g"),
        ("ASPACE_PROFILE", "loose"),
    ]);
    assert_mentions(&error, &["ASPACE_PROFILE", "\"loose\"", "not a profile"]);
    let error = refused(&[("ASPACE_SEEDS", "10.1.2.3:7500"), ("ASPACE_GROUP", "g")]);
    assert_mentions(
        &error,
        &["ASPACE_SEEDS holds tcp://10.1.2.3:7500", "dev-local"],
    );
    let error = refused(&[("ASPACE_SEEDS", "localhost:7711")]);
    assert_mentions(&error, &["no group to join", "ASPACE_JOIN", "ASPACE_GROUP"]);
}
