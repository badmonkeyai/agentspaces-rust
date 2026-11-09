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

//! The file keystore (SPEC §4.1): a peer's Ed25519 identity persisted in a directory every
//! AgentSpaces host shares, so Java, Python, Ruby, and Rust peers started on the same directory are
//! the same peer. A port of `identity.py`'s `Identity.load_or_create`, `agent_keys`, `save_pkcs8`,
//! and `write_key_file`, with Java `FileKeystore`, `KeyFiles`, and `AgentKeystore` as the authority
//! on the layout and Ruby's `load_or_create` for the permission rule.
//!
//! # Layout
//!
//! ```text
//! <dir>/peer.key                          Ed25519 PKCS#8 DER (the 48-byte RFC 8410 form), 0600
//! <dir>/peer.pub                          the raw 32-byte public key, 0644 less the umask
//! <dir>/<peer-id>/<local-name>/agent.key  an agent's own key in the same forms (agent_keys)
//! <dir>/<peer-id>/<local-name>/agent.pub
//! ```
//!
//! # Rules
//!
//! - A missing directory is created owner-only (0700 on Unix), its missing parents too.
//! - Every file is written atomically: a temporary file in the same directory, created with its
//!   final mode (0600 for a private key, so no other local user can ever read it), written,
//!   flushed to disk, and renamed into place.
//! - A half-written pair (one file without the other) is refused with a message naming both
//!   files, never repaired: minting a new key would silently change the PeerID.
//! - First use is one process at a time: a load that does not find both files takes an exclusive
//!   lock (`flock` on the keystore directory itself, Unix; no file is added) and looks again
//!   before it mints, so processes
//!   started together on a fresh directory (a daemon and its first visitor, parallel hooks, CI
//!   steps sharing a keystore) all load the one identity the first of them minted. A minted file
//!   is published without replacing anything (a hard link of the finished temporary file, which
//!   fails when the name exists), so even a writer that takes no lock never has its key
//!   overwritten; a pair another such writer is still writing is given 2 s to complete before it
//!   is refused as half written.
//! - A public key file that is not 32 bytes, or not the public key of the private key file, is
//!   refused, as is a private key file that is not the 48-byte PKCS#8 form.
//! - On Unix, a private key readable by its group or by others (any group or other bit of its
//!   mode) is refused unless the caller allows it ([`KeystoreOptions::allow_readable`]), as the
//!   Ruby peer does: `aspace --allow-readable-key`, or [`ENV_ALLOW_READABLE_KEY`] set to a true
//!   value ([`KeystoreOptions::from_vars`]). The refusal names the file, its mode, and the
//!   `chmod 600` that fixes it.
//! - Peer ids and agent names that could escape the directory are refused, never sanitized.
//!
//! Key bytes are never printed: errors name files, modes, and lengths only.
#![warn(missing_docs)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agentspaces_wire::crypto::{self, CryptoError, KEY_LENGTH};
use agentspaces_wire::identity::Identity;
use zeroize::Zeroizing;

/// The private key file of a peer keystore.
pub const PRIVATE_FILE: &str = "peer.key";
/// The public key file of a peer keystore.
pub const PUBLIC_FILE: &str = "peer.pub";
/// The private key file of an agent's key directory ([`agent_keys`]).
pub const AGENT_PRIVATE_FILE: &str = "agent.key";
/// The public key file of an agent's key directory ([`agent_keys`]).
pub const AGENT_PUBLIC_FILE: &str = "agent.pub";
/// The longest name [`is_safe_name`] accepts.
pub const MAX_NAME_LENGTH: usize = 64;
/// How long a load waits for another process minting the same keystore before it gives up.
const MINT_WAIT: Duration = Duration::from_secs(5);
/// How long a half pair is given to complete: a writer that takes no lock (another
/// implementation) may be between its two files.
const HALF_PAIR_WAIT: Duration = Duration::from_secs(2);
/// How often a waiting load looks again.
const POLL: Duration = Duration::from_millis(10);

/// The most bytes read from a key file. Both files are far smaller (48 and 32 bytes); the bound
/// keeps a mistaken path (a log, a device) from being read whole.
const MAX_KEY_FILE_BYTES: usize = 4096;

/// How many temporary names are tried before a write gives up (a collision needs another writer
/// with the same process id drawing the same 32 random bits).
const TEMP_ATTEMPTS: usize = 8;

/// Why a keystore could not be loaded or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeystoreError {
    /// A file-system operation failed.
    #[error("keystore i/o failure: cannot {action} {}: {source}", path.display())]
    Io {
        /// What was being done ("create the directory", "read", "rename into place", ...).
        action: &'static str,
        /// The file or directory.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// One file of a pair exists without the other.
    #[error(
        "incomplete keystore: {} exists but {} does not; restore the missing file from backup, \
         or remove both to mint a new identity (which changes the PeerID or agent key)",
        present.display(),
        missing.display()
    )]
    HalfPair {
        /// The file that exists.
        present: PathBuf,
        /// The file that does not.
        missing: PathBuf,
    },
    /// The private key file is not the 48-byte RFC 8410 PKCS#8 form of an Ed25519 key.
    #[error(
        "corrupt keystore: {} is not an Ed25519 private key in the 48-byte PKCS#8 form \
         ({length} bytes read); restore it from backup, or remove {} and {} to mint a new \
         identity",
        path.display(),
        path.display(),
        public.display()
    )]
    MalformedPrivateKey {
        /// The private key file.
        path: PathBuf,
        /// The public key file of the same pair.
        public: PathBuf,
        /// How many bytes were read (at most 4096).
        length: usize,
        /// Why the bytes were refused.
        #[source]
        source: CryptoError,
    },
    /// The public key file is not 32 bytes.
    #[error(
        "corrupt keystore: {} is not a raw Ed25519 public key ({length} bytes, expected 32); \
         restore it from backup",
        path.display()
    )]
    MalformedPublicKey {
        /// The public key file.
        path: PathBuf,
        /// How many bytes were read (at most 4096).
        length: usize,
    },
    /// The public key file does not hold the public key of the private key file.
    #[error(
        "corrupt keystore: {} does not belong to the public key in {}; restore the matching \
         pair from backup, or remove both to mint a new identity (which changes the PeerID or \
         agent key)",
        private.display(),
        public.display()
    )]
    Mismatch {
        /// The private key file.
        private: PathBuf,
        /// The public key file.
        public: PathBuf,
    },
    /// A key path names something other than a regular file (a directory, a device, a pipe).
    #[error("corrupt keystore: {} is not a regular file", path.display())]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
    /// The private key file grants its group or others any access (`mode & 0o077` is not zero;
    /// Unix only).
    #[error(
        "{} is readable by group or others (mode {mode:03o}, any group or other bit counts); \
         run `chmod 600 {}`, or accept a readable key explicitly (aspace \
         --allow-readable-key, ASPACE_ALLOW_READABLE_KEY=1, or KeystoreOptions::allow_readable)",
        path.display(),
        path.display()
    )]
    Readable {
        /// The private key file.
        path: PathBuf,
        /// Its permission bits (`mode & 0o777`).
        mode: u32,
    },
    /// A peer id or agent name could escape the keystore directory or is not a plain token.
    #[error(
        "{what} {name:?} is not a safe file name: use 1 to 64 letters, digits, '.', '_' or '-', \
         and not '.' or '..'"
    )]
    UnsafeName {
        /// "peer id" or "agent name".
        what: &'static str,
        /// The name as given.
        name: String,
    },
    /// The random source failed while minting a key or naming a temporary file.
    #[error("keystore: {0}")]
    Random(#[source] CryptoError),
    /// Another process held the keystore directory's lock (`flock`) for longer than a mint
    /// takes.
    #[error(
        "another process has held the lock of the keystore {} for more than 5 s while minting \
         its identity; stop it, and run the command again",
        path.display()
    )]
    Locked {
        /// The keystore directory.
        path: PathBuf,
    },
    /// A variable of the keystore's options ([`ENV_ALLOW_READABLE_KEY`]) is not a boolean.
    #[error(
        "{name}={value:?} is not a boolean; write 1, true, yes, or on to accept a readable \
         private key, or 0, false, no, off (or leave it unset) to refuse one"
    )]
    InvalidVariable {
        /// The variable.
        name: &'static str,
        /// Its value as set.
        value: String,
    },
}

impl KeystoreError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// The variable that accepts a private key readable by its group or others, as `aspace
/// --allow-readable-key` does ([`KeystoreOptions::from_vars`]).
pub const ENV_ALLOW_READABLE_KEY: &str = "ASPACE_ALLOW_READABLE_KEY";

/// How a keystore is loaded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeystoreOptions {
    /// Accept a private key file its group or others may read (Unix). Off by default: such a key
    /// is refused with [`KeystoreError::Readable`]. Turn it on only where something else guards
    /// the file (a single-user container volume, an ACL-managed mount).
    pub allow_readable: bool,
}

impl KeystoreOptions {
    /// The options the variables give, read through `lookup`: [`ENV_ALLOW_READABLE_KEY`] set to
    /// `1`, `true`, `yes`, or `on` (any letter case) accepts a readable key; `0`, `false`, `no`,
    /// or `off` refuses one, as an unset variable or one set to the empty string (or spaces
    /// only) does. Any other value is refused ([`KeystoreError::InvalidVariable`]) rather than
    /// guessed at.
    pub fn from_vars(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<KeystoreOptions, KeystoreError> {
        let allow_readable = match lookup(ENV_ALLOW_READABLE_KEY) {
            None => false,
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "" | "0" | "false" | "no" | "off" => false,
                "1" | "true" | "yes" | "on" => true,
                _ => {
                    return Err(KeystoreError::InvalidVariable {
                        name: ENV_ALLOW_READABLE_KEY,
                        value,
                    });
                }
            },
        };
        Ok(KeystoreOptions { allow_readable })
    }

    /// [`KeystoreOptions::from_vars`] over the process environment.
    pub fn from_env() -> Result<KeystoreOptions, KeystoreError> {
        KeystoreOptions::from_vars(|name| std::env::var(name).ok())
    }

    /// These options, accepting a readable key also when `allow` is set: a command-line flag
    /// over the variable, which can only widen what the variable allows.
    pub fn allowing_readable(self, allow: bool) -> KeystoreOptions {
        KeystoreOptions {
            allow_readable: self.allow_readable || allow,
        }
    }
}

/// `FileKeystore.loadOrCreate`: the identity in `dir` (`peer.key` and `peer.pub`), or a fresh one
/// minted and persisted there when the directory holds neither file. The directory is created
/// (0700) when missing. Refuses a half-written pair, a malformed or mismatched pair, and a
/// private key readable by group or others; see the [module rules](self).
pub fn load_or_create(dir: &Path) -> Result<Identity, KeystoreError> {
    load_or_create_with(dir, KeystoreOptions::default())
}

/// [`load_or_create`] with options: `allow_readable` accepts a group- or world-readable key.
pub fn load_or_create_with(
    dir: &Path,
    options: KeystoreOptions,
) -> Result<Identity, KeystoreError> {
    load_or_create_pair(dir, PRIVATE_FILE, PUBLIC_FILE, options)
}

/// `AgentKeystore.signingKeys` (Python `Identity.agent_keys`): an agent's own Ed25519 key at
/// `<dir>/<peer_id>/<local_name>/agent.key` and `agent.pub`, loaded or minted and persisted under
/// the same rules as a peer keystore. `peer_id` and `local_name` must each pass
/// [`is_safe_name`]; a name that could escape `dir` is refused ([`KeystoreError::UnsafeName`]),
/// never sanitized. The peer level keeps two peers sharing a directory from loading each other's
/// agent keys. Certificates are not stored: the peer re-issues them at start.
pub fn agent_keys(dir: &Path, peer_id: &str, local_name: &str) -> Result<Identity, KeystoreError> {
    agent_keys_with(dir, peer_id, local_name, KeystoreOptions::default())
}

/// [`agent_keys`] with options.
pub fn agent_keys_with(
    dir: &Path,
    peer_id: &str,
    local_name: &str,
    options: KeystoreOptions,
) -> Result<Identity, KeystoreError> {
    let agent_dir = agent_dir(dir, peer_id, local_name)?;
    load_or_create_pair(&agent_dir, AGENT_PRIVATE_FILE, AGENT_PUBLIC_FILE, options)
}

/// The directory [`agent_keys`] keeps an agent's key pair in, `<dir>/<peer_id>/<local_name>`,
/// after checking both names with [`is_safe_name`] (the peer id first). Touches no file.
pub fn agent_dir(dir: &Path, peer_id: &str, local_name: &str) -> Result<PathBuf, KeystoreError> {
    for (name, what) in [(peer_id, "peer id"), (local_name, "agent name")] {
        if !is_safe_name(name) {
            return Err(KeystoreError::UnsafeName {
                what,
                name: name.to_owned(),
            });
        }
    }
    Ok(dir.join(peer_id).join(local_name))
}

/// The safe-name rule of Java `KeyFiles.safeName` and Python `_SAFE_NAME`: 1 to 64 ASCII
/// letters, digits, `.`, `_`, or `-`, and neither `.` nor `..`. Such a name is one plain path
/// component on every file system the keystore runs on.
pub fn is_safe_name(name: &str) -> bool {
    (1..=MAX_NAME_LENGTH).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "."
        && name != ".."
}

/// Python `Identity.save_pkcs8`: writes `identity`'s private key as 48-byte PKCS#8 DER to `path`
/// through [`write_key_file`] as a secret (0600).
pub fn save_pkcs8(identity: &Identity, path: &Path) -> Result<(), KeystoreError> {
    write_key_file(path, &identity.pkcs8(), true)
}

/// `KeyFiles.write` (Python `write_key_file`): replaces `path` atomically with `data`. The bytes
/// go to a new temporary file in the same directory (created exclusively, 0600 from creation for
/// a `secret`, 0644 less the umask otherwise), are flushed to disk, and the file is renamed over
/// `path`; a failure removes the temporary file. The directory is created (0700) when missing.
pub fn write_key_file(path: &Path, data: &[u8], secret: bool) -> Result<(), KeystoreError> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    create_dir(directory)?;
    let (temp, mut file) = create_temp(directory, secret)?;
    let guard = TempGuard(Some(temp));
    let temp = guard.path();
    file.write_all(data)
        .map_err(|e| KeystoreError::io("write", temp, e))?;
    file.sync_all()
        .map_err(|e| KeystoreError::io("flush to disk", temp, e))?;
    drop(file);
    fs::rename(temp, path).map_err(|e| KeystoreError::io("rename into place", path, e))?;
    guard.disarm();
    sync_dir(directory);
    Ok(())
}

/// Publishes `data` at `path` only when nothing is there: written to a new temporary file in the
/// same directory as [`write_key_file`] writes it (created exclusively with its final mode, flushed
/// to disk), then hard-linked to `path`, which fails when `path` exists. Answers whether this
/// call placed the file (`false`: another writer's file was there first, and stays). On a file
/// system without hard links, the temporary file is renamed into place when `path` is still
/// free.
fn publish_key_file(path: &Path, data: &[u8], secret: bool) -> Result<bool, KeystoreError> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let (temp, mut file) = create_temp(directory, secret)?;
    let guard = TempGuard(Some(temp));
    let temp = guard.path();
    file.write_all(data)
        .map_err(|e| KeystoreError::io("write", temp, e))?;
    file.sync_all()
        .map_err(|e| KeystoreError::io("flush to disk", temp, e))?;
    drop(file);
    let placed = match fs::hard_link(temp, path) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(_) if exists(path)? => false,
        Err(_) => {
            fs::rename(temp, path).map_err(|e| KeystoreError::io("rename into place", path, e))?;
            guard.disarm();
            sync_dir(directory);
            return Ok(true);
        }
    };
    // The temporary name goes either way (the guard removes it); the placed file keeps its link.
    drop(guard);
    sync_dir(directory);
    Ok(placed)
}

// ---------------------------------------------------------------------------------------------

fn load_or_create_pair(
    dir: &Path,
    private_name: &str,
    public_name: &str,
    options: KeystoreOptions,
) -> Result<Identity, KeystoreError> {
    create_dir(dir)?;
    let private_path = dir.join(private_name);
    let public_path = dir.join(public_name);
    // The common case, a keystore in use: both files there, no lock needed.
    if exists(&private_path)? && exists(&public_path)? {
        return load_pair(&private_path, &public_path, options);
    }
    // First use, or a pair being written: one process at a time from here, and every one looks
    // again once it holds the lock, so only the first mints.
    let _lock = MintLock::take(dir)?;
    let mut waited = false;
    loop {
        match (exists(&private_path)?, exists(&public_path)?) {
            (true, true) => return load_pair(&private_path, &public_path, options),
            (false, false) => return mint(&private_path, &public_path, options),
            (private, _) if waited => {
                let (present, missing) = if private {
                    (private_path, public_path)
                } else {
                    (public_path, private_path)
                };
                return Err(KeystoreError::HalfPair { present, missing });
            }
            _ => {
                // Another implementation's writer takes no lock and may be between its files.
                wait_for_pair(&private_path, &public_path)?;
                waited = true;
            }
        }
    }
}

/// Mints an identity into a keystore that holds neither file, under its lock. Each file is
/// published without replacing one already there ([`publish_key_file`]): a pair another writer
/// put in place first is the keystore's identity, and is loaded instead.
fn mint(
    private_path: &Path,
    public_path: &Path,
    options: KeystoreOptions,
) -> Result<Identity, KeystoreError> {
    let identity = Identity::generate().map_err(KeystoreError::Random)?;
    // Private first, as Java and Python write: a crash between the two leaves a half pair,
    // which the next load refuses rather than replaces.
    if !publish_key_file(private_path, &identity.pkcs8(), true)? {
        wait_for_pair(private_path, public_path)?;
        return load_pair(private_path, public_path, options);
    }
    if !publish_key_file(public_path, identity.public_raw(), false)? {
        // Someone else's public key next to this private key: the load says whether they match.
        return load_pair(private_path, public_path, options);
    }
    Ok(identity)
}

/// Waits up to [`HALF_PAIR_WAIT`] for both files of a pair to exist.
fn wait_for_pair(private_path: &Path, public_path: &Path) -> Result<(), KeystoreError> {
    let deadline = Instant::now() + HALF_PAIR_WAIT;
    while Instant::now() < deadline {
        if exists(private_path)? && exists(public_path)? {
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}

/// The exclusive lock of a keystore's first use: the keystore directory itself, opened and
/// `flock`ed (Unix), released when dropped; nothing is added to the directory. Where the
/// directory cannot be opened or locked (a file system without locks) there is no lock, and
/// [`publish_key_file`] alone keeps a key from being replaced.
struct MintLock {
    #[cfg(unix)]
    _file: Option<File>,
}

impl MintLock {
    #[cfg(unix)]
    fn take(dir: &Path) -> Result<MintLock, KeystoreError> {
        use rustix::fs::{FlockOperation, flock};
        let Ok(file) = File::open(dir) else {
            return Ok(MintLock { _file: None });
        };
        let deadline = Instant::now() + MINT_WAIT;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(MintLock { _file: Some(file) }),
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK
                        || error == rustix::io::Errno::AGAIN =>
                {
                    if Instant::now() >= deadline {
                        return Err(KeystoreError::Locked {
                            path: dir.to_path_buf(),
                        });
                    }
                    std::thread::sleep(POLL);
                }
                Err(error) if error == rustix::io::Errno::INTR => {}
                // A file system without locks: the publish rule still holds.
                Err(_) => return Ok(MintLock { _file: None }),
            }
        }
    }

    #[cfg(not(unix))]
    fn take(_dir: &Path) -> Result<MintLock, KeystoreError> {
        Ok(MintLock {})
    }
}

fn load_pair(
    private_path: &Path,
    public_path: &Path,
    options: KeystoreOptions,
) -> Result<Identity, KeystoreError> {
    let private = read_key_file(private_path, Some(options))?;
    let identity =
        Identity::from_pkcs8(&private).map_err(|source| KeystoreError::MalformedPrivateKey {
            path: private_path.to_path_buf(),
            public: public_path.to_path_buf(),
            length: private.len(),
            source,
        })?;
    let public = read_key_file(public_path, None)?;
    if public.len() != KEY_LENGTH {
        return Err(KeystoreError::MalformedPublicKey {
            path: public_path.to_path_buf(),
            length: public.len(),
        });
    }
    // The key derived from the private seed must be the stored one byte for byte: this implies
    // the sign-and-verify probe of the Java and Python keystores.
    if public.as_slice() != identity.public_raw().as_slice() {
        return Err(KeystoreError::Mismatch {
            private: private_path.to_path_buf(),
            public: public_path.to_path_buf(),
        });
    }
    Ok(identity)
}

/// Reads at most [`MAX_KEY_FILE_BYTES`] of a key file into a buffer wiped on drop. The checks run
/// on the opened file, so the file judged is the file read. `private` carries the options of a
/// private key, whose permissions are judged; `None` reads a public key.
fn read_key_file(
    path: &Path,
    private: Option<KeystoreOptions>,
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let file = File::open(path).map_err(|e| KeystoreError::io("open", path, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| KeystoreError::io("inspect", path, e))?;
    if !metadata.is_file() {
        return Err(KeystoreError::NotAFile {
            path: path.to_path_buf(),
        });
    }
    if let Some(options) = private {
        check_private_mode(path, &metadata, options)?;
    }
    // Room for the whole bound and one more byte up front, so the buffer never grows (a growing
    // buffer would leave an unwiped copy of the key behind).
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES + 1));
    file.take(MAX_KEY_FILE_BYTES as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| KeystoreError::io("read", path, e))?;
    Ok(bytes)
}

#[cfg(unix)]
fn check_private_mode(
    path: &Path,
    metadata: &fs::Metadata,
    options: KeystoreOptions,
) -> Result<(), KeystoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 && !options.allow_readable {
        return Err(KeystoreError::Readable {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _options: KeystoreOptions,
) -> Result<(), KeystoreError> {
    // No POSIX permission bits: access is the operating system's ACLs, as Java's KeyFiles notes.
    Ok(())
}

fn exists(path: &Path) -> Result<bool, KeystoreError> {
    path.try_exists()
        .map_err(|e| KeystoreError::io("check for", path, e))
}

/// Creates `dir` and its missing parents, owner-only (0700) on Unix. An existing directory is
/// left as it is.
fn create_dir(dir: &Path) -> Result<(), KeystoreError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| KeystoreError::io("create the directory", dir, e))
}

/// A new temporary file in `directory`, created exclusively with its final mode, named
/// `.key-<pid>-<hex>.tmp` (a secret) or `.pub-<pid>-<hex>.tmp`.
fn create_temp(directory: &Path, secret: bool) -> Result<(PathBuf, File), KeystoreError> {
    let stem = if secret { "key" } else { "pub" };
    let mut last_error = None;
    for _ in 0..TEMP_ATTEMPTS {
        let mut suffix = [0u8; 4];
        crypto::port()
            .fill_random(&mut suffix)
            .map_err(KeystoreError::Random)?;
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let temp = directory.join(format!(".{stem}-{}-{hex}.tmp", std::process::id()));
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(if secret { 0o600 } else { 0o644 });
        }
        match open.open(&temp) {
            Ok(file) => {
                let guard = TempGuard(Some(temp));
                if secret {
                    set_owner_only(&file, guard.path())?;
                }
                return Ok((guard.disarm(), file));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_error = Some(e),
            Err(e) => {
                return Err(KeystoreError::io(
                    "create a temporary file in",
                    directory,
                    e,
                ));
            }
        }
    }
    Err(KeystoreError::io(
        "create a temporary file in",
        directory,
        last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
    ))
}

/// Sets a secret file to exactly 0600 through its handle: the umask can only have narrowed the
/// creation mode, but a narrower one could leave the owner unable to read the key back.
#[cfg(unix)]
fn set_owner_only(file: &File, path: &Path) -> Result<(), KeystoreError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| KeystoreError::io("restrict to its owner", path, e))
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File, _path: &Path) -> Result<(), KeystoreError> {
    Ok(())
}

/// Flushes a directory's entries after a rename, where the platform allows it. Best effort: the
/// file itself is already on disk, and not every platform can sync a directory.
fn sync_dir(directory: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = File::open(directory) {
        // A failure leaves the rename to the file system's next commit; nothing else to do.
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = directory;
}

/// Removes a temporary file on drop unless disarmed.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or_else(|| Path::new(""))
    }

    fn disarm(mut self) -> PathBuf {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            // Nothing more can be done about a temporary file that will not go away.
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh scratch directory of this test process.
    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "asrs-keystore-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Processes (here threads, each with its own open of the lock file) started together on a
    /// fresh keystore all load one identity, none fails, and the pair left behind is that
    /// identity's. Repeated, so an unserialized check-then-mint shows within a run.
    #[test]
    fn concurrent_first_use_mints_one_identity() {
        use std::sync::{Arc, Barrier};
        const THREADS: usize = 12;
        for round in 0..25 {
            let dir = scratch("race");
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (dir, barrier) = (dir.clone(), Arc::clone(&barrier));
                    std::thread::spawn(move || {
                        barrier.wait();
                        load_or_create(&dir).map(|identity| identity.peer_id().to_owned())
                    })
                })
                .collect();
            let ids: Vec<String> = handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(Ok(id)) => id,
                    Ok(Err(error)) => panic!("round {round}: a load failed: {error}"),
                    Err(_) => panic!("round {round}: a loader panicked"),
                })
                .collect();
            assert!(
                ids.iter().all(|id| *id == ids[0]),
                "round {round}: several identities were minted: {ids:?}"
            );
            let reloaded = load_or_create(&dir).expect("the pair left behind loads");
            assert_eq!(reloaded.peer_id(), ids[0], "round {round}");
            let leftovers: Vec<String> = fs::read_dir(&dir)
                .expect("dir")
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".tmp"))
                .collect();
            assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// A file already at a key path is never replaced by a publish, and a half pair a writer
    /// that takes no lock leaves is refused once its grace has passed.
    #[test]
    fn a_publish_never_replaces_and_a_half_pair_is_refused() {
        let dir = scratch("publish");
        create_dir(&dir).expect("dir");
        let path = dir.join("peer.pub");
        assert!(publish_key_file(&path, b"first", false).expect("placed"));
        assert!(!publish_key_file(&path, b"second", false).expect("not placed"));
        assert_eq!(fs::read(&path).expect("read"), b"first");
        let half = scratch("half");
        let identity = Identity::generate().expect("identity");
        create_dir(&half).expect("dir");
        write_key_file(&half.join(PRIVATE_FILE), &identity.pkcs8(), true).expect("private");
        let started = Instant::now();
        match load_or_create(&half) {
            Err(KeystoreError::HalfPair { present, missing }) => {
                assert_eq!(present, half.join(PRIVATE_FILE));
                assert_eq!(missing, half.join(PUBLIC_FILE));
            }
            other => panic!("a half pair loads as {other:?}"),
        }
        assert!(started.elapsed() >= HALF_PAIR_WAIT, "the grace was given");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&half);
    }

    #[test]
    fn safe_names() {
        let longest = "x".repeat(MAX_NAME_LENGTH);
        for good in ["a", "agent-1", "A.b_c", longest.as_str(), "...", ".hidden"] {
            assert!(is_safe_name(good), "{good}");
        }
        let too_long = "x".repeat(MAX_NAME_LENGTH + 1);
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "é",
            "a b",
            too_long.as_str(),
            "a\0",
        ] {
            assert!(!is_safe_name(bad), "{bad:?}");
        }
    }
}
