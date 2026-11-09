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

//! Where the daemon's socket lives, and the owner-only rules of its directory, socket, and lock
//! file.
//!
//! The socket is `--socket`, else `ASPACE_SOCKET`, else `daemon.sock` in a directory of this
//! user's: `$XDG_RUNTIME_DIR/aspace` when the runtime directory is set (systemd makes it 0700 and
//! the user's), else `${TMPDIR:-/tmp}/aspace-<uid>` (on macOS `$TMPDIR` is already per user).
//! The daemon creates a missing directory 0700, the socket 0600, and its lock file
//! (`<socket>.lock`, holding its pid) 0600. Both sides refuse a directory owned by another user
//! or writable by its group or others, since whoever can write it could put a socket of theirs
//! in the daemon's place; a visitor also refuses a socket file another user owns. Those
//! refusals exit 4, as a readable private key does; a path that is not a socket exits 2.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

use crate::exit::Failure;

/// The socket's file name in the default directory.
pub const SOCKET_FILE: &str = "daemon.sock";

/// The runtime directory variable (XDG).
pub const ENV_XDG_RUNTIME_DIR: &str = "XDG_RUNTIME_DIR";

/// The temporary directory variable, per user on macOS.
pub const ENV_TMPDIR: &str = "TMPDIR";

/// The longest socket path a Unix domain socket takes (`sun_path` is 104 bytes on macOS and the
/// BSDs and 108 on Linux, its last byte the terminator): the smaller of the two, so a path that
/// works on one works on both.
pub const MAX_SOCKET_PATH: usize = 103;

/// This process's user id.
pub fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// The socket a configuration names (`--socket`, `ASPACE_SOCKET`), made absolute, else the
/// default of `lookup`'s environment for user `uid` ([`default_socket`]).
pub fn socket_path(
    configured: Option<&Path>,
    lookup: impl Fn(&str) -> Option<String>,
    uid: u32,
) -> Result<PathBuf, Failure> {
    let path = match configured {
        Some(path) => path.to_path_buf(),
        None => default_socket(lookup, uid),
    };
    let path = std::path::absolute(&path).map_err(|error| {
        Failure::refused(format!("cannot make {} absolute: {error}", path.display()))
    })?;
    if path.file_name().is_none() {
        return Err(Failure::refused(format!(
            "{} names no socket file; pass --socket <dir>/<name>",
            path.display()
        )));
    }
    Ok(path)
}

/// The default socket: `$XDG_RUNTIME_DIR/aspace/daemon.sock` when the runtime directory is set
/// (and absolute), else `${TMPDIR:-/tmp}/aspace-<uid>/daemon.sock`.
pub fn default_socket(lookup: impl Fn(&str) -> Option<String>, uid: u32) -> PathBuf {
    let absolute = |name: &str| {
        lookup(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && Path::new(value).is_absolute())
            .map(PathBuf::from)
    };
    if let Some(runtime) = absolute(ENV_XDG_RUNTIME_DIR) {
        return runtime.join("aspace").join(SOCKET_FILE);
    }
    let base = absolute(ENV_TMPDIR).unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(format!("aspace-{uid}")).join(SOCKET_FILE)
}

/// The lock file of a socket: `<socket>.lock`.
pub fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// The directory a socket lives in.
pub fn socket_dir(socket: &Path) -> &Path {
    match socket.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Refuses a socket path too long for a Unix domain socket.
pub fn check_length(socket: &Path) -> Result<(), Failure> {
    let length = socket.as_os_str().len();
    if length > MAX_SOCKET_PATH {
        return Err(Failure::refused(format!(
            "the socket path {} is {length} bytes, longer than a Unix domain socket takes \
             ({MAX_SOCKET_PATH}); pass a shorter --socket or ASPACE_SOCKET",
            socket.display()
        )));
    }
    Ok(())
}

/// Whether a directory's owner and mode may hold this user's socket: owned by `uid`, and not
/// writable by its group or others.
pub fn judge_dir(dir: &Path, owner: u32, mode: u32, uid: u32) -> Result<(), Failure> {
    if owner != uid {
        return Err(Failure::auth(format!(
            "{} is owned by uid {owner}, not by this user (uid {uid}); another user could put a \
             socket of theirs there: remove it, or pass --socket in a directory of yours",
            dir.display()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Failure::auth(format!(
            "{} is writable by its group or others (mode {:03o}); another user could put a \
             socket of theirs there: run `chmod 700 {}`, or pass --socket in a directory of \
             yours",
            dir.display(),
            mode & 0o777,
            dir.display()
        )));
    }
    Ok(())
}

/// Checks the directory of `socket` as it is ([`judge_dir`]); `Ok(false)` when it does not exist.
pub fn check_dir(socket: &Path, uid: u32) -> Result<bool, Failure> {
    use std::os::unix::fs::MetadataExt as _;
    let dir = socket_dir(socket);
    match fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {
            judge_dir(dir, metadata.uid(), metadata.mode(), uid).map(|()| true)
        }
        Ok(_) => Err(Failure::refused(format!(
            "{} is not a directory",
            dir.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Failure::error(format!(
            "cannot inspect {}: {error}",
            dir.display()
        ))),
    }
}

/// Creates the directory of `socket` (and its missing parents) owner-only, 0700, and checks it
/// ([`judge_dir`]). An existing directory keeps its mode, and must pass as it is.
pub fn ensure_dir(socket: &Path, uid: u32) -> Result<(), Failure> {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = socket_dir(socket);
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(dir)
        .map_err(|error| Failure::error(format!("cannot create {}: {error}", dir.display())))?;
    if check_dir(socket, uid)? {
        Ok(())
    } else {
        Err(Failure::error(format!(
            "{} vanished after it was created",
            dir.display()
        )))
    }
}

/// What is at a socket path before a daemon binds it, or a visitor connects to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtPath {
    /// Nothing.
    Nothing,
    /// A socket this user owns.
    OwnSocket,
}

/// Judges what is at `socket` without following a link: nothing, or a socket `uid` owns; any
/// other file, or another user's socket, is refused.
pub fn check_socket_file(socket: &Path, uid: u32) -> Result<AtPath, Failure> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    match fs::symlink_metadata(socket) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(Failure::refused(format!(
                    "{} exists and is not a socket; remove it, or pass another --socket",
                    socket.display()
                )));
            }
            if metadata.uid() != uid {
                return Err(Failure::auth(format!(
                    "{} is a socket of uid {}, not of this user (uid {uid})",
                    socket.display(),
                    metadata.uid()
                )));
            }
            Ok(AtPath::OwnSocket)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AtPath::Nothing),
        Err(error) => Err(Failure::error(format!(
            "cannot inspect {}: {error}",
            socket.display()
        ))),
    }
}

/// Sets the socket's mode to 0600.
pub fn restrict_socket(socket: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|error| {
        Failure::error(format!(
            "cannot restrict {} to its owner: {error}",
            socket.display()
        ))
    })
}

/// The identity of a file (device and inode), so a daemon removes only the socket it bound.
pub fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// The daemon's lock: `<socket>.lock`, 0600, exclusively locked (`flock`) for the daemon's life
/// and holding its pid. The file stays when the daemon stops (removing a locked file races
/// with the next daemon's open); the lock goes with the process.
#[derive(Debug)]
pub struct Lock {
    _file: File,
}

/// Why the lock was not taken.
#[derive(Debug)]
pub enum LockError {
    /// Another process holds it; its pid when the file names one.
    Held(Option<u32>),
    /// The file could not be opened, locked, or written.
    Failed(String),
}

impl Lock {
    /// Takes the lock of `socket`, without waiting.
    pub fn take(socket: &Path) -> Result<Lock, LockError> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let path = lock_path(socket);
        let failed = |what: &str, error: std::io::Error| {
            LockError::Failed(format!("cannot {what} {}: {error}", path.display()))
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|error| failed("open", error))?;
        if let Err(error) = flock(&file, FlockOperation::NonBlockingLockExclusive) {
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
                return Err(LockError::Held(read_pid(&mut file)));
            }
            return Err(failed("lock", error.into()));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| failed("restrict", error))?;
        file.set_len(0).map_err(|error| failed("truncate", error))?;
        file.rewind().map_err(|error| failed("rewind", error))?;
        writeln!(file, "{}", std::process::id())
            .and_then(|()| file.flush())
            .map_err(|error| failed("write", error))?;
        Ok(Lock { _file: file })
    }
}

/// The pid a lock file names.
fn read_pid(file: &mut File) -> Option<u32> {
    let mut text = String::new();
    file.rewind().ok()?;
    file.take(64).read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let path =
                std::env::temp_dir().join(format!("aspace-paths-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("scratch");
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_default_socket_is_in_the_runtime_dir_else_a_per_user_temporary_dir() {
        assert_eq!(
            default_socket(
                vars(&[("XDG_RUNTIME_DIR", "/run/user/501"), ("TMPDIR", "/t")]),
                501
            ),
            PathBuf::from("/run/user/501/aspace/daemon.sock")
        );
        assert_eq!(
            default_socket(vars(&[("TMPDIR", "/var/folders/x/T/")]), 501),
            PathBuf::from("/var/folders/x/T/aspace-501/daemon.sock")
        );
        // Empty or relative values count as unset.
        assert_eq!(
            default_socket(vars(&[("XDG_RUNTIME_DIR", " "), ("TMPDIR", "rel")]), 7),
            PathBuf::from("/tmp/aspace-7/daemon.sock")
        );
        let configured = socket_path(Some(Path::new("/x/d.sock")), vars(&[]), 1).expect("path");
        assert_eq!(configured, PathBuf::from("/x/d.sock"));
        let relative = socket_path(Some(Path::new("d.sock")), vars(&[]), 1).expect("path");
        assert!(relative.is_absolute(), "{}", relative.display());
        assert_eq!(
            lock_path(Path::new("/r/daemon.sock")),
            PathBuf::from("/r/daemon.sock.lock")
        );
    }

    #[test]
    fn directories_of_another_user_or_writable_by_others_are_refused() {
        assert!(judge_dir(Path::new("/d"), 501, 0o40700, 501).is_ok());
        assert!(judge_dir(Path::new("/d"), 501, 0o755, 501).is_ok());
        let other = judge_dir(Path::new("/d"), 0, 0o700, 501).expect_err("another owner");
        assert_eq!(other.code, crate::exit::AUTH);
        assert!(other.message.contains("owned by uid 0"), "{other}");
        for mode in [0o777, 0o770, 0o702, 0o1777] {
            let writable = judge_dir(Path::new("/d"), 501, mode, 501).expect_err("writable");
            assert_eq!(writable.code, crate::exit::AUTH);
            assert!(writable.message.contains("chmod 700 /d"), "{writable}");
        }
    }

    #[test]
    fn the_directory_is_created_owner_only_and_long_paths_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("dir");
        let uid = own_uid();
        let socket = scratch.0.join("a/b/daemon.sock");
        assert_eq!(check_dir(&socket, uid), Ok(false));
        ensure_dir(&socket, uid).expect("created");
        let mode = |path: &Path| fs::metadata(path).expect("dir").permissions().mode() & 0o777;
        assert_eq!(mode(&scratch.0.join("a/b")), 0o700);
        assert_eq!(mode(&scratch.0.join("a")), 0o700);
        assert_eq!(check_dir(&socket, uid), Ok(true));
        fs::set_permissions(scratch.0.join("a/b"), fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let error = ensure_dir(&socket, uid).expect_err("world-writable");
        assert!(
            error.message.contains("writable by its group or others"),
            "{error}"
        );
        assert_eq!(check_socket_file(&socket, uid), Ok(AtPath::Nothing));
        fs::write(&socket, b"not a socket").expect("file");
        let error = check_socket_file(&socket, uid).expect_err("a plain file");
        assert_eq!(error.code, crate::exit::REFUSED);
        assert!(error.message.contains("is not a socket"), "{error}");
        let long = PathBuf::from(format!("/{}", "x".repeat(MAX_SOCKET_PATH)));
        assert!(check_length(&long).is_err());
        assert!(check_length(Path::new("/run/user/1/aspace/daemon.sock")).is_ok());
    }

    #[test]
    fn the_lock_is_exclusive_and_names_its_holder() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("lock");
        let socket = scratch.0.join("daemon.sock");
        let lock = Lock::take(&socket).expect("the first lock");
        assert_eq!(
            fs::metadata(lock_path(&socket))
                .expect("lock file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        match Lock::take(&socket) {
            Err(LockError::Held(pid)) => assert_eq!(pid, Some(std::process::id())),
            other => panic!("not held: {other:?}"),
        }
        drop(lock);
        let again = Lock::take(&socket).expect("free once dropped");
        drop(again);
    }
}
