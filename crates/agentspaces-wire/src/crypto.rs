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

//! The crypto seam: every signature, hash, key derivation, key agreement, and random byte in the
//! crate goes through the installed [`CryptoPort`] (the Rust mirror of the TypeScript client's
//! `CryptoPort` and the Ruby gem's `Crypto.port`). The default port, [`RustCrypto`], runs on the
//! audited RustCrypto and dalek crates; a host may [`install`] another (a FIPS module, a hardware
//! token) once, before first use. Every port must reproduce the golden vectors byte for byte, and
//! Ed25519 (RFC 8032) is deterministic, so even signatures are fixed.
//!
//! The module also reads and writes the key files Java writes: the 48-byte RFC 8410 PKCS#8 forms
//! of Ed25519 seeds and X25519 scalars, and the 44-byte Ed25519 SubjectPublicKeyInfo.
//!
//! # Secrets
//!
//! Private seeds, scalars, shared secrets, and derived keys are returned in
//! [`Zeroizing`] wrappers that wipe them on drop; they dereference to the plain array or vector.
//! Callers that hold secrets should keep them in [`Zeroizing`] (re-exported here) too.
#![warn(missing_docs)]

use std::sync::OnceLock;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub use zeroize::Zeroizing;

/// The length of an Ed25519 public key, seed, and X25519 key or scalar.
pub const KEY_LENGTH: usize = 32;

/// The length of an Ed25519 signature.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of a SHA-256 digest and an HMAC-SHA-256 tag.
pub const DIGEST_LENGTH: usize = 32;

/// The longest HKDF-SHA-256 output (RFC 5869: 255 blocks of 32 bytes).
pub const HKDF_MAX_LENGTH: usize = 255 * DIGEST_LENGTH;

/// The 16 bytes before the seed in an RFC 8410 Ed25519 PKCS#8 PrivateKeyInfo (version 0, OID
/// 1.3.101.112): the whole 48-byte form Java's keystore writes is this prefix and the seed.
pub const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The 16 bytes before the scalar in an RFC 8410 X25519 PKCS#8 PrivateKeyInfo (version 0, OID
/// 1.3.101.110), as Java writes an agent's encryption key.
pub const X25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// The 12 bytes before the key in an Ed25519 X.509 SubjectPublicKeyInfo (RFC 8410).
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Why a crypto operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The bytes are not the exact RFC 8410 DER this wire uses for the named algorithm.
    #[error("not an RFC 8410 {algorithm} key in the 48-byte PKCS#8 or 44-byte SPKI form")]
    MalformedKey {
        /// "Ed25519" or "X25519".
        algorithm: &'static str,
    },
    /// An HKDF-SHA-256 output longer than [`HKDF_MAX_LENGTH`] was asked for.
    #[error("HKDF-SHA-256 output of {requested} bytes exceeds the {HKDF_MAX_LENGTH}-byte maximum")]
    HkdfLength {
        /// The requested length.
        requested: usize,
    },
    /// X25519 produced the all-zero shared secret: the public key has low order, so the
    /// agreement contributes nothing secret (RFC 7748 §6.1). Java's `KeyAgreement` and noble
    /// refuse it the same way.
    #[error("X25519 agreement with a low-order public key")]
    NonContributory,
    /// The operating system's random source failed.
    #[error("the operating system random source failed: {0}")]
    Random(String),
    /// [`install`] was called after a port was already installed or used.
    #[error("a crypto port is already in use; install one before the first crypto operation")]
    PortAlreadyInstalled,
}

/// The primitives the protocol needs. Implementations must be deterministic where the primitive
/// is (everything but randomness) and must not panic on any input.
pub trait CryptoPort: Send + Sync {
    /// A short name for diagnostics ("rustcrypto").
    fn name(&self) -> &str;

    /// The Ed25519 public key of a 32-byte RFC 8032 seed.
    fn ed25519_public_key(&self, seed: &[u8; 32]) -> [u8; 32];

    /// The Ed25519 signature (RFC 8032, deterministic) of `message` by the seed's key.
    fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64];

    /// Strict Ed25519 verification: true only for a 32-byte canonical public key of large order,
    /// a 64-byte canonical signature whose `R` has large order, and a valid equation. False on
    /// any malformed input, never a panic.
    fn ed25519_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;

    /// The X25519 public key (u-coordinate) of a 32-byte private scalar (clamped per RFC 7748).
    fn x25519_public_key(&self, scalar: &[u8; 32]) -> [u8; 32];

    /// The X25519 shared secret (RFC 7748) of a private scalar and a peer's public key; refuses
    /// the all-zero result of a low-order public key with [`CryptoError::NonContributory`].
    fn x25519(
        &self,
        scalar: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError>;

    /// SHA-256 of `data`.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// HMAC-SHA-256 (RFC 2104) of `data` under `key` (any length).
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];

    /// HKDF-SHA-256 (RFC 5869), extract then expand to `length` bytes. An empty `salt` is the
    /// RFC's absent salt. Refuses a `length` over [`HKDF_MAX_LENGTH`].
    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Fills `dest` from a cryptographically secure random source.
    fn fill_random(&self, dest: &mut [u8]) -> Result<(), CryptoError>;

    /// `length` cryptographically secure random bytes. For secrets prefer [`random_seed`] or
    /// [`CryptoPort::fill_random`] into a [`Zeroizing`] buffer.
    fn random_bytes(&self, length: usize) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = vec![0u8; length];
        self.fill_random(&mut bytes)?;
        Ok(bytes)
    }

    /// Whether `a` and `b` are equal, in time independent of their contents when their lengths
    /// are equal (lengths are not secret). Use it for every MAC or secret comparison.
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

/// The default [`CryptoPort`]: `ed25519-dalek` (strict verification), `x25519-dalek`, `sha2`,
/// `hmac`, `hkdf`, `subtle`, and the operating system's random source through `getrandom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCrypto;

impl CryptoPort for RustCrypto {
    fn name(&self) -> &str {
        "rustcrypto"
    }

    fn ed25519_public_key(&self, seed: &[u8; 32]) -> [u8; 32] {
        // SigningKey wipes its copy of the seed on drop.
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(seed).sign(message).to_bytes()
    }

    fn ed25519_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public_key) = <&[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify_strict(message, &signature).is_ok()
    }

    fn x25519_public_key(&self, scalar: &[u8; 32]) -> [u8; 32] {
        // StaticSecret wipes its copy of the scalar on drop.
        PublicKey::from(&StaticSecret::from(*scalar)).to_bytes()
    }

    fn x25519(
        &self,
        scalar: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let shared = StaticSecret::from(*scalar).diffie_hellman(&PublicKey::from(*public_key));
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributory);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        // HMAC accepts a key of any length (RFC 2104 hashes a long key and pads a short one),
        // so `new_from_slice` cannot fail for it.
        #[allow(clippy::expect_used)]
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if length > HKDF_MAX_LENGTH {
            return Err(CryptoError::HkdfLength { requested: length });
        }
        let mut okm = Zeroizing::new(vec![0u8; length]);
        Hkdf::<Sha256>::new(Some(salt), ikm)
            .expand(info, okm.as_mut_slice())
            .map_err(|_| CryptoError::HkdfLength { requested: length })?;
        Ok(okm)
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(dest).map_err(|error| CryptoError::Random(error.to_string()))
    }
}

static PORT: OnceLock<Box<dyn CryptoPort>> = OnceLock::new();

/// The installed crypto port: the one passed to [`install`], else [`RustCrypto`]. The first call
/// fixes the choice for the life of the process.
pub fn port() -> &'static dyn CryptoPort {
    PORT.get_or_init(|| Box::new(RustCrypto)).as_ref()
}

/// Installs the process-wide crypto port. Succeeds only before the first [`port`] call (any
/// crypto operation of this crate makes one), so a process never mixes two ports; afterwards it
/// returns [`CryptoError::PortAlreadyInstalled`] and the port in use stays.
pub fn install(port: Box<dyn CryptoPort>) -> Result<(), CryptoError> {
    PORT.set(port)
        .map_err(|_| CryptoError::PortAlreadyInstalled)
}

/// A fresh 32-byte secret (an Ed25519 seed or X25519 scalar) from the installed port.
pub fn random_seed() -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    port().fill_random(seed.as_mut_slice())?;
    Ok(seed)
}

fn key_after(
    prefix: &[u8],
    der: &[u8],
    algorithm: &'static str,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let key = der
        .strip_prefix(prefix)
        .and_then(|rest| <&[u8; 32]>::try_from(rest).ok())
        .ok_or(CryptoError::MalformedKey { algorithm })?;
    Ok(Zeroizing::new(*key))
}

fn prefixed(prefix: &[u8], key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut der = Zeroizing::new(Vec::with_capacity(prefix.len() + key.len()));
    der.extend_from_slice(prefix);
    der.extend_from_slice(key);
    der
}

/// The 32-byte seed of an Ed25519 PKCS#8 PrivateKeyInfo in the exact 48-byte RFC 8410 form Java
/// writes ([`ED25519_PKCS8_PREFIX`] then the seed). Any other length or prefix (including the
/// RFC 5958 version 1 form with the public key appended) is refused.
pub fn ed25519_seed_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    key_after(&ED25519_PKCS8_PREFIX, der, "Ed25519")
}

/// The 48-byte RFC 8410 PKCS#8 PrivateKeyInfo of an Ed25519 seed, as Java writes it.
pub fn ed25519_pkcs8(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    prefixed(&ED25519_PKCS8_PREFIX, seed)
}

/// The 32-byte scalar of an X25519 PKCS#8 PrivateKeyInfo in the exact 48-byte RFC 8410 form Java
/// writes ([`X25519_PKCS8_PREFIX`] then the scalar). Anything else is refused.
pub fn x25519_scalar_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    key_after(&X25519_PKCS8_PREFIX, der, "X25519")
}

/// The 48-byte RFC 8410 PKCS#8 PrivateKeyInfo of an X25519 scalar, as Java writes it.
pub fn x25519_pkcs8(scalar: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    prefixed(&X25519_PKCS8_PREFIX, scalar)
}

/// The raw 32-byte key of an Ed25519 SubjectPublicKeyInfo in the exact 44-byte RFC 8410 form
/// ([`ED25519_SPKI_PREFIX`] then the key). Anything else is refused. The key itself is not
/// checked to be a curve point; [`CryptoPort::ed25519_verify`] does that.
pub fn ed25519_public_key_from_spki(der: &[u8]) -> Result<[u8; 32], CryptoError> {
    key_after(&ED25519_SPKI_PREFIX, der, "Ed25519").map(|key| *key)
}

/// The 44-byte RFC 8410 SubjectPublicKeyInfo of a raw Ed25519 public key.
pub fn ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + public_key.len());
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_after_first_use_is_refused() {
        let _ = port();
        assert_eq!(
            install(Box::new(RustCrypto)),
            Err(CryptoError::PortAlreadyInstalled)
        );
        assert_eq!(port().name(), "rustcrypto");
    }

    #[test]
    fn constant_time_equality() {
        let crypto = RustCrypto;
        assert!(crypto.ct_eq(b"", b""));
        assert!(crypto.ct_eq(b"abc", b"abc"));
        assert!(!crypto.ct_eq(b"abc", b"abd"));
        assert!(!crypto.ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn low_order_public_keys_are_refused() {
        let crypto = RustCrypto;
        let scalar = [7u8; 32];
        assert_eq!(
            crypto.x25519(&scalar, &[0u8; 32]),
            Err(CryptoError::NonContributory)
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(
            crypto.x25519(&scalar, &one),
            Err(CryptoError::NonContributory)
        );
    }

    #[test]
    fn random_bytes_are_random() {
        let crypto = RustCrypto;
        let a = crypto.random_bytes(32).unwrap();
        let b = crypto.random_bytes(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_ne!(*random_seed().unwrap(), *random_seed().unwrap());
        assert!(crypto.random_bytes(0).unwrap().is_empty());
    }

    #[test]
    fn hkdf_length_bounds() {
        let crypto = RustCrypto;
        assert_eq!(
            crypto
                .hkdf_sha256(b"k", b"", b"", HKDF_MAX_LENGTH)
                .unwrap()
                .len(),
            HKDF_MAX_LENGTH
        );
        assert_eq!(
            crypto.hkdf_sha256(b"k", b"", b"", HKDF_MAX_LENGTH + 1),
            Err(CryptoError::HkdfLength {
                requested: HKDF_MAX_LENGTH + 1
            })
        );
        assert!(crypto.hkdf_sha256(b"k", b"", b"", 0).unwrap().is_empty());
    }

    #[test]
    fn spki_round_trips_and_refuses_other_shapes() {
        let key = [9u8; 32];
        let der = ed25519_spki(&key);
        assert_eq!(der.len(), 44);
        assert_eq!(ed25519_public_key_from_spki(&der), Ok(key));
        assert!(ed25519_public_key_from_spki(&der[..43]).is_err());
        assert!(ed25519_public_key_from_spki(&ed25519_pkcs8(&key)).is_err());
    }
}
