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

//! Channel certificates (SPEC §5.6): the identity-endorsed TLS certificate of the `tls` binding,
//! a port of Java `ChannelCertificate`.
//!
//! A channel certificate carries a fresh EC P-256 key for the TLS handshake in a self-signed
//! X.509 v3 certificate whose subject and issuer are `CN=multibase(identity key)` and whose
//! X.509 signature is the peer's Ed25519 identity signature over the TBSCertificate (signature
//! algorithm id-Ed25519, 1.3.101.112, RFC 8410). The handshake (RFC 8446) proves the remote end
//! holds the P-256 key; the endorsement proves the identity stands behind exactly that key; both
//! together bind the channel to `PeerID = multibase(sha-256(identity key))`. No CA participates:
//! the only trust decision is [`attest`], run on the certificate the remote end presented.
//!
//! The identity's private key signs once, at generation, through [`Identity::sign`], and never
//! enters the TLS machinery. The certificate is assembled by `rcgen` with the identity as the
//! issuer's signing key, so the DER comes from a maintained library rather than hand-rolled TLV
//! code (the Java core made the same move). A presented certificate is checked for strict DER by
//! webpki, the parser the handshake verifier already ran on it, and its fields are read with
//! `x509-parser`, for the same reason.

use std::fmt;

use agentspaces_wire::base58;
use agentspaces_wire::crypto;
use agentspaces_wire::identity::Identity;
use agentspaces_wire::ids;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ED25519, PublicKeyData, SerialNumber, SignatureAlgorithm, SigningKey,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ParsedCertificate;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{OID_SIG_ED25519, OID_X509_COMMON_NAME};
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};

/// id-Ed25519 (RFC 8410), the signature algorithm of every channel certificate.
pub const ED25519_SIG_OID: &str = "1.3.101.112";

/// The longest subject CN [`attest`] decodes: a 32-byte key is about 45 characters of multibase,
/// so a larger CN is refused before any decoding work (Java `identityKeyFromCn`).
pub const MAX_CN_CHARS: usize = 64;

/// How far before generation a certificate's validity starts (clock skew), in milliseconds.
const BACKDATE_MS: i64 = 3_600_000;

/// How long a certificate is valid from its start, in milliseconds (365 days).
const VALIDITY_MS: i64 = 365 * 86_400_000;

/// The serial number's length in random bytes, read as a positive integer.
const SERIAL_BYTES: usize = 9;

/// Why a channel certificate could not be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelCertificateError {
    /// The random source, the P-256 key generation, or the certificate assembly failed.
    #[error("channel certificate: {0}")]
    Generate(String),
}

/// A TLS credential: a private key (PKCS#8 DER) and the certificate (DER) presenting its public
/// key. [`ChannelCertificate::generate`] makes the identity-endorsed channel certificate; any
/// other credential ([`ChannelCertificate::from_der`]) is presented as given and attests only
/// what [`attest`] finds in it.
///
/// The private key is wiped on drop and never printed.
#[derive(Clone)]
pub struct ChannelCertificate {
    key: Zeroizing<Vec<u8>>,
    certificate: Vec<u8>,
}

impl ChannelCertificate {
    /// Java `ChannelCertificate.generate`: a fresh P-256 key and the certificate `identity`
    /// endorses for it, valid from an hour ago for 365 days.
    pub fn generate(identity: &Identity) -> Result<Self, ChannelCertificateError> {
        Self::generate_at(identity, SystemClock.now_ms())
    }

    /// [`ChannelCertificate::generate`] with the generation time given (epoch milliseconds):
    /// valid from `now_ms` minus an hour for 365 days, at whole-second precision.
    pub fn generate_at(identity: &Identity, now_ms: i64) -> Result<Self, ChannelCertificateError> {
        Self::build(identity.public_raw(), identity, now_ms)
    }

    /// The general form of [`ChannelCertificate::generate_at`]: a certificate naming `subject`
    /// (a raw Ed25519 key) in its subject and issuer CN, signed by `endorser`. It attests
    /// `subject`'s PeerID only when `endorser` holds `subject`; tests build the other case to
    /// prove [`attest`] refuses it.
    pub fn build(
        subject: &[u8; 32],
        endorser: &Identity,
        now_ms: i64,
    ) -> Result<Self, ChannelCertificateError> {
        let tls_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(failed)?;
        let random = crypto::random_seed().map_err(failed)?;
        let serial = random.get(..SERIAL_BYTES).unwrap_or_default();

        let not_before_ms = now_ms.saturating_sub(BACKDATE_MS);
        let not_after_ms = not_before_ms.saturating_add(VALIDITY_MS);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, base58::multibase(subject));
        let mut params = CertificateParams::default();
        params.distinguished_name = name;
        params.serial_number = Some(SerialNumber::from_slice(serial));
        params.not_before = instant(not_before_ms)?;
        params.not_after = instant(not_after_ms)?;
        // No extensions: the default parameters carry no SANs, usages, or CA constraints, and
        // the authority key identifier stays off, exactly as Java's builder leaves them.
        let issuer = Issuer::from_params(&params, IdentitySigner(endorser));
        let certificate = params.signed_by(&tls_key, &issuer).map_err(failed)?;
        Ok(Self {
            key: Zeroizing::new(tls_key.serialize_der()),
            certificate: certificate.der().to_vec(),
        })
    }

    /// A credential from its parts: a private key as PKCS#8 DER and the certificate (DER) that
    /// presents its public key. Nothing is checked here; a mismatched pair fails when a TLS
    /// configuration is built from it.
    pub fn from_der(key_pkcs8: Vec<u8>, certificate: Vec<u8>) -> Self {
        Self {
            key: Zeroizing::new(key_pkcs8),
            certificate,
        }
    }

    /// The certificate, DER.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// The TLS private key, PKCS#8 DER.
    pub fn key_der(&self) -> &[u8] {
        &self.key
    }

    /// The PeerID this certificate attests ([`attest`]), or `None`.
    pub fn attested(&self) -> Option<String> {
        attest(&self.certificate)
    }

    /// The certificate as the one-element chain rustls presents.
    pub fn rustls_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.certificate.clone())]
    }

    /// The private key as rustls takes it.
    pub fn rustls_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.to_vec()))
    }
}

impl fmt::Debug for ChannelCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelCertificate")
            .field("attested", &self.attested())
            .field("certificate_bytes", &self.certificate.len())
            .finish_non_exhaustive()
    }
}

/// Java `ChannelCertificate.attest`: the PeerID a presented certificate (DER) binds the channel
/// to, or `None` when it proves nothing.
///
/// - The bytes must be one strict-DER X.509 v3 certificate whose TBSCertificate names the same
///   signature algorithm as the certificate, with nothing after it: the parse rustls's
///   handshake verifier (webpki) makes of the certificate whose key it checked, so attestation
///   reads exactly what the handshake proved (the JDK's parser refuses the same defects; it also
///   reads v1 certificates, which no implementation issues as channel certificates).
/// - The signature algorithm is id-Ed25519.
/// - The subject is one CN of at most [`MAX_CN_CHARS`] characters: `z`, then base58btc
///   decoding to 32 bytes.
/// - That key's Ed25519 signature over the TBSCertificate verifies.
///
/// Validity dates are not consulted, as in Java. Never panics: any defect in the bytes is
/// "attests nobody".
pub fn attest(certificate: &[u8]) -> Option<String> {
    let der = CertificateDer::from(certificate);
    ParsedCertificate::try_from(&der).ok()?;
    let (rest, parsed) = X509Certificate::from_der(certificate).ok()?;
    if !rest.is_empty()
        || parsed.signature_algorithm.algorithm != OID_SIG_ED25519
        || parsed.tbs_certificate.signature != parsed.signature_algorithm
        || parsed.signature_value.unused_bits != 0
    {
        return None;
    }
    let key = identity_key(&parsed.tbs_certificate.subject)?;
    let endorsed = Identity::verify(
        &key,
        parsed.tbs_certificate.as_ref(),
        &parsed.signature_value.data,
    );
    endorsed.then(|| ids::derive_id(&key))
}

/// The raw Ed25519 key a subject names: exactly one RDN holding exactly one attribute, the CN,
/// whose string is `z` + base58btc of 32 bytes, bounded before decoding. Java reads the RFC 2253
/// form `CN=<value>`, which any further attribute would break, so this asks the same.
fn identity_key(subject: &X509Name<'_>) -> Option<[u8; 32]> {
    let mut rdns = subject.iter();
    let rdn = rdns.next()?;
    let mut attributes = rdn.iter();
    let attribute = attributes.next()?;
    if rdns.next().is_some()
        || attributes.next().is_some()
        || attribute.attr_type() != &OID_X509_COMMON_NAME
    {
        return None;
    }
    let cn = attribute.as_str().ok()?;
    if cn.len() > MAX_CN_CHARS {
        return None;
    }
    let raw = base58::multibase_decode(cn).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

/// The identity as the certificate issuer's signing key: rcgen hands it the TBSCertificate and
/// receives the Ed25519 endorsement.
struct IdentitySigner<'a>(&'a Identity);

impl PublicKeyData for IdentitySigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.public_raw()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl SigningKey for IdentitySigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.sign(message).to_vec())
    }
}

/// Epoch milliseconds as the whole-second instant a certificate's validity records.
fn instant(epoch_ms: i64) -> Result<time::OffsetDateTime, ChannelCertificateError> {
    time::OffsetDateTime::from_unix_timestamp(epoch_ms.div_euclid(1000)).map_err(failed)
}

fn failed(error: impl fmt::Display) -> ChannelCertificateError {
    ChannelCertificateError::Generate(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_certificate_attests_its_identity_and_a_stranger_signature_attests_nobody() {
        let identity = Identity::from_seed(&[7; 32]);
        let certificate = ChannelCertificate::generate(&identity).expect("generate");
        assert_eq!(
            attest(certificate.certificate_der()).as_deref(),
            Some(identity.peer_id())
        );
        let stranger = Identity::from_seed(&[8; 32]);
        let forged = ChannelCertificate::build(identity.public_raw(), &stranger, 0).expect("build");
        assert_eq!(forged.attested(), None);
        let debug = format!("{certificate:?}");
        assert!(debug.contains(identity.peer_id()) && !debug.contains("key:"));
    }
}
