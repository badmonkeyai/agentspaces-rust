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

//! Session attestation (SPEC §5.6, v0.1.17), a sans-IO port of the Ruby gem's `session.rb` and
//! the Java node's `PeerNode.Session`.
//!
//! On a connection the transport cannot attest (`tcp`, `ws`, `http`), one fully signed
//! `SESSION_HELLO` each way establishes a key, after which frames carry an HMAC-SHA-256 tag under
//! it in place of the Ed25519 signature. This module holds everything that is not I/O:
//!
//! - the hello body ([`hello_body`], [`parse_hello`]) in the Java record order of
//!   `Bodies.SessionHello`;
//! - the key derivation ([`derive_key`]): HKDF-SHA-256 over the X25519 agreement, bound to both
//!   PeerIDs and both nonces;
//! - the session frame ([`encode_session_frame`], [`session_tag`], [`verify_session_tag`]);
//! - the age rule ([`hello_is_fresh`]);
//! - the per-connection state machine ([`Session`]): when an opening hello may go out, the tie
//!   rule when both ends open at once, the echo check on an answer, and key confirmation.
//!
//! # The exchange
//!
//! ```text
//! opener (lower PeerID on a tie)                 answerer
//!   open()        -- SESSION_HELLO, no echo -->    on_hello() => Answer(body)
//!                 <-- SESSION_HELLO, echo ------   (key derived, not yet confirmed)
//!   on_hello() => Confirmed
//!   key_for() = key: frames go tagged  -- tagged frame -->  decoder verifies, confirm()
//!                                                   key_for() = key from now on
//! ```
//!
//! Both hellos travel fully signed; the decoder admits a hello in no other form. The caller does
//! the I/O: it wraps each body in a signed `SESSION_HELLO` envelope addressed to the remote,
//! sends it on the connection the session belongs to, and calls [`Session::send_failed`] when the
//! send fails. One [`Session`] stands per connection and ends with it.
//!
//! The Ruby session locks a mutex around `accept`; here every transition takes `&mut self`, so
//! the borrow checker gives the same exclusion and a shared session goes behind the caller's own
//! lock.
#![warn(missing_docs)]

use std::fmt;

use crate::bodies::{KIND_CHANNEL_HELLO, KIND_SESSION_HELLO};
use crate::cbor::{self, Value};
use crate::cbor_map;
use crate::crypto::{self, CryptoError, KEY_LENGTH, Zeroizing};
use crate::util::java_order;

/// How old a hello may be, by its stamp's physical time against the recipient's clock, and
/// still be answered, in milliseconds (30 s, SPEC §5.6, the hello replay window). An
/// older hello is ignored and counted as stale, never a strike.
///
/// Ruby `Session::HELLO_MAX_AGE_MILLIS`; Java `PeerNode.SESSION_HELLO_MAX_AGE_MILLIS`.
pub const HELLO_MAX_AGE_MILLIS: i64 = 30_000;

/// How long an unanswered opening hello stands before it may be repeated, in milliseconds (5 s).
///
/// Ruby `Session::HELLO_RETRY_MILLIS`; Java `PeerNode.SESSION_HELLO_RETRY_MILLIS`.
pub const HELLO_RETRY_MILLIS: i64 = 5_000;

/// The resource hint a node advertises (with the value `"1"`) when it runs the `SESSION` mode;
/// a session opens only toward a member whose advertisement carries it.
///
/// Ruby `Session::HINT`; Java `PeerNode.SESSION_HINT`.
pub const HINT: &str = "wire.session";

/// The length of a session tag and a session key: a session frame carries exactly this many
/// bytes in the signature field.
///
/// Ruby `Session::MAC_LENGTH`; Java `WireCodec.SESSION_MAC_LENGTH`.
pub const MAC_LENGTH: usize = 32;

/// The length of the nonce this end sends in its hello.
///
/// Java `PeerNode.SESSION_NONCE_LENGTH`.
pub const NONCE_LENGTH: usize = 32;

/// The shortest nonce a received hello may carry.
pub const MIN_NONCE_LENGTH: usize = 16;

/// The longest nonce a received hello may carry.
pub const MAX_NONCE_LENGTH: usize = 64;

/// The fixed prefix of the HKDF info string.
///
/// Ruby `Session::INFO`; Java `PeerNode.SESSION_INFO`.
pub const INFO: &[u8] = b"agentspaces session v1";

/// The envelope kinds that establish channel or session authentication and so always travel
/// fully signed, never under a session tag ([`Session::key_for`] refuses them).
///
/// Python `wire.HELLO_KINDS`.
pub const HELLO_KINDS: [&str; 2] = [KIND_SESSION_HELLO, KIND_CHANNEL_HELLO];

// ---------------------------------------------------------------------------------------------
// The hello body

/// A received `SESSION_HELLO` body that passed the shape checks of [`parse_hello`]
/// (`Bodies.SessionHello`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHello {
    /// The sender's ephemeral X25519 public key.
    pub ephemeral_key: [u8; KEY_LENGTH],
    /// The sender's nonce, [`MIN_NONCE_LENGTH`] to [`MAX_NONCE_LENGTH`] bytes.
    pub nonce: Vec<u8>,
    /// The PeerID the sender addressed the hello to; a recipient counts only a hello naming it.
    pub remote: String,
    /// The opener's nonce on an answering hello; `None` on an opening one.
    pub echo: Option<Vec<u8>>,
}

impl SessionHello {
    /// Whether this hello opens a session (it echoes nothing) rather than answering one.
    pub fn is_opening(&self) -> bool {
        self.echo.is_none()
    }
}

/// The `SESSION_HELLO` body: the CBOR map `{ephemeralKey, nonce, remote, echo}` in the Java
/// record order of `Bodies.SessionHello`, with `echo` null on an opening hello.
pub fn hello_body(
    ephemeral_key: &[u8; KEY_LENGTH],
    nonce: &[u8],
    remote: &str,
    echo: Option<&[u8]>,
) -> Vec<u8> {
    cbor::encode(&cbor_map! {
        "ephemeralKey" => ephemeral_key,
        "nonce" => nonce,
        "remote" => remote,
        "echo" => echo,
    })
}

/// The hello a body decodes to, or `None` when it is not one: the body must be a
/// `Bodies.SessionHello` record under the wire encoding (SPEC §9.1, annex I: the four fields in
/// order and no other, with the canonical-bytes check) whose `ephemeralKey` is a 32-byte string,
/// whose `nonce` is a byte string of [`MIN_NONCE_LENGTH`] to [`MAX_NONCE_LENGTH`] bytes, whose
/// `remote` is text, and whose `echo` is null or a byte string. Never panics.
pub fn parse_hello(body: &[u8]) -> Option<SessionHello> {
    let value = crate::schema::decode(body, "Bodies.SessionHello")?;
    let hello = value.as_map()?;
    let ephemeral_key =
        <[u8; KEY_LENGTH]>::try_from(hello.get("ephemeralKey")?.as_bytes()?).ok()?;
    let nonce = hello.get("nonce")?.as_bytes()?;
    if !(MIN_NONCE_LENGTH..=MAX_NONCE_LENGTH).contains(&nonce.len()) {
        return None;
    }
    let remote = hello.get("remote")?.as_str()?;
    let echo = match hello.get("echo") {
        None | Some(Value::Null) => None,
        Some(Value::Bytes(echo)) => Some(echo.clone()),
        Some(_) => return None,
    };
    Some(SessionHello {
        ephemeral_key,
        nonce: nonce.to_vec(),
        remote: remote.to_owned(),
        echo,
    })
}

/// Whether a hello stamped at `stamp_physical_millis` (the physical part of its envelope's HLC
/// stamp) is young enough to answer at `now_millis` on the recipient's clock: at most
/// [`HELLO_MAX_AGE_MILLIS`] old. A stamp ahead of the clock is fresh here; the stamp filter
/// bounds that skew. Saturating, so a hostile stamp cannot overflow.
pub fn hello_is_fresh(now_millis: i64, stamp_physical_millis: i64) -> bool {
    now_millis.saturating_sub(stamp_physical_millis) <= HELLO_MAX_AGE_MILLIS
}

// ---------------------------------------------------------------------------------------------
// The key

/// Whether PeerID `a` ranks below `b` in Java's `String.compareTo` order (UTF-16 code units), the
/// order the Java node ranks PeerIDs in. For the ASCII base58 PeerIDs of this wire it is plain
/// byte order, which is what the Ruby and TypeScript twins compare.
fn ranks_below(a: &str, b: &str) -> bool {
    java_order(a, b).is_lt()
}

/// `PeerNode.deriveSessionKey`: HKDF-SHA-256 over the X25519 agreement of this end's ephemeral
/// scalar and the remote's ephemeral public key, with an empty salt and the info
/// `INFO || lower PeerID || 0 || higher PeerID || 0 || lower's nonce || higher's nonce`, 32 bytes.
/// Both ends derive the same key.
///
/// Fails with [`CryptoError::NonContributory`] when the remote key has low order (the agreement
/// would be all zeros), or with whatever error the installed crypto port reports.
pub fn derive_key(
    own_scalar: &[u8; KEY_LENGTH],
    own_peer_id: &str,
    own_nonce: &[u8],
    remote_key: &[u8; KEY_LENGTH],
    remote_peer_id: &str,
    remote_nonce: &[u8],
) -> Result<Zeroizing<[u8; MAC_LENGTH]>, CryptoError> {
    let port = crypto::port();
    let shared = port.x25519(own_scalar, remote_key)?;
    let ((first, first_nonce), (second, second_nonce)) = if ranks_below(own_peer_id, remote_peer_id)
    {
        ((own_peer_id, own_nonce), (remote_peer_id, remote_nonce))
    } else {
        ((remote_peer_id, remote_nonce), (own_peer_id, own_nonce))
    };
    let mut info = Vec::with_capacity(
        INFO.len() + first.len() + second.len() + 2 + first_nonce.len() + second_nonce.len(),
    );
    info.extend_from_slice(INFO);
    info.extend_from_slice(first.as_bytes());
    info.push(0);
    info.extend_from_slice(second.as_bytes());
    info.push(0);
    info.extend_from_slice(first_nonce);
    info.extend_from_slice(second_nonce);
    let okm = port.hkdf_sha256(shared.as_slice(), &[], &info, MAC_LENGTH)?;
    // A conforming port returns exactly the length asked for; one that does not is reported as
    // the length error rather than trusted.
    let key =
        <[u8; MAC_LENGTH]>::try_from(okm.as_slice()).map_err(|_| CryptoError::HkdfLength {
            requested: MAC_LENGTH,
        })?;
    Ok(Zeroizing::new(key))
}

// ---------------------------------------------------------------------------------------------
// The session frame

/// The session tag of an envelope: HMAC-SHA-256 under the session key of the envelope's
/// canonical encoding (`cbor::encode` of the envelope map, the bytes a signature would cover).
pub fn session_tag(envelope_bytes: &[u8], key: &[u8; MAC_LENGTH]) -> [u8; MAC_LENGTH] {
    crypto::port().hmac_sha256(key, envelope_bytes)
}

/// Whether `tag` is the session tag of the envelope encoded as `envelope_bytes` under `key`:
/// exactly [`MAC_LENGTH`] bytes, compared in constant time. `envelope_bytes` is the canonical
/// encoding of the decoded envelope, as the Java codec re-encodes it to verify. Never panics.
pub fn verify_session_tag(envelope_bytes: &[u8], tag: &[u8], key: &[u8; MAC_LENGTH]) -> bool {
    tag.len() == MAC_LENGTH && crypto::port().ct_eq(&session_tag(envelope_bytes, key), tag)
}

/// `WireCodec.encodeSession`: the frame `{envelope, senderPublicKey: null, signature: tag}` with
/// the session tag of the envelope in place of the signature. Only an envelope this node itself
/// originated travels this way, on the connection the session belongs to.
///
/// [`crate::envelope::encode_session_frame`] does the same for an envelope [`crate::cbor::Map`]
/// without wrapping it in a [`Value`].
pub fn encode_session_frame(envelope: &Value, key: &[u8; MAC_LENGTH]) -> Vec<u8> {
    session_frame(&cbor::encode(envelope), key)
}

/// The session frame around an envelope already encoded as `envelope_bytes` (its canonical
/// encoding, the bytes the tag covers).
pub(crate) fn session_frame(envelope_bytes: &[u8], key: &[u8; MAC_LENGTH]) -> Vec<u8> {
    // The envelope is encoded once and spliced into the frame map, which the codec writes as
    // 0xBF, its entries in order, and 0xFF: the same bytes as encoding the map built with
    // `cbor_map!`, without cloning the envelope (and its body) into it.
    let tag = session_tag(envelope_bytes, key);
    let mut frame = Vec::with_capacity(envelope_bytes.len() + 64);
    frame.push(0xBF);
    cbor::encode_into(&Value::from("envelope"), &mut frame);
    frame.extend_from_slice(envelope_bytes);
    cbor::encode_into(&Value::from("senderPublicKey"), &mut frame);
    cbor::encode_into(&Value::Null, &mut frame);
    cbor::encode_into(&Value::from("signature"), &mut frame);
    cbor::encode_into(&Value::from(tag), &mut frame);
    frame.push(0xFF);
    frame
}

// ---------------------------------------------------------------------------------------------
// The state machine

/// What [`Session::accept`] decided about a remote half it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// An opening hello was taken: the key is derived but unconfirmed, and this end must send
    /// its answering hello echoing the opener's nonce. It keeps signing its frames until the
    /// opener's first session frame verifies ([`Session::confirm`]).
    Answer,
    /// An answer echoing this end's nonce was taken: the key is derived and confirmed, and
    /// frames to the remote carry session tags from now on.
    Confirmed,
}

/// What [`Session::on_hello`] made of a received `SESSION_HELLO`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum HelloOutcome {
    /// An opening hello was accepted and the answer is already marked sent: send this body as
    /// a fully signed `SESSION_HELLO` addressed to the opener, and call
    /// [`Session::send_failed`] if it cannot leave.
    Answer(Vec<u8>),
    /// An answer to this end's opening arrived: the key is confirmed.
    Confirmed,
    /// The hello is older than [`HELLO_MAX_AGE_MILLIS`]: ignored and counted as stale, never a
    /// strike.
    Stale,
    /// Not a hello for this end (malformed, or naming another peer), or one the state machine
    /// refuses (a second peer, a repeat, the tie rule, a wrong echo, a low-order key): ignored.
    Ignored,
}

/// The hello marks [`Session::sent`] sets and [`Session::send_failed`] restores.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Marks {
    hello_sent: bool,
    hello_sent_at_millis: i64,
    /// Whether this end's hello was the answering one.
    answered: bool,
}

/// One connection's session, the state machine of `PeerNode.Session` and the Ruby `Session`:
/// this end's ephemeral key and nonce, the hello sent and answered marks, the remote PeerID once
/// its half arrives, the derived key, and whether the other end provably holds it (outbound
/// frames carry a tag only then).
///
/// Secrets (the ephemeral scalar and the key) are wiped on drop, and [`fmt::Debug`] shows only
/// the remote and the confirmation flag.
pub struct Session {
    own_peer_id: String,
    ephemeral_scalar: Zeroizing<[u8; KEY_LENGTH]>,
    ephemeral_public: [u8; KEY_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    marks: Marks,
    /// The marks the last [`Session::sent`] replaced, for [`Session::send_failed`].
    marks_before_send: Option<Marks>,
    remote: Option<String>,
    key: Option<Zeroizing<[u8; MAC_LENGTH]>>,
    confirmed: bool,
}

impl Session {
    /// A session for this node (`own_peer_id`) with a fresh ephemeral X25519 key and nonce from
    /// the installed crypto port. Fails only when the random source does.
    pub fn new(own_peer_id: impl Into<String>) -> Result<Self, CryptoError> {
        let scalar = crypto::random_seed()?;
        let mut nonce = [0u8; NONCE_LENGTH];
        crypto::port().fill_random(&mut nonce)?;
        Ok(Self::with_ephemeral(own_peer_id, scalar, nonce))
    }

    /// A session with the given ephemeral X25519 scalar and nonce, for tests and for hosts that
    /// draw their own randomness. Both must be fresh per connection in real use.
    pub fn with_ephemeral(
        own_peer_id: impl Into<String>,
        ephemeral_scalar: Zeroizing<[u8; KEY_LENGTH]>,
        nonce: [u8; NONCE_LENGTH],
    ) -> Self {
        let ephemeral_public = crypto::port().x25519_public_key(&ephemeral_scalar);
        Self {
            own_peer_id: own_peer_id.into(),
            ephemeral_scalar,
            ephemeral_public,
            nonce,
            marks: Marks::default(),
            marks_before_send: None,
            remote: None,
            key: None,
            confirmed: false,
        }
    }

    /// This node's PeerID.
    pub fn own_peer_id(&self) -> &str {
        &self.own_peer_id
    }

    /// This end's ephemeral X25519 public key, the `ephemeralKey` of its hello.
    pub fn ephemeral_public(&self) -> &[u8; KEY_LENGTH] {
        &self.ephemeral_public
    }

    /// This end's nonce, the `nonce` of its hello and what an answer must echo.
    pub fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.nonce
    }

    /// The remote PeerID, once its half has been accepted.
    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// The derived key, once the remote's half has been accepted (confirmed or not).
    pub fn key(&self) -> Option<&[u8; MAC_LENGTH]> {
        self.key.as_deref()
    }

    /// Whether the other end provably holds the key, so outbound frames may carry tags.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Whether a hello (opening or answering) has been marked sent.
    pub fn hello_sent(&self) -> bool {
        self.marks.hello_sent
    }

    /// Whether this end's hello was the answering one.
    pub fn answered(&self) -> bool {
        self.marks.answered
    }

    /// The hello body toward `remote`: opening when `echo` is `None`, answering (echoing the
    /// opener's nonce) otherwise.
    pub fn hello(&self, remote: &str, echo: Option<&[u8]>) -> Vec<u8> {
        hello_body(&self.ephemeral_public, &self.nonce, remote, echo)
    }

    /// Whether an opening hello may go out at `now_millis` (`PeerNode.maybeSessionHello`'s
    /// guard): no key yet, this end has not answered, and no opening is standing younger than
    /// [`HELLO_RETRY_MILLIS`].
    pub fn may_open(&self, now_millis: i64) -> bool {
        self.key.is_none()
            && !self.marks.answered
            && !(self.marks.hello_sent
                && now_millis.saturating_sub(self.marks.hello_sent_at_millis) < HELLO_RETRY_MILLIS)
    }

    /// Marks a hello as sent at `now_millis` (`answering` for an answer). Call it before the
    /// send, as the Java node does: a synchronous transport can deliver the remote's answer
    /// before the send returns, and the answer is accepted only against the mark.
    pub fn sent(&mut self, now_millis: i64, answering: bool) {
        self.marks_before_send = Some(self.marks);
        self.marks = Marks {
            hello_sent: true,
            hello_sent_at_millis: now_millis,
            answered: answering,
        };
    }

    /// The hello last marked with [`Session::sent`] did not leave (`PeerNode.sendSessionHello`
    /// on an I/O error): restores the marks it replaced, so the next trigger repeats an opening;
    /// and when the lost hello was an answer, undoes the accept it answered, so the opener opens
    /// again. Does nothing when no mark is outstanding.
    pub fn send_failed(&mut self) {
        let Some(previous) = self.marks_before_send.take() else {
            return;
        };
        let lost_answer = self.marks.answered;
        self.marks = previous;
        if lost_answer && !self.marks.answered {
            self.remote = None;
            self.key = None;
            self.confirmed = false;
        }
    }

    /// The opening hello toward `remote` if one may go out at `now_millis` ([`Session::may_open`],
    /// and never toward this node itself), already marked sent. Send it fully signed and call
    /// [`Session::send_failed`] if it cannot leave.
    pub fn open(&mut self, remote: &str, now_millis: i64) -> Option<Vec<u8>> {
        if remote == self.own_peer_id || !self.may_open(now_millis) {
            return None;
        }
        self.sent(now_millis, false);
        Some(self.hello(remote, None))
    }

    /// Takes the remote's half from `from` (`PeerNode.onSessionHello`'s core). Refuses (returns
    /// `None`, changing nothing) once a key stands, a half from a second peer, an opening from a
    /// higher PeerID while this end's own opening is unanswered (when both ends open at once the
    /// lower PeerID stays the opener), an answer to a hello this end never opened or that
    /// echoes another nonce (compared in constant time), and a low-order ephemeral key.
    ///
    /// The caller checks first that the hello names this node ([`SessionHello::remote`]) and is
    /// fresh ([`hello_is_fresh`]); [`Session::on_hello`] does all three.
    #[must_use]
    pub fn accept(&mut self, from: &str, hello: &SessionHello) -> Option<Verdict> {
        if self.key.is_some() || self.remote.as_deref().is_some_and(|remote| remote != from) {
            return None; // one session per connection, with one peer
        }
        let opening = hello.is_opening();
        match &hello.echo {
            None => {
                if self.marks.hello_sent
                    && !self.marks.answered
                    && ranks_below(&self.own_peer_id, from)
                {
                    return None; // both opened at once: this end is the opener and waits
                }
            }
            Some(echo) => {
                if !self.marks.hello_sent
                    || self.marks.answered
                    || !crypto::port().ct_eq(echo, &self.nonce)
                {
                    return None; // an answer to a hello this end never opened
                }
            }
        }
        let key = derive_key(
            &self.ephemeral_scalar,
            &self.own_peer_id,
            &self.nonce,
            &hello.ephemeral_key,
            from,
            &hello.nonce,
        )
        .ok()?;
        self.remote = Some(from.to_owned());
        self.key = Some(key);
        self.confirmed = !opening;
        Some(if opening {
            Verdict::Answer
        } else {
            Verdict::Confirmed
        })
    }

    /// Handles a fully signed `SESSION_HELLO` from `from` whose envelope stamp's physical time is
    /// `stamp_physical_millis`, at `now_millis` (`PeerNode.onSessionHello`): parses the body,
    /// ignores a hello that does not name this node, reports a stale one, and otherwise runs
    /// [`Session::accept`]. On an accepted opening it marks the answer sent and returns its
    /// body.
    pub fn on_hello(
        &mut self,
        from: &str,
        body: &[u8],
        stamp_physical_millis: i64,
        now_millis: i64,
    ) -> HelloOutcome {
        let Some(hello) = parse_hello(body) else {
            return HelloOutcome::Ignored;
        };
        if hello.remote != self.own_peer_id {
            return HelloOutcome::Ignored;
        }
        if !hello_is_fresh(now_millis, stamp_physical_millis) {
            return HelloOutcome::Stale;
        }
        match self.accept(from, &hello) {
            Some(Verdict::Answer) => {
                self.sent(now_millis, true);
                HelloOutcome::Answer(self.hello(from, Some(&hello.nonce)))
            }
            Some(Verdict::Confirmed) => HelloOutcome::Confirmed,
            None => HelloOutcome::Ignored,
        }
    }

    /// Records key confirmation: a session frame from the remote verified under the key, so the
    /// other end holds it and this end may tag its own frames. Ignored while no key stands.
    pub fn confirm(&mut self) {
        self.confirmed = self.key.is_some();
    }

    /// The key to tag a frame of `kind` addressed `to` with, or `None` (sign it instead): while
    /// unconfirmed, for an unaddressed frame or one to another peer, and always for
    /// `SESSION_HELLO` and `CHANNEL_HELLO`, which travel fully signed.
    pub fn key_for(&self, to: Option<&str>, kind: &str) -> Option<&[u8; MAC_LENGTH]> {
        if !self.confirmed || HELLO_KINDS.contains(&kind) {
            return None;
        }
        match (to, self.remote.as_deref()) {
            (Some(to), Some(remote)) if to == remote => self.key.as_deref(),
            _ => None,
        }
    }

    /// The remote PeerID and key the decoder verifies this connection's session frames against,
    /// once the remote's half has been accepted (before confirmation too: the answerer must
    /// verify the opener's first tagged frame to confirm).
    pub fn established(&self) -> Option<(&str, &[u8; MAC_LENGTH])> {
        Some((self.remote.as_deref()?, self.key.as_deref()?))
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("remote", &self.remote)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}
