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

//! The AgentSpaces protocol core: wire version 3 as SPEC v0.1.33 defines it for a member of
//! layers 0 to 3, with no I/O, no threads, no async runtime, and no clock of its own. Callers
//! feed bytes and time in and take frames, judgments, and events out. Every byte this crate signs
//! or hashes matches the Java codec, which the golden vectors in `tests/golden.json` and the wire
//! encoding vectors of annex I in `tests/wire-encoding-vectors.json` prove.
//!
//! Module map (each module ports the named Python module of `agentspaces-python`):
//! - [`cbor`]: the Jackson-shaped CBOR codec (`cbor.py`), with the item rules S1 to S12.
//! - [`schema`]: the protocol records of annex I and the record rules P1 to P4 (`records.py`).
//! - [`base58`], [`ids`], [`time`], [`limits`]: encodings, derived ids, ISO instants and durations, constants.
//! - [`crypto`]: the `CryptoPort` and its RustCrypto implementation.
//! - [`identity`], [`founding`]: keys, agent certificates, founding documents (`identity.py`).
//! - [`hlc`], [`envelope`], [`bodies`], [`ads`]: stamps, frames, frame bodies, advertisements (`wire.py`).
//! - [`records`]: sign views, records, state transitions, claims and their lattice (`wire.py`).
//! - [`revocation`], [`fold`], [`vote`]: revocation judgment, the space fold, ballots (`revocation.py`, `peer.py`, `vote.py`).
//! - [`filters`], [`seed`], [`session`], [`social`], [`beacon`]: the filter grammar, seeds, session
//!   attestation (`session.rb`), invite keys, beacon documents.
//! - [`serving`]: the digest and delta encodings a node that answers anti-entropy produces and
//!   reads (`ReplicatedSpace`, `AdCache`, the revocation registries, and the membership view).
//!
//! # What SPEC v0.1.29 to v0.1.33 changed here
//!
//! - *The wire encoding (§9.1, §9.2).* Every carrier this crate reads from the network (a frame and
//!   its body, a space delta, a pulled sync delta, a stored or peer advertisement, a signed
//!   revocation, a session hello) decodes by the receiver's procedure: the item rules, the record
//!   rules of its annex I schema ([`schema`]), and the canonical-bytes check, so a carrier is
//!   refused unless re-encoding what was decoded gives back exactly the bytes received. A field the
//!   schema does not name, a field out of order, a wrong-typed field, or a null where the record
//!   omits the field makes the carrier undecodable. A bare frame writes its null key and signature.
//! - *The clock (§7.3, §7.4, §9, §11a.4; v0.1.30).* A stamp has one canonical text
//!   ([`hlc::Stamp::parse`]); a counter above 65,536 is refused at every merge point; the clock
//!   carries instead of saturating and clamps a merged stamp one millisecond inside the drift
//!   ceiling ([`hlc::Hlc`]); the frame filters run in the order of §9 with the five-second skew
//!   margin ([`envelope::FrameFilter`]); a verified state or claim stamped past the ceiling is
//!   deferred, or refused when an hour further out, an agent-signed state's `signedAt` included,
//!   and each refusal counts once per distinct signed content ([`fold`]).
//! - *The AppCard revision (§6.1a.2 to §6.1a.6, §6.1b, §6.3; v0.1.32).* The closed `kind` and
//!   `signOn`, `origin` and `formats`, the card spill and its parts documents, the `wire.appcard=2`
//!   level, the content store's asset card, and the cache byte budget ([`ads`]).
//! - *The beacon document (§9.1).* A signed document arrives as exactly its canonical JSON, and
//!   every member holds Java's type ([`beacon`]).
//!
//! Persistent data trees (annex H and PDT 2), the content swarm and its `pdt` level, fetching a
//! spilled card's parts, the hashed digest exchange, and the lazy-push tree's waits (§9.4) are not
//! implemented: this crate serves a dial-only member and a hub-and-spoke listening member (which
//! answers full digests), which run none of them.
#![forbid(unsafe_code)]

pub mod ads;
pub mod base58;
pub mod beacon;
pub mod bodies;
pub mod cbor;
pub mod crypto;
pub mod envelope;
pub mod filters;
pub mod fold;
pub mod founding;
pub mod hlc;
pub mod identity;
pub mod ids;
pub mod limits;
pub mod records;
pub mod revocation;
pub mod schema;
pub mod seed;
pub mod serving;
pub mod session;
pub mod social;
pub mod time;
mod util;
pub mod vote;
