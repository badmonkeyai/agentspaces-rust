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

//! The AgentSpaces protocol core: wire version 3 as SPEC v0.1.28 defines it, with no I/O,
//! no threads, no async runtime, and no clock of its own. Callers feed bytes and time in and
//! take frames, judgments, and events out. Every byte this crate signs or hashes matches the
//! Java codec, which the golden vectors in `tests/golden.json` prove.
//!
//! Module map (each module ports the named Python module of `agentspaces-python`):
//! - [`cbor`]: the Jackson-shaped CBOR codec (`cbor.py`).
//! - [`base58`], [`ids`], [`time`], [`limits`]: encodings, derived ids, ISO instants and durations, constants.
//! - [`crypto`]: the `CryptoPort` and its RustCrypto implementation.
//! - [`identity`], [`founding`]: keys, agent certificates, founding documents (`identity.py`).
//! - [`hlc`], [`envelope`], [`bodies`], [`ads`]: stamps, frames, frame bodies, advertisements (`wire.py`).
//! - [`records`]: sign views, records, state transitions, claims and their lattice (`wire.py`).
//! - [`revocation`], [`fold`], [`vote`]: revocation judgment, the space fold, ballots (`revocation.py`, `peer.py`, `vote.py`).
//! - [`filters`], [`seed`], [`session`], [`social`], [`beacon`]: the filter grammar, seeds, session
//!   attestation (`session.rb`), invite keys, beacon documents.
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
pub mod seed;
pub mod session;
pub mod social;
pub mod time;
mod util;
pub mod vote;
