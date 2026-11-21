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

//! Persistent data trees for AgentSpaces in Rust (SPEC annex H): named refs whose heads are
//! `PRef` entries in the group's ref space and whose values are trees of content-addressed nodes
//! that move over the content swarm's tree exchange.
//!
//! [`Pdt`] runs over a started [`Content`] service and its node store. A [`Ref`] reads its live
//! heads, loads each head's tree (the head's inline delta first, then the tree exchange from the
//! head's writer and the tree's holders), and reads one head's value or the merge of several: a
//! key-wise three-way merge against the common base that a breadth-first walk over `base` links
//! finds (the version graph's `vg` nodes stand in for versions whose entries are gone), with the
//! later head winning a key both sides changed. A swap writes the new nodes, a `vg` node, and a
//! head whose `base` lists the heads it read; [`Pdt::tick`] renews the heads this member wrote at
//! half their lease and withdraws its superseded heads after a grace of two gossip rounds.
//!
//! [`FileShare`] is the Groovy console's file share on these refs, with download and withdraw.
//!
//! The values here are the level-1 map kinds (`map`, `set`, `tree`) of
//! [`agentspaces::wire::pdt`]. A ref whose heads say `linear` reads here and refuses a swap.

pub mod files;
mod refs;
pub mod store;

pub use files::{FileShare, FileShareConfig, Inspected, Listed, Receipt, ShareError};
pub use refs::{Head, Pdt, PdtConfig, PdtError, Ref, RefStats, Swapped};
pub use store::FileNodes;
