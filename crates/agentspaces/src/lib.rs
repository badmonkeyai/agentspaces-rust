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

//! AgentSpaces for Rust: a wire-compatible fleet member over [`agentspaces_wire`].
//!
//! This crate drives the protocol core with real I/O: transports ([`transport`]: `tcp`, `tls`
//! with [`channel_cert`] attestation, and an in-memory network for tests), the keystore
//! ([`keystore`]), configuration ([`config`]), and the [`peer`], a dial-only fleet member that
//! joins a group through a seed, answers membership probes, folds replicated state, verifies
//! every signature, and reconnects after a lost link. The Python and Ruby peers are its
//! behavioural references; the Java node is the authority.
//!
//! Over the peer sit the Space API ([`space`]: leased writes, reads, exclusive takes and their
//! completion, and watches, with [`blocking`] mirroring it for code without an async runtime)
//! and the entry layer ([`entry`]: `#[derive(Entry)]` binds a Rust type to its wire schema and
//! writes the payload Jackson writes for the equivalent Java record; [`json`] maps payloads to
//! and from JSON). The typed verbs ([`space::typed`]) join the two:
//!
//! ```no_run
//! # async fn run(config: agentspaces::peer::PeerConfig) -> Result<(), agentspaces::space::SpaceError> {
//! use std::time::Duration;
//! use agentspaces::Entry;
//! use agentspaces::space::{Fleet, Lease, Template};
//! use agentspaces::wire::cbor::Map;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Serialize, Deserialize, Entry)]
//! #[entry(schema = "com.acme.Task#v1")]
//! struct Task {
//!     topic: String,
//!     priority: i32,
//! }
//!
//! let fleet = Fleet::join(config).await?;
//! let tasks = fleet.space("tasks");
//! tasks.write(&Task { topic: "index".into(), priority: 3 }, Lease::DEFAULT_WRITE, Map::new()).await?;
//! let urgent = Template::of::<Task>().where_clause("priority>=3")?;
//! if let Some(taken) = tasks.take_typed::<Task>(&urgent, Lease::DEFAULT_TAKE, Duration::from_secs(15)).await? {
//!     println!("took {:?}", taken.value());
//!     taken.complete(None, Lease::DEFAULT_RESULT, Map::new()).await?;
//! }
//! fleet.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Joining a fleet
//!
//! [`Peer::join_from_env`](peer::Peer::join_from_env) reads the configuration ([`Config`]): the
//! `ASPACE_SEEDS`, `ASPACE_GROUP` or `ASPACE_JOIN`, `ASPACE_KEYSTORE`, `ASPACE_PROFILE`, and
//! `ASPACE_SPACES` variables over the shared fleet YAML (`ASPACE_CONFIG`, else
//! `~/.config/agentspaces/fleet.yaml` when it exists; [`config`]). It loads (or mints) the
//! identity in the keystore, dials the first seed that answers over `tcp` or `tls`, joins, and
//! pulls the named spaces:
//!
//! ```no_run
//! # async fn run() -> Result<(), agentspaces::peer::PeerError> {
//! use agentspaces::peer::Peer;
//!
//! let peer = Peer::join_from_env().await?;
//! println!("{} joined {}", peer.peer_id(), peer.group_id());
//! for state in peer.space_states("tasks").await {
//!     println!("{state:?}");
//! }
//! peer.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Fleet::join_config`](space::Fleet::join_config) joins with a fleet file read explicitly
//! (`Fleet::join_config(&Config::load("fleet.yaml")?)`); [`config::PeerSettings`] and
//! [`peer::PeerConfig`] build the same peer in code.
//!
//! # Agents, remote actions, and the catalogue
//!
//! Over the spaces sit the worker layer ([`agent`]: `take` and `notify` handlers bound as an
//! agent with its own identity and an AgentCard), the remote actions the fleet's cards declare
//! ([`remote`]: listed, invoked, and their results correlated), and the fleet catalogue
//! ([`catalog`]: the remote actions folded into named offerings, as every AgentSpaces gateway
//! names them). The `aspace` command is built on these three.
#![forbid(unsafe_code)]

pub mod agent;
pub mod blocking;
pub mod catalog;
pub mod channel_cert;
pub mod clock;
pub mod config;
pub mod entry;
pub mod group;
pub mod json;
pub mod keystore;
pub mod peer;
pub mod remote;
pub mod space;
pub mod transport;

pub use agentspaces_wire as wire;
/// The resolved configuration: flags, `ASPACE_*` variables, and the fleet YAML ([`config`]).
pub use config::Config;
/// The [`Entry`] trait and its derive, `#[derive(Entry)]`.
pub use entry::Entry;
