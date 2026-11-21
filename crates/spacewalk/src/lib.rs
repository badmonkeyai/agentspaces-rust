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
//! spacewalk: share files from a local directory into an agent space, and pull them back, from
//! a terminal. It writes and reads exactly what the Groovy console's "Add to space" writes: the
//! bytes as a chunked `PBlob` on the content swarm, the `file-share` map entry under
//! `<space>/<relative path>`, and a `SharedFile` record in the space.
//!
//! The modules: [`connect`] joins and starts the services, [`app`] is the state machine (no
//! terminal, no network), [`ui`] draws it, [`local`] reads the directory, and [`sanitize`] makes
//! remote text safe for a terminal.

pub mod app;
pub mod connect;
pub mod local;
pub mod sanitize;
pub mod ui;
