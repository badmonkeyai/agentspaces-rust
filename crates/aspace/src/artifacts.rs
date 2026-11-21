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
//! `aspace put`, `aspace get`, and `aspace content ls`: artifacts on the content swarm.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentspaces::content::{Content, ContentConfig, FetchOptions, FilePieces, MemoryPieces, PieceStore, PublishOptions};
use agentspaces::space::Template;
use agentspaces::wire::content::{HOLDING_TYPE, Holding, MANIFEST_TYPE, Manifest};
use agentspaces::wire::pdt::store::MemoryNodes;
use serde_json::json;

use crate::cli::Global;
use crate::exit::Failure;
use crate::io::{print_line, printable};
use crate::session::{Session, note};

async fn start(session: &Session, store: Option<&Path>) -> Result<Content, Failure> {
    let pieces: Arc<dyn PieceStore> = match store {
        Some(dir) => Arc::new(
            FilePieces::open(dir, u64::MAX).map_err(|e| Failure::error(format!("the piece store {}: {e}", dir.display())))?,
        ),
        None => Arc::new(MemoryPieces::new()),
    };
    Content::start_with(session.peer().clone(), Arc::new(MemoryNodes::new()), pieces, ContentConfig::default())
        .await
        .map_err(|e| Failure::error(e.to_string()))
}

/// `aspace put`: publish a file as an artifact, print its manifest, and serve it until
/// interrupted (unless `--exit`).
pub async fn put(
    global: &Global,
    path: &Path,
    piece_size: Option<u64>,
    name: Option<String>,
    in_place: bool,
    exit: bool,
) -> Result<(), Failure> {
    let meta = std::fs::metadata(path).map_err(|e| Failure::refused(format!("{}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(Failure::refused(format!("{} is not a regular file", path.display())));
    }
    let session = Session::join(global).await?;
    let outcome = async {
        let content = start(&session, None).await?;
        let options = PublishOptions {
            piece_size: piece_size.map_or(agentspaces::wire::content::DEFAULT_PIECE_SIZE, |p| p as i64),
            name: name.or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned())),
            in_place,
            ..PublishOptions::default()
        };
        let m = content.publish_file(path, options).await.map_err(|e| Failure::refused(e.to_string()))?;
        print_line(&json!({"root": m.root, "size": m.size, "pieceSize": m.piece_size, "pieces": m.pieces, "name": m.name}))?;
        if !exit {
            note("serving the artifact to the fleet; Ctrl-C stops");
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = content.close().await;
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace get`: fetch an artifact by root into a file, resuming through `--store`.
pub async fn get(global: &Global, root: &str, out: &Path, store: Option<PathBuf>, timeout: Duration) -> Result<(), Failure> {
    let session = Session::join(global).await?;
    let outcome = async {
        let content = start(&session, store.as_deref()).await?;
        let progress = {
            let (content, root) = (content.clone(), root.to_string());
            tokio::spawn(async move {
                let mut last = -1;
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Some(a) = content.artifacts().into_iter().find(|a| a.manifest.root == root)
                        && a.held != last
                    {
                        last = a.held;
                        note(format!("{} of {} pieces", a.held, a.manifest.pieces));
                    }
                }
            })
        };
        let fetched = content.fetch_artifact(root, FetchOptions { timeout: Some(timeout), ..FetchOptions::default() }).await;
        progress.abort();
        let report = fetched.map_err(|e| match e {
            agentspaces::content::ContentError::TimedOut { .. } => Failure::timeout(e.to_string()),
            other => Failure::error(other.to_string()),
        })?;
        let temp = out.with_extension("aspace-part");
        let mut file = std::fs::File::create(&temp).map_err(|e| Failure::error(format!("{}: {e}", temp.display())))?;
        let size = content.read_artifact(root, &mut file).map_err(|e| Failure::error(e.to_string()))?;
        file.sync_all().map_err(|e| Failure::error(e.to_string()))?;
        std::fs::rename(&temp, out).map_err(|e| Failure::error(format!("{}: {e}", out.display())))?;
        print_line(&json!({"root": root, "path": out.display().to_string(), "size": size, "piecesFetched": report.nodes}))?;
        let _ = content.close().await;
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}

/// `aspace content ls`: the artifacts the content space describes, with their holders.
pub async fn ls(global: &Global, as_json: bool) -> Result<(), Failure> {
    let session = Session::join(global).await?;
    let outcome = async {
        let space = session.peer().space("content");
        session.pull_and_settle(&space).await?;
        let manifests = space.read_all(&Template::new(MANIFEST_TYPE), 4096).await.map_err(|e| Failure::error(e.to_string()))?;
        let holdings = space.read_all(&Template::new(HOLDING_TYPE), 4096).await.map_err(|e| Failure::error(e.to_string()))?;
        let mut seen = std::collections::HashSet::new();
        for e in manifests {
            let Some(m) = e.payload().as_map().and_then(Manifest::from_map) else { continue };
            if m.violation().is_some() || !seen.insert(m.root.clone()) {
                continue;
            }
            let holders: Vec<(String, bool)> = holdings
                .iter()
                .filter_map(|h| h.payload().as_map().and_then(Holding::from_map))
                .filter(|h| h.root == m.root)
                .map(|h| (h.holder, h.complete))
                .collect();
            let complete = holders.iter().filter(|(_, c)| *c).count();
            if as_json {
                print_line(&json!({
                    "root": m.root, "size": m.size, "pieces": m.pieces, "name": m.name, "mediaType": m.media_type,
                    "origin": m.origin, "holders": holders.len(), "complete": complete,
                }))?;
            } else {
                crate::commands::print_text(&format!(
                    "{}  {:>12}  {:>3} holder(s)  {}",
                    m.root,
                    m.size,
                    holders.len(),
                    printable(m.name.as_deref().unwrap_or(""))
                ))?;
            }
        }
        Ok(())
    }
    .await;
    session.close().await;
    outcome
}
