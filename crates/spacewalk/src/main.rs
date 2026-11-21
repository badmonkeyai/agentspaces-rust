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
//! The `spacewalk` command: the terminal UI, and `ls`, `put`, `get`, and `rm` for scripts.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentspaces::config::Overrides;
use agentspaces_pdt::ShareError;
use clap::{Parser, Subcommand};
use ratatui::crossterm::event::{self, Event};
use spacewalk::app::{Action, App, Command, Header, Update};
use spacewalk::connect::{Connection, JoinOptions, connect};
use spacewalk::ui::{self, Theme};
use tokio::sync::mpsc;

const EXAMPLES: &str = "\
Examples:
  # join the Groovy console's notebook peer (its YAML and its bind address) and share ~/proj
  spacewalk --config notebook.yaml --seeds tcp://127.0.0.1:7760 --space catalogue -C ~/proj

  # a console share, by the URL its Share > Copy beacon URL gives
  spacewalk --beacon http://127.0.0.1:63554/.well-known/agentspaces/beacon.json -C ~/proj

  # keep shared and fetched files across runs
  spacewalk --seeds tcp://127.0.0.1:7760 --group shop --space catalogue --store ~/.spacewalk/store

  # the same group by founding text, from a script
  spacewalk --seeds tcp://127.0.0.1:7760 --group shop --space catalogue ls
  spacewalk --seeds tcp://127.0.0.1:7760 --group shop --space catalogue put data/report.csv
  spacewalk --seeds tcp://127.0.0.1:7760 --group shop --space catalogue get data/report.csv -C ./in

Configuration layers as aspace reads them: these flags, then ASPACE_* variables, then the fleet
YAML (--config, ASPACE_CONFIG, ~/.config/agentspaces/fleet.yaml).";

#[derive(Debug, Parser)]
#[command(
    name = "spacewalk",
    version,
    about = "Share files from a local directory into an agent space, and pull them back, from a terminal.",
    long_about = "Share files from a local directory into an agent space, and pull them back. spacewalk \
                  writes and reads what the Groovy console's Add to space writes: the bytes as a blob on \
                  the content swarm, the file-share map entry under <space>/<path>, and a SharedFile \
                  record in the space. With no command it opens the terminal UI.",
    after_help = EXAMPLES
)]
struct Cli {
    /// The local directory: what the UI shows and shares, and where downloads land.
    #[arg(short = 'C', long = "dir", value_name = "DIR", default_value = ".", global = true)]
    dir: PathBuf,
    /// The space to share into (default: the first space the fleet file lists for the group).
    #[arg(short, long, value_name = "NAME", global = true)]
    space: Option<String>,
    /// The fleet YAML file, the agentspaces: subtree of the Java starter's (a console notebook's YAML reads).
    #[arg(long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,
    /// Comma-separated seeds, scheme://host:port or host:port (the console notebook peer's bind address).
    #[arg(long, value_name = "SEEDS", global = true)]
    seeds: Option<String>,
    /// A group of the fleet file by name, or else a founding text.
    #[arg(long, value_name = "NAME", global = true)]
    group: Option<String>,
    /// Join a group by id, aspace://<group-id>.
    #[arg(long, value_name = "URI", global = true)]
    join: Option<String>,
    /// Join the group a beacon serves, by its URL (the Groovy console's Copy beacon URL); with
    /// several groups in the document, --group names one.
    #[arg(long, value_name = "URL", global = true)]
    beacon: Option<String>,
    /// Keep the nodes of shared and fetched files in this directory across runs, and hold again
    /// what this store shared (default: memory, gone when spacewalk stops).
    #[arg(long, value_name = "DIR", global = true)]
    store: Option<PathBuf>,
    /// Write a log to this file (level from SPACEWALK_LOG, default info).
    #[arg(long, value_name = "FILE", global = true)]
    log: Option<PathBuf>,
    /// The keystore directory for a lasting identity (default: a fresh identity each run).
    #[arg(long, value_name = "DIR", global = true)]
    keystore: Option<String>,
    /// The security profile: mtls (the default) or dev-local.
    #[arg(long, value_name = "PROFILE", global = true)]
    profile: Option<String>,
    /// How long joining may take, in seconds (default 10).
    #[arg(long, value_name = "SECONDS", global = true)]
    join_timeout: Option<u64>,
    /// The size limit of a shared file, in bytes (default 64 MiB, the console's).
    #[arg(long, value_name = "BYTES", global = true)]
    max_file: Option<u64>,
    /// Show dot files in the local pane.
    #[arg(long, global = true)]
    show_hidden: bool,
    /// No colour (also NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// List the files shared into the space.
    Ls {
        /// One JSON object per file.
        #[arg(long)]
        json: bool,
    },
    /// Share files or directories (paths inside --dir), then hold them until Ctrl-C.
    Put {
        /// Files or directories.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Leave right after sharing, without holding the files for others to fetch.
        #[arg(long)]
        exit: bool,
    },
    /// Download shared files into --dir at their relative paths.
    Get {
        /// Keys, with or without the <space>/ prefix.
        #[arg(required = true)]
        keys: Vec<String>,
        /// Replace existing files.
        #[arg(long)]
        overwrite: bool,
    },
    /// Remove files from the space's file share.
    Rm {
        /// Keys, with or without the <space>/ prefix.
        #[arg(required = true)]
        keys: Vec<String>,
    },
}

/// Sends tracing output to a file: SPACEWALK_LOG picks the level (default info).
fn start_log(path: &Path) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let filter = tracing_subscriber::EnvFilter::try_from_env("SPACEWALK_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_writer(std::sync::Mutex::new(file)).with_ansi(false).with_env_filter(filter).init();
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = match cli.dir.canonicalize() {
        Ok(d) if d.is_dir() => d,
        _ => {
            eprintln!("spacewalk: {} is not a directory", cli.dir.display());
            return ExitCode::from(2);
        }
    };
    if let Some(path) = &cli.log
        && let Err(e) = start_log(path)
    {
        eprintln!("spacewalk: the log {}: {e}", path.display());
        return ExitCode::from(2);
    }
    let (mut seeds, mut group, mut join) = (cli.seeds.clone(), cli.group.clone(), cli.join.clone());
    if let Some(url) = &cli.beacon {
        match spacewalk::connect::fetch_beacon(url, cli.group.as_deref()).await {
            Ok(b) => {
                tracing::info!(group = %b.name, join = %b.join, seeds = %b.seeds, signer = ?b.signer, "beacon read");
                if cli.command.is_none() {
                    eprintln!("spacewalk: the beacon names {} ({}), seeds {}", b.name, b.join, b.seeds);
                }
                seeds = Some(seeds.map_or(b.seeds.clone(), |s| format!("{s},{}", b.seeds)));
                join = Some(b.join);
                group = None;
            }
            Err(e) => {
                eprintln!("spacewalk: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let overrides = Overrides {
        config: cli.config.clone(),
        seeds,
        group,
        join,
        keystore: cli.keystore.clone(),
        profile: cli.profile.clone(),
        join_timeout: cli.join_timeout.map(Duration::from_secs),
        ..Overrides::default()
    };
    if cli.command.is_none() {
        eprintln!("spacewalk: joining…");
    }
    let conn = match connect(JoinOptions { overrides, max_bytes: cli.max_file.unwrap_or(0), store: cli.store.clone() }).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("spacewalk: {e}");
            return ExitCode::from(1);
        }
    };
    let space = cli.space.clone().or_else(|| conn.spaces.first().cloned());
    let code = match (cli.command, space) {
        (None, space) => run_tui(&conn, &dir, space.unwrap_or_default(), cli.show_hidden, cli.no_color).await,
        (Some(cmd), Some(space)) => run_command(&conn, &dir, &space, cmd).await,
        (Some(_), None) => {
            settle(&conn, "pdt", true).await;
            let known = spacewalk::connect::known_spaces(&conn).await;
            let known = if known.is_empty() { "none found".to_string() } else { known.join(", ") };
            eprintln!("spacewalk: name the space with --space (the group's spaces: {known})");
            ExitCode::from(2)
        }
    };
    let _ = conn.content.close().await;
    let _ = conn.peer.close().await;
    code
}

/// Waits for the group to show itself: the space and the ref space pulled, and, for a command
/// that reads, a member serving trees; a short settle lets the heads and records arrive.
async fn settle(conn: &Connection, space: &str, reads: bool) {
    let _ = conn.peer.space(space).pull().await;
    let _ = conn.peer.space("pdt").pull().await;
    let deadline = Instant::now() + Duration::from_secs(if reads { 5 } else { 0 });
    while Instant::now() < deadline {
        if !conn.content.tree_members().await.unwrap_or_default().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

fn key_of(space: &str, key: &str) -> String {
    if key.starts_with(&format!("{space}/")) { key.to_string() } else { format!("{space}/{}", key.trim_start_matches("./")) }
}

async fn run_command(conn: &Connection, dir: &Path, space: &str, cmd: Cmd) -> ExitCode {
    settle(conn, space, !matches!(cmd, Cmd::Put { .. })).await;
    let files = &conn.files;
    match cmd {
        Cmd::Ls { json } => match files.list(space).await {
            Ok(listed) => {
                for l in listed {
                    if json {
                        let v = serde_json::json!({
                            "key": l.key, "path": l.relative, "root": l.entry.root, "size": l.entry.size,
                            "mediaType": l.entry.media_type, "sharer": l.sharer, "sharedAt": l.shared_at, "mine": l.mine,
                        });
                        println!("{v}");
                    } else {
                        println!("{:>10}  {:<10}  {}", spacewalk::sanitize::size(l.entry.size), spacewalk::sanitize::fit(l.sharer.as_deref().unwrap_or("?"), 10), spacewalk::sanitize::clean(&l.relative));
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Cmd::Put { paths, exit } => {
            let mut failed = false;
            for path in paths {
                let path = if path.is_absolute() { path } else { dir.join(path) };
                let targets = if path.is_dir() {
                    match files.files_under(&path) {
                        Ok((found, skipped)) => {
                            for s in skipped {
                                eprintln!("skipped {} (a link, a dot file, or past the file count)", s.display());
                            }
                            found
                        }
                        Err(e) => return fail(e),
                    }
                } else {
                    vec![path]
                };
                for t in targets {
                    match files.publish(space, dir, &t, |_| {}).await {
                        Ok(r) => println!("shared {} ({} bytes, root {})", r.key, r.size, r.root),
                        Err(e) => {
                            eprintln!("spacewalk: {e}");
                            failed = true;
                        }
                    }
                }
            }
            if !exit && !failed {
                eprintln!("holding the shared files for other members; Ctrl-C stops");
                let _ = tokio::signal::ctrl_c().await;
            }
            if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
        }
        Cmd::Get { keys, overwrite } => {
            let mut failed = false;
            for k in keys {
                match files.download(space, &key_of(space, &k), dir, overwrite, |_| {}).await {
                    Ok(p) => println!("{}", p.display()),
                    Err(e) => {
                        eprintln!("spacewalk: {e}");
                        failed = true;
                    }
                }
            }
            if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
        }
        Cmd::Rm { keys } => {
            for k in keys {
                if let Err(e) = files.withdraw(space, &key_of(space, &k)).await {
                    return fail(e);
                }
                println!("withdrew {}", key_of(space, &k));
            }
            ExitCode::SUCCESS
        }
    }
}

fn fail(e: ShareError) -> ExitCode {
    eprintln!("spacewalk: {e}");
    ExitCode::from(1)
}

/// The header facts the peer can tell now.
async fn header(conn: &Connection) -> Header {
    let link = conn.peer.link();
    let transport = link.as_ref().map(|l| format!("{} {}", l.scheme, l.remote)).unwrap_or_else(|| "no link".to_string());
    Header {
        group: conn.group.clone(),
        peer: conn.peer.peer_id().to_string(),
        unencrypted: link.as_ref().is_some_and(|l| l.scheme == "tcp"),
        transport,
        members: conn.peer.linked_members().await.len(),
        trees: !conn.content.tree_members().await.unwrap_or_default().is_empty(),
    }
}

/// Reads the space's files and the member counts again, unless a read already runs.
fn refresh(conn: &Connection, space: &str, updates: &mpsc::UnboundedSender<Update>, busy: &Arc<AtomicBool>) {
    if space.is_empty() || busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let (files, content, peer, space, updates, busy) =
        (conn.files.clone(), conn.content.clone(), conn.peer.clone(), space.to_string(), updates.clone(), busy.clone());
    tokio::spawn(async move {
        let count = peer.members().await.len();
        let trees = !content.tree_members().await.unwrap_or_default().is_empty();
        let _ = updates.send(Update::Members { count, trees });
        match files.list(&space).await {
            Ok(listed) => {
                let _ = updates.send(Update::Listed(listed));
            }
            Err(e) => {
                let _ = updates.send(Update::Notice(format!("reading the space: {e}")));
            }
        }
        busy.store(false, Ordering::SeqCst);
    });
}

/// A progress callback that sends at most ten updates a second.
fn throttled(updates: mpsc::UnboundedSender<Update>, what: String, total: u64) -> impl FnMut(u64) + Send + 'static {
    let mut last = Instant::now() - Duration::from_secs(1);
    move |done| {
        if last.elapsed() >= Duration::from_millis(100) || done >= total {
            last = Instant::now();
            let _ = updates.send(Update::Progress(format!(
                "{what}: {} of {}",
                spacewalk::sanitize::size(done),
                spacewalk::sanitize::size(total)
            )));
        }
    }
}

/// Runs a confirmed action and reports it.
fn run_action(conn: &Connection, dir: &Path, space: &str, action: Action, updates: &mpsc::UnboundedSender<Update>) {
    let (files, dir, space, updates) = (conn.files.clone(), dir.to_path_buf(), space.to_string(), updates.clone());
    tokio::spawn(async move {
        let (mut ok, mut kept, mut errors) = (0usize, 0usize, Vec::new());
        match action {
            Action::Share(paths) => {
                let n = paths.len();
                for (i, p) in paths.iter().enumerate() {
                    let total = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let what = format!("sharing {}/{n} {}", i + 1, p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default());
                    match files.publish(&space, &dir, p, throttled(updates.clone(), what, total)).await {
                        Ok(_) => ok += 1,
                        Err(e) => errors.push(e.to_string()),
                    }
                }
                report(&updates, format!("shared {ok} file(s) into {space}"), kept, &errors);
            }
            Action::Download { keys, overwrite } => {
                let n = keys.len();
                for (i, k) in keys.iter().enumerate() {
                    let what = format!("downloading {}/{n} {}", i + 1, k.rsplit('/').next().unwrap_or(k));
                    let total = files.list(&space).await.ok().and_then(|l| l.into_iter().find(|f| &f.key == k)).map(|f| f.entry.size).unwrap_or(0);
                    match files.download(&space, k, &dir, overwrite, throttled(updates.clone(), what, total)).await {
                        Ok(_) => ok += 1,
                        Err(ShareError::Exists(_)) => kept += 1,
                        Err(e) => errors.push(e.to_string()),
                    }
                }
                report(&updates, format!("downloaded {ok} file(s) into {}", dir.display()), kept, &errors);
            }
            Action::Withdraw(keys) => {
                for k in &keys {
                    let _ = updates.send(Update::Progress(format!("withdrawing {k}")));
                    match files.withdraw(&space, k).await {
                        Ok(()) => ok += 1,
                        Err(e) => errors.push(e.to_string()),
                    }
                }
                report(&updates, format!("withdrew {ok} file(s) from {space}"), kept, &errors);
            }
        }
    });
}

fn report(updates: &mpsc::UnboundedSender<Update>, done: String, kept: usize, errors: &[String]) {
    let kept = if kept > 0 { format!("; kept {kept} existing file(s) (o replaces them)") } else { String::new() };
    for e in errors {
        tracing::warn!(error = %e, "action failed");
    }
    tracing::info!("{done}{kept}");
    let _ = updates.send(match errors.first() {
        None => Update::Done(format!("{done}{kept}")),
        Some(first) => Update::Failed(format!("{done}{kept}; {} failed: {first}", errors.len())),
    });
}

enum Input {
    Key(event::KeyEvent),
    Redraw,
}

/// Finds the spaces for the picker and reports them.
fn list_spaces(conn: &Connection, updates: &mpsc::UnboundedSender<Update>) {
    let (peer, content, pdt, files, spaces, group, updates) =
        (conn.peer.clone(), conn.content.clone(), conn.pdt.clone(), conn.files.clone(), conn.spaces.clone(), conn.group.clone(), updates.clone());
    tokio::spawn(async move {
        let probe = Connection { peer, content, pdt, files, group, spaces };
        let _ = probe.peer.space("pdt").pull().await;
        for _ in 0..3 {
            let _ = updates.send(Update::Spaces(spacewalk::connect::known_spaces(&probe).await));
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn run_tui(conn: &Connection, dir: &Path, initial: String, show_hidden: bool, no_color: bool) -> ExitCode {
    let mut space = initial;
    let mut app = App::new(dir, &space, header(conn).await, conn.files.max_bytes());
    app.local.show_hidden = show_hidden;
    app.refresh_local();
    let theme = Theme { plain: no_color || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) };
    let (input_tx, mut input) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = stop.clone();
    std::thread::spawn(move || {
        while !reader_stop.load(Ordering::SeqCst) {
            if !event::poll(Duration::from_millis(200)).unwrap_or(false) {
                continue;
            }
            let sent = match event::read() {
                Ok(Event::Key(k)) => input_tx.send(Input::Key(k)),
                Ok(Event::Resize(..)) => input_tx.send(Input::Redraw),
                _ => Ok(()),
            };
            if sent.is_err() {
                break;
            }
        }
    });
    let (updates_tx, mut updates) = mpsc::unbounded_channel();
    let reading = Arc::new(AtomicBool::new(false));
    let mut terminal = ratatui::init();
    if space.is_empty() {
        app.open_picker();
        list_spaces(conn, &updates_tx);
    }
    refresh(conn, &space, &updates_tx, &reading);
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut result = ExitCode::SUCCESS;
    loop {
        app.now_ms = now_ms();
        if let Err(e) = terminal.draw(|f| ui::draw(f, &app, theme)) {
            ratatui::restore();
            eprintln!("spacewalk: the terminal: {e}");
            result = ExitCode::from(1);
            break;
        }
        #[cfg(unix)]
        let term = async {
            match terminate.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! {
            Some(i) = input.recv() => match i {
                Input::Key(k) => match app.on_key(k) {
                    Some(Command::Quit) => break,
                    Some(Command::Refresh) => refresh(conn, &space, &updates_tx, &reading),
                    Some(Command::Run(action)) => run_action(conn, dir, &space, action, &updates_tx),
                    Some(Command::ListSpaces) => list_spaces(conn, &updates_tx),
                    Some(Command::SetSpace(chosen)) => {
                        tracing::info!(space = %chosen, "space chosen");
                        space = chosen;
                        let _ = conn.peer.space(&space).pull().await;
                        refresh(conn, &space, &updates_tx, &reading);
                    }
                    None => {}
                },
                Input::Redraw => {}
            },
            Some(u) = updates.recv() => {
                let finished = matches!(u, Update::Done(_) | Update::Failed(_));
                app.apply(u);
                if finished {
                    refresh(conn, &space, &updates_tx, &reading);
                }
            }
            _ = tick.tick() => {
                if !app.busy {
                    refresh(conn, &space, &updates_tx, &reading);
                }
                let files = conn.files.clone();
                tokio::spawn(async move { files.renew_records().await });
                let fresh = header(conn).await;
                app.header.transport = fresh.transport;
                app.header.unencrypted = fresh.unencrypted;
            }
            () = term => break,
        }
    }
    stop.store(true, Ordering::SeqCst);
    ratatui::restore();
    result
}
