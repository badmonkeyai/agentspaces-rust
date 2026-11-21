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
//! The application state and its key handling. Nothing here touches the terminal or the
//! network: a key yields a [`Command`] for the runtime, and the runtime's work comes back as
//! [`Update`]s, so the whole state machine is testable without either.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agentspaces_pdt::Listed;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::local::{LocalRow, LocalTree};
use crate::sanitize;

/// The most files one share action takes.
pub const MAX_FILES_PER_ACTION: usize = 1000;

/// Which pane has the focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    /// The local directory.
    Local,
    /// The space's shared files.
    Space,
}

/// Work the user confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Share these files.
    Share(Vec<PathBuf>),
    /// Download these keys into the root directory.
    Download {
        /// The keys.
        keys: Vec<String>,
        /// Replace existing files.
        overwrite: bool,
    },
    /// Remove these keys from the map.
    Withdraw(Vec<String>),
}

/// What the runtime should do after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run a confirmed action off the UI thread.
    Run(Action),
    /// Read the space's files again.
    Refresh,
    /// Leave.
    Quit,
    /// Find the spaces this member can name, for the picker.
    ListSpaces,
    /// Work in this space from now on.
    SetSpace(String),
}

/// What the runtime reports back.
#[derive(Debug, Clone, PartialEq)]
pub enum Update {
    /// The space's files, read again.
    Listed(Vec<Listed>),
    /// Progress of the running action.
    Progress(String),
    /// The action finished.
    Done(String),
    /// The action failed.
    Failed(String),
    /// A note for the status line that is no result.
    Notice(String),
    /// The spaces the picker offers.
    Spaces(Vec<String>),
    /// The members seen, and whether any other member serves trees.
    Members {
        /// Members linked.
        count: usize,
        /// Whether another member advertises the tree exchange.
        trees: bool,
    },
}

/// A dialog over the panes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    /// Confirm an action: `y` runs it, `o` runs a download that replaces files, `n` closes.
    Confirm {
        /// The title.
        title: String,
        /// The lines of the body.
        lines: Vec<String>,
        /// The action.
        action: Action,
    },
    /// The key help.
    Help,
    /// Choose the space: from the list, or a typed name.
    PickSpace {
        /// The spaces offered.
        options: Vec<String>,
        /// The selected option.
        selected: usize,
        /// A typed name, which wins over the selection.
        input: String,
    },
}

/// How a shared file compares with the local copy at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalState {
    /// No local file.
    Absent,
    /// A local file of the same size.
    Same,
    /// A local file of another size.
    Differs,
}

/// What the status line shows above the panes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// The group joined.
    pub group: String,
    /// This peer's id.
    pub peer: String,
    /// The transport of the link, as text.
    pub transport: String,
    /// Members linked.
    pub members: usize,
    /// Whether another member serves trees.
    pub trees: bool,
    /// Whether the link is an unencrypted development link.
    pub unencrypted: bool,
}

/// The application.
#[derive(Debug)]
pub struct App {
    /// The header facts.
    pub header: Header,
    /// The space.
    pub space: String,
    /// The focused pane.
    pub pane: Pane,
    /// The local tree.
    pub local: LocalTree,
    /// Its visible rows.
    pub local_rows: Vec<LocalRow>,
    /// The selected local row (in the filtered list).
    pub local_sel: usize,
    /// Marked local files.
    pub marked_local: BTreeSet<PathBuf>,
    /// The space's files.
    pub remote: Vec<Listed>,
    /// The selected space row (in the filtered list).
    pub remote_sel: usize,
    /// Marked keys.
    pub marked_remote: BTreeSet<String>,
    /// The filter text.
    pub filter: String,
    /// Whether keys go to the filter.
    pub filtering: bool,
    /// The open dialog.
    pub dialog: Option<Dialog>,
    /// The status message.
    pub status: String,
    /// Whether the status reports a failure.
    pub status_error: bool,
    /// The running action's progress.
    pub progress: Option<String>,
    /// Whether an action runs.
    pub busy: bool,
    /// Set once the user asked to leave while an action ran.
    pub quit_armed: bool,
    /// The size limit.
    pub max_bytes: u64,
    /// The clock, for ages (epoch milliseconds).
    pub now_ms: i64,
}

impl App {
    /// The application over `root` and `space`.
    pub fn new(root: &Path, space: &str, header: Header, max_bytes: u64) -> App {
        let local = LocalTree::new(root);
        let local_rows = local.rows();
        App {
            header,
            space: space.to_string(),
            pane: Pane::Local,
            local,
            local_rows,
            local_sel: 0,
            marked_local: BTreeSet::new(),
            remote: Vec::new(),
            remote_sel: 0,
            marked_remote: BTreeSet::new(),
            filter: String::new(),
            filtering: false,
            dialog: None,
            status: "tab switches panes, space marks, s shares, d downloads, ? for help".to_string(),
            status_error: false,
            progress: None,
            busy: false,
            quit_armed: false,
            max_bytes,
            now_ms: 0,
        }
    }

    /// Opens the space picker, the current space first among its options.
    pub fn open_picker(&mut self) -> Command {
        let options: Vec<String> = if self.space.is_empty() { Vec::new() } else { vec![self.space.clone()] };
        self.dialog = Some(Dialog::PickSpace { options, selected: 0, input: String::new() });
        Command::ListSpaces
    }

    /// Whether a space is chosen.
    pub fn has_space(&self) -> bool {
        !self.space.is_empty()
    }

    /// Reads the local tree again.
    pub fn refresh_local(&mut self) {
        self.local_rows = self.local.rows();
        self.clamp();
    }

    fn matches(&self, text: &str) -> bool {
        self.filter.is_empty() || text.to_lowercase().contains(&self.filter.to_lowercase())
    }

    /// The local rows the filter passes.
    pub fn visible_local(&self) -> Vec<&LocalRow> {
        self.local_rows.iter().filter(|r| r.is_dir || self.matches(&r.relative)).collect()
    }

    /// The shared files the filter passes.
    pub fn visible_remote(&self) -> Vec<&Listed> {
        self.remote.iter().filter(|l| self.matches(&l.relative)).collect()
    }

    /// How a shared file compares with the local file at its path.
    pub fn local_state(&self, listed: &Listed) -> LocalState {
        let Ok(path) = agentspaces_pdt::files::safe_relative(&listed.relative) else { return LocalState::Absent };
        match std::fs::symlink_metadata(self.local.root().join(path)) {
            Ok(m) if m.is_file() && m.len() == listed.entry.size => LocalState::Same,
            Ok(m) if m.is_file() => LocalState::Differs,
            _ => LocalState::Absent,
        }
    }

    fn clamp(&mut self) {
        let (l, r) = (self.visible_local().len(), self.visible_remote().len());
        self.local_sel = self.local_sel.min(l.saturating_sub(1));
        self.remote_sel = self.remote_sel.min(r.saturating_sub(1));
    }

    fn say(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.status_error = false;
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.status_error = true;
    }

    /// Applies what the runtime reports.
    pub fn apply(&mut self, update: Update) {
        match update {
            Update::Listed(files) => {
                let keys: BTreeSet<String> = files.iter().map(|f| f.key.clone()).collect();
                self.marked_remote.retain(|k| keys.contains(k));
                self.remote = files;
                self.clamp();
            }
            Update::Progress(text) => self.progress = Some(text),
            Update::Done(text) => {
                self.busy = false;
                self.progress = None;
                self.say(text);
                self.refresh_local();
            }
            Update::Failed(text) => {
                self.busy = false;
                self.progress = None;
                self.warn(text);
                self.refresh_local();
            }
            Update::Notice(text) => self.say(text),
            Update::Spaces(found) => {
                if let Some(Dialog::PickSpace { options, selected, .. }) = &mut self.dialog {
                    for f in found {
                        if !options.contains(&f) {
                            options.push(f);
                        }
                    }
                    options.sort();
                    *selected = (*selected).min(options.len().saturating_sub(1));
                }
            }
            Update::Members { count, trees } => {
                self.header.members = count;
                self.header.trees = trees;
            }
        }
    }

    fn move_by(&mut self, delta: isize) {
        let (sel, len) = match self.pane {
            Pane::Local => (&mut self.local_sel, self.local_rows.iter().filter(|r| r.is_dir || self.filter.is_empty() || r.relative.to_lowercase().contains(&self.filter.to_lowercase())).count()),
            Pane::Space => (&mut self.remote_sel, self.remote.iter().filter(|l| self.filter.is_empty() || l.relative.to_lowercase().contains(&self.filter.to_lowercase())).count()),
        };
        if len == 0 {
            *sel = 0;
            return;
        }
        let next = (*sel as isize + delta).clamp(0, len as isize - 1);
        *sel = next as usize;
    }

    fn selected_local(&self) -> Option<LocalRow> {
        self.visible_local().get(self.local_sel).map(|r| (*r).clone())
    }

    fn selected_remote(&self) -> Option<Listed> {
        self.visible_remote().get(self.remote_sel).map(|l| (*l).clone())
    }

    /// The files a share takes: the marked ones, else the selection (a directory's regular files,
    /// dot files and links skipped), at most [`MAX_FILES_PER_ACTION`].
    fn share_targets(&self) -> (Vec<PathBuf>, usize) {
        let roots: Vec<PathBuf> = if self.marked_local.is_empty() {
            self.selected_local().map(|r| r.path).into_iter().collect()
        } else {
            self.marked_local.iter().cloned().collect()
        };
        let mut files = Vec::new();
        let mut skipped = 0;
        let mut stack: Vec<PathBuf> = roots.into_iter().rev().collect();
        while let Some(p) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.file_type().is_symlink() {
                skipped += 1;
            } else if meta.is_dir() {
                let mut children: Vec<PathBuf> = std::fs::read_dir(&p)
                    .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
                    .unwrap_or_default();
                children.sort();
                for c in children.into_iter().rev() {
                    if c.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
                        skipped += 1;
                    } else {
                        stack.push(c);
                    }
                }
            } else if meta.is_file() {
                if files.len() >= MAX_FILES_PER_ACTION || meta.len() > self.max_bytes {
                    skipped += 1;
                } else {
                    files.push(p);
                }
            }
        }
        (files, skipped)
    }

    fn relative_of(&self, path: &Path) -> String {
        path.strip_prefix(self.local.root())
            .map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"))
            .unwrap_or_else(|_| path.display().to_string())
    }

    fn confirm_share(&mut self) {
        let (files, skipped) = self.share_targets();
        if files.is_empty() {
            self.warn(if skipped > 0 {
                format!("nothing to share: {skipped} item(s) skipped (links, dot files, or over the size limit)")
            } else {
                "select or mark a file or directory to share".to_string()
            });
            return;
        }
        let total: u64 = files.iter().filter_map(|f| std::fs::metadata(f).ok()).map(|m| m.len()).sum();
        let mut lines = vec![
            format!("share {} file(s), {}, into {} of {}:", files.len(), sanitize::size(total), self.space, self.header.group),
            String::new(),
        ];
        for f in files.iter().take(12) {
            lines.push(format!("  {}/{}", self.space, self.relative_of(f)));
        }
        if files.len() > 12 {
            lines.push(format!("  … and {} more", files.len() - 12));
        }
        if skipped > 0 {
            lines.push(format!("{skipped} item(s) skipped: links, dot files, or over {}", sanitize::size(self.max_bytes)));
        }
        lines.push(String::new());
        lines.push("Members fetch the bytes from this peer while spacewalk runs.".to_string());
        if !self.header.trees {
            lines.push("No other member serves trees: in the Groovy console, enable Configure peer > File sharing.".to_string());
        }
        self.dialog = Some(Dialog::Confirm { title: "Share".to_string(), lines, action: Action::Share(files) });
    }

    fn remote_targets(&self) -> Vec<Listed> {
        if self.marked_remote.is_empty() {
            self.selected_remote().into_iter().collect()
        } else {
            self.remote.iter().filter(|l| self.marked_remote.contains(&l.key)).cloned().collect()
        }
    }

    fn confirm_download(&mut self) {
        let targets = self.remote_targets();
        if targets.is_empty() {
            self.warn("select or mark a shared file to download");
            return;
        }
        let total: u64 = targets.iter().map(|l| l.entry.size).sum();
        let existing = targets.iter().filter(|l| self.local_state(l) != LocalState::Absent).count();
        let mut lines = vec![
            format!("download {} file(s), {}, into {}:", targets.len(), sanitize::size(total), self.local.root().display()),
            String::new(),
        ];
        for l in targets.iter().take(12) {
            lines.push(format!("  {}", sanitize::clean(&l.relative)));
        }
        if targets.len() > 12 {
            lines.push(format!("  … and {} more", targets.len() - 12));
        }
        lines.push(String::new());
        if existing > 0 {
            lines.push(format!("{existing} already exist here: y keeps them, o replaces them."));
        }
        let keys = targets.into_iter().map(|l| l.key).collect();
        self.dialog = Some(Dialog::Confirm { title: "Download".to_string(), lines, action: Action::Download { keys, overwrite: false } });
    }

    fn confirm_withdraw(&mut self) {
        let targets = self.remote_targets();
        if targets.is_empty() {
            self.warn("select or mark a shared file to withdraw");
            return;
        }
        let mut lines = vec![format!("remove {} file(s) from the {} file share:", targets.len(), self.space), String::new()];
        for l in targets.iter().take(12) {
            let by = if l.mine { String::new() } else { format!("  (shared by {})", sanitize::fit(l.sharer.as_deref().unwrap_or("another member"), 14)) };
            lines.push(format!("  {}{by}", sanitize::clean(&l.relative)));
        }
        lines.push(String::new());
        lines.push("Members that fetched a file keep their copy.".to_string());
        let keys = targets.into_iter().map(|l| l.key).collect();
        self.dialog = Some(Dialog::Confirm { title: "Withdraw".to_string(), lines, action: Action::Withdraw(keys) });
    }

    /// Handles one key; returns what the runtime must do.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Command> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Command::Quit);
        }
        if let Some(dialog) = self.dialog.take() {
            return match dialog {
                Dialog::Help => None,
                Dialog::PickSpace { options, mut selected, mut input } => match key.code {
                    KeyCode::Enter => {
                        let chosen = if input.trim().is_empty() { options.get(selected).cloned() } else { Some(input.trim().to_string()) };
                        match chosen.filter(|c| !c.contains('/')) {
                            Some(space) => {
                                self.space = space.clone();
                                self.remote.clear();
                                self.marked_remote.clear();
                                self.say(format!("working in {space}"));
                                Some(Command::SetSpace(space))
                            }
                            None => {
                                self.warn("type a space name (no '/'), or choose one from the list");
                                self.dialog = Some(Dialog::PickSpace { options, selected, input });
                                None
                            }
                        }
                    }
                    KeyCode::Esc if self.has_space() => None,
                    KeyCode::Esc => {
                        self.warn("choose a space to work in (type a name and press enter)");
                        self.dialog = Some(Dialog::PickSpace { options, selected, input });
                        None
                    }
                    code => {
                        match code {
                            KeyCode::Up => selected = selected.saturating_sub(1),
                            KeyCode::Down => selected = (selected + 1).min(options.len().saturating_sub(1)),
                            KeyCode::Backspace => {
                                input.pop();
                            }
                            KeyCode::Char(c) if !c.is_control() => input.push(c),
                            _ => {}
                        }
                        self.dialog = Some(Dialog::PickSpace { options, selected, input });
                        None
                    }
                },
                Dialog::Confirm { action, title, lines } => match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => self.start(action),
                    KeyCode::Char('o') if matches!(action, Action::Download { .. }) => {
                        let Action::Download { keys, .. } = action else { return None };
                        self.start(Action::Download { keys, overwrite: true })
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {
                        self.say("cancelled");
                        None
                    }
                    _ => {
                        self.dialog = Some(Dialog::Confirm { title, lines, action });
                        None
                    }
                },
            };
        }
        if self.filtering {
            match key.code {
                KeyCode::Enter => self.filtering = false,
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.clamp();
            return None;
        }
        match key.code {
            KeyCode::Char('q') => {
                if self.busy && !self.quit_armed {
                    self.quit_armed = true;
                    self.warn("an action is running; press q again to quit and drop it");
                    return None;
                }
                return Some(Command::Quit);
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.pane = if self.pane == Pane::Local { Pane::Space } else { Pane::Local };
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::Home | KeyCode::Char('g') => self.move_by(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_by(isize::MAX / 2),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if self.pane == Pane::Local => {
                if let Some(row) = self.selected_local().filter(|r| r.is_dir) {
                    self.local.toggle(&row.path);
                    self.refresh_local();
                }
            }
            KeyCode::Char(' ') => match self.pane {
                Pane::Local => {
                    if let Some(row) = self.selected_local().filter(|r| !r.is_link) {
                        if !self.marked_local.remove(&row.path) {
                            self.marked_local.insert(row.path);
                        }
                        self.move_by(1);
                    }
                }
                Pane::Space => {
                    if let Some(l) = self.selected_remote() {
                        if !self.marked_remote.remove(&l.key) {
                            self.marked_remote.insert(l.key);
                        }
                        self.move_by(1);
                    }
                }
            },
            KeyCode::Char('c') => return Some(self.open_picker()),
            KeyCode::Char('s' | 'd' | 'x') if !self.has_space() => {
                return Some(self.open_picker());
            }
            KeyCode::Char('s') if !self.busy => self.confirm_share(),
            KeyCode::Char('d') if !self.busy => self.confirm_download(),
            KeyCode::Char('x') if !self.busy => self.confirm_withdraw(),
            KeyCode::Char('s' | 'd' | 'x') => self.warn("an action is running; wait for it to finish"),
            KeyCode::Char('r') => {
                self.refresh_local();
                self.say("refreshing");
                return Some(Command::Refresh);
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                self.filter.clear();
            }
            KeyCode::Char('.') => {
                self.local.show_hidden = !self.local.show_hidden;
                self.refresh_local();
                self.say(if self.local.show_hidden { "showing dot files" } else { "hiding dot files" });
            }
            KeyCode::Char('?') => self.dialog = Some(Dialog::Help),
            KeyCode::Esc => {
                self.marked_local.clear();
                self.marked_remote.clear();
                self.filter.clear();
                self.clamp();
                self.say("marks and filter cleared");
            }
            _ => {}
        }
        None
    }

    fn start(&mut self, action: Action) -> Option<Command> {
        self.busy = true;
        self.quit_armed = false;
        self.progress = Some("starting".to_string());
        match &action {
            Action::Share(_) => self.marked_local.clear(),
            Action::Download { .. } | Action::Withdraw(_) => self.marked_remote.clear(),
        }
        Some(Command::Run(action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentspaces::wire::pdt::cid;
    use agentspaces::wire::pdt::file_entry::{FileEntry, REGULAR};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn listed(relative: &str, size: u64) -> Listed {
        Listed {
            key: format!("catalogue/{relative}"),
            relative: relative.to_string(),
            entry: FileEntry::new(&cid::of(relative.as_bytes(), cid::RAW), size, REGULAR, "text/plain").unwrap(),
            sharer: Some("zPeer".to_string()),
            shared_at: Some(0),
            mine: false,
        }
    }

    /// A directory of its own for each test, so tests running at once never share one.
    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("spacewalk-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("data/report.csv"), b"a,b,c").unwrap();
        std::fs::write(root.join("README.md"), b"hello").unwrap();
        root
    }

    #[test]
    fn share_asks_first_then_runs() {
        let root = scratch("share_asks_first_then_runs");
        let mut app = App::new(&root, "catalogue", Header { trees: true, ..Header::default() }, 1 << 20);
        // README.md is the second row; mark it and share
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.on_key(key(KeyCode::Char(' '))), None);
        assert_eq!(app.on_key(key(KeyCode::Char('s'))), None);
        let Some(Dialog::Confirm { lines, .. }) = &app.dialog else { panic!("a confirmation") };
        assert!(lines.iter().any(|l| l.contains("catalogue/README.md")), "{lines:?}");
        let cmd = app.on_key(key(KeyCode::Char('y')));
        assert_eq!(cmd, Some(Command::Run(Action::Share(vec![root.join("README.md")]))));
        assert!(app.busy && app.marked_local.is_empty());
        app.apply(Update::Done("shared 1 file".to_string()));
        assert!(!app.busy && app.status == "shared 1 file");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_shares_its_files_and_n_cancels() {
        let root = scratch("a_directory_shares_its_files_and_n_cancels");
        let mut app = App::new(&root, "catalogue", Header::default(), 1 << 20);
        app.on_key(key(KeyCode::Char('s')));
        let Some(Dialog::Confirm { action, lines, .. }) = &app.dialog else { panic!("a confirmation") };
        assert_eq!(action, &Action::Share(vec![root.join("data/report.csv")]));
        assert!(lines.iter().any(|l| l.contains("enable Configure peer")), "warns when nobody serves trees");
        assert_eq!(app.on_key(key(KeyCode::Char('n'))), None);
        assert!(app.dialog.is_none() && !app.busy);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn downloads_offer_to_replace_existing_files() {
        let root = scratch("downloads_offer_to_replace_existing_files");
        let mut app = App::new(&root, "catalogue", Header::default(), 1 << 20);
        app.apply(Update::Listed(vec![listed("README.md", 5), listed("new/plan.md", 10)]));
        assert_eq!(app.local_state(&app.remote[0]), LocalState::Same);
        assert_eq!(app.local_state(&app.remote[1]), LocalState::Absent);
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Char('d')));
        let Some(Dialog::Confirm { lines, .. }) = &app.dialog else { panic!("a confirmation") };
        assert!(lines.iter().any(|l| l.contains("o replaces them")), "{lines:?}");
        let cmd = app.on_key(key(KeyCode::Char('o')));
        let Some(Command::Run(Action::Download { keys, overwrite })) = cmd else { panic!("{cmd:?}") };
        assert!(overwrite);
        assert_eq!(keys, ["catalogue/README.md", "catalogue/new/plan.md"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_picker_chooses_or_takes_a_typed_name() {
        let root = scratch("the_picker_chooses_or_takes_a_typed_name");
        let mut app = App::new(&root, "", Header::default(), 1 << 20);
        assert_eq!(app.open_picker(), Command::ListSpaces);
        app.apply(Update::Spaces(vec!["orders".to_string(), "catalogue".to_string()]));
        assert_eq!(app.on_key(key(KeyCode::Esc)), None, "no space yet: the picker stays");
        assert!(matches!(app.dialog, Some(Dialog::PickSpace { .. })));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.on_key(key(KeyCode::Enter)), Some(Command::SetSpace("orders".to_string())));
        assert_eq!(app.space, "orders");
        app.open_picker();
        for c in "drafts".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.on_key(key(KeyCode::Enter)), Some(Command::SetSpace("drafts".to_string())));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn filter_quit_and_busy_rules() {
        let root = scratch("filter_quit_and_busy_rules");
        let mut app = App::new(&root, "catalogue", Header::default(), 1 << 20);
        app.apply(Update::Listed(vec![listed("a.txt", 1), listed("b.csv", 1)]));
        app.on_key(key(KeyCode::Char('/')));
        for c in "csv".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.visible_remote().len(), 1);
        app.busy = true;
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), None, "asks again while busy");
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Command::Quit));
        assert_eq!(app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), Some(Command::Quit));
        let _ = std::fs::remove_dir_all(&root);
    }
}
