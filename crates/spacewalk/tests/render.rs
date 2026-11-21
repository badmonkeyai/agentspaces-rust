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
//! The screen, drawn into ratatui's test backend: the header warnings, both panes, the local
//! state marks, a hostile key made safe, the one-pane layout, and the dialogs.

use std::path::{Path, PathBuf};

use agentspaces::wire::pdt::cid;
use agentspaces::wire::pdt::file_entry::{FileEntry, REGULAR};
use agentspaces_pdt::Listed;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use spacewalk::app::{App, Header, Update};
use spacewalk::ui::{Theme, draw};

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("spacewalk-render-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::write(root.join("data/report.csv"), b"a,b,c").unwrap();
    std::fs::write(root.join("README.md"), b"hello").unwrap();
    root
}

fn listed(relative: &str, size: u64, sharer: &str) -> Listed {
    Listed {
        key: format!("catalogue/{relative}"),
        relative: relative.to_string(),
        entry: FileEntry::new(&cid::of(relative.as_bytes(), cid::RAW), size, REGULAR, "text/plain").unwrap(),
        sharer: Some(sharer.to_string()),
        shared_at: Some(1_000),
        mine: false,
    }
}

fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| draw(f, app, Theme { plain: true })).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn app(root: &Path) -> App {
    let header = Header {
        group: "shop".to_string(),
        peer: "zPeerOfThisMachine".to_string(),
        transport: "tcp 127.0.0.1:7760".to_string(),
        members: 2,
        trees: true,
        unencrypted: true,
    };
    let mut app = App::new(root, "catalogue", header, 64 << 20);
    app.now_ms = 121_000;
    app.apply(Update::Listed(vec![
        listed("README.md", 5, "zAnaPeer"),
        listed("model.json", 1_150_000, "zAnaPeer"),
        listed("evil\u{1b}[2J.txt", 3, "zMallory"),
    ]));
    app
}

#[test]
fn both_panes_draw_with_their_marks() {
    let root = scratch("panes");
    let app = app(&root);
    let text = screen(&app, 110, 16);
    assert!(text.contains("spacewalk"), "{text}");
    assert!(text.contains("shop / catalogue"), "{text}");
    assert!(text.contains("development share: unencrypted"), "{text}");
    assert!(text.contains("data/"), "{text}");
    assert!(text.contains("README.md"), "{text}");
    assert!(text.contains("model.json"), "{text}");
    assert!(text.contains("1.1 MiB"), "{text}");
    assert!(text.contains("= [ ] README.md"), "the same-size local copy is marked: {text}");
    assert!(text.contains("evil?[2J.txt"), "the escape is drawn harmless: {text}");
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("2m"), "{text}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_narrow_terminal_shows_one_pane_and_dialogs_draw() {
    let root = scratch("narrow");
    let mut app = app(&root);
    let narrow = screen(&app, 50, 14);
    assert!(narrow.contains("README.md") && !narrow.contains("model.json"), "{narrow}");
    app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    let narrow = screen(&app, 50, 14);
    assert!(narrow.contains("model.json"), "{narrow}");
    app.on_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    let dialog = screen(&app, 100, 20);
    assert!(dialog.contains("Download") && dialog.contains("[o]verwrite existing"), "{dialog}");
    app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    let help = screen(&app, 100, 24);
    assert!(help.contains("spacewalk keys") && help.contains("withdraw"), "{help}");
    let _ = std::fs::remove_dir_all(&root);
}
