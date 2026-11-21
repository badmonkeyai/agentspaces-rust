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
//! Drawing the application: the header, the two panes (one below 60 columns), the progress and
//! status lines, the key line, and the dialogs. Every remote string goes through
//! [`sanitize`](crate::sanitize) before it reaches the terminal.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::app::{App, Dialog, LocalState, Pane};
use crate::sanitize;

/// The colours, or none.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Whether colour is off (`--no-color`, `NO_COLOR`).
    pub plain: bool,
}

impl Theme {
    fn style(self, color: Color) -> Style {
        if self.plain { Style::default() } else { Style::default().fg(color) }
    }

    fn selected(self) -> Style {
        if self.plain {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD)
        }
    }
}

const HELP: &[(&str, &str)] = &[
    ("tab", "switch between the local pane and the space pane"),
    ("up/down, j/k", "move; PgUp/PgDn, g/G jump"),
    ("enter, l", "open or close a directory (local pane)"),
    ("space", "mark or unmark the row"),
    ("s", "share the marked files, or the selected file or directory"),
    ("d", "download the marked or selected shared files into the directory"),
    ("x", "withdraw the marked or selected shared files from the space"),
    ("r", "read the space and the directory again"),
    ("c", "choose another space"),
    ("/", "filter both panes by path; enter keeps it, esc clears it"),
    (".", "show or hide dot files"),
    ("esc", "clear marks and the filter"),
    ("q, ctrl-c", "quit"),
];

/// Draws the whole screen.
pub fn draw(frame: &mut Frame, app: &App, theme: Theme) {
    let [header, body, progress, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_header(frame, app, theme, header);
    if body.width < 60 {
        match app.pane {
            Pane::Local => draw_local(frame, app, theme, body),
            Pane::Space => draw_space(frame, app, theme, body),
        }
    } else {
        let [left, right] = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);
        draw_local(frame, app, theme, left);
        draw_space(frame, app, theme, right);
    }
    let progress_text = match (&app.progress, app.filtering, app.filter.is_empty()) {
        (Some(p), _, _) => format!(" working: {}", sanitize::clean(p)),
        (None, true, _) => format!(" filter: {}_", sanitize::clean(&app.filter)),
        (None, false, false) => format!(" filter: {} (esc clears)", sanitize::clean(&app.filter)),
        _ => String::new(),
    };
    frame.render_widget(Paragraph::new(progress_text).style(theme.style(Color::Yellow)), progress);
    let status_style = if app.status_error { theme.style(Color::Red) } else { Style::default() };
    frame.render_widget(Paragraph::new(format!(" {}", sanitize::clean(&app.status))).style(status_style), status);
    let key_line = " tab pane  space mark  s share  d download  x withdraw  r refresh  c space  / filter  ? help  q quit";
    frame.render_widget(Paragraph::new(sanitize::fit(key_line, keys.width as usize)).style(theme.style(Color::DarkGray)), keys);
    match &app.dialog {
        Some(Dialog::Help) => draw_help(frame, theme),
        Some(Dialog::PickSpace { options, selected, input }) => draw_picker(frame, theme, options, *selected, input),
        Some(Dialog::Confirm { title, lines, action }) => {
            let download = matches!(action, crate::app::Action::Download { .. });
            draw_confirm(frame, theme, title, lines, download);
        }
        None => {}
    }
}

fn draw_header(frame: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let h = &app.header;
    let mut spans = vec![
        Span::styled(" spacewalk ", theme.style(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            " {} / {}  peer {}  members {}  {}",
            sanitize::fit(&h.group, 24),
            if app.space.is_empty() { "(choose a space: c)".to_string() } else { sanitize::clean(&app.space) },
            sanitize::fit(&h.peer, 12),
            h.members,
            sanitize::clean(&h.transport),
        )),
    ];
    if h.unencrypted {
        spans.push(Span::styled("  development share: unencrypted", theme.style(Color::Yellow)));
    }
    if !h.trees {
        spans.push(Span::styled("  no member serves trees yet", theme.style(Color::Red)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn pane_block(title: String, focused: bool, theme: Theme) -> Block<'static> {
    let style = if focused { theme.style(Color::Cyan) } else { theme.style(Color::DarkGray) };
    Block::default().borders(Borders::ALL).border_style(style).title(title)
}

fn draw_local(frame: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let width = area.width.saturating_sub(4) as usize;
    let rows = app.visible_local();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| {
            let mark = if app.marked_local.contains(&r.path) { "[x] " } else if r.is_dir || r.is_link { "    " } else { "[ ] " };
            let name = r.relative.rsplit('/').next().unwrap_or(&r.relative);
            let indent = "  ".repeat(r.depth);
            let (icon, suffix, style) = if r.is_dir {
                (if r.expanded { "v " } else { "> " }, "/".to_string(), theme.style(Color::Blue))
            } else if r.is_link {
                ("  ", " (link, not shared)".to_string(), theme.style(Color::DarkGray))
            } else {
                ("  ", String::new(), Style::default())
            };
            let size = if r.is_dir || r.is_link { String::new() } else { sanitize::size(r.size) };
            let left = sanitize::fit(&format!("{indent}{icon}{mark}{name}{suffix}"), width.saturating_sub(size.len() + 1));
            let pad = width.saturating_sub(unicode_width::UnicodeWidthStr::width(left.as_str()) + size.len());
            ListItem::new(Line::from(vec![Span::styled(left, style), Span::raw(" ".repeat(pad)), Span::raw(size)]))
        })
        .collect();
    let title = format!(" {} ", sanitize::fit(&app.local.root().display().to_string(), width.saturating_sub(2)));
    let list = List::new(items)
        .block(pane_block(title, app.pane == Pane::Local, theme))
        .highlight_style(if app.pane == Pane::Local { theme.selected() } else { Style::default() });
    let mut state = ListState::default().with_selected((!rows.is_empty()).then_some(app.local_sel));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_space(frame: &mut Frame, app: &App, theme: Theme, area: Rect) {
    let width = area.width.saturating_sub(4) as usize;
    let rows = app.visible_remote();
    let items: Vec<ListItem> = if rows.is_empty() {
        vec![ListItem::new(Span::styled(
            if app.remote.is_empty() { "nothing shared in this space yet" } else { "no shared file matches the filter" },
            theme.style(Color::DarkGray),
        ))]
    } else {
        rows.iter()
            .map(|l| {
                let mark = if app.marked_remote.contains(&l.key) { "[x] " } else { "[ ] " };
                let (state, state_style) = match app.local_state(l) {
                    LocalState::Absent => (" ", Style::default()),
                    LocalState::Same => ("=", theme.style(Color::Green)),
                    LocalState::Differs => ("~", theme.style(Color::Yellow)),
                };
                let who = if l.mine {
                    "you".to_string()
                } else {
                    l.sharer.as_deref().map(|s| sanitize::fit(s, 8)).unwrap_or_else(|| "?".to_string())
                };
                let age = l.shared_at.map(|t| sanitize::age(t, app.now_ms)).unwrap_or_default();
                let right = format!("{:>9} {:>8} {:>4}", sanitize::size(l.entry.size), who, age);
                let left = sanitize::fit(&format!("{mark}{}", l.relative), width.saturating_sub(right.len() + 3));
                let pad = width.saturating_sub(unicode_width::UnicodeWidthStr::width(left.as_str()) + right.len() + 2);
                ListItem::new(Line::from(vec![
                    Span::styled(state, state_style),
                    Span::raw(" "),
                    Span::raw(left),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(right, theme.style(Color::Gray)),
                ]))
            })
            .collect()
    };
    let title = format!(" {} (file-share, {} file(s)) ", sanitize::clean(&app.space), app.remote.len());
    let list = List::new(items)
        .block(pane_block(title, app.pane == Pane::Space, theme))
        .highlight_style(if app.pane == Pane::Space { theme.selected() } else { Style::default() });
    let mut state = ListState::default().with_selected((!rows.is_empty()).then_some(app.remote_sel));
    frame.render_stateful_widget(list, area, &mut state);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2)).max(10);
    let h = height.min(area.height.saturating_sub(2)).max(3);
    Rect { x: area.x + (area.width.saturating_sub(w)) / 2, y: area.y + (area.height.saturating_sub(h)) / 2, width: w, height: h }
}

/// `text` cut into rows of at most `width` columns.
fn hard_wrap(text: &str, width: usize) -> Vec<String> {
    use unicode_width::UnicodeWidthChar;
    let mut rows = vec![String::new()];
    let mut used = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > width && used > 0 {
            rows.push(String::new());
            used = 0;
        }
        if let Some(row) = rows.last_mut() {
            row.push(c);
        }
        used += w;
    }
    rows
}

fn draw_confirm(frame: &mut Frame, theme: Theme, title: &str, lines: &[String], download: bool) {
    // rows wrapped here, so the height is exact and the choices line is never cut off
    let width = 76.min(frame.area().width.saturating_sub(2)).max(10);
    let inner = usize::from(width.saturating_sub(2)).max(1);
    let mut text: Vec<Line> = lines.iter().flat_map(|l| hard_wrap(&sanitize::clean(l), inner)).map(Line::raw).collect();
    text.push(Line::raw(""));
    let choices = if download { "[y]es   [o]verwrite existing   [n]o" } else { "[y]es   [n]o" };
    text.push(Line::styled(choices, theme.style(Color::Cyan).add_modifier(Modifier::BOLD)));
    let area = centered(frame.area(), width, text.len() as u16 + 2);
    frame.render_widget(Clear, area);
    let block = Block::default().borders(Borders::ALL).title(format!(" {title} ")).border_style(theme.style(Color::Cyan));
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_picker(frame: &mut Frame, theme: Theme, options: &[String], selected: usize, input: &str) {
    let mut text: Vec<Line> = vec![Line::raw("Choose the space to share into, or type a name:"), Line::raw("")];
    if options.is_empty() {
        text.push(Line::styled("  looking for the group's spaces…", theme.style(Color::DarkGray)));
    }
    for (i, o) in options.iter().enumerate() {
        let line = format!("  {}", sanitize::fit(o, 60));
        text.push(if i == selected && input.is_empty() { Line::styled(line, theme.selected()) } else { Line::raw(line) });
    }
    text.push(Line::raw(""));
    text.push(Line::from(vec![Span::raw("name: "), Span::styled(format!("{}_", sanitize::clean(input)), theme.style(Color::Cyan))]));
    text.push(Line::styled("up/down choose, type a name, enter opens it", theme.style(Color::DarkGray)));
    let area = centered(frame.area(), 70, text.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Space ")), area);
}

fn draw_help(frame: &mut Frame, theme: Theme) {
    let mut text: Vec<Line> = HELP
        .iter()
        .map(|(k, v)| Line::from(vec![Span::styled(format!("{k:>14}  "), theme.style(Color::Cyan)), Span::raw(*v)]))
        .collect();
    text.push(Line::raw(""));
    text.push(Line::raw("  = the local copy has the same size   ~ the local copy differs"));
    text.push(Line::raw(""));
    text.push(Line::styled("  any key closes this help", theme.style(Color::DarkGray)));
    let area = centered(frame.area(), 80, text.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" spacewalk keys ")), area);
}
