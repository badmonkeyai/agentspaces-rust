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

//! Remote text made safe for a terminal: keys, names, and peer ids that other members chose.

use unicode_width::UnicodeWidthChar;

/// Whether a character could move the cursor, change the terminal, or reorder the text around
/// it: C0 and C1 controls, DEL, and the bidirectional overrides and isolates.
fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `text` with every unsafe character replaced by `?`.
pub fn clean(text: &str) -> String {
    text.chars().map(|c| if unsafe_char(c) { '?' } else { c }).collect()
}

/// `text` cleaned and cut to at most `width` terminal columns, with `…` when it was cut.
pub fn fit(text: &str, width: usize) -> String {
    let cleaned = clean(text);
    let total: usize = cleaned.chars().map(|c| c.width().unwrap_or(0)).sum();
    if total <= width {
        return cleaned;
    }
    let mut out = String::new();
    let mut used = 0;
    for c in cleaned.chars() {
        let w = c.width().unwrap_or(0);
        if used + w + 1 > width {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// A byte count in a short human form.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// How long ago `millis` was, from `now`, in a short form.
pub fn age(millis: i64, now: i64) -> String {
    let s = ((now - millis) / 1000).max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_overrides_are_removed() {
        assert_eq!(clean("a\u{1b}[2Jb"), "a?[2Jb");
        assert_eq!(clean("x\u{202E}gnp.exe"), "x?gnp.exe");
        assert_eq!(clean("tab\there\u{9b}"), "tab?here?");
        assert_eq!(clean("plain/ünïcode.md"), "plain/ünïcode.md");
    }

    #[test]
    fn fits_by_columns() {
        assert_eq!(fit("abcdef", 6), "abcdef");
        assert_eq!(fit("abcdefg", 6), "abcde…");
        assert_eq!(size(12_700), "12.4 KiB");
        assert_eq!(age(0, 125_000), "2m");
    }
}
