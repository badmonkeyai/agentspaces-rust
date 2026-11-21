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

//! FastCDC in the per-byte 2016 form with normalized chunking level 2 and cut-point skipping
//! (annex H, blobs): minimum 16 KiB, average 64 KiB, maximum 256 KiB. GEAR[i] is the big-endian
//! u64 of the first 8 bytes of sha2-256 of the single byte i; the rolling hash is
//! h = (h << 1) + GEAR[b] over u64; MaskS applies before the average size and MaskL after it; a
//! cut falls at the first position at or past the minimum where (h & mask) == 0, else at the
//! maximum.

use std::io::{self, Read};
use std::sync::OnceLock;

/// The smallest chunk (except the last).
pub const MIN_SIZE: usize = 16 * 1024;
/// The average chunk.
pub const AVG_SIZE: usize = 64 * 1024;
/// The largest chunk.
pub const MAX_SIZE: usize = 256 * 1024;
/// The mask before the average size.
pub const MASK_S: u64 = 0xFFFF_C000_0000_0000;
/// The mask after the average size.
pub const MASK_L: u64 = 0xFFFC_0000_0000_0000;

/// The Gear table.
pub fn gear() -> &'static [u64; 256] {
    static GEAR: OnceLock<[u64; 256]> = OnceLock::new();
    GEAR.get_or_init(|| {
        let mut table = [0u64; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let digest = super::sha256(&[i as u8]);
            let mut first = [0u8; 8];
            first.copy_from_slice(&digest[..8]);
            *slot = u64::from_be_bytes(first);
        }
        table
    })
}

/// The length of the chunk at the start of `data`.
pub fn cut(data: &[u8]) -> usize {
    let mut n = data.len();
    if n <= MIN_SIZE {
        return n;
    }
    let mut normal = AVG_SIZE;
    if n >= MAX_SIZE {
        n = MAX_SIZE;
    } else if n <= normal {
        normal = n;
    }
    let gear = gear();
    let mut h: u64 = 0;
    let mut i = MIN_SIZE;
    while i < normal {
        h = (h << 1).wrapping_add(gear[data[i] as usize]);
        if h & MASK_S == 0 {
            return i;
        }
        i += 1;
    }
    while i < n {
        h = (h << 1).wrapping_add(gear[data[i] as usize]);
        if h & MASK_L == 0 {
            return i;
        }
        i += 1;
    }
    i
}

/// The end offset of every chunk of `data`, ascending; the last equals the length.
pub fn cuts(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        offset += cut(&data[offset..]);
        out.push(offset);
    }
    out
}

/// Chunks a stream through a buffer of twice the maximum chunk size.
pub struct Chunker<R> {
    source: R,
    buffer: Vec<u8>,
    start: usize,
    eof: bool,
}

impl<R: Read> Chunker<R> {
    /// A chunker over `source`.
    pub fn new(source: R) -> Self {
        Chunker {
            source,
            buffer: Vec::with_capacity(2 * MAX_SIZE),
            start: 0,
            eof: false,
        }
    }

    /// The next chunk, or `None` at the end of the stream.
    pub fn next_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.start > 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        while !self.eof && self.buffer.len() < 2 * MAX_SIZE {
            let have = self.buffer.len();
            self.buffer.resize(2 * MAX_SIZE, 0);
            match self.source.read(&mut self.buffer[have..]) {
                Ok(0) => {
                    self.buffer.truncate(have);
                    self.eof = true;
                }
                Ok(read) => self.buffer.truncate(have + read),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => self.buffer.truncate(have),
                Err(e) => {
                    self.buffer.truncate(have);
                    return Err(e);
                }
            }
        }
        if self.buffer.is_empty() {
            return Ok(None);
        }
        let length = cut(&self.buffer);
        self.start = length;
        Ok(Some(self.buffer[..length].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gear_ends_match_annex_h() {
        assert_eq!(gear()[0], 0x6e34_0b9c_ffb3_7a98);
        assert_eq!(gear()[255], 0xa810_0ae6_aa19_40d0);
    }

    #[test]
    fn stream_cuts_match_whole_cuts() {
        let data: Vec<u8> = (0..900_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let mut chunker = Chunker::new(&data[..]);
        let mut ends = Vec::new();
        let mut at = 0;
        while let Some(chunk) = chunker.next_chunk().unwrap() {
            at += chunk.len();
            ends.push(at);
        }
        assert_eq!(ends, cuts(&data));
    }
}
