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

//! The blocks a peer holds: its own (written here, or stored with `put_block`) and those it
//! fetched for entries it read, each within its own byte budget.
//!
//! Own blocks are never displaced: once their budget is used, a further own block is refused and
//! the write that needed it fails. Fetched blocks are a cache: the oldest is evicted to make room,
//! so blocks fetched for other members' entries can never fill the store and refuse this peer's own
//! writes. A block over the single-block cap is refused either way: no binding could ever deliver
//! it (Java `BlockExchange.DEFAULT_MAX_BLOCK_BYTES`).
//!
//! A block an entry pinned is released when the entry is collected (as in Java, a collected entry
//! unpins its block), unless a held entry still names it or it was stored with `put_block`, which
//! pins it for the peer's life.

use std::collections::{HashMap, HashSet, VecDeque};

use agentspaces_wire::limits::MAX_FRAME_BYTES;

/// The largest block a peer holds or serves: a frame's cap less 64 KiB, so a BLOCK answer (and
/// the RELAY_FRAME a seed wraps it in) still fits a frame (Java
/// `BlockExchange.DEFAULT_MAX_BLOCK_BYTES`).
pub(super) const MAX_SINGLE_BLOCK_BYTES: usize = MAX_FRAME_BYTES - 64 * 1024;

/// The bytes of own blocks a peer holds.
pub(super) const MAX_OWN_BLOCK_BYTES: usize = 256 * 1024 * 1024;

/// The bytes of fetched blocks a peer keeps (the oldest evicted first).
pub(super) const MAX_FETCHED_BLOCK_BYTES: usize = 128 * 1024 * 1024;

/// Why a block was not held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// The block is over [`MAX_SINGLE_BLOCK_BYTES`].
    Oversize,
    /// The own-block budget is used up.
    Full,
}

/// Own and fetched blocks by id. See the [module docs](self).
#[derive(Debug)]
pub(super) struct BlockStore {
    own: HashMap<String, Vec<u8>>,
    own_bytes: usize,
    own_budget: usize,
    /// Own blocks stored with `put_block`: never released.
    pinned: HashSet<String>,
    fetched: HashMap<String, Vec<u8>>,
    fetched_order: VecDeque<String>,
    fetched_bytes: usize,
    fetched_budget: usize,
}

impl Default for BlockStore {
    fn default() -> Self {
        Self::new(MAX_OWN_BLOCK_BYTES, MAX_FETCHED_BLOCK_BYTES)
    }
}

impl BlockStore {
    /// An empty store with these budgets.
    pub fn new(own_budget: usize, fetched_budget: usize) -> Self {
        Self {
            own: HashMap::new(),
            own_bytes: 0,
            own_budget,
            pinned: HashSet::new(),
            fetched: HashMap::new(),
            fetched_order: VecDeque::new(),
            fetched_bytes: 0,
            fetched_budget,
        }
    }

    /// A held block, own or fetched.
    pub fn get(&self, cid: &str) -> Option<&Vec<u8>> {
        self.own.get(cid).or_else(|| self.fetched.get(cid))
    }

    /// Whether `cid` is one of this peer's own blocks.
    pub fn is_own(&self, cid: &str) -> bool {
        self.own.contains_key(cid)
    }

    /// Holds one of this peer's own blocks. A block already fetched becomes an own one.
    pub fn hold_own(&mut self, cid: String, data: Vec<u8>) -> Result<(), Refused> {
        if self.own.contains_key(&cid) {
            return Ok(());
        }
        if data.len() > MAX_SINGLE_BLOCK_BYTES {
            return Err(Refused::Oversize);
        }
        let total = self.own_bytes.saturating_add(data.len());
        if total > self.own_budget {
            return Err(Refused::Full);
        }
        if let Some(fetched) = self.fetched.remove(&cid) {
            self.fetched_bytes = self.fetched_bytes.saturating_sub(fetched.len());
            self.fetched_order.retain(|held| *held != cid);
        }
        self.own_bytes = total;
        self.own.insert(cid, data);
        Ok(())
    }

    /// Holds one of this peer's own blocks for good (`put_block`): [`BlockStore::release`] keeps
    /// it.
    pub fn pin_own(&mut self, cid: String, data: Vec<u8>) -> Result<(), Refused> {
        self.hold_own(cid.clone(), data)?;
        self.pinned.insert(cid);
        Ok(())
    }

    /// Drops a block no held entry names any longer (its entry was collected), own or fetched;
    /// a pinned own block stays. Whether anything was dropped.
    pub fn release(&mut self, cid: &str) -> bool {
        if self.pinned.contains(cid) {
            return false;
        }
        if let Some(own) = self.own.remove(cid) {
            self.own_bytes = self.own_bytes.saturating_sub(own.len());
            return true;
        }
        if let Some(fetched) = self.fetched.remove(cid) {
            self.fetched_bytes = self.fetched_bytes.saturating_sub(fetched.len());
            self.fetched_order.retain(|held| held != cid);
            return true;
        }
        false
    }

    /// Keeps a fetched block, evicting the oldest fetched ones to make room; whether it is held
    /// (a block over the cap, or larger than the whole fetched budget, is not).
    pub fn hold_fetched(&mut self, cid: String, data: Vec<u8>) -> bool {
        if self.get(&cid).is_some() {
            return true;
        }
        if data.len() > MAX_SINGLE_BLOCK_BYTES || data.len() > self.fetched_budget {
            return false;
        }
        while self.fetched_bytes.saturating_add(data.len()) > self.fetched_budget {
            let Some(oldest) = self.fetched_order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.fetched.remove(&oldest) {
                self.fetched_bytes = self.fetched_bytes.saturating_sub(evicted.len());
            }
        }
        self.fetched_bytes = self.fetched_bytes.saturating_add(data.len());
        self.fetched_order.push_back(cid.clone());
        self.fetched.insert(cid, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_blocks_never_displace_or_refuse_own_ones() {
        let mut store = BlockStore::new(10, 6);
        assert_eq!(store.hold_own("own-a".into(), vec![1; 4]), Ok(()));
        // Fetched blocks fill their own budget; the oldest goes first.
        for (cid, byte) in [("f1", 1u8), ("f2", 2), ("f3", 3)] {
            assert!(store.hold_fetched(cid.into(), vec![byte; 3]));
        }
        assert!(
            store.get("f1").is_none(),
            "the oldest fetched block was evicted"
        );
        assert!(store.get("f2").is_some() && store.get("f3").is_some());
        assert!(
            store.get("own-a").is_some(),
            "an own block is never evicted"
        );
        // Own blocks still have their whole budget.
        assert_eq!(store.hold_own("own-b".into(), vec![2; 6]), Ok(()));
        assert_eq!(
            store.hold_own("own-c".into(), vec![3; 1]),
            Err(Refused::Full)
        );
        // A block larger than the fetched budget is not kept; nothing is evicted for it.
        assert!(!store.hold_fetched("huge".into(), vec![0; 7]));
        assert!(store.get("f2").is_some());
        // A fetched block written here becomes an own one.
        let mut promoted = BlockStore::new(10, 6);
        assert!(promoted.hold_fetched("same".into(), vec![5; 3]));
        assert_eq!(promoted.hold_own("same".into(), vec![5; 3]), Ok(()));
        assert!(
            promoted.hold_fetched("next".into(), vec![6; 6]),
            "its bytes left the cache"
        );
        assert!(promoted.get("same").is_some());
    }

    #[test]
    fn released_blocks_free_their_budget_but_pinned_ones_stay() {
        let mut store = BlockStore::new(8, 8);
        assert_eq!(store.hold_own("own".into(), vec![1; 8]), Ok(()));
        assert_eq!(
            store.hold_own("next".into(), vec![2; 1]),
            Err(Refused::Full)
        );
        assert!(store.release("own"));
        assert!(store.get("own").is_none());
        assert_eq!(
            store.hold_own("next".into(), vec![2; 1]),
            Ok(()),
            "its bytes are free"
        );
        assert_eq!(store.pin_own("put".into(), vec![3; 2]), Ok(()));
        assert!(!store.release("put"), "a put block stays");
        assert!(store.get("put").is_some());
        assert!(store.hold_fetched("f".into(), vec![4; 8]));
        assert!(store.release("f"));
        assert!(
            store.hold_fetched("g".into(), vec![5; 8]),
            "the cache has room again"
        );
        assert!(!store.release("unknown"));
    }

    #[test]
    fn a_block_over_the_single_block_cap_is_refused() {
        let mut store = BlockStore::new(usize::MAX, usize::MAX);
        let over = vec![0u8; MAX_SINGLE_BLOCK_BYTES + 1];
        assert_eq!(
            store.hold_own("over".into(), over.clone()),
            Err(Refused::Oversize)
        );
        assert!(!store.hold_fetched("over".into(), over));
        assert_eq!(
            store.hold_own("max".into(), vec![0u8; MAX_SINGLE_BLOCK_BYTES]),
            Ok(())
        );
    }
}
