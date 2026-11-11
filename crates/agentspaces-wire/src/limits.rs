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

//! The protocol's fixed numbers: the wire version and every bound a receiver enforces on what a
//! hostile or buggy sender may assert. Each constant names its source (the SPEC section, the
//! Python client constant in `agentspaces-python`, and the Java constant it mirrors), so a change
//! on any side can be traced here.
//!
//! Durations are `i64` milliseconds, matching [`crate::time`] and the Java `long` millis they
//! mirror; sizes and counts are `usize`.
#![warn(missing_docs)]

/// The wire version every envelope carries and the only one a receiver accepts (SPEC §9, wire
/// version 3 since v0.1.15). A frame of any other version is dropped before
/// its signature is checked, and the drop never strikes the sender.
///
/// Python `wire.WIRE_VERSION`; Java `WireCodec.WIRE_VERSION`.
pub const WIRE_VERSION: u32 = 3;

/// The largest frame accepted or sent, in bytes (8 MiB): a stream length prefix beyond it is
/// hostile or corrupt, never legitimate. Also the bound every decoder input is held to.
///
/// Python `wire.MAX_FRAME_BYTES`; Java `TcpTransport.MAX_FRAME` / `TlsTcpTransport.MAX_FRAME`.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// The largest payload a record carries inline, in bytes (64 KiB); a larger payload travels as a
/// block or an artifact and the record carries a reference (SPEC §7.1).
///
/// Python `wire.INLINE_PAYLOAD_LIMIT`; Java `EntryRecord.INLINE_PAYLOAD_LIMIT`.
pub const INLINE_PAYLOAD_LIMIT: usize = 64 * 1024;

/// The largest epoch advance a remote claim may assert over the locally observed epoch (2^20). A
/// claim that jumps further is refused, so a hostile peer cannot burn the epoch space.
///
/// Python `wire.MAX_CLAIM_EPOCH_JUMP`; Java `ReplicatedSpace.MAX_CLAIM_EPOCH_JUMP`.
pub const MAX_CLAIM_EPOCH_JUMP: i64 = 1 << 20;

/// The longest TAKE hold a remote claim may assert beyond the receiver's clock, in milliseconds
/// (24 hours). An "eternal" claim beyond it is refused.
///
/// Python `wire.MAX_CLAIM_HOLD_MILLIS`; Java `ReplicatedSpace.MAX_CLAIM_HOLD_MILLIS`.
pub const MAX_CLAIM_HOLD_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// How far ahead of the receiver's wall clock a remote hybrid-logical-clock stamp may run before
/// it is ignored rather than merged, in milliseconds (10 minutes, the HLC clamp). A frame whose
/// stamp leads by more is dropped as "ahead" (SPEC §9).
///
/// Python `wire.MAX_HLC_SKEW_MILLIS`; Java `HybridLogicalClock.MAX_DRIFT_MILLIS`.
pub const MAX_HLC_SKEW_MILLIS: i64 = 10 * 60 * 1000;

/// How far in the past a frame's stamp may be before the frame is dropped as stale, in
/// milliseconds (5 minutes, SPEC §9).
///
/// Python `wire.MAX_FRAME_AGE_MILLIS`; Java `PeerNode.MAX_FRAME_AGE_MILLIS`.
pub const MAX_FRAME_AGE_MILLIS: i64 = 5 * 60 * 1000;

/// How many `(sender, stamp)` pairs the replay filter remembers (SPEC §9); the oldest
/// is forgotten first.
///
/// Python `wire.FRAME_FILTER_CAPACITY`; Java `PeerNode`'s recent-frames cache.
pub const FRAME_FILTER_CAPACITY: usize = 4096;

/// How far a signing time may lead the receiver's clock, in milliseconds (10 minutes, the HLC
/// drift ceiling): a certificate-covered record or claim stamped later is refused (SPEC §4.2,
/// v0.1.13, `AgentCertificates.verifyAt`).
///
/// Python `identity.MAX_DRIFT_MILLIS`; Java `HybridLogicalClock.MAX_DRIFT_MILLIS`.
pub const MAX_DRIFT_MILLIS: i64 = 10 * 60 * 1000;

/// The largest logical counter a remote stamp may carry, 2^16 (SPEC §9, v0.1.30): every merge,
/// order, and deduplication point refuses a remote stamp above it, and a local clock carries
/// into the next millisecond instead of passing it ([`crate::hlc::Hlc`]).
///
/// Python `wire.LOGICAL_LIMIT`; Java `HybridLogicalClock.LOGICAL_LIMIT`.
pub const LOGICAL_LIMIT: i32 = 1 << 16;

/// How far past `wall + MAX_DRIFT` a frame's stamp may run before the receiver treats it as an
/// attack rather than skew, in milliseconds (5 seconds, SPEC §9, v0.1.30). A frame at most this
/// far past the ceiling is dropped and counted as skewed; a state or claim within the ceiling plus
/// this margin merges (SPEC §7.3).
///
/// Python `wire.FAR_FUTURE_SKEW_MARGIN_MILLIS`; Java `PeerNode.FAR_FUTURE_SKEW_MARGIN_MILLIS`.
pub const SKEW_MARGIN_MILLIS: i64 = 5_000;

/// How far past `wall + MAX_DRIFT + SKEW_MARGIN` a verified state or claim may be stamped and
/// still be deferred rather than refused as hostile, in milliseconds (one hour, SPEC §7.3,
/// v0.1.30).
///
/// Python `wire.FAR_FUTURE_HOSTILE_MILLIS`; Java `ReplicatedSpace.FAR_FUTURE_HOSTILE_MILLIS`.
pub const FAR_FUTURE_HOSTILE_MILLIS: i64 = 60 * 60 * 1000;

/// The longest stamp text, in UTF-16 code units (SPEC §9, v0.1.31): a stamp travels as one
/// definite CBOR text, and a longer text travels only in Jackson's chunks, which no stamp uses.
///
/// Python `wire.MAX_STAMP_UNITS`; Java `HlcTimestamp.MAX_STAMP_UNITS`.
pub const MAX_STAMP_UNITS: usize = 3996;

/// The longest node a clock stamps with, in UTF-16 code units (SPEC §9, v0.1.31):
/// [`MAX_STAMP_UNITS`] less the longest physical part (19 digits), the longest logical part (10
/// digits), and the two colons, so every stamp a clock issues fits one definite text.
///
/// Python `wire.MAX_NODE_UNITS`; Java `HlcTimestamp.MAX_NODE_UNITS`.
pub const MAX_NODE_UNITS: usize = MAX_STAMP_UNITS - 31;

/// How many distinct refused states and claims, and as many deferred ones, a replica remembers so
/// a re-offer counts once (SPEC §7.3, v0.1.30); past the bound the least recently offered key is
/// forgotten first.
///
/// Python `peer.REFUSED_STAMPS_CAPACITY`; Java `ReplicatedSpace`'s refused-offer cache.
pub const REFUSED_OFFERS_CAPACITY: usize = 4096;

/// A card whose canonical encoding is more than this many bytes travels as a stub whose large
/// parts sit in a content-swarm document (SPEC §6.1a.5, v0.1.32): the inline limit of a payload.
///
/// Java `CardSpill.SPILL_THRESHOLD_BYTES`; golden `card_spill_threshold_bytes`.
pub const CARD_SPILL_THRESHOLD_BYTES: usize = 65_536;

/// A publisher warns once a card's encoding passes this many bytes, 56 KiB (SPEC §6.1a.5).
///
/// Java `CardSpill.WARN_THRESHOLD_BYTES`; golden `card_spill_warn_bytes`.
pub const CARD_SPILL_WARN_BYTES: usize = 57_344;

/// The default bound on the advertisements one cache holds (SPEC §6.3), multiplied by four on a
/// peer with the RENDEZVOUS role.
///
/// Java `AdCache.DEFAULT_MAX_ENTRIES`.
pub const AD_CACHE_MAX_ENTRIES: usize = 8_192;

/// The default byte budget of one advertisement cache, 32 MiB: the sum of the lengths of the
/// cached advertisements' canonical encodings (SPEC §6.3, v0.1.32), multiplied by four on a peer
/// with the RENDEZVOUS role.
///
/// Java `AdCache.DEFAULT_MAX_BYTES`.
pub const AD_CACHE_MAX_BYTES: usize = 33_554_432;

/// The deepest container nesting the CBOR decoder accepts: at most 64 arrays or maps
/// nested inside one another. Hostile deep nesting would otherwise overflow the stack; honest
/// wire structures stay far below it. The `adv_deep_nesting_cbor` golden vector exceeds it.
///
/// Python `cbor._MAX_DEPTH`; Ruby `CBOR::MAX_DEPTH`; Java `CborCodec.MAX_NESTING_DEPTH` (Jackson
/// `StreamReadConstraints.maxNestingDepth`, whose counting [`crate::cbor::decode`] follows).
pub const MAX_CBOR_DEPTH: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_the_reference_values() {
        assert_eq!(MAX_CLAIM_HOLD_MILLIS, 86_400_000);
        assert_eq!(MAX_HLC_SKEW_MILLIS, 600_000);
        assert_eq!(MAX_DRIFT_MILLIS, 600_000);
        assert_eq!(MAX_FRAME_AGE_MILLIS, 300_000);
        assert_eq!(MAX_CLAIM_EPOCH_JUMP, 1_048_576);
        assert_eq!(MAX_FRAME_BYTES, 8_388_608);
        assert_eq!(INLINE_PAYLOAD_LIMIT, 65_536);
        assert_eq!(LOGICAL_LIMIT, 65_536);
        assert_eq!(SKEW_MARGIN_MILLIS, 5_000);
        assert_eq!(FAR_FUTURE_HOSTILE_MILLIS, 3_600_000);
        assert_eq!(MAX_STAMP_UNITS, 3_996);
        assert_eq!(MAX_NODE_UNITS, 3_965);
        assert_eq!(REFUSED_OFFERS_CAPACITY, 4_096);
        assert_eq!(CARD_SPILL_THRESHOLD_BYTES, 65_536);
        assert_eq!(CARD_SPILL_WARN_BYTES, 57_344);
        assert_eq!(AD_CACHE_MAX_ENTRIES, 8_192);
        assert_eq!(AD_CACHE_MAX_BYTES, 33_554_432);
    }
}
