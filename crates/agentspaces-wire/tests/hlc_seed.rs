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

//! Hybrid logical clock stamps and seeds: the golden stamp `hlc_encoded` parses and re-renders,
//! the clock issues what `wire.py`'s `hlc_now` and `hlc_observe` issue (sequences recorded from
//! the Python reference), the skew ceiling holds, the strict and lenient stamp parsers keep their
//! documented differences, and seeds parse and refuse as `seed.py` does (`test_tls.py`'s seed
//! cases and the edges recorded from `parse_seed`).

mod common;

use agentspaces_wire::beacon;
use agentspaces_wire::cbor::Value;
use agentspaces_wire::envelope::{self, stamp_physical};
use agentspaces_wire::hlc::{Hlc, Stamp, physical_lenient};
use agentspaces_wire::limits::MAX_HLC_SKEW_MILLIS;
use agentspaces_wire::seed::{DEFAULT_SCHEME, Seed, SeedError, parse_seed, seed_address};
use common::s;

// ---------------------------------------------------------------------------------------------
// Stamps

#[test]
fn the_golden_stamp_parses_and_re_renders() {
    let encoded = s("hlc_encoded");
    let stamp = Stamp::parse(encoded).expect("the golden stamp parses");
    assert_eq!(stamp.physical, 1_735_689_600_000);
    assert_eq!(stamp.logical, 3);
    assert_eq!(stamp.node, s("peer_id"));
    assert_eq!(stamp.to_string(), encoded);
    assert_eq!(physical_lenient(encoded), Some(stamp.physical));
    let field = Value::from(encoded);
    assert_eq!(Stamp::of(Some(&field)), Some(stamp));
    assert_eq!(Stamp::of(Some(&Value::Int(5))), None);
    assert_eq!(Stamp::of(None), None);
}

#[test]
fn the_clock_reissues_the_golden_stamp() {
    // The Java node stamped four events in one millisecond; the fourth is the golden stamp.
    let mut hlc = Hlc::new(s("peer_id"));
    assert_eq!(hlc.node(), s("peer_id"));
    assert_eq!(hlc.last(), None);
    let stamps: Vec<String> = (0..4).map(|_| hlc.now(1_735_689_600_000)).collect();
    assert_eq!(stamps[3], s("hlc_encoded"));
    assert_eq!(hlc.last(), Some((1_735_689_600_000, 3)));
}

#[test]
fn stamps_order_as_java_orders_them() {
    let parse = |text| Stamp::parse(text).expect(text);
    assert!(parse("5:1:a") > parse("5:0:a"));
    assert!(parse("6:0:a") > parse("5:9:z"));
    assert!(parse("5:0:b") > parse("5:0:a"));
    assert!(parse("10:0:a") > parse("9:0:a"), "by number, not by text");
    // The node in Java string order: a supplementary character sorts before U+FFFD.
    assert!(parse("5:0:\u{1F600}") < parse("5:0:\u{FFFD}"));
}

#[test]
fn the_clock_issues_what_hlc_now_issues() {
    // wire.hlc_now("zN", t) for t in [5, 5, 3, 10, 10, 0, 11], recorded from the Python client.
    let mut hlc = Hlc::new("zN");
    let issued: Vec<String> = [5, 5, 3, 10, 10, 0, 11]
        .into_iter()
        .map(|now| hlc.now(now))
        .collect();
    assert_eq!(
        issued,
        [
            "5:0:zN", "5:1:zN", "5:2:zN", "10:0:zN", "10:1:zN", "10:2:zN", "11:0:zN"
        ]
    );
    // A clock at or before zero starts at 0:0, then counts.
    let mut zero = Hlc::new("zK");
    assert_eq!(
        [zero.now(0), zero.now(-5), zero.now(0)],
        ["0:0:zK", "0:1:zK", "0:2:zK"]
    );
}

#[test]
fn stamps_are_strictly_monotonic_under_a_backwards_clock() {
    let mut hlc = Hlc::new("zMono");
    let clock = [
        100,
        100,
        99,
        50,
        101,
        101,
        0,
        -7,
        101,
        102,
        i64::MAX,
        5,
        i64::MAX,
    ];
    let issued: Vec<String> = clock.iter().map(|&now| hlc.now(now)).collect();
    for pair in issued.windows(2) {
        let (earlier, later) = (Stamp::parse(&pair[0]), Stamp::parse(&pair[1]));
        assert!(earlier.is_some() && later.is_some(), "{pair:?}");
        assert!(later > earlier, "{} then {}", pair[0], pair[1]);
    }
}

#[test]
fn observed_stamps_advance_the_clock_up_to_the_skew_ceiling() {
    // wire.hlc_observe / hlc_now on "zM" at a wall clock of 1000, recorded from the Python client.
    let mut hlc = Hlc::new("zM");
    assert_eq!(hlc.now(1000), "1000:0:zM");
    assert!(hlc.observe("1500:7:zR", 1000));
    assert_eq!(hlc.now(1000), "1500:8:zM");
    // Exactly at the ceiling is merged ...
    let at_ceiling = format!("{}:2:zR", 1000 + MAX_HLC_SKEW_MILLIS);
    assert!(hlc.observe(&at_ceiling, 1000));
    assert_eq!(hlc.now(1000), "601000:3:zM");
    // ... one millisecond beyond it is ignored, and so is an older stamp.
    let beyond = format!("{}:9:zR", 1001 + MAX_HLC_SKEW_MILLIS);
    assert!(!hlc.observe(&beyond, 1000));
    assert_eq!(hlc.now(1000), "601000:4:zM");
    assert!(!hlc.observe("5:0:zR", 1000));
    assert_eq!(hlc.now(1000), "601000:5:zM");
    assert_eq!(hlc.now(700_000), "700000:0:zM");

    // A later counter at the same millisecond merges; an equal pair does not.
    assert!(hlc.observe("700000:4:zR", 700_000));
    assert!(!hlc.observe("700000:4:zS", 700_000));
    assert_eq!(hlc.now(700_000), "700000:5:zM");

    // A hostile far-future stamp cannot pin the clock, and nothing overflows.
    let mut edge = Hlc::new("zE");
    assert!(!edge.observe(&format!("{}:0:zR", i64::MAX), 0));
    assert!(edge.observe(&format!("{}:0:zR", i64::MAX), i64::MAX));
    assert!(!edge.observe(
        &format!("{}:0:zR", i64::MAX),
        i64::MAX - MAX_HLC_SKEW_MILLIS
    ));
    assert_eq!(edge.now(i64::MAX), format!("{}:1:zE", i64::MAX));
    assert!(!edge.observe("1:0:zR", i64::MIN));
}

#[test]
fn malformed_stamps_are_not_observed() {
    let mut hlc = Hlc::new("zM");
    for bad in [
        "", "5", "5:0", "5:0:", "-5:0:n", "5:-1:n", "x:0:n", "5:0:a:b", " 5:0:n",
    ] {
        assert!(!hlc.observe(bad, 10), "{bad:?}");
    }
    assert_eq!(hlc.last(), None);
    assert_eq!(hlc.now(10), "10:0:zM");
}

#[test]
fn the_counter_saturates_so_a_stamp_stays_one_java_parses() {
    let mut hlc = Hlc::new("zS");
    assert!(hlc.observe(&format!("5:{}:zR", i32::MAX), 5));
    let next = hlc.now(5);
    assert_eq!(next, format!("5:{}:zS", i32::MAX));
    assert!(Stamp::parse(&next).is_some());
    assert_eq!(
        hlc.now(6),
        "6:0:zS",
        "the counter resets when time moves on"
    );
}

/// A stamp's parts as the strict parser reads them: physical, logical, node.
type Parts = (i64, i32, &'static str);

#[test]
fn the_strict_and_lenient_parsers_keep_their_differences() {
    // (stamp, Java HlcTimestamp.parse, Java Long.parseLong of the text before the first ':')
    let cases: [(&str, Option<Parts>, Option<i64>); 17] = [
        ("5:0:n", Some((5, 0, "n")), Some(5)),
        ("+5:+0:n", Some((5, 0, "n")), Some(5)),
        ("-0:0:n", Some((0, 0, "n")), Some(0)),
        ("5:0:n/agent", Some((5, 0, "n/agent")), Some(5)),
        ("-5:0:n", None, Some(-5)),
        ("5", None, Some(5)),
        ("5:x", None, Some(5)),
        ("5:0", None, Some(5)),
        ("5:-1:n", None, Some(5)),
        ("5:2147483648:n", None, Some(5)),
        ("5:0:", None, Some(5)),
        ("5:0:a:b", None, Some(5)),
        (
            "9223372036854775807:0:n",
            Some((i64::MAX, 0, "n")),
            Some(i64::MAX),
        ),
        ("9223372036854775808:0:n", None, None),
        (" 5:0:n", None, None),
        ("x:0:n", None, None),
        ("", None, None),
    ];
    for (text, strict, lenient) in cases {
        let parsed = Stamp::parse(text).map(|s| (s.physical, s.logical, s.node));
        assert_eq!(parsed, strict, "strict {text:?}");
        assert_eq!(physical_lenient(text), lenient, "lenient {text:?}");
        // The envelope's frame filter reads the lenient way.
        let env = envelope::envelope("g", "PING", "zA", text, b"", None);
        assert_eq!(stamp_physical(&env), lenient, "envelope {text:?}");
    }
    // Unicode digits are not ASCII digits to either parser.
    assert_eq!(Stamp::parse("\u{661}:0:n"), None);
    assert_eq!(physical_lenient("\u{661}"), None);
}

// ---------------------------------------------------------------------------------------------
// Seeds

fn seed(host: &str, port: u16, scheme: &str) -> Seed {
    Seed::new(host, port, scheme)
}

#[test]
fn seeds_parse_as_seed_py_parses_them() {
    // test_tls.py.
    assert_eq!(
        parse_seed("tls://seed.example:7500", "tcp"),
        Ok(seed("seed.example", 7500, "tls"))
    );
    assert_eq!(
        parse_seed("seed.example:7500", "tcp"),
        Ok(seed("seed.example", 7500, "tcp"))
    );
    assert_eq!(
        parse_seed("TCP://[::1]:7500", "tcp"),
        Ok(seed("::1", 7500, "tcp"))
    );
    assert_eq!(
        parse_seed("wss://seed.example:443/aspace", "tcp"),
        Err(SeedError::Path {
            scheme: "wss".into(),
            seed: "wss://seed.example:443/aspace".into()
        })
    );
    assert_eq!(
        parse_seed("seed.example", "tcp"),
        Err(SeedError::NotAnAddress("seed.example".into()))
    );

    // Recorded from parse_seed: (text, (host, port, scheme)).
    let accepted = [
        ("\u{130}tcp://h:1", ("h", 1, "i\u{307}tcp")),
        ("\u{212A}tcp://h:1", ("h", 1, "ktcp")),
        ("\u{17F}://h:1", ("h", 1, "\u{17F}")),
        (" \u{1C}h:5\u{1F} ", ("h", 5, "tcp")),
        ("a:b:7", ("a:b", 7, "tcp")),
        ("tcp+x.y-z://h:9", ("h", 9, "tcp+x.y-z")),
        ("h:007", ("h", 7, "tcp")),
        ("tcp://[::1]::7500", ("::1", 7500, "tcp")),
        ("TLS://H:1", ("H", 1, "tls")),
        ("\u{3000}h:1\u{3000}", ("h", 1, "tcp")),
        ("\u{85}h:1", ("h", 1, "tcp")),
        ("h:0", ("h", 0, "tcp")),
    ];
    for (text, (host, port, scheme)) in accepted {
        assert_eq!(
            parse_seed(text, "tcp"),
            Ok(seed(host, port, scheme)),
            "{text:?}"
        );
    }
    // The default scheme is taken as given; a written one is lower-cased.
    assert_eq!(parse_seed("h:1", "TLS"), Ok(seed("h", 1, "TLS")));
    assert_eq!("h:1".parse::<Seed>(), Ok(seed("h", 1, DEFAULT_SCHEME)));
    assert_eq!(DEFAULT_SCHEME, "tcp");
}

#[test]
fn seeds_are_refused_as_seed_py_refuses_them() {
    // Recorded from parse_seed: a path (any '/', also of a scheme that did not parse) ...
    let path = [
        ("1tcp://h:1", "tcp"),
        ("tcp://", "tcp"),
        ("tcp://h:1\nx", "tcp"),
        ("tcp:/h:1", "tcp"),
        ("tcp//h:1", "tcp"),
        ("tcp://h:1/", "tcp"),
    ];
    for (text, scheme) in path {
        assert_eq!(
            parse_seed(text, "tcp"),
            Err(SeedError::Path {
                scheme: scheme.into(),
                seed: text.into()
            }),
            "{text:?}"
        );
    }
    // ... and an address with no host or no digit port.
    let not_addresses = [
        ("[::1]", "[::1]"),
        ("[::1]:", "[::1]:"),
        ("[::1]x:7", "[::1]x:7"),
        (":7", ":7"),
        ("h:", "h:"),
        ("tcp://:1", ":1"),
        ("tcp:// h : 1", " h : 1"),
        ("h:\u{B2}", "h:\u{B2}"),
        // seed.py accepts these and fails when it dials: a port must fit a u16 of ASCII digits.
        ("h:70000", "h:70000"),
        ("h:\u{661}\u{662}", "h:\u{661}\u{662}"),
    ];
    for (text, address) in not_addresses {
        assert_eq!(
            parse_seed(text, "tcp"),
            Err(SeedError::NotAnAddress(address.into())),
            "{text:?}"
        );
    }
    assert!(
        parse_seed("wss://h:1/x", "tcp")
            .unwrap_err()
            .to_string()
            .starts_with("a wss seed takes no path")
    );
    assert!(
        parse_seed("h", "tcp")
            .unwrap_err()
            .to_string()
            .starts_with("not a seed address")
    );
}

#[test]
fn seed_addresses_split_host_and_port() {
    assert_eq!(seed_address(" h:1 "), Ok(("h".into(), 1)));
    assert_eq!(seed_address("[::1]:7500"), Ok(("::1".into(), 7500)));
    assert_eq!(seed_address("[::1]::7500"), Ok(("::1".into(), 7500)));
    assert_eq!(seed_address("a:b:7"), Ok(("a:b".into(), 7)));
    assert_eq!(seed_address("h:65535"), Ok(("h".into(), 65535)));
    for bad in [
        "h:",
        ":7",
        "h",
        "h:65536",
        "h:7/aspace",
        "",
        "[]:7",
        "h:-1",
        "h:+1",
    ] {
        assert_eq!(
            seed_address(bad),
            Err(SeedError::NotAnAddress(bad.into())),
            "{bad:?}"
        );
    }
    // The beacon reads seed addresses with the same function.
    assert_eq!(beacon::seed_address("[::1]:7"), seed_address("[::1]:7"));
}

#[test]
fn a_seed_prints_and_reads_back() {
    let cases = [
        (
            seed("seed.example", 7500, "tls"),
            "tls://seed.example:7500",
            "seed.example:7500",
        ),
        (seed("::1", 7, "tcp"), "tcp://[::1]:7", "[::1]:7"),
        (seed("a:b", 9, "tcp"), "tcp://[a:b]:9", "[a:b]:9"),
    ];
    for (seed, printed, address) in cases {
        assert_eq!(seed.to_string(), printed);
        assert_eq!(seed.address(), address);
        assert_eq!(parse_seed(printed, "x"), Ok(seed.clone()));
        assert_eq!(printed.parse::<Seed>(), Ok(seed));
    }
}
