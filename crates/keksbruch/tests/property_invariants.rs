//! The generative layer: proptest feeds random and structured-mutation wire
//! through the same three universal invariants Layer A pins on the curated
//! corpus (never panics, never echoes an injection byte, strict ⊆ lenient) —
//! plus the codec's round-trip promise. The invariants are unconditional, so
//! any counterexample proptest finds is a real kekse bug, never test flake.
//!
//! Case counts are bounded (256 per property, short wires) so the whole file
//! stays in the sub-second range and rides the normal `cargo test` CI legs;
//! `PROPTEST_CASES=100000 cargo test -p keksbruch` deepens a local run.
//! Failure persistence is off (an integration test has no `lib.rs` anchor, and
//! the sealed CI mounts the repo read-only anyway): a failure *prints* its
//! minimal input and seed — copy those into a regular #[test] to replay.

use proptest::prelude::*;

use keksbruch::{
    assert_no_injection_echo, assert_no_injection_echo_bytes, assert_strict_subset_of_lenient,
    assert_strict_subset_of_lenient_bytes, drive, drive_bytes,
};
use kekse::{Cookie, ValueEncoding, parse_pairs, parse_pairs_strict};

/// A cookie-name: 1–12 RFC 7230 tchars.
fn name_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,12}").expect("valid name regex")
}

/// A logical value: arbitrary UTF-8 (escaping it is the codec's job, so the
/// strategy deliberately includes whitespace, quotes, `%`, `;`, non-ASCII, …).
fn value_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex(".{0,24}").expect("valid value regex")
}

/// 1–5 `(name, value)` pairs — duplicate names are legal on the wire and the
/// readers preserve order, so plain `Vec` equality is the round-trip oracle.
fn pairs_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::collection::vec((name_strategy(), value_strategy()), 1..=5)
}

/// One of the managed (lossless) encodings — `Raw` is excluded on purpose: the
/// caller owns wire-correctness there, so it carries no round-trip promise.
fn encoding_strategy() -> impl Strategy<Value = ValueEncoding> {
    prop::sample::select(vec![
        ValueEncoding::Auto,
        ValueEncoding::Percent,
        ValueEncoding::Quoted,
    ])
}

/// A well-formed header rendered by kekse's own writers.
fn rendered_header_strategy() -> impl Strategy<Value = String> {
    (pairs_strategy(), encoding_strategy()).prop_map(|(pairs, encoding)| {
        pairs
            .iter()
            .map(|(name, value)| Cookie::new(name, value.clone()).to_pair(encoding))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

/// Valid wire with one adversarial byte spliced in at a random position — the
/// generative sibling of the curated corpus's splice recipes: delimiters,
/// controls, quote/escape introducers, obs-text, and raw non-UTF-8.
fn spliced_wire_strategy() -> impl Strategy<Value = Vec<u8>> {
    let adversarial = prop::sample::select(vec![
        0x00u8, 0x1f, 0x7f, b';', b'"', b'%', b'=', b' ', 0xe9, 0xff,
    ]);
    (
        rendered_header_strategy(),
        any::<prop::sample::Index>(),
        adversarial,
    )
        .prop_map(|(header, index, byte)| {
            let mut wire = header.into_bytes();
            let at = index.index(wire.len() + 1); // 0..=len: any splice point incl. the ends
            wire.insert(at, byte);
            wire
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Arbitrary UTF-8 through the `&str` readers.
    #[test]
    fn arbitrary_utf8_upholds_the_invariants(wire in ".{0,200}") {
        drive(&wire);
        assert_no_injection_echo(&wire);
        assert_strict_subset_of_lenient(&wire);
    }

    /// Header-shaped ASCII (printable + HTAB) — denser coverage of the
    /// delimiter/quote/escape space than uniform UTF-8 reaches.
    #[test]
    fn header_shaped_ascii_upholds_the_invariants(wire in r"[ -~\t]{0,120}") {
        drive(&wire);
        assert_no_injection_echo(&wire);
        assert_strict_subset_of_lenient(&wire);
    }

    /// Arbitrary bytes through the byte-level readers — the space a `&str` can
    /// never reach (invalid UTF-8, obs-text, lone continuation bytes).
    #[test]
    fn arbitrary_bytes_uphold_the_invariants(wire in prop::collection::vec(any::<u8>(), 0..256)) {
        drive_bytes(&wire);
        assert_no_injection_echo_bytes(&wire);
        assert_strict_subset_of_lenient_bytes(&wire);
    }

    /// kekse-rendered wire with one adversarial byte spliced in: the corruption
    /// must cost at most the pairs it lands in, never the invariants.
    #[test]
    fn spliced_valid_wire_upholds_the_invariants(wire in spliced_wire_strategy()) {
        drive_bytes(&wire);
        assert_no_injection_echo_bytes(&wire);
        assert_strict_subset_of_lenient_bytes(&wire);
    }

    /// Every managed encoding round-trips losslessly through the lenient reader
    /// — and `Percent` (the strict-compatible one) through the strict reader.
    #[test]
    fn managed_encodings_round_trip_the_readers(
        pairs in pairs_strategy(),
        encoding in encoding_strategy(),
    ) {
        let header = pairs
            .iter()
            .map(|(name, value)| Cookie::new(name, value.clone()).to_pair(encoding))
            .collect::<Vec<_>>()
            .join("; ");
        let lenient: Vec<(String, String)> = parse_pairs(&header)
            .map(|(n, v)| (n.to_string(), v.into_owned()))
            .collect();
        prop_assert_eq!(&lenient, &pairs, "lenient round-trip via {:?} of {:?}", encoding, header);
        if encoding == ValueEncoding::Percent {
            let strict: Vec<(String, String)> = parse_pairs_strict(&header)
                .map(|(n, v)| (n.to_string(), v.into_owned()))
                .collect();
            prop_assert_eq!(&strict, &pairs, "strict round-trip of {:?}", header);
        }
    }
}
