//! The universal invariants every `Keksbruch` must satisfy, regardless of scenario —
//! kekse's standing promises. Shared by Layer A (which asserts them in CI) and,
//! later, the differential harness (which uses them to sanity-check kekse's
//! own column before comparing it to other parsers).
//!
//! Each invariant comes in two forms: over `&str` (the classic readers) and over
//! raw `&[u8]` wire (the `parse_pairs_bytes` readers, which can be fed the
//! non-UTF-8 payloads a `&str` can never carry). The str form *is* the bytes
//! form over `as_bytes()`, mirroring kekse's own layering.

use kekse::{Cookie, is_cookie_name, parse_pairs_bytes, parse_pairs_bytes_strict};
use rfc_6265::grammar::is_ctl;

/// Drive both request readers to completion. kekse's no-panic promise is
/// structural — the readers return iterators, so merely exhausting them in a test
/// that is not `#[should_panic]` is the proof.
pub fn drive(wire: &str) {
    drive_bytes(wire.as_bytes());
}

/// [`drive`] over raw wire bytes — the byte-level readers must be as
/// panic-proof as the str ones, including on non-UTF-8 input.
pub fn drive_bytes(wire: &[u8]) {
    let _ = parse_pairs_bytes(wire).count();
    let _ = parse_pairs_bytes_strict(wire).count();
}

/// No parsed pair can smuggle a wire hazard downstream. Three prongs, because a decoded *value*
/// is the **logical** value — a percent-escape may legitimately decode to any byte the
/// application chose to transport (that is the round-trip working as designed; kekse's writer
/// escaped it on the way out):
///
/// - A parsed *name* is a full RFC 7230 token — no `;`, no control, no whitespace, ever.
/// - On wire that carries **no `%`**, decoding is the identity (minus quotes/OWS), so a value
///   byte *is* a wire byte: nothing dangerous may appear — no `;`, no CTL (see
///   [`rfc_6265::grammar::is_ctl`]). Sole exemption: `HTAB`, the whitespace the lenient reader
///   documents as tolerated (with `SP`, which is no CTL) — RFC 7230 allows it raw in a field
///   value, so echoing it cannot break the header. This prong is what catches a reader that
///   starts admitting a *raw* control.
/// - On **any** wire, the composition tripwire: re-encoding every parsed pair through the
///   canonical writer must yield header-safe wire (no `;`, no CTL at all) — an escape-decoded
///   control may live in the logical value, but it can never re-reach a header unescaped.
pub fn assert_no_injection_echo(wire: &str) {
    assert_no_injection_echo_bytes(wire.as_bytes());
}

/// [`assert_no_injection_echo`] over raw wire bytes.
pub fn assert_no_injection_echo_bytes(wire: &[u8]) {
    let wire_has_escape = wire.contains(&b'%');
    for (name, value) in parse_pairs_bytes(wire) {
        assert!(
            is_cookie_name(name),
            "non-token name parsed from {wire:?}: {name:?}"
        );
        if !wire_has_escape {
            assert!(
                !value
                    .bytes()
                    .any(|b| b == b';' || (is_ctl(b) && b != b'\t')),
                "raw injection byte echoed in a value from {wire:?}: {value:?}"
            );
        }
        let reencoded = Cookie::new(name, value.as_ref()).to_request_pair();
        assert!(
            !reencoded.bytes().any(|b| b == b';' || is_ctl(b)),
            "re-encoded pair carries an injection byte for {wire:?}: {reencoded:?}"
        );
    }
}

/// Strict-accepted ⊆ lenient-accepted: every pair the strict reader yields must
/// also be yielded by the lenient reader. Strict can only *remove* pairs (refuse
/// whitespace and the quoted form), never add or alter one.
pub fn assert_strict_subset_of_lenient(wire: &str) {
    assert_strict_subset_of_lenient_bytes(wire.as_bytes());
}

/// [`assert_strict_subset_of_lenient`] over raw wire bytes.
pub fn assert_strict_subset_of_lenient_bytes(wire: &[u8]) {
    let lenient: Vec<(String, String)> = parse_pairs_bytes(wire)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
        .collect();
    for pair in parse_pairs_bytes_strict(wire).map(|(n, v)| (n.to_string(), v.into_owned())) {
        assert!(
            lenient.contains(&pair),
            "strict yielded {pair:?}, not present in lenient, for {wire:?}"
        );
    }
}
