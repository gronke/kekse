//! The universal invariants every `Keksbruch` must satisfy, regardless of scenario —
//! kekse's standing promises. Shared by Layer A (which asserts them in CI) and,
//! later, the differential harness (which uses them to sanity-check kekse's
//! own column before comparing it to other parsers).

use kekse::{parse_pairs, parse_pairs_strict};
use rfc_6265::grammar::is_ctl;

/// Drive both request readers to completion. kekse's no-panic promise is
/// structural — the readers return iterators, so merely exhausting them in a test
/// that is not `#[should_panic]` is the proof.
pub fn drive(wire: &str) {
    let _ = parse_pairs(wire).count();
    let _ = parse_pairs_strict(wire).count();
}

/// No parsed name or value may carry the `;` separator or any control byte (RFC 5234 `CTL` —
/// which includes CR, LF, and NUL — see [`rfc_6265::grammar::is_ctl`]). The security invariant:
/// attacker bytes can never survive the decode into a pair that would split or smuggle a header
/// downstream.
pub fn assert_no_injection_echo(wire: &str) {
    for (name, value) in parse_pairs(wire) {
        for field in [name, value.as_ref()] {
            assert!(
                !field.bytes().any(|b| b == b';' || is_ctl(b)),
                "injection byte echoed from {wire:?}: {field:?}"
            );
        }
    }
}

/// Strict-accepted ⊆ lenient-accepted: every pair the strict reader yields must
/// also be yielded by the lenient reader. Strict can only *remove* pairs (refuse
/// whitespace and the quoted form), never add or alter one.
pub fn assert_strict_subset_of_lenient(wire: &str) {
    let lenient: Vec<(String, String)> = parse_pairs(wire)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
        .collect();
    for pair in parse_pairs_strict(wire).map(|(n, v)| (n.to_string(), v.into_owned())) {
        assert!(
            lenient.contains(&pair),
            "strict yielded {pair:?}, not present in lenient, for {wire:?}"
        );
    }
}
