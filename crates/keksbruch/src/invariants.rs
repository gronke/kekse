//! The universal invariants every `Keksbruch` must satisfy, regardless of scenario —
//! kekse's standing promises. Shared by Layer A (which asserts them in CI) and,
//! later, the differential harness (which uses them to sanity-check kekse's
//! own column before comparing it to other parsers).
//!
//! Each invariant comes in two forms: over `&str` (the classic readers) and over
//! raw `&[u8]` wire (the `parse_pairs_bytes` readers, which can be fed the
//! non-UTF-8 payloads a `&str` can never carry). The str form *is* the bytes
//! form over `as_bytes()`, mirroring kekse's own layering.

use kekse::{
    Cookie, CookieJar, SetCookie, is_cookie_name, parse_pairs_bytes, parse_pairs_bytes_strict,
};
use rfc_6265::grammar::is_ctl;

use crate::taxonomy::Direction;

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
    for (name, value) in parse_pairs_bytes(wire).filter_map(Result::ok) {
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
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
        .collect();
    for pair in parse_pairs_bytes_strict(wire)
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
    {
        assert!(
            lenient.contains(&pair),
            "strict yielded {pair:?}, not present in lenient, for {wire:?}"
        );
    }
}

/// A rendered issue must never carry a raw control byte — the report's own
/// no-echo promise: printing what the wire did wrong must not let the wire do
/// it again in whatever log line or response the report lands in.
fn assert_issue_display_safe(rendered: &str, wire: &[u8]) {
    assert!(
        !rendered.bytes().any(|b| b.is_ascii_control()),
        "rendered issue echoes a control byte for {wire:?}: {rendered:?}"
    );
}

/// The issue channel is graded consistently across the request readers.
/// Three prongs:
///
/// - The jar constructors partition the stream exactly: `value` is the `Ok`
///   items, `issues` the `Err` items, both in wire order — the typed view can
///   never change what parses.
/// - Lenient's issue set is a subset of strict's — the report dual of
///   strict ⊆ lenient: everything lenient refuses, strict refuses too.
/// - Every rendered issue is control-byte-free (see the no-echo promise).
pub fn assert_report_consistency(wire: &str) {
    assert_report_consistency_bytes(wire.as_bytes());
}

/// [`assert_report_consistency`] over raw wire bytes.
pub fn assert_report_consistency_bytes(wire: &[u8]) {
    for strict in [false, true] {
        let stream: Vec<Result<(String, String), _>> = if strict {
            parse_pairs_bytes_strict(wire)
                .map(|r| r.map(|(n, v)| (n.to_string(), v.into_owned())))
                .collect()
        } else {
            parse_pairs_bytes(wire)
                .map(|r| r.map(|(n, v)| (n.to_string(), v.into_owned())))
                .collect()
        };
        let jar = if strict {
            CookieJar::parse_bytes_strict(wire)
        } else {
            CookieJar::parse_bytes(wire)
        };
        let jar_pairs: Vec<(String, String)> = jar
            .value
            .iter()
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect();
        let ok_items: Vec<(String, String)> =
            stream.iter().filter_map(|r| r.clone().ok()).collect();
        assert_eq!(
            jar_pairs, ok_items,
            "jar pairs diverge from the stream (strict={strict}) for {wire:?}"
        );
        let err_items: Vec<_> = stream.iter().filter_map(|r| r.clone().err()).collect();
        assert_eq!(
            jar.issues, err_items,
            "jar issues diverge from the stream (strict={strict}) for {wire:?}"
        );
    }
    let lenient_issues: Vec<_> = parse_pairs_bytes(wire).filter_map(Result::err).collect();
    let strict_issues: Vec<_> = parse_pairs_bytes_strict(wire)
        .filter_map(Result::err)
        .collect();
    for issue in &lenient_issues {
        assert!(
            strict_issues.contains(issue),
            "lenient reported {issue:?}, absent from strict, for {wire:?}"
        );
    }
    for issue in lenient_issues.iter().chain(&strict_issues) {
        assert_issue_display_safe(&issue.to_string(), wire);
    }
}

/// `SetCookie`'s reporting readers agree with the plain ones: the same inputs
/// are fatal (`Err` exactly when `parse*` is `None`), a parsed cookie is the
/// same cookie (equal, and rendering identically), and every issue — fatal or
/// reported — renders control-byte-free.
pub fn assert_set_cookie_report_consistency(wire: &str) {
    for strict in [false, true] {
        let plain = if strict {
            SetCookie::parse_strict(wire)
        } else {
            SetCookie::parse(wire)
        };
        let reported = if strict {
            SetCookie::try_parse_strict(wire)
        } else {
            SetCookie::try_parse(wire)
        };
        match (plain, reported) {
            (Some(plain), Ok(reported)) => {
                assert_eq!(
                    plain, reported.value,
                    "reported cookie diverges (strict={strict}) for {wire:?}"
                );
                assert_eq!(
                    plain.to_set_cookie(),
                    reported.value.to_set_cookie(),
                    "reported cookie renders differently (strict={strict}) for {wire:?}"
                );
                for issue in &reported.issues {
                    assert_issue_display_safe(&issue.to_string(), wire.as_bytes());
                }
            }
            (None, Err(fatal)) => {
                assert_issue_display_safe(&fatal.to_string(), wire.as_bytes());
            }
            (plain, reported) => panic!(
                "fatality diverges (strict={strict}) for {wire:?}: plain parsed {}, reporting {}",
                plain.is_some(),
                reported.is_ok()
            ),
        }
    }
}

/// kekse's own clean wire reads back clean: a baseline rendered *through kekse*
/// must produce an empty report — if kekse's writer emits something its own
/// reporting reader flags, writer and reader have drifted.
pub fn assert_baseline_parses_clean(baseline: &str, direction: Direction) {
    match direction {
        Direction::Request => {
            let reported = CookieJar::parse(baseline);
            assert!(
                reported.is_clean(),
                "kekse-rendered request baseline reported issues: {baseline:?} -> {:?}",
                reported.issues
            );
        }
        Direction::Response => match SetCookie::try_parse(baseline) {
            Ok(reported) => assert!(
                reported.is_clean(),
                "kekse-rendered Set-Cookie baseline reported issues: {baseline:?} -> {:?}",
                reported.issues
            ),
            Err(fatal) => {
                panic!("kekse-rendered Set-Cookie baseline is fatal: {baseline:?} -> {fatal}")
            }
        },
    }
}
