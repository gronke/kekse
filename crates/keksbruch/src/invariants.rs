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

/// Conservation: every `;`-segment that is not structural noise (empty or
/// SP/HTAB-only) yields exactly one stream item — an `Ok` pair or an issue —
/// in either grading. Nothing on the wire can vanish unwitnessed; this is the
/// law that makes a silently swallowed pair impossible.
pub fn assert_pair_conservation(wire: &str) {
    assert_pair_conservation_bytes(wire.as_bytes());
}

/// [`assert_pair_conservation`] over raw wire bytes.
pub fn assert_pair_conservation_bytes(wire: &[u8]) {
    let segments = wire
        .split(|&b| b == b';')
        .filter(|segment| !segment.iter().all(|&b| b == b' ' || b == b'\t'))
        .count();
    for strict in [false, true] {
        let items = if strict {
            parse_pairs_bytes_strict(wire).count()
        } else {
            parse_pairs_bytes(wire).count()
        };
        assert_eq!(
            items, segments,
            "{segments} non-noise segments but {items} stream items \
             (strict={strict}) for {wire:?}"
        );
    }
}

/// Every recovered response deviation is witnessed, in either grading. For a
/// salvaged `Set-Cookie`:
///
/// - An attribute segment that did not land in the parsed attribute set is
///   covered by an issue — `segments − set_attributes ≤ issues` — so a
///   dropped `Max-Age=banana` or an ignored `Priority` can never vanish
///   without a trace.
/// - The salvage is a fixpoint: re-rendering it and re-parsing under the same
///   grading yields the same cookie, and the only surviving issues are the
///   salvage's own standing constraint violations
///   (`SetCookie::constraint_violations`) — properties of the cookie itself,
///   not of the wire's syntax. Whatever the parse changed is visible in the
///   salvage, never smuggled.
pub fn assert_response_divergence_witnessed(wire: &str) {
    for strict in [false, true] {
        let parsed = if strict {
            SetCookie::parse_strict(wire)
        } else {
            SetCookie::parse(wire)
        };
        let Ok(reported) = parsed else {
            continue; // fatal: nothing was salvaged, nothing can be silent
        };
        let attribute_segments = wire
            .split(';')
            .skip(1)
            .filter(|segment| !segment.bytes().all(|b| b == b' ' || b == b'\t'))
            .count();
        let a = reported.value.attributes();
        let set_attributes = usize::from(a.http_only)
            + usize::from(a.secure)
            + usize::from(a.partitioned)
            + usize::from(a.same_site.is_some())
            + usize::from(a.path.is_some())
            + usize::from(a.domain.is_some())
            + usize::from(a.max_age.is_some())
            + usize::from(a.expires.is_some());
        assert!(
            attribute_segments.saturating_sub(set_attributes) <= reported.issues.len(),
            "unwitnessed drop (strict={strict}) for {wire:?}: {attribute_segments} attribute \
             segments, {set_attributes} set, {} issue(s)",
            reported.issues.len()
        );
        let rendered = reported.value.to_set_cookie();
        let again = if strict {
            SetCookie::parse_strict(&rendered)
        } else {
            SetCookie::parse(&rendered)
        }
        .unwrap_or_else(|fatal| {
            panic!("salvage of {wire:?} re-renders unparseable ({fatal}): {rendered:?}")
        });
        assert_eq!(
            again.issues,
            reported.value.constraint_violations(),
            "salvage of {wire:?} re-parses with issues beyond its own standing \
             constraint violations (strict={strict}): {rendered:?}"
        );
        assert_eq!(
            again.value, reported.value,
            "salvage of {wire:?} drifts through a render round-trip (strict={strict})"
        );
    }
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

/// The `Set-Cookie` gradings agree the way the request readers do. Four
/// prongs:
///
/// - Fatality is grading-independent: strict and lenient reject exactly the
///   same wires (the unusable pair), so strict-accepted = lenient-accepted.
/// - Strict's salvage carries no attribute lenient's does not: every
///   attribute strict sets equals lenient's — strict grading can only drop
///   more (an `Expires` outside the IMF-fixdate), never invent or alter.
/// - Lenient's issues are a subset of strict's — everything lenient
///   witnesses, strict witnesses too.
/// - Every issue — fatal or reported, either grading — renders
///   control-byte-free (the no-echo promise).
pub fn assert_set_cookie_report_consistency(wire: &str) {
    let lenient = SetCookie::parse(wire);
    let strict = SetCookie::parse_strict(wire);
    assert_eq!(
        lenient.is_ok(),
        strict.is_ok(),
        "fatality diverges between the gradings for {wire:?}"
    );
    if let Ok(reported) = &lenient {
        for issue in &reported.issues {
            assert_issue_display_safe(&issue.to_string(), wire.as_bytes());
        }
    } else if let Err(fatal) = &lenient {
        assert_issue_display_safe(&fatal.to_string(), wire.as_bytes());
    }
    match &strict {
        Ok(reported) => {
            for issue in &reported.issues {
                assert_issue_display_safe(&issue.to_string(), wire.as_bytes());
            }
            let lenient = lenient
                .as_ref()
                .expect("strict salvaged a cookie lenient found fatal");
            for issue in &lenient.issues {
                assert!(
                    reported.issues.contains(issue),
                    "lenient witnessed {issue:?}, absent from strict, for {wire:?}"
                );
            }
            let s = reported.value.attributes();
            let l = lenient.value.attributes();
            assert_eq!(s.http_only, l.http_only, "HttpOnly diverges for {wire:?}");
            assert_eq!(s.secure, l.secure, "Secure diverges for {wire:?}");
            assert_eq!(
                s.partitioned, l.partitioned,
                "Partitioned diverges for {wire:?}"
            );
            for (name, strict_set, lenient_set) in [
                ("SameSite", s.same_site.is_some(), l.same_site.is_some()),
                ("Path", s.path.is_some(), l.path.is_some()),
                ("Domain", s.domain.is_some(), l.domain.is_some()),
                ("Max-Age", s.max_age.is_some(), l.max_age.is_some()),
                ("Expires", s.expires.is_some(), l.expires.is_some()),
            ] {
                assert!(
                    !strict_set || lenient_set,
                    "{name} set under strict but not lenient for {wire:?}"
                );
            }
            assert_eq!(s.same_site, l.same_site, "SameSite value for {wire:?}");
            assert_eq!(s.path, l.path, "Path value for {wire:?}");
            assert_eq!(s.domain, l.domain, "Domain value for {wire:?}");
            assert_eq!(s.max_age, l.max_age, "Max-Age value for {wire:?}");
            if s.expires.is_some() {
                assert_eq!(s.expires, l.expires, "Expires value for {wire:?}");
            }
        }
        Err(fatal) => assert_issue_display_safe(&fatal.to_string(), wire.as_bytes()),
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
        Direction::Response => match SetCookie::parse(baseline) {
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
