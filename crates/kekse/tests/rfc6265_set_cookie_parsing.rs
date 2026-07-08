//! RFC 6265 §5.2: parsing the `Set-Cookie` header into a `SetCookie`.
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.2>
//!
//! Black-box over `SetCookie::parse` (lenient grading) and
//! `SetCookie::parse_strict`. Both return the reported form, so these tests
//! pin the salvage *and* its witnesses.

use kekse::{SameSite, SetCookie, SetCookieIssue};

/// The salvaged cookie of a lenient parse the test knows must succeed.
fn lenient(header: &str) -> SetCookie<'_> {
    SetCookie::parse(header).expect("usable pair").into_value()
}

#[test]
fn splits_first_semicolon_then_first_equals() {
    // §5.2: the name-value-pair runs up to the first ';', the name up to the
    // first '=' (so '=' survives in the value).
    let c = lenient("a=b=c; Path=/x");
    assert_eq!(c.name(), "a");
    assert_eq!(c.value(), "b=c");
    assert_eq!(c.attributes().path.as_ref().map(|p| p.as_str()), Some("/x"));
}

#[test]
fn empty_and_trailing_semicolons_tolerated_but_pair_must_lead() {
    assert!(SetCookie::parse("SID=x;").is_ok());
    assert!(SetCookie::parse("SID=x;;;").is_ok());
    assert!(lenient("SID=x; ; Secure").attributes().secure);
    // Structural noise is not an issue — the reports stay clean.
    assert!(SetCookie::parse("SID=x;;;").unwrap().is_clean());
    // A leading ';' makes the first (pair) segment empty — no usable pair.
    assert!(SetCookie::parse("; SID=x").is_err());
}

#[test]
fn max_age_digit_grammar() {
    // §5.2.2: Max-Age is 1*DIGIT (kekse parses it as a u64).
    let max_age = |h: &str| lenient(h).attributes().max_age;
    assert_eq!(max_age("n=v; Max-Age=60"), Some(60));
    assert_eq!(max_age("n=v; Max-Age=0"), Some(0)); // delete sentinel
    assert_eq!(max_age("n=v; Max-Age=007"), Some(7)); // leading zeros
    assert_eq!(max_age("n=v; Max-Age=18446744073709551615"), Some(u64::MAX));
    assert_eq!(max_age("n=v; Max-Age = 60 "), Some(60)); // whitespace trimmed

    // Each of these drops the attribute (cookie still parses, value kept) —
    // and the drop is witnessed as an InvalidAttributeValue issue.
    for bad in [
        "n=v; Max-Age=-1",
        "n=v; Max-Age=banana",
        "n=v; Max-Age=1.5",
        "n=v; Max-Age=12x",
        "n=v; Max-Age=",
        "n=v; Max-Age=18446744073709551616", // u64::MAX + 1 overflows
        "n=v; Max-Age=99999999999999999999999", // far past u64
    ] {
        let parsed = SetCookie::parse(bad).unwrap();
        assert_eq!(parsed.value.attributes().max_age, None, "{bad:?}");
        assert_eq!(parsed.value.value(), "v", "{bad:?} must keep the cookie");
        assert!(
            matches!(
                parsed.issues[..],
                [SetCookieIssue::InvalidAttributeValue { .. }]
            ),
            "{bad:?} must witness the drop, got {:?}",
            parsed.issues
        );
    }
}

#[test]
fn flags_are_presence_only_and_a_value_is_witnessed() {
    // §5.2.5 / §5.2.6: Secure and HttpOnly are valueless; a spurious `=x`
    // still sets the flag, and the discarded value is reported.
    for h in ["n=v; Secure", "n=v; Secure=anything"] {
        assert!(lenient(h).attributes().secure, "{h:?}");
    }
    for h in ["n=v; HttpOnly", "n=v; HttpOnly=x"] {
        assert!(lenient(h).attributes().http_only, "{h:?}");
    }
    assert!(!lenient("n=v").attributes().secure);
    let valued = SetCookie::parse("n=v; Secure=anything").unwrap();
    assert!(matches!(
        valued.issues[..],
        [SetCookieIssue::FlagWithValue {
            value: "anything",
            ..
        }]
    ));
    assert!(SetCookie::parse("n=v; Secure").unwrap().is_clean());
}

#[test]
fn attribute_names_are_case_insensitive() {
    let c = lenient(
        "n=v; SECURE; httponly; samesite=lax; PATH=/x; max-age=60; \
         EXPIRES=Sun, 06 Nov 1994 08:49:37 GMT",
    );
    let a = c.attributes();
    assert!(a.secure && a.http_only);
    assert_eq!(a.same_site, Some(SameSite::Lax));
    assert_eq!(a.path.as_ref().map(|p| p.as_str()), Some("/x"));
    assert_eq!(a.max_age, Some(60));
    assert!(a.expires.is_some());
}

#[test]
fn unknown_attribute_is_recovered_and_witnessed_in_both_gradings() {
    // §5.2: an unrecognised attribute is ignored — and witnessed — under
    // either grading; refusing it is the caller's is_clean gate.
    let parsed = SetCookie::parse("SID=x; Priority=High; Max-Age=60").unwrap();
    assert_eq!(parsed.value.attributes().max_age, Some(60));
    assert!(matches!(
        parsed.issues[..],
        [SetCookieIssue::UnknownAttribute {
            name: "Priority",
            ..
        }]
    ));
    let strict = SetCookie::parse_strict("SID=x; Priority=High").unwrap();
    assert!(matches!(
        strict.issues[..],
        [SetCookieIssue::UnknownAttribute {
            name: "Priority",
            ..
        }]
    ));
}

#[test]
fn partitioned_parses_as_a_typed_flag_in_both_gradings() {
    // CHIPS' `Partitioned` is a modeled presence flag, not an unknown: the
    // conformant `Secure` pairing parses clean under either grading.
    for parsed in [
        SetCookie::parse("SID=x; Partitioned; Secure").unwrap(),
        SetCookie::parse_strict("SID=x; Partitioned; Secure").unwrap(),
    ] {
        assert!(parsed.value.attributes().partitioned);
        assert!(parsed.value.attributes().secure);
        assert!(parsed.is_clean(), "issues: {:?}", parsed.issues);
    }
}

#[test]
fn malformed_known_attribute_is_recovered_in_both_gradings() {
    // A *known* attribute with a bad value is dropped (it is not "unknown"), so
    // even strict keeps the cookie — with each drop witnessed.
    let parsed = SetCookie::parse_strict("SID=x; Max-Age=banana; SameSite=Bogus").unwrap();
    assert_eq!(parsed.value.value(), "x");
    assert_eq!(parsed.value.attributes().max_age, None);
    assert_eq!(parsed.value.attributes().same_site, None);
    assert_eq!(parsed.issues.len(), 2);
}

#[test]
fn rejects_when_there_is_no_usable_pair() {
    for bad in ["HttpOnly", "", "=v", "   =v", "na me=v"] {
        assert!(SetCookie::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn value_is_decoded_like_the_request_reader() {
    assert_eq!(lenient("pref=caf%C3%A9").value(), "café");
    assert_eq!(lenient(r#"pref="a b""#).value(), "a b");
    // An invalid UTF-8 escape leaves no usable value, so the whole cookie drops.
    assert!(SetCookie::parse("pref=%FF").is_err());
}
