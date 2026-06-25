//! RFC 6265 §5.2: parsing the `Set-Cookie` header into a `SetCookie`.
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.2>
//!
//! Black-box over `SetCookie::parse` (lenient) and `SetCookie::parse_strict`.

use kekse::{SameSite, SetCookie};

#[test]
fn splits_first_semicolon_then_first_equals() {
    // §5.2: the name-value-pair runs up to the first ';', the name up to the
    // first '=' (so '=' survives in the value).
    let c = SetCookie::parse("a=b=c; Path=/x").unwrap();
    assert_eq!(c.name(), "a");
    assert_eq!(c.value(), "b=c");
    assert_eq!(c.attributes().path.as_ref().map(|p| p.as_str()), Some("/x"));
}

#[test]
fn empty_and_trailing_semicolons_tolerated_but_pair_must_lead() {
    assert!(SetCookie::parse("SID=x;").is_some());
    assert!(SetCookie::parse("SID=x;;;").is_some());
    assert!(
        SetCookie::parse("SID=x; ; Secure")
            .unwrap()
            .attributes()
            .secure
    );
    // A leading ';' makes the first (pair) segment empty — no usable pair.
    assert!(SetCookie::parse("; SID=x").is_none());
}

#[test]
fn max_age_digit_grammar() {
    // §5.2.2: Max-Age is 1*DIGIT (kekse parses it as a u64).
    let max_age = |h: &str| SetCookie::parse(h).and_then(|c| c.attributes().max_age);
    assert_eq!(max_age("n=v; Max-Age=60"), Some(60));
    assert_eq!(max_age("n=v; Max-Age=0"), Some(0)); // delete sentinel
    assert_eq!(max_age("n=v; Max-Age=007"), Some(7)); // leading zeros
    assert_eq!(max_age("n=v; Max-Age=18446744073709551615"), Some(u64::MAX));
    assert_eq!(max_age("n=v; Max-Age = 60 "), Some(60)); // whitespace trimmed

    // Each of these drops the attribute (cookie still parses, value kept).
    for bad in [
        "n=v; Max-Age=-1",
        "n=v; Max-Age=banana",
        "n=v; Max-Age=1.5",
        "n=v; Max-Age=12x",
        "n=v; Max-Age=",
        "n=v; Max-Age=18446744073709551616", // u64::MAX + 1 overflows
        "n=v; Max-Age=99999999999999999999999", // far past u64
    ] {
        let c = SetCookie::parse(bad).unwrap();
        assert_eq!(c.attributes().max_age, None, "{bad:?}");
        assert_eq!(c.value(), "v", "{bad:?} must keep the cookie");
    }
}

#[test]
fn flags_are_presence_only_and_ignore_a_value() {
    // §5.2.5 / §5.2.6: Secure and HttpOnly are valueless; a spurious `=x` is ignored.
    for h in ["n=v; Secure", "n=v; Secure=anything"] {
        assert!(SetCookie::parse(h).unwrap().attributes().secure, "{h:?}");
    }
    for h in ["n=v; HttpOnly", "n=v; HttpOnly=x"] {
        assert!(SetCookie::parse(h).unwrap().attributes().http_only, "{h:?}");
    }
    assert!(!SetCookie::parse("n=v").unwrap().attributes().secure);
}

#[test]
fn attribute_names_are_case_insensitive() {
    let c = SetCookie::parse(
        "n=v; SECURE; httponly; samesite=lax; PATH=/x; max-age=60; \
         EXPIRES=Sun, 06 Nov 1994 08:49:37 GMT",
    )
    .unwrap();
    let a = c.attributes();
    assert!(a.secure && a.http_only);
    assert_eq!(a.same_site, Some(SameSite::Lax));
    assert_eq!(a.path.as_ref().map(|p| p.as_str()), Some("/x"));
    assert_eq!(a.max_age, Some(60));
    assert!(a.expires.is_some());
}

#[test]
fn unknown_attribute_ignored_by_default_rejected_by_strict() {
    // §5.2: an unrecognised attribute is ignored by default, rejected by strict.
    let c = SetCookie::parse("SID=x; Priority=High; Partitioned; Max-Age=60").unwrap();
    assert_eq!(c.attributes().max_age, Some(60));
    assert!(SetCookie::parse_strict("SID=x; Priority=High").is_none());
    assert!(SetCookie::parse_strict("SID=x; Partitioned").is_none());
}

#[test]
fn malformed_known_attribute_is_dropped_not_fatal_even_in_strict() {
    // A *known* attribute with a bad value is dropped (it is not "unknown"), so
    // even strict keeps the cookie.
    let c = SetCookie::parse_strict("SID=x; Max-Age=banana; SameSite=Bogus").unwrap();
    assert_eq!(c.value(), "x");
    assert_eq!(c.attributes().max_age, None);
    assert_eq!(c.attributes().same_site, None);
}

#[test]
fn rejects_when_there_is_no_usable_pair() {
    for bad in ["HttpOnly", "", "=v", "   =v", "na me=v"] {
        assert!(SetCookie::parse(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn value_is_decoded_like_the_request_reader() {
    assert_eq!(SetCookie::parse("pref=caf%C3%A9").unwrap().value(), "café");
    assert_eq!(SetCookie::parse(r#"pref="a b""#).unwrap().value(), "a b");
    // An invalid UTF-8 escape leaves no usable value, so the whole cookie drops.
    assert!(SetCookie::parse("pref=%FF").is_none());
}
