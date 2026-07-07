//! RFC 6265 §5.4: the request `Cookie` header.
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.4>
//!
//! Black-box over `parse_pairs`, `parse_pairs_strict`, and `CookieJar`.

use kekse::{CookieJar, parse_pairs, parse_pairs_strict};

fn pairs(h: &str) -> Vec<(String, String)> {
    parse_pairs(h)
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
        .collect()
}

fn pairs_strict(h: &str) -> Vec<(String, String)> {
    parse_pairs_strict(h)
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_string(), v.into_owned()))
        .collect()
}

#[test]
fn pairs_yielded_in_header_order() {
    assert_eq!(
        pairs("a=1; b=2; c=3"),
        vec![
            ("a".into(), "1".into()),
            ("b".into(), "2".into()),
            ("c".into(), "3".into()),
        ]
    );
}

#[test]
fn duplicate_names_kept_in_order_with_first_match_get() {
    let jar = CookieJar::parse("k=1; k=2; k=3").into_value();
    let vals: Vec<_> = jar.get_all("k").map(|c| c.value().to_string()).collect();
    assert_eq!(vals, ["1", "2", "3"]);
    assert_eq!(jar.get("k").map(|c| c.value()), Some("1")); // first match wins
}

#[test]
fn empty_value_is_a_cookie_that_first_match_finds() {
    let jar = CookieJar::parse("SID=; x=1").into_value();
    assert_eq!(jar.get("SID").map(|c| c.value()), Some(""));
    // The "skip empties" idiom then finds no non-empty SID here.
    assert!(!jar.get_all("SID").any(|c| !c.value().is_empty()));
}

#[test]
fn equals_survives_in_value() {
    assert_eq!(pairs("n=a=b=c"), vec![("n".into(), "a=b=c".into())]);
    assert_eq!(pairs("n==x"), vec![("n".into(), "=x".into())]);
}

#[test]
fn names_are_case_sensitive() {
    let jar = CookieJar::parse("sid=lo; SID=hi").into_value();
    assert_eq!(jar.get("sid").map(|c| c.value()), Some("lo"));
    assert_eq!(jar.get("SID").map(|c| c.value()), Some("hi"));
}

#[test]
fn malformed_segments_are_skipped_keeping_later_pairs() {
    let only_sid = vec![("SID".to_string(), "ok".to_string())];
    for h in [
        "junk; SID=ok",      // no '='
        "=v; SID=ok",        // empty name
        "n=a\u{1}b; SID=ok", // control byte in value
        "naïve=v; SID=ok",   // non-token name
    ] {
        assert_eq!(pairs(h), only_sid, "{h:?} (lenient)");
        assert_eq!(pairs_strict(h), only_sid, "{h:?} (strict)");
    }
}

#[test]
fn lenient_tolerates_whitespace_strict_refuses() {
    assert_eq!(
        parse_pairs("n=a b").next().unwrap().unwrap().1.into_owned(),
        "a b"
    );
    assert!(parse_pairs_strict("n=a b").next().unwrap().is_err()); // refused, witnessed
    // Unquoted edge whitespace is trimmed in both modes.
    assert_eq!(pairs("  n  =  v  "), vec![("n".into(), "v".into())]);
}

#[test]
fn one_quote_pair_stripped_including_empty() {
    assert_eq!(
        parse_pairs(r#"n="v""#)
            .next()
            .unwrap()
            .unwrap()
            .1
            .into_owned(),
        "v"
    );
    assert_eq!(
        parse_pairs(r#"n="""#)
            .next()
            .unwrap()
            .unwrap()
            .1
            .into_owned(),
        ""
    ); // empty quoted
    assert_eq!(
        parse_pairs(r#"n="a b""#)
            .next()
            .unwrap()
            .unwrap()
            .1
            .into_owned(),
        "a b"
    );
    // strict refuses the space the quotes were carrying.
    assert!(parse_pairs_strict(r#"n="a b""#).next().unwrap().is_err());
}
