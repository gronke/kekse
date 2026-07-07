//! The `SameSite` attribute — RFC 6265bis (draft) §5.4.7. SameSite is not in
//! RFC 6265 proper; it is standardised in the 6265bis draft.
//! <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.4.7>

use kekse::{SameSite, SetCookie};

#[test]
fn canonical_casing() {
    assert_eq!(SameSite::Strict.as_str(), "Strict");
    assert_eq!(SameSite::Lax.as_str(), "Lax");
    assert_eq!(SameSite::None.as_str(), "None");
    assert_eq!(SameSite::None.to_string(), "None");
}

#[test]
fn case_insensitive_parse_through_set_cookie() {
    for (token, want) in [
        ("strict", SameSite::Strict),
        ("sTrIcT", SameSite::Strict),
        ("LAX", SameSite::Lax),
        ("none", SameSite::None),
        ("NONE", SameSite::None),
    ] {
        let header = format!("n=v; SameSite={token}");
        let c = SetCookie::parse(&header).unwrap().into_value();
        assert_eq!(c.attributes().same_site, Some(want), "{token:?}");
    }
}

#[test]
fn unknown_token_dropped_cookie_kept() {
    for bad in [
        "n=v; SameSite=Bogus",
        "n=v; SameSite=",
        "n=v; SameSite=Strictish",
    ] {
        let c = SetCookie::parse(bad).unwrap().into_value();
        assert_eq!(c.attributes().same_site, None, "{bad:?}");
        assert_eq!(c.value(), "v");
    }
}

#[test]
fn round_trips_through_render() {
    for v in [SameSite::Strict, SameSite::Lax, SameSite::None] {
        let rendered = SetCookie::new("n", "v").same_site(v).to_set_cookie();
        let reparsed = SetCookie::parse(&rendered).unwrap().into_value();
        assert_eq!(reparsed.attributes().same_site, Some(v));
    }
}

#[test]
fn none_does_not_require_or_add_secure() {
    // kekse is a codec, not a policy engine: `SameSite=None` is stored and
    // rendered without a `Secure` flag, and is not rejected for lacking one.
    let c = SetCookie::parse("n=v; SameSite=None").unwrap().into_value();
    assert_eq!(c.attributes().same_site, Some(SameSite::None));
    assert!(!c.attributes().secure);
    assert_eq!(
        SetCookie::new("n", "v")
            .same_site(SameSite::None)
            .to_set_cookie(),
        "n=v; SameSite=None"
    );
}
