//! `Expires` dates: the strict RFC 7231 §7.1.1.1 IMF-fixdate vs the lenient
//! RFC 6265 §5.1.1 cookie-date.
//! <https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1>
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1>

use kekse::{OffsetDateTime, SetCookie};
use time::macros::datetime;

fn lenient(h: &str) -> Option<OffsetDateTime> {
    SetCookie::parse(h).and_then(|c| c.attributes().expires)
}

fn strict(h: &str) -> Option<OffsetDateTime> {
    SetCookie::parse_strict(h).and_then(|c| c.attributes().expires)
}

#[test]
fn lenient_accepts_the_real_world_formats() {
    let want = datetime!(1994-11-06 08:49:37 UTC);
    assert_eq!(
        lenient("n=v; Expires=Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(want)
    );
    assert_eq!(
        lenient("n=v; Expires=Sunday, 06-Nov-94 08:49:37 GMT"),
        Some(want)
    ); // RFC 850
    assert_eq!(lenient("n=v; Expires=Sun Nov  6 08:49:37 1994"), Some(want)); // asctime()
}

#[test]
fn strict_accepts_only_the_imf_fixdate() {
    let want = datetime!(1994-11-06 08:49:37 UTC);
    assert_eq!(
        strict("n=v; Expires=Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(want)
    );
    for bad in [
        "n=v; Expires=Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
        "n=v; Expires=Sun Nov  6 08:49:37 1994",       // asctime()
        "n=v; Expires=sun, 06 nov 1994 08:49:37 gmt",  // wrong casing
    ] {
        let c = SetCookie::parse_strict(bad).unwrap();
        assert_eq!(c.attributes().expires, None, "{bad:?}");
        assert_eq!(c.value(), "v", "{bad:?} keeps the cookie, drops the date");
    }
}

#[test]
fn two_digit_year_pivots_and_out_of_range_is_rejected() {
    // RFC 6265 §5.1.1: 70..=99 -> 1900+, 0..=69 -> 2000+.
    assert_eq!(
        lenient("n=v; Expires=Mon, 01 Jan 70 00:00:00 GMT").map(|d| d.year()),
        Some(1970)
    );
    assert_eq!(
        lenient("n=v; Expires=Fri, 01 Jan 69 00:00:00 GMT").map(|d| d.year()),
        Some(2069)
    );
    assert_eq!(lenient("n=v; Expires=Sun, 06 Nov 1994 25:00:00 GMT"), None); // hour > 23
    assert_eq!(lenient("n=v; Expires=Tue, 31 Feb 1994 00:00:00 GMT"), None); // impossible day
}

#[test]
fn write_side_emits_canonical_imf_fixdate() {
    let dt = datetime!(2021-06-09 10:18:14 UTC);
    let header = SetCookie::new("SID", "x").expires(dt).to_set_cookie();
    assert_eq!(header, "SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT");
}

#[test]
fn expires_round_trips_through_render_and_strict_parse() {
    let dt = datetime!(2030-12-31 23:59:59 UTC);
    let rendered = SetCookie::new("SID", "x").expires(dt).to_set_cookie();
    let reparsed = SetCookie::parse_strict(&rendered).unwrap();
    assert_eq!(reparsed.attributes().expires, Some(dt));
}

#[test]
fn expires_and_max_age_coexist_independently() {
    // §5.3 precedence (Max-Age wins) is a cookie-store concern; the codec keeps both.
    let dt = datetime!(2021-06-09 10:18:14 UTC);
    let c = SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=60").unwrap();
    assert_eq!(c.attributes().expires, Some(dt));
    assert_eq!(c.attributes().max_age, Some(60));
}
