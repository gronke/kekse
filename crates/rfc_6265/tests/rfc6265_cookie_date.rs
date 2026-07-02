//! RFC 6265 §5.1.1 cookie-date conformance — black-box tests over the public `date` API.
//!
//! A companion to the exhaustive inline unit tests in `src/date.rs`, written to walk the spec
//! step by step so the conformance surface is legible straight from the repository.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1> ·
//! <https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1>
#![cfg(feature = "date")]

use rfc_6265::OffsetDateTime;
use rfc_6265::date::{
    HttpDateFormat, format_http_date, format_imf_fixdate, parse_cookie_date, parse_imf_fixdate,
};

/// The RFC 6265 §5.1.1 / RFC 7231 running example instant: `Sun, 06 Nov 1994 08:49:37 GMT`.
fn example() -> OffsetDateTime {
    parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").expect("canonical IMF-fixdate parses")
}

/// §5.1.1 — the three HTTP-date syntaxes a cookie-date may take all denote the one instant.
#[test]
fn accepts_the_three_canonical_http_date_forms() {
    let want = Some(example());
    assert_eq!(parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"), want); // IMF-fixdate
    assert_eq!(parse_cookie_date("Sunday, 06-Nov-94 08:49:37 GMT"), want); // RFC 850
    assert_eq!(parse_cookie_date("Sun Nov  6 08:49:37 1994"), want); // asctime()
}

/// §5.1.1 steps 1–2 — the scan is a tolerant, order-independent token walk: it ignores the
/// weekday, the time zone, the delimiter choice, extra whitespace, and any trailing tokens.
#[test]
fn is_tolerant_of_shape_weekday_zone_and_order() {
    let want = Some(example());
    for input in [
        "06 Nov 1994 08:49:37 GMT",            // no weekday
        "Sun, 06 Nov 1994 08:49:37",           // no zone
        "Sun, 06-Nov-1994 08:49:37 GMT",       // '-' delimiters, four-digit year
        "Sun,  06  Nov  1994  08:49:37  GMT",  // collapsed runs of whitespace
        "08:49:37 1994 Nov 06",                // fully reordered
        "Sun, 06 Nov 1994 08:49:37 GMT (UTC)", // trailing comment
    ] {
        assert_eq!(parse_cookie_date(input), want, "{input:?}");
    }
}

/// §5.1.1 steps 3–4 — a two-digit year pivots: 70–99 → 19xx, 00–69 → 20xx.
#[test]
fn two_digit_year_pivots() {
    let year = |yy: &str| parse_cookie_date(&format!("06 Nov {yy} 08:49:37")).map(|d| d.year());
    assert_eq!(year("69"), Some(2069));
    assert_eq!(year("70"), Some(1970));
    assert_eq!(year("94"), Some(1994));
}

/// §5.1.1 step 5 — the parse fails unless a time, day-of-month, month, and year were all found.
#[test]
fn requires_all_four_components() {
    for incomplete in [
        "06 Nov 1994",       // no time
        "Nov 1994 08:49:37", // no day-of-month
        "06 1994 08:49:37",  // no month
        "06 Nov 08:49:37",   // no year
    ] {
        assert!(parse_cookie_date(incomplete).is_none(), "{incomplete:?}");
    }
}

/// §5.1.1 step 5 — numeric bounds: day 1–31, year ≥ 1601, hour ≤ 23, minute ≤ 59, second ≤ 59.
#[test]
fn rejects_values_outside_the_mandated_bounds() {
    for out_of_range in [
        "00 Nov 1994 08:49:37", // day < 1
        "32 Nov 1994 08:49:37", // day > 31
        "31 Feb 1994 08:49:37", // impossible calendar day
        "06 Nov 1600 08:49:37", // year < 1601 (the far-past footgun)
        "06 Nov 1994 25:49:37", // hour > 23
        "06 Nov 1994 08:60:37", // minute > 59
        "06 Nov 1994 08:49:60", // second > 59
    ] {
        assert!(
            parse_cookie_date(out_of_range).is_none(),
            "{out_of_range:?}"
        );
    }
    // 1601 is the boundary and is accepted.
    assert!(parse_cookie_date("01 Jan 1601 00:00:00").is_some());
}

/// RFC 7231 §7.1.1.1 — the strict parser accepts only the canonical IMF-fixdate.
#[test]
fn strict_imf_fixdate_is_exact() {
    assert_eq!(
        parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(example())
    );
    for rejected in [
        "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
        "Sun Nov  6 08:49:37 1994",       // asctime()
        "Sun, 6 Nov 1994 08:49:37 GMT",   // unpadded day
        "Sun, 06 Nov 1994 08:49:37 UTC",  // non-GMT zone
        "Sun, 06 Nov 1600 08:49:37 GMT",  // year < 1601
    ] {
        assert!(parse_imf_fixdate(rejected).is_none(), "{rejected:?}");
    }
}

/// Anything the strict parser accepts, the lenient parser accepts identically (strict ⊆ lenient).
#[test]
fn strict_is_a_subset_of_lenient() {
    for s in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Tue, 19 Jan 2038 03:14:07 GMT",
    ] {
        let strict = parse_imf_fixdate(s).expect("valid IMF-fixdate");
        assert_eq!(parse_cookie_date(s), Some(strict), "{s:?}");
    }
}

/// Formatting is the selectable inverse of the one tolerant parser; every variant round-trips.
#[test]
fn formats_each_variant_and_round_trips() {
    let when = example();
    assert_eq!(
        format_http_date(when, HttpDateFormat::ImfFixdate),
        "Sun, 06 Nov 1994 08:49:37 GMT"
    );
    assert_eq!(
        format_http_date(when, HttpDateFormat::Rfc850),
        "Sunday, 06-Nov-94 08:49:37 GMT"
    );
    assert_eq!(
        format_http_date(when, HttpDateFormat::Asctime),
        "Sun Nov  6 08:49:37 1994"
    );
    for fmt in [
        HttpDateFormat::ImfFixdate,
        HttpDateFormat::Rfc850,
        HttpDateFormat::Asctime,
    ] {
        assert_eq!(parse_cookie_date(&format_http_date(when, fmt)), Some(when));
    }
    assert_eq!(format_imf_fixdate(when), "Sun, 06 Nov 1994 08:49:37 GMT");
}
