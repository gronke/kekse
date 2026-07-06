//! The `rfc_6265` HTTP-date formatters, exercised from keksbruch.
//!
//! Proof that the corpus's canonical `Expires` date literals (`date-imf-fixdate`, `date-rfc850`,
//! `date-asctime`) are the genuine RFC forms of a *single* instant rather than hand-typed strings —
//! and a worked example of the "format in a selected variant" tool keksbruch uses to build payloads.

use rfc_6265::date::{
    HttpDateFormat, format_http_date, format_imf_fixdate, parse_cookie_date, parse_imf_fixdate,
};

#[test]
fn corpus_date_literals_are_the_genuine_rfc_forms_of_one_instant() {
    // The instant behind the `date-imf-fixdate` / `date-rfc850` / `date-asctime` scenarios.
    let when = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").expect("canonical IMF-fixdate");
    assert_eq!(
        format_http_date(when, HttpDateFormat::ImfFixdate),
        "Sun, 06 Nov 1994 08:49:37 GMT",
    );
    assert_eq!(
        format_http_date(when, HttpDateFormat::Rfc850),
        "Sunday, 06-Nov-94 08:49:37 GMT",
    );
    assert_eq!(
        format_http_date(when, HttpDateFormat::Asctime),
        "Sun Nov  6 08:49:37 1994",
    );
}

#[test]
fn weekday_bearing_date_literals_carry_the_true_weekday() {
    // The lenient §5.1.1 scan ignores the weekday token, so a wrong one in a corpus wire would
    // go unnoticed by the pins — but these rows isolate *other* variables (the pivot, the year
    // floor, casing, delimiters), so their weekdays must be genuine: re-derive each instant and
    // check its canonical rendering opens with the literal's own weekday token.
    for lit in [
        "Tue, 01 Jan 69 00:00:00 GMT",        // date-2digit-year-69 → 2069
        "Thu, 01 Jan 70 00:00:00 GMT",        // date-2digit-year-70 → 1970
        "Mon, 01 Jan 1601 00:00:00 GMT",      // date-year-1601-boundary
        "Sun, 6 Nov 1994 08:49:37 GMT",       // date-1-digit-day
        "Sun, 06 NOV 1994 08:49:37 GMT",      // date-month-case
        "Sun, 06 Nov 1994 08:49:37 GMT+0100", // date-zone-offset
        "Sun,\t06\tNov\t1994\t08:49:37\tGMT", // date-tab-delims
    ] {
        let when = parse_cookie_date(lit).unwrap_or_else(|| panic!("{lit:?} must parse"));
        let canonical = format_imf_fixdate(when);
        assert_eq!(&canonical[..3], &lit[..3], "weekday of {lit:?}");
    }
}
