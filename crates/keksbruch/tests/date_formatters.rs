//! The `rfc_6265` HTTP-date formatters, exercised from keksbruch.
//!
//! Proof that the corpus's canonical `Expires` date literals (`date-imf-fixdate`, `date-rfc850`,
//! `date-asctime`) are the genuine RFC forms of a *single* instant rather than hand-typed strings —
//! and a worked example of the "format in a selected variant" tool keksbruch uses to build payloads.

use rfc_6265::date::{format_http_date, parse_imf_fixdate, HttpDateFormat};

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
