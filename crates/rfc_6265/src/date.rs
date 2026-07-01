//! Cookie-date handling: the RFC 6265 §5.1.1 cookie-date scan and the RFC 7231 §7.1.1.1 IMF-fixdate.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1> ·
//! <https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1>
//!
//! Two parsers, matching the *brutally strict vs. compliant-and-tolerant* split:
//!
//! - [`parse_cookie_date`] is the RFC 6265 §5.1.1 **cookie-date** parser — the spec's deliberately
//!   *tolerant* algorithm. It splits the input on a delimiter byte-set and scans the tokens,
//!   order-independently, for a time, day-of-month, month, and year, ignoring anything else
//!   (weekday names, time zones, trailing comments). This is what a `Set-Cookie` `Expires` value
//!   should be read with, and it is not hand-rolled arithmetic: `time` still builds and validates
//!   the final date.
//! - [`parse_imf_fixdate`] is **strict**: only the canonical RFC 7231 IMF-fixdate
//!   (`Sun, 06 Nov 1994 08:49:37 GMT`) — exact casing, exact spacing, full-input match, always GMT.
//!
//! Both apply the RFC 6265 §5.1.1 numeric sanity conditions (a valid calendar day, **year ≥ 1601**,
//! `hour ≤ 23`, `minute ≤ 59`, `second ≤ 59`), so neither yields an absurd far-past expiry.
//!
//! Formatting is the inverse. [`format_imf_fixdate`] renders the canonical IMF-fixdate senders
//! should emit; [`format_http_date`] renders any of the three [`HttpDateFormat`] variants — one
//! tolerant parser in, a selectable variant out.
//!
//! ```
//! use rfc_6265::date::{parse_cookie_date, parse_imf_fixdate};
//! // Lenient §5.1.1: tolerant of a missing weekday and zone, order-independent.
//! assert!(parse_cookie_date("06 Nov 1994 08:49:37").is_some());
//! // Strict RFC 7231: only the canonical IMF-fixdate.
//! assert!(parse_imf_fixdate("06 Nov 1994 08:49:37").is_none());
//! assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
//! ```

use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::parsing::Parsed;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// RFC 7231 IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`. Drives strict parsing and canonical formatting.
const IMF_FIXDATE: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);
/// Obsolete RFC 850 form: `Sunday, 06-Nov-94 08:49:37 GMT` (two-digit year). Formatting only.
const RFC_850: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:long], [day]-[month repr:short]-[year repr:last_two] [hour]:[minute]:[second] GMT"
);
/// Obsolete `asctime()` form: `Sun Nov  6 08:49:37 1994` (space-padded day, no zone). Formatting only.
const ASCTIME: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
);

/// Build a UTC [`OffsetDateTime`] from cookie-date components, applying the RFC 6265 §5.1.1 sanity
/// conditions: `year ≥ 1601` explicitly, plus — via `time`'s constructors — a valid calendar day
/// (e.g. 31 Feb and day 0 are rejected) and `hour ≤ 23` / `minute ≤ 59` / `second ≤ 59`.
fn make_utc(
    year: i32,
    month: Month,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<OffsetDateTime> {
    if year < 1601 {
        return None;
    }
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// Parse `value` fully against `items` (the entire input must be consumed), or `None`.
fn parse_full(value: &str, items: &[BorrowedFormatItem<'_>]) -> Option<Parsed> {
    let mut parsed = Parsed::new();
    let rest = parsed.parse_items(value.as_bytes(), items).ok()?;
    rest.is_empty().then_some(parsed)
}

/// Assemble a UTC [`OffsetDateTime`] from a known full `year` plus the month/day/time in `parsed`.
fn assemble(year: i32, parsed: &Parsed) -> Option<OffsetDateTime> {
    make_utc(
        year,
        parsed.month()?,
        parsed.day()?.get(),
        parsed.hour_24()?,
        parsed.minute()?,
        parsed.second()?,
    )
}

/// Strictly parse the RFC 7231 §7.1.1.1 IMF-fixdate: exact casing/spacing, full-input match, always
/// GMT. Rejects the obsolete RFC 850 / `asctime()` forms — and, per the RFC 6265 §5.1.1 sanity
/// floor this cookie crate applies to both parsers, any `year < 1601`.
///
/// ```
/// use rfc_6265::date::parse_imf_fixdate;
/// assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
/// assert!(parse_imf_fixdate("Sunday, 06-Nov-94 08:49:37 GMT").is_none()); // RFC 850, rejected
/// ```
#[must_use]
pub fn parse_imf_fixdate(value: &str) -> Option<OffsetDateTime> {
    let parsed = parse_full(value, IMF_FIXDATE)?;
    assemble(parsed.year()?, &parsed)
}

// ---- RFC 6265 §5.1.1 cookie-date scan --------------------------------------

/// RFC 6265 §5.1.1 `delimiter`: `%x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E`. Everything else —
/// notably DIGIT, `:`, and ALPHA — is a `non-delimiter` that a date-token is built from.
const fn is_delimiter(b: u8) -> bool {
    matches!(b, 0x09 | 0x20..=0x2f | 0x3b..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e)
}

/// Read a `1*2DIGIT` field (1 or 2 leading ASCII digits) from `b`, returning its value and the
/// unconsumed tail, or `None` if `b` does not start with a digit.
fn take_1_2_digits(b: &[u8]) -> Option<(u8, &[u8])> {
    let first = *b.first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    match b.get(1) {
        Some(&second) if second.is_ascii_digit() => {
            Some(((first - b'0') * 10 + (second - b'0'), &b[2..]))
        }
        _ => Some((first - b'0', &b[1..])),
    }
}

/// Whether the optional `( non-digit *OCTET )` tail of a numeric production is well-formed: it is
/// either absent, or begins with a non-digit (after which any octets are ignored).
fn tail_is_not_a_digit(rest: &[u8]) -> bool {
    !matches!(rest.first(), Some(b) if b.is_ascii_digit())
}

/// `time = hms-time ( non-digit *OCTET )` — three `1*2DIGIT` fields joined by `:`.
fn match_time(token: &[u8]) -> Option<(u8, u8, u8)> {
    let (hour, rest) = take_1_2_digits(token)?;
    let (minute, rest) = take_1_2_digits(rest.strip_prefix(b":")?)?;
    let (second, rest) = take_1_2_digits(rest.strip_prefix(b":")?)?;
    tail_is_not_a_digit(rest).then_some((hour, minute, second))
}

/// `day-of-month = 1*2DIGIT ( non-digit *OCTET )`.
fn match_day_of_month(token: &[u8]) -> Option<u8> {
    let (day, rest) = take_1_2_digits(token)?;
    tail_is_not_a_digit(rest).then_some(day)
}

/// `month` — the first three bytes name a month, case-insensitively; trailing octets are ignored.
fn match_month(token: &[u8]) -> Option<Month> {
    let head: [u8; 3] = token.get(..3)?.try_into().ok()?;
    Some(match &head.map(|b| b.to_ascii_lowercase()) {
        b"jan" => Month::January,
        b"feb" => Month::February,
        b"mar" => Month::March,
        b"apr" => Month::April,
        b"may" => Month::May,
        b"jun" => Month::June,
        b"jul" => Month::July,
        b"aug" => Month::August,
        b"sep" => Month::September,
        b"oct" => Month::October,
        b"nov" => Month::November,
        b"dec" => Month::December,
        _ => return None,
    })
}

/// `year = 2*4DIGIT ( non-digit *OCTET )` — 2 to 4 leading digits, then an optional non-digit tail.
fn match_year(token: &[u8]) -> Option<i32> {
    let digits = token.iter().take_while(|b| b.is_ascii_digit()).count();
    if !(2..=4).contains(&digits) {
        return None;
    }
    // The `digits` leading bytes are the year; anything after is a non-digit by construction.
    Some(
        token[..digits]
            .iter()
            .fold(0i32, |acc, &b| acc * 10 + i32::from(b - b'0')),
    )
}

/// Parse a `Set-Cookie` `Expires` value with the RFC 6265 §5.1.1 cookie-date algorithm: a tolerant,
/// order-independent scan over delimiter-separated tokens for a time, day-of-month, month, and year.
/// Unknown tokens (the weekday, a time zone, trailing comments) are ignored. `None` if any of the
/// four components is missing or the §5.1.1 sanity conditions fail (bad calendar day, `year < 1601`,
/// `hour > 23`, `minute > 59`, `second > 59`).
///
/// ```
/// use rfc_6265::date::parse_cookie_date;
/// // Order-independent, weekday/zone optional — all denote the same instant:
/// assert_eq!(
///     parse_cookie_date("08:49:37 1994 Nov 06"),
///     parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"),
/// );
/// // A two-digit year pivots (00–69 → 2000+, 70–99 → 1900+):
/// assert_eq!(parse_cookie_date("06 Nov 94 08:49:37").map(|d| d.year()), Some(1994));
/// // The §5.1.1 sanity floor rejects a year before 1601:
/// assert!(parse_cookie_date("06 Nov 1600 08:49:37").is_none());
/// ```
#[must_use]
pub fn parse_cookie_date(value: &str) -> Option<OffsetDateTime> {
    let mut hms: Option<(u8, u8, u8)> = None;
    let mut day: Option<u8> = None;
    let mut month: Option<Month> = None;
    let mut year: Option<i32> = None;

    // §5.1.1 steps 1–2: split on the delimiter set, then bind each token to the first unset
    // category in the order time, day-of-month, month, year (runs of delimiters yield empties).
    for token in value.as_bytes().split(|&b| is_delimiter(b)) {
        if token.is_empty() {
            continue;
        }
        if hms.is_none() {
            if let Some(t) = match_time(token) {
                hms = Some(t);
                continue;
            }
        }
        if day.is_none() {
            if let Some(d) = match_day_of_month(token) {
                day = Some(d);
                continue;
            }
        }
        if month.is_none() {
            if let Some(m) = match_month(token) {
                month = Some(m);
                continue;
            }
        }
        if year.is_none() {
            if let Some(y) = match_year(token) {
                year = Some(y);
                continue;
            }
        }
    }

    let (hour, minute, second) = hms?;
    let (day, month) = (day?, month?);
    let mut year = year?;

    // §5.1.1 steps 3–4: two-digit-year century pivot, applied to the year-*value*.
    if (70..=99).contains(&year) {
        year += 1900;
    } else if (0..=69).contains(&year) {
        year += 2000;
    }

    // §5.1.1 steps 5–6: the sanity conditions and UTC construction.
    make_utc(year, month, day, hour, minute, second)
}

// ---- Formatting ------------------------------------------------------------

/// Which HTTP-date syntax [`format_http_date`] should emit. RFC 6265 §5.1.1 accepts all three on
/// the parse side; this lets a caller choose one to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpDateFormat {
    /// Canonical RFC 7231 IMF-fixdate — `Sun, 06 Nov 1994 08:49:37 GMT`. What senders should use.
    ImfFixdate,
    /// Obsolete RFC 850 form — `Sunday, 06-Nov-94 08:49:37 GMT`. The two-digit year is lossy outside 1970–2069.
    Rfc850,
    /// Obsolete C `asctime()` form — `Sun Nov  6 08:49:37 1994` (space-padded day, no zone).
    Asctime,
}

/// Render `when` (converted to UTC) in the selected [`HttpDateFormat`].
///
/// The inverse of [`parse_cookie_date`], which accepts all three shapes: this emits a chosen one —
/// useful for interoperability testing against other stacks. Because RFC 850 carries only a
/// two-digit year, `HttpDateFormat::Rfc850` round-trips unambiguously only for years 1970–2069.
///
/// ```
/// use rfc_6265::date::{format_http_date, parse_imf_fixdate, HttpDateFormat};
/// let when = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
/// assert_eq!(format_http_date(when, HttpDateFormat::Rfc850), "Sunday, 06-Nov-94 08:49:37 GMT");
/// assert_eq!(format_http_date(when, HttpDateFormat::Asctime), "Sun Nov  6 08:49:37 1994");
/// ```
#[must_use]
pub fn format_http_date(when: OffsetDateTime, format: HttpDateFormat) -> String {
    let items = match format {
        HttpDateFormat::ImfFixdate => IMF_FIXDATE,
        HttpDateFormat::Rfc850 => RFC_850,
        HttpDateFormat::Asctime => ASCTIME,
    };
    when.to_offset(UtcOffset::UTC)
        .format(items)
        .expect("HTTP-date formatting of a valid OffsetDateTime is infallible")
}

/// Render `when` (converted to UTC) as the canonical RFC 7231 IMF-fixdate — the form senders should emit.
///
/// ```
/// use rfc_6265::date::{format_imf_fixdate, parse_imf_fixdate};
/// let when = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
/// assert_eq!(format_imf_fixdate(when), "Sun, 06 Nov 1994 08:49:37 GMT");
/// ```
#[must_use]
pub fn format_imf_fixdate(when: OffsetDateTime) -> String {
    format_http_date(when, HttpDateFormat::ImfFixdate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const WHEN: OffsetDateTime = datetime!(1994-11-06 08:49:37 UTC);

    // ---- parse_imf_fixdate: strict RFC 7231 -------------------------------

    #[test]
    fn strict_parses_the_canonical_imf_fixdate() {
        assert_eq!(
            parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(WHEN)
        );
    }

    #[test]
    fn strict_rejects_non_canonical_forms() {
        for bad in [
            "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
            "Sun Nov  6 08:49:37 1994",       // asctime()
            "sun, 06 Nov 1994 08:49:37 GMT",  // lowercase weekday
            "Sun, 06 nov 1994 08:49:37 GMT",  // lowercase month
            "Sun, 6 Nov 1994 08:49:37 GMT",   // 1-digit day
            "Sun, 06 Nov 1994 08:49:37 UTC",  // wrong zone
            "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing space
            "Sun, 06 Nov 1994 08:49:37 GMTx", // trailing junk
            "Sun, 06 Nov 1994 08:49:37",      // missing zone
            "",
        ] {
            assert!(parse_imf_fixdate(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn strict_applies_the_year_1601_floor() {
        // The §5.1.1 sanity floor applies to the strict parser too, so it can never accept a
        // far-past date that the lenient parser rejects.
        assert!(parse_imf_fixdate("Sun, 06 Nov 1600 08:49:37 GMT").is_none());
        assert!(parse_imf_fixdate("Mon, 01 Jan 1601 00:00:00 GMT").is_some());
    }

    // ---- parse_cookie_date: RFC 6265 §5.1.1 tolerant scan -----------------

    #[test]
    fn lenient_accepts_all_three_http_date_formats() {
        assert_eq!(
            parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(WHEN)
        );
        assert_eq!(
            parse_cookie_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(WHEN)
        );
        assert_eq!(parse_cookie_date("Sun Nov  6 08:49:37 1994"), Some(WHEN));
    }

    #[test]
    fn lenient_is_tolerant_per_section_5_1_1() {
        // Each denotes the same instant; the scan is order-independent and ignores the weekday,
        // zone, delimiter choice, extra whitespace, and trailing tokens.
        for ok in [
            "06 Nov 1994 08:49:37 GMT",            // no weekday
            "Sun, 06 Nov 1994 08:49:37",           // no zone
            "Sun, 06-Nov-1994 08:49:37 GMT",       // dash delimiters, 4-digit year
            "Sun,  06  Nov  1994  08:49:37  GMT",  // doubled spaces
            "08:49:37 1994 Nov 06",                // reordered
            "Sun, 06 Nov 1994 08:49:37 GMT (UTC)", // trailing comment
            "Sun, 06 Nov 94 08:49:37 GMT",         // two-digit year in IMF shape
        ] {
            assert_eq!(
                parse_cookie_date(ok),
                Some(WHEN),
                "{ok:?} should parse to WHEN"
            );
        }
    }

    #[test]
    fn lenient_two_digit_year_pivots_across_the_full_range() {
        // RFC 6265 §5.1.1 steps 3–4: 70–99 → 1900+, 00–69 → 2000+.
        let year_of = |yy: &str| {
            parse_cookie_date(&format!("Wed, 01 Jan {yy} 00:00:00 GMT")).map(|d| d.year())
        };
        assert_eq!(year_of("00"), Some(2000));
        assert_eq!(year_of("68"), Some(2068));
        assert_eq!(year_of("69"), Some(2069));
        assert_eq!(year_of("70"), Some(1970));
        assert_eq!(year_of("71"), Some(1971));
        assert_eq!(year_of("99"), Some(1999));
    }

    #[test]
    fn lenient_rejects_out_of_range_and_impossible() {
        for bad in [
            "Tue, 31 Feb 1994 00:00:00 GMT", // impossible calendar day
            "Sun, 06 Nov 1994 25:00:00 GMT", // hour > 23
            "Sun, 06 Nov 1994 08:60:00 GMT", // minute > 59
            "Sun, 06 Nov 1994 08:49:60 GMT", // second > 59
            "Sun, 32 Nov 1994 08:49:37 GMT", // day > 31
            "Sun, 00 Nov 1994 08:49:37 GMT", // day < 1
            "not-a-date",
            "",
        ] {
            assert!(parse_cookie_date(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn lenient_requires_all_four_components() {
        for missing in [
            "06 Nov 1994",       // no time
            "Nov 1994 08:49:37", // no day-of-month
            "06 1994 08:49:37",  // no month
            "06 Nov 08:49:37",   // no year
        ] {
            assert!(
                parse_cookie_date(missing).is_none(),
                "{missing:?} is missing a component"
            );
        }
    }

    #[test]
    fn lenient_applies_the_year_1601_floor() {
        assert!(parse_cookie_date("Mon, 01 Jan 1601 00:00:00 GMT").is_some());
        assert!(parse_cookie_date("Sun, 06 Nov 1600 08:49:37 GMT").is_none());
        // The historical footgun: a far-past year must not yield a date.
        assert!(parse_cookie_date("Sun, 06 Nov 1000 08:49:37 GMT").is_none());
    }

    #[test]
    fn strict_is_a_subset_of_lenient() {
        // Anything the strict parser accepts, the lenient parser accepts identically.
        for s in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Mon, 01 Jan 1601 00:00:00 GMT",
            "Tue, 19 Jan 2038 03:14:07 GMT",
        ] {
            if let Some(dt) = parse_imf_fixdate(s) {
                assert_eq!(parse_cookie_date(s), Some(dt), "{s:?}");
            }
        }
    }

    // ---- Formatting -------------------------------------------------------

    #[test]
    fn format_imf_fixdate_is_canonical_and_converts_to_utc() {
        assert_eq!(format_imf_fixdate(WHEN), "Sun, 06 Nov 1994 08:49:37 GMT");
        // The same instant expressed at +02:00 must render in GMT.
        assert_eq!(
            format_imf_fixdate(datetime!(1994-11-06 10:49:37 +2)),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn format_http_date_emits_each_variant() {
        assert_eq!(
            format_http_date(WHEN, HttpDateFormat::ImfFixdate),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            format_http_date(WHEN, HttpDateFormat::Rfc850),
            "Sunday, 06-Nov-94 08:49:37 GMT"
        );
        assert_eq!(
            format_http_date(WHEN, HttpDateFormat::Asctime),
            "Sun Nov  6 08:49:37 1994"
        );
    }

    #[test]
    fn format_variants_round_trip_through_the_lenient_parser() {
        for fmt in [
            HttpDateFormat::ImfFixdate,
            HttpDateFormat::Rfc850,
            HttpDateFormat::Asctime,
        ] {
            let rendered = format_http_date(WHEN, fmt);
            assert_eq!(parse_cookie_date(&rendered), Some(WHEN), "{rendered:?}");
        }
        // The canonical form round-trips through the strict parser too.
        assert_eq!(parse_imf_fixdate(&format_imf_fixdate(WHEN)), Some(WHEN));
    }
}
