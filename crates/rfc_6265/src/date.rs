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

use std::{fmt, io};

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
/// GMT, and a weekday that agrees with the date. Rejects the obsolete RFC 850 / `asctime()` forms —
/// and, per the RFC 6265 §5.1.1 sanity floor this cookie crate applies to both parsers, any
/// `year < 1601`.
///
/// The leading weekday is redundant with the date; `time` parses the token but does not verify it,
/// so this parser does: a well-formed line whose weekday disagrees with its date is rejected.
///
/// ```
/// use rfc_6265::date::parse_imf_fixdate;
/// assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
/// assert!(parse_imf_fixdate("Mon, 06 Nov 1994 08:49:37 GMT").is_none()); // 06 Nov 1994 was a Sunday
/// assert!(parse_imf_fixdate("Sunday, 06-Nov-94 08:49:37 GMT").is_none()); // RFC 850, rejected
/// ```
#[must_use]
pub fn parse_imf_fixdate(value: &str) -> Option<OffsetDateTime> {
    let parsed = parse_full(value, IMF_FIXDATE)?;
    let when = assemble(parsed.year()?, &parsed)?;
    // The IMF-fixdate always carries a weekday. Reject one inconsistent with the date it precedes.
    if parsed.weekday()? != when.weekday() {
        return None;
    }
    Some(when)
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
        if hms.is_none()
            && let Some(t) = match_time(token)
        {
            hms = Some(t);
            continue;
        }
        if day.is_none()
            && let Some(d) = match_day_of_month(token)
        {
            day = Some(d);
            continue;
        }
        if month.is_none()
            && let Some(m) = match_month(token)
        {
            month = Some(m);
            continue;
        }
        if year.is_none()
            && let Some(y) = match_year(token)
        {
            year = Some(y);
            continue;
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
/// The `String`-allocating form of [`ImfFixdate`]; both render the same bytes.
///
/// ```
/// use rfc_6265::date::{format_imf_fixdate, parse_imf_fixdate};
/// let when = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
/// assert_eq!(format_imf_fixdate(when), "Sun, 06 Nov 1994 08:49:37 GMT");
/// ```
#[must_use]
pub fn format_imf_fixdate(when: OffsetDateTime) -> String {
    ImfFixdate(when).to_string()
}

/// The canonical RFC 7231 IMF-fixdate rendering of an instant, as a lazy
/// [`Display`](fmt::Display) — the same bytes [`format_imf_fixdate`] returns,
/// without the intermediate `String`, for writing straight into an existing
/// buffer (a `Set-Cookie` serializer's `Expires=`, a preallocated header).
///
/// ```
/// use rfc_6265::date::{ImfFixdate, parse_imf_fixdate};
/// let when = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
/// assert_eq!(
///     format!("Expires={}", ImfFixdate(when)),
///     "Expires=Sun, 06 Nov 1994 08:49:37 GMT"
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImfFixdate(pub OffsetDateTime);

impl fmt::Display for ImfFixdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An IMF-fixdate is 29 bytes for four-digit years, and every year `time`
        // can represent fits 32. `format_into` wants `io::Write`, so render into
        // a stack buffer and hand the bytes on as the ASCII they are; each `Err`
        // arm is unreachable but keeps the no-panic promise without `unsafe`.
        let mut buf = [0u8; 32];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.0
            .to_offset(UtcOffset::UTC)
            .format_into(&mut cursor, IMF_FIXDATE)
            .map_err(|_| fmt::Error)?;
        let written = cursor.position() as usize;
        let rendered = std::str::from_utf8(&buf[..written]).map_err(|_| fmt::Error)?;
        f.write_str(rendered)
    }
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
    fn imf_fixdate_display_matches_the_independent_formatter() {
        // The adapter renders through `format_into`; `format_http_date` renders
        // through `format`. Pinning them equal guards the two paths against
        // drift — across the RFC floor, the far future, a zone conversion,
        // every weekday, and every month.
        let mut corpus = vec![
            WHEN,
            datetime!(1601-01-01 00:00:00 UTC),
            datetime!(9999-12-31 23:59:59 UTC),
            datetime!(1994-11-06 10:49:37 +2),
        ];
        corpus.extend((0..7).map(|days| WHEN + time::Duration::days(days)));
        corpus.extend((1..=12).map(|month| {
            Date::from_calendar_date(2021, Month::try_from(month).unwrap(), 15)
                .unwrap()
                .with_hms(12, 30, 45)
                .unwrap()
                .assume_utc()
        }));
        for when in corpus {
            assert_eq!(
                ImfFixdate(when).to_string(),
                format_http_date(when, HttpDateFormat::ImfFixdate),
                "{when}"
            );
        }
        // The adapter embeds without an intermediate String.
        assert_eq!(
            format!("Expires={}", ImfFixdate(WHEN)),
            "Expires=Sun, 06 Nov 1994 08:49:37 GMT"
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

    // ---- Enumerated finite sub-domains ------------------------------------

    #[test]
    fn every_month_token_maps_to_its_month() {
        // A hand-written 12-arm table (match_month) is exactly where a transposition hides, and the
        // day/month/year round-trips otherwise only ever exercise November. Pin all twelve, both at
        // the token level and end-to-end so each arm is wired to the right calendar month.
        for (tok, month) in [
            ("Jan", Month::January),
            ("Feb", Month::February),
            ("Mar", Month::March),
            ("Apr", Month::April),
            ("May", Month::May),
            ("Jun", Month::June),
            ("Jul", Month::July),
            ("Aug", Month::August),
            ("Sep", Month::September),
            ("Oct", Month::October),
            ("Nov", Month::November),
            ("Dec", Month::December),
        ] {
            assert_eq!(match_month(tok.as_bytes()), Some(month), "{tok}");
            let d = parse_cookie_date(&format!("15 {tok} 2001 00:00:00")).unwrap();
            assert_eq!(d.month(), month, "{tok}");
        }
        assert_eq!(match_month(b"Foo"), None); // not a month
        assert_eq!(match_month(b"Ja"), None); // too short
    }

    #[test]
    fn month_token_is_case_insensitive_in_the_lenient_scan() {
        for tok in ["Nov", "nov", "NOV", "nOv"] {
            assert_eq!(
                parse_cookie_date(&format!("06 {tok} 1994 08:49:37")),
                Some(WHEN),
                "{tok}"
            );
        }
    }

    #[test]
    fn two_digit_year_pivot_is_exhaustive() {
        // RFC 6265 §5.1.1 steps 3–4, over every value 00..=99: 00–69 → 2000s, 70–99 → 1900s.
        for yy in 0u8..=99 {
            let want = if yy <= 69 {
                2000 + i32::from(yy)
            } else {
                1900 + i32::from(yy)
            };
            let got = parse_cookie_date(&format!("06 Nov {yy:02} 08:49:37")).map(|d| d.year());
            assert_eq!(got, Some(want), "yy={yy:02}");
        }
    }

    #[test]
    fn calendar_day_validity_follows_the_month_and_leap_year() {
        // Valid: the leap day in a leap year, and day 31 in a 31-day month.
        assert!(parse_cookie_date("29 Feb 2000 00:00:00").is_some()); // 2000 is a leap year
        assert!(parse_cookie_date("31 Jan 2001 00:00:00").is_some());
        assert!(parse_cookie_date("31 Mar 2001 00:00:00").is_some());
        // Invalid: the leap day in non-leap years (incl. the 1900 century rule), day 31 in 30-day months.
        for bad in [
            "29 Feb 1900 00:00:00", // divisible by 100 but not 400 → not a leap year
            "29 Feb 1994 00:00:00",
            "31 Apr 2001 00:00:00",
            "31 Jun 2001 00:00:00",
            "31 Sep 2001 00:00:00",
            "31 Nov 2001 00:00:00",
        ] {
            assert!(parse_cookie_date(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn time_field_upper_bounds() {
        assert!(parse_cookie_date("06 Nov 1994 23:59:59").is_some()); // the accepted upper edge
        for bad in [
            "06 Nov 1994 24:00:00", // hour 24
            "06 Nov 1994 08:60:00", // minute 60
            "06 Nov 1994 08:49:60", // second 60 — no leap-second
        ] {
            assert!(parse_cookie_date(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn is_delimiter_matches_the_rfc_prose_over_all_bytes() {
        // Independent oracle: RFC 6265 §5.1.1 defines the *non-delimiter* set as
        // %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF; a delimiter is its complement.
        // This is formulated from the non-delimiter production, not the impl's delimiter ranges.
        for b in 0u8..=0xff {
            let non_delimiter = matches!(b,
                0x00..=0x08 | 0x0a..=0x1f
                | b'0'..=b'9' | b':' | b'A'..=b'Z' | b'a'..=b'z'
                | 0x7f..=0xff
            );
            assert_eq!(is_delimiter(b), !non_delimiter, "0x{b:02x}");
        }
    }

    // ---- Weekday: strict validates it, lenient ignores it -----------------

    #[test]
    fn strict_rejects_a_weekday_inconsistent_with_the_date() {
        // 06 Nov 1994 was a Sunday.
        assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
        for wrong in [
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Sat, 06 Nov 1994 08:49:37 GMT",
        ] {
            assert!(parse_imf_fixdate(wrong).is_none(), "{wrong:?}");
        }
    }

    #[test]
    fn lenient_ignores_the_weekday_token_entirely() {
        // §5.1.1 treats the weekday as an unknown token: a wrong one, a nonsense one, or none at
        // all is ignored as long as the four date components are present. (keksbruch's matrix
        // compares this against other stacks; here we pin kekse's own §5.1.1 behaviour.)
        for s in [
            "Mon, 06 Nov 1994 08:49:37 GMT",      // wrong weekday
            "Birthday, 06 Nov 1994 08:49:37 GMT", // not a weekday at all
            "06 Nov 1994 08:49:37 GMT",           // no weekday
        ] {
            assert_eq!(parse_cookie_date(s), Some(WHEN), "{s:?}");
        }
    }

    // ---- Lower-risk edges -------------------------------------------------

    #[test]
    fn lenient_keeps_the_first_match_per_field() {
        // §5.1.1 keeps the first token matching each production; a second month token is ignored.
        assert_eq!(
            parse_cookie_date("08:49:37 06 Nov Dec 1994"),
            Some(WHEN),
            "the second month token must be ignored"
        );
    }

    #[test]
    fn year_token_digit_count_bounds() {
        // year = 2*4DIGIT: a 1-digit year never matches; a 3-digit year is taken verbatim (then the
        // 1601 floor rejects it); a 5-digit run matches no year token, so the year stays missing.
        assert!(parse_cookie_date("06 Nov 8 08:49:37").is_none()); // 1 digit
        assert!(parse_cookie_date("06 Nov 800 08:49:37").is_none()); // 3 digits → 800 < 1601
        assert!(parse_cookie_date("06 Nov 19945 08:49:37").is_none()); // 5 digits
    }

    #[test]
    fn rfc850_two_digit_year_round_trip_is_lossy_past_2069() {
        // format_http_date documents the RFC 850 two-digit-year footgun; pin it. A 2069 instant
        // survives the round-trip; a 2070 instant reads back as 1970 (the pivot maps "70" → 1900s).
        let y2069 = datetime!(2069-06-15 12:00:00 UTC);
        let rendered = format_http_date(y2069, HttpDateFormat::Rfc850);
        assert_eq!(parse_cookie_date(&rendered), Some(y2069));
        let y2070 = datetime!(2070-06-15 12:00:00 UTC);
        let rendered = format_http_date(y2070, HttpDateFormat::Rfc850);
        assert_eq!(parse_cookie_date(&rendered).map(|d| d.year()), Some(1970));
    }
}
