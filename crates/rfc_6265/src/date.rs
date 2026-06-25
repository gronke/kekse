//! `Expires` date handling, built on `time`'s format machinery — never hand-rolled.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1> ·
//! <https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1>
//!
//! - [`parse_imf_fixdate`] is **strict**: only the RFC 7231 IMF-fixdate
//!   (`Sun, 06 Nov 1994 08:49:37 GMT`) — exact casing, exact spacing, full-input match.
//! - [`parse_cookie_date`] is **lenient**: the three HTTP-date formats RFC 6265 §5.1.1 accepts —
//!   IMF-fixdate, RFC 850, and `asctime()` — tried in turn.
//! - [`format_imf_fixdate`] renders the canonical IMF-fixdate.
//!
//! Each format is a `time` [`format_description!`]. The only logic not delegated to `time` is the
//! RFC 850 two-digit-year **century pivot** (70–99 → 1900+, 0–69 → 2000+), which `time` leaves to
//! the caller — it is RFC 6265 policy, not parsing.

use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::parsing::Parsed;
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// RFC 7231 IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
const IMF_FIXDATE: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);
/// Obsolete RFC 850 form: `Sunday, 06-Nov-94 08:49:37 GMT` (two-digit year).
const RFC_850: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:long], [day]-[month repr:short]-[year repr:last_two] [hour]:[minute]:[second] GMT"
);
/// Obsolete `asctime()` form: `Sun Nov  6 08:49:37 1994` (space-padded day, no zone).
const ASCTIME: &[BorrowedFormatItem<'_>] = format_description!(
    "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
);

/// Parse `value` fully against `items` (the entire input must be consumed), or `None`.
fn parse_full(value: &str, items: &[BorrowedFormatItem<'_>]) -> Option<Parsed> {
    let mut parsed = Parsed::new();
    let rest = parsed.parse_items(value.as_bytes(), items).ok()?;
    rest.is_empty().then_some(parsed)
}

/// Assemble a UTC [`OffsetDateTime`] from a known full `year` plus the month/day/time in `parsed`.
/// `Date::from_calendar_date` rejects impossible calendar dates (e.g. 31 Feb).
fn assemble(year: i32, parsed: &Parsed) -> Option<OffsetDateTime> {
    let date = Date::from_calendar_date(year, parsed.month()?, parsed.day()?.get()).ok()?;
    let time = Time::from_hms(parsed.hour_24()?, parsed.minute()?, parsed.second()?).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// Strictly parse the RFC 7231 §7.1.1.1 IMF-fixdate. Exact casing/spacing, full-input match,
/// always GMT. `None` for anything else (including the obsolete RFC 850 / `asctime()` forms).
#[must_use]
pub fn parse_imf_fixdate(value: &str) -> Option<OffsetDateTime> {
    let parsed = parse_full(value, IMF_FIXDATE)?;
    assemble(parsed.year()?, &parsed)
}

/// RFC 850, applying the RFC 6265 §5.1.1 two-digit-year pivot.
fn parse_rfc_850(value: &str) -> Option<OffsetDateTime> {
    let parsed = parse_full(value, RFC_850)?;
    let yy = i32::from(parsed.year_last_two()?);
    let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
    assemble(year, &parsed)
}

/// `asctime()` — four-digit year, no zone (assumed UTC).
fn parse_asctime(value: &str) -> Option<OffsetDateTime> {
    let parsed = parse_full(value, ASCTIME)?;
    assemble(parsed.year()?, &parsed)
}

/// Leniently parse a `Set-Cookie` `Expires` value: the three HTTP-date formats RFC 6265 §5.1.1
/// accepts (IMF-fixdate, RFC 850, `asctime()`), tried in turn. `None` if none match.
#[must_use]
pub fn parse_cookie_date(value: &str) -> Option<OffsetDateTime> {
    parse_imf_fixdate(value)
        .or_else(|| parse_rfc_850(value))
        .or_else(|| parse_asctime(value))
}

/// Render `when` (converted to UTC) as the canonical RFC 7231 IMF-fixdate.
#[must_use]
pub fn format_imf_fixdate(when: OffsetDateTime) -> String {
    when.to_offset(UtcOffset::UTC)
        .format(IMF_FIXDATE)
        .expect("IMF-fixdate formatting of a valid OffsetDateTime is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const WHEN: OffsetDateTime = datetime!(1994-11-06 08:49:37 UTC);

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
    fn lenient_two_digit_year_pivots_at_69_70() {
        // RFC 850 uses the long weekday name; `assemble` builds from y/m/d and ignores it.
        assert_eq!(
            parse_cookie_date("Thursday, 01-Jan-70 00:00:00 GMT").map(|d| d.year()),
            Some(1970)
        );
        assert_eq!(
            parse_cookie_date("Wednesday, 01-Jan-69 00:00:00 GMT").map(|d| d.year()),
            Some(2069)
        );
    }

    #[test]
    fn rejects_impossible_and_out_of_range() {
        assert_eq!(parse_cookie_date("Tue, 31 Feb 1994 00:00:00 GMT"), None); // impossible day
        assert_eq!(parse_cookie_date("Sun, 06 Nov 1994 25:00:00 GMT"), None); // hour > 23
        assert_eq!(parse_cookie_date("not-a-date"), None);
        assert_eq!(parse_cookie_date(""), None);
    }

    #[test]
    fn format_is_canonical_and_round_trips() {
        assert_eq!(format_imf_fixdate(WHEN), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(parse_imf_fixdate(&format_imf_fixdate(WHEN)), Some(WHEN));
    }

    #[test]
    fn format_converts_to_utc() {
        // Same absolute instant as WHEN, expressed at +02:00 — must render in GMT.
        let plus_two = datetime!(1994-11-06 10:49:37 +2);
        assert_eq!(
            format_imf_fixdate(plus_two),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }
}
