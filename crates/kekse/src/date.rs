//! `Expires` date handling: parse a `Set-Cookie` `Expires` value into an
//! [`OffsetDateTime`](time::OffsetDateTime) and render the canonical wire form.
//!
//! Two readers, matching kekse's lenient/strict split:
//!
//! * [`parse_lenient`] implements the **RFC 6265 §5.1.1** "cookie-date" algorithm
//!   — the permissive parser browsers use. It tokenises on the spec's delimiter
//!   set and picks out the time, day-of-month, month, and year wherever they fall,
//!   so it accepts the IMF-fixdate plus the obsolete RFC 850 and `asctime()` forms
//!   and a good deal of real-world slop.
//! * [`parse_strict`] accepts **only** the **RFC 7231 §7.1.1.1** IMF-fixdate
//!   (`Sun, 06 Nov 1994 08:49:37 GMT`) — the one canonical form, exact casing.
//!
//! The writer ([`format_imf_fixdate`]) always emits the IMF-fixdate, so a value
//! kekse renders round-trips back through either reader.

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};

// ---- RFC 6265 §5.1.1: the lenient cookie-date algorithm --------------------

/// RFC 6265 §5.1.1 `delimiter`: `%x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E`.
fn is_delimiter(b: u8) -> bool {
    matches!(b, 0x09 | 0x20..=0x2f | 0x3b..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e)
}

/// Parse a `Set-Cookie` `Expires` value leniently, per the RFC 6265 §5.1.1
/// cookie-date algorithm. Returns `None` unless the tokens yield a complete,
/// in-range, real calendar date.
pub(crate) fn parse_lenient(value: &str) -> Option<OffsetDateTime> {
    let bytes = value.as_bytes();

    let (mut hour, mut minute, mut second) = (0u8, 0u8, 0u8);
    let (mut day, mut month, mut year) = (0u8, 0u16, 0i32);
    let (mut found_time, mut found_day, mut found_month, mut found_year) =
        (false, false, false, false);

    let mut i = 0;
    while i < bytes.len() {
        if is_delimiter(bytes[i]) {
            i += 1;
            continue;
        }
        // One date-token: a run of non-delimiters.
        let start = i;
        while i < bytes.len() && !is_delimiter(bytes[i]) {
            i += 1;
        }
        let token = &bytes[start..i];

        // The productions are tried in the spec's order; the first that matches an
        // as-yet-unfilled field claims the token.
        if !found_time {
            if let Some((h, m, s)) = parse_hms(token) {
                (hour, minute, second) = (h, m, s);
                found_time = true;
                continue;
            }
        }
        if !found_day {
            if let Some(d) = leading_number(token, 1, 2) {
                day = d as u8;
                found_day = true;
                continue;
            }
        }
        if !found_month {
            if let Some(m) = month_ci(token) {
                month = m;
                found_month = true;
                continue;
            }
        }
        if !found_year {
            if let Some(y) = leading_number(token, 2, 4) {
                year = y as i32;
                found_year = true;
                continue;
            }
        }
    }

    if !(found_time && found_day && found_month && found_year) {
        return None;
    }

    // Two-digit year handling (RFC 6265 §5.1.1), applied before the year check.
    if (70..=99).contains(&year) {
        year += 1900;
    } else if (0..=69).contains(&year) {
        year += 2000;
    }

    // Field ranges per §5.1.1. `build` re-checks and additionally rejects an
    // impossible calendar day (e.g. 31 Feb).
    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    build(year, month, day, hour, minute, second)
}

/// `hms-time ( non-digit *OCTET )`: three 1–2 digit fields joined by `:`, then the
/// token must end or continue with a non-digit. Out-of-range fields are tolerated
/// here and rejected by the caller's range checks.
fn parse_hms(token: &[u8]) -> Option<(u8, u8, u8)> {
    let mut idx = 0;
    let h = time_field(token, &mut idx)?;
    eat_colon(token, &mut idx)?;
    let m = time_field(token, &mut idx)?;
    eat_colon(token, &mut idx)?;
    let s = time_field(token, &mut idx)?;
    if idx < token.len() && token[idx].is_ascii_digit() {
        return None; // a 4th digit means this was not an hms-time
    }
    Some((h, m, s))
}

/// Read a 1–2 digit `time-field`, advancing `idx`.
fn time_field(token: &[u8], idx: &mut usize) -> Option<u8> {
    let start = *idx;
    while *idx < token.len() && *idx - start < 2 && token[*idx].is_ascii_digit() {
        *idx += 1;
    }
    if *idx == start {
        return None;
    }
    let mut v = 0u8;
    for &b in &token[start..*idx] {
        v = v * 10 + (b - b'0');
    }
    Some(v)
}

/// Expect a `:` at `idx`, advancing past it.
fn eat_colon(token: &[u8], idx: &mut usize) -> Option<()> {
    if token.get(*idx) == Some(&b':') {
        *idx += 1;
        Some(())
    } else {
        None
    }
}

/// A `day-of-month` / `year` token: `min..=max` leading digits, then end or a
/// non-digit. A longer digit run (e.g. `100` for a day) does not match. The value
/// is the leading digits.
fn leading_number(token: &[u8], min: usize, max: usize) -> Option<u32> {
    let len = token.iter().take_while(|b| b.is_ascii_digit()).count();
    if len < min || len > max {
        return None;
    }
    let mut v = 0u32;
    for &b in &token[..len] {
        v = v * 10 + u32::from(b - b'0');
    }
    Some(v)
}

/// Month number (1–12) from the first three letters, case-insensitively
/// (RFC 6265 §5.1.1 matches `*OCTET` after the name, so trailing slop is fine).
fn month_ci(token: &[u8]) -> Option<u16> {
    if token.len() < 3 {
        return None;
    }
    let key = [
        token[0].to_ascii_lowercase(),
        token[1].to_ascii_lowercase(),
        token[2].to_ascii_lowercase(),
    ];
    Some(match &key {
        b"jan" => 1,
        b"feb" => 2,
        b"mar" => 3,
        b"apr" => 4,
        b"may" => 5,
        b"jun" => 6,
        b"jul" => 7,
        b"aug" => 8,
        b"sep" => 9,
        b"oct" => 10,
        b"nov" => 11,
        b"dec" => 12,
        _ => return None,
    })
}

// ---- RFC 7231 §7.1.1.1: the strict IMF-fixdate reader ----------------------

/// Parse only the RFC 7231 IMF-fixdate `Sun, 06 Nov 1994 08:49:37 GMT` — fixed
/// width, exact casing, always GMT. The day-name must be one of the seven valid
/// tokens but, per HTTP convention, is not cross-checked against the date.
pub(crate) fn parse_strict(value: &str) -> Option<OffsetDateTime> {
    let b = value.as_bytes();
    if b.len() != 29 {
        return None;
    }
    if weekday_exact(&b[0..3]).is_none() || &b[3..5] != b", " {
        return None;
    }
    let day = two_digits(&b[5..7])?;
    if b[7] != b' ' {
        return None;
    }
    let month = month_exact(&b[8..11])?;
    if b[11] != b' ' {
        return None;
    }
    let year = four_digits(&b[12..16])?;
    if b[16] != b' ' {
        return None;
    }
    let hour = two_digits(&b[17..19])?;
    if b[19] != b':' {
        return None;
    }
    let minute = two_digits(&b[20..22])?;
    if b[22] != b':' {
        return None;
    }
    let second = two_digits(&b[23..25])?;
    if &b[25..29] != b" GMT" {
        return None;
    }
    build(i32::from(year), month, day, hour, minute, second)
}

/// Exactly two ASCII digits → value.
fn two_digits(b: &[u8]) -> Option<u8> {
    match b {
        [a, c] if a.is_ascii_digit() && c.is_ascii_digit() => Some((a - b'0') * 10 + (c - b'0')),
        _ => None,
    }
}

/// Exactly four ASCII digits → value.
fn four_digits(b: &[u8]) -> Option<u16> {
    if b.len() != 4 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        b.iter()
            .fold(0u16, |acc, &d| acc * 10 + u16::from(d - b'0')),
    )
}

/// Whether `b` is one of the seven canonical IMF-fixdate day-names (exact case).
fn weekday_exact(b: &[u8]) -> Option<()> {
    matches!(
        b,
        b"Mon" | b"Tue" | b"Wed" | b"Thu" | b"Fri" | b"Sat" | b"Sun"
    )
    .then_some(())
}

/// Month number (1–12) from a canonical IMF-fixdate month name (exact case).
fn month_exact(b: &[u8]) -> Option<u16> {
    Some(match b {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    })
}

// ---- shared construction + the canonical writer ----------------------------

/// Assemble a UTC [`OffsetDateTime`] from validated fields, or `None` if the
/// calendar date is impossible (e.g. 31 Feb) or a field is out of range.
fn build(
    year: i32,
    month: u16,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<OffsetDateTime> {
    let month = Month::try_from(month as u8).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// Render `when` (converted to UTC) as the canonical RFC 7231 IMF-fixdate.
pub(crate) fn format_imf_fixdate(when: OffsetDateTime) -> String {
    let when = when.to_offset(UtcOffset::UTC);
    let weekday = match when.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = match when.month() {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        day = when.day(),
        year = when.year(),
        hour = when.hour(),
        minute = when.minute(),
        second = when.second(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn strict_parses_the_canonical_imf_fixdate() {
        let dt = parse_strict("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(dt, datetime!(1994-11-06 08:49:37 UTC));
    }

    #[test]
    fn strict_rejects_non_canonical_forms() {
        // RFC 850 and asctime() forms, and casing / spacing / zone deviations.
        for bad in [
            "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
            "Sun Nov  6 08:49:37 1994",       // asctime()
            "sun, 06 Nov 1994 08:49:37 GMT",  // lowercase day-name
            "Sun, 06 nov 1994 08:49:37 GMT",  // lowercase month
            "Sun, 6 Nov 1994 08:49:37 GMT",   // 1-digit day
            "Sun, 06 Nov 1994 08:49:37 UTC",  // wrong zone token
            "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing space
            "Xyz, 06 Nov 1994 08:49:37 GMT",  // bogus day-name
            "",
        ] {
            assert!(
                parse_strict(bad).is_none(),
                "{bad:?} must be rejected by strict"
            );
        }
    }

    #[test]
    fn lenient_accepts_imf_rfc850_and_asctime() {
        let expected = datetime!(1994-11-06 08:49:37 UTC);
        assert_eq!(
            parse_lenient("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(
            parse_lenient("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(parse_lenient("Sun Nov  6 08:49:37 1994"), Some(expected));
    }

    #[test]
    fn lenient_two_digit_year_pivots_at_69_70() {
        // 70..=99 -> 1900+, 0..=69 -> 2000+.
        assert_eq!(
            parse_lenient("Mon, 01 Jan 70 00:00:00 GMT").unwrap().year(),
            1970
        );
        assert_eq!(
            parse_lenient("Fri, 01 Jan 69 00:00:00 GMT").unwrap().year(),
            2069
        );
    }

    #[test]
    fn lenient_rejects_incomplete_and_out_of_range() {
        assert_eq!(parse_lenient("Nov 1994 08:49:37"), None); // no day-of-month
        assert_eq!(parse_lenient("06 Nov 1994"), None); // no time
        assert_eq!(parse_lenient("Sun, 06 Nov 1994 25:00:00 GMT"), None); // hour > 23
        assert_eq!(parse_lenient("Sun, 31 Feb 1994 00:00:00 GMT"), None); // impossible day
        assert_eq!(parse_lenient("Sun, 06 Nov 1500 00:00:00 GMT"), None); // year < 1601
        assert_eq!(parse_lenient(""), None);
    }

    #[test]
    fn format_emits_the_canonical_form_and_round_trips() {
        let dt = datetime!(1994-11-06 08:49:37 UTC);
        assert_eq!(format_imf_fixdate(dt), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(parse_strict(&format_imf_fixdate(dt)), Some(dt));
    }

    #[test]
    fn format_converts_to_utc() {
        // A non-UTC instant renders in GMT (the same absolute instant).
        let plus_two = datetime!(1994-11-06 10:49:37 +2);
        assert_eq!(
            format_imf_fixdate(plus_two),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }
}
