//! RFC 6265 §4.1.1 byte classes and the RFC 7230 §3.2.6 `token` used for cookie-names.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1> ·
//! <https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6>
//!
//! Every predicate is a `const fn`, and each is pinned by an exhaustive `0x00..=0xFF` test against
//! an *independently formulated* oracle — the RFC's prose definition vs the impl's ABNF ranges —
//! so an off-by-one in any range fails the suite rather than agreeing with itself.

/// Whether `b` is an RFC 6265 §4.1.1 **cookie-octet** — a byte a cookie *value* may carry bare:
/// `%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E` (US-ASCII visible characters excluding the
/// CTLs, whitespace, `"`, `,`, `;`, and `\`).
///
/// ```
/// use rfc_6265::grammar::is_cookie_octet;
/// assert!(is_cookie_octet(b'a') && is_cookie_octet(b'!'));
/// assert!(!is_cookie_octet(b';') && !is_cookie_octet(b' '));
/// ```
#[must_use]
#[inline]
pub const fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

/// Whether `b` is an RFC 6265 §4.1.1 **av-octet** — a byte a `Set-Cookie` attribute value
/// (`Path` / `Domain`) may carry: `%x20-3A / %x3C-7E` (any visible character or `SP`, minus the
/// `;` attribute delimiter, the CTLs, and DEL).
///
/// ```
/// use rfc_6265::grammar::is_av_octet;
/// assert!(is_av_octet(b'/') && is_av_octet(b' ')); // a `Path` may carry `SP`
/// assert!(!is_av_octet(b';')); // the attribute delimiter
/// ```
#[must_use]
#[inline]
pub const fn is_av_octet(b: u8) -> bool {
    matches!(b, 0x20..=0x3a | 0x3c..=0x7e)
}

/// Whether `b` is `SP` or `HTAB` — the optional whitespace around a cookie pair.
///
/// ```
/// use rfc_6265::grammar::is_ws;
/// assert!(is_ws(b' ') && is_ws(b'\t'));
/// assert!(!is_ws(b'\n'));
/// ```
#[must_use]
#[inline]
pub const fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Whether `b` is a control byte — the C0 controls (`%x00-1F`) and DEL (`%x7F`), i.e. RFC 5234
/// `CTL`. CR, LF, and NUL — the header-injection bytes — are all CTLs.
///
/// ```
/// use rfc_6265::grammar::is_ctl;
/// assert!(is_ctl(b'\r') && is_ctl(b'\n') && is_ctl(0x7f));
/// assert!(!is_ctl(b'a'));
/// ```
#[must_use]
#[inline]
pub const fn is_ctl(b: u8) -> bool {
    matches!(b, 0x00..=0x1f | 0x7f)
}

/// Whether `b` is an RFC 7230 §3.2.6 **tchar** — a byte a `token` (and therefore a cookie-name)
/// may contain: ``ALPHA / DIGIT`` or one of ``! # $ % & ' * + - . ^ _ ` | ~``.
///
/// ```
/// use rfc_6265::grammar::is_tchar;
/// assert!(is_tchar(b'A') && is_tchar(b'9') && is_tchar(b'-'));
/// assert!(!is_tchar(b'(') && !is_tchar(b'/')); // delimiters
/// ```
#[must_use]
#[inline]
pub const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
        | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
    )
}

/// Whether `name` is a valid RFC 6265 cookie-name — a non-empty RFC 7230 `token` (every byte a
/// [`tchar`](is_tchar)).
///
/// ```
/// use rfc_6265::grammar::is_cookie_name;
/// assert!(is_cookie_name("SID"));
/// assert!(!is_cookie_name("") && !is_cookie_name("a b") && !is_cookie_name("a=b"));
/// ```
#[must_use]
#[inline]
pub const fn is_cookie_name(name: &str) -> bool {
    is_cookie_name_bytes(name.as_bytes())
}

/// [`is_cookie_name`] on raw bytes, for callers still on the wire side of UTF-8 validation. The
/// two can never drift: the `&str` form *is* this predicate over `as_bytes()`. A `token` is ASCII
/// by construction, so a byte slice this accepts is always valid UTF-8.
///
/// ```
/// use rfc_6265::grammar::is_cookie_name_bytes;
/// assert!(is_cookie_name_bytes(b"SID"));
/// assert!(!is_cookie_name_bytes(b"") && !is_cookie_name_bytes(b"a b"));
/// assert!(!is_cookie_name_bytes(b"caf\xc3\xa9")); // non-ASCII is never a token
/// ```
#[must_use]
#[inline]
pub const fn is_cookie_name_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    // `const fn` still means no iterator adapters; an index walk is the ~one place a manual loop
    // beats `.bytes().all(..)`.
    let mut i = 0;
    while i < name.len() {
        if !is_tchar(name[i]) {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_octet_matches_the_rfc_prose_over_all_bytes() {
        // Prose (RFC 6265 §4.1.1): US-ASCII visible chars minus DQUOTE, comma, semicolon,
        // backslash — formulated independently of the impl's ABNF ranges.
        for b in 0u8..=0xff {
            let prose = b.is_ascii_graphic() && !matches!(b, b'"' | b',' | b';' | b'\\');
            assert_eq!(is_cookie_octet(b), prose, "0x{b:02x}");
        }
    }

    #[test]
    fn av_octet_matches_the_rfc_prose_over_all_bytes() {
        // Prose: any character in %x20-7E except the ';' delimiter.
        for b in 0u8..=0xff {
            let prose = matches!(b, 0x20..=0x7e) && b != b';';
            assert_eq!(is_av_octet(b), prose, "0x{b:02x}");
        }
    }

    #[test]
    fn tchar_matches_vchar_minus_delimiters_over_all_bytes() {
        // RFC 7230: a token is VCHAR minus the delimiters `"(),/:;<=>?@[\]{}`.
        for b in 0u8..=0xff {
            let delimiter = matches!(
                b,
                b'"' | b'('
                    | b')'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'<'
                    | b'='
                    | b'>'
                    | b'?'
                    | b'@'
                    | b'['
                    | b'\\'
                    | b']'
                    | b'{'
                    | b'}'
            );
            assert_eq!(is_tchar(b), b.is_ascii_graphic() && !delimiter, "0x{b:02x}");
        }
    }

    #[test]
    fn ws_and_ctl_match_the_rfc_prose_over_all_bytes() {
        // Sweep every byte for both predicates, so the module's "each pinned by an exhaustive
        // 0x00..=0xFF test" holds for is_ws too — SP/HTAB only, and RFC 5234 CTL.
        for b in 0u8..=0xff {
            assert_eq!(is_ws(b), b == b' ' || b == b'\t', "0x{b:02x}");
            assert_eq!(is_ctl(b), matches!(b, 0x00..=0x1f | 0x7f), "0x{b:02x}");
        }
        // The header-injection bytes are all CTLs, and none of them are whitespace.
        assert!(is_ctl(b'\r') && is_ctl(b'\n') && is_ctl(0));
        assert!(!is_ws(b'\n') && !is_ws(0) && !is_ws(b'a'));
    }

    #[test]
    fn cookie_name_is_a_non_empty_token() {
        assert!(is_cookie_name("SID"));
        assert!(is_cookie_name("a!#$%&'*+-.^_`|~9"));
        for bad in ["", "a b", "a;b", "a=b", "naïve", "a\r", "\"q\"", "a(b"] {
            assert!(!is_cookie_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn cookie_name_bytes_agrees_with_the_str_form() {
        // The str form delegates to the bytes form, but pin the agreement anyway so a
        // future divergence (e.g. an extra check on one side) fails here.
        for s in ["SID", "a!#$%&'*+-.^_`|~9", "", "a b", "a;b", "a=b", "naïve"] {
            assert_eq!(
                is_cookie_name_bytes(s.as_bytes()),
                is_cookie_name(s),
                "{s:?}"
            );
        }
        // Over every single byte: exactly the tchars form a one-byte name.
        for b in 0u8..=0xff {
            assert_eq!(is_cookie_name_bytes(&[b]), is_tchar(b), "0x{b:02x}");
        }
        // Non-UTF-8 input is expressible only through the bytes form — and refused.
        assert!(!is_cookie_name_bytes(b"\xff"));
        assert!(!is_cookie_name_bytes(b"a\xffb"));
    }
}
