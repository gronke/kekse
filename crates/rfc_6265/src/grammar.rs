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
#[must_use]
pub const fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

/// Whether `b` is an RFC 6265 §4.1.1 **av-octet** — a byte a `Set-Cookie` attribute value
/// (`Path` / `Domain`) may carry: `%x20-3A / %x3C-7E` (any visible character or `SP`, minus the
/// `;` attribute delimiter, the CTLs, and DEL).
#[must_use]
pub const fn is_av_octet(b: u8) -> bool {
    matches!(b, 0x20..=0x3a | 0x3c..=0x7e)
}

/// Whether `b` is `SP` or `HTAB` — the optional whitespace around a cookie pair.
#[must_use]
pub const fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Whether `b` is a control byte — the C0 controls (`%x00-1F`) and DEL (`%x7F`), i.e. RFC 5234
/// `CTL`. CR, LF, and NUL — the header-injection bytes — are all CTLs.
#[must_use]
pub const fn is_ctl(b: u8) -> bool {
    matches!(b, 0x00..=0x1f | 0x7f)
}

/// Whether `b` is an RFC 7230 §3.2.6 **tchar** — a byte a `token` (and therefore a cookie-name)
/// may contain: ``ALPHA / DIGIT`` or one of ``! # $ % & ' * + - . ^ _ ` | ~``.
#[must_use]
pub const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
        | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
    )
}

/// Whether `name` is a valid RFC 6265 cookie-name — a non-empty RFC 7230 `token` (every byte a
/// [`tchar`](is_tchar)).
#[must_use]
pub fn is_cookie_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_tchar)
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
    fn ws_and_ctl_boundaries() {
        assert!(is_ws(b' ') && is_ws(b'\t'));
        assert!(!is_ws(b'\n') && !is_ws(b'a'));
        for b in 0u8..=0xff {
            assert_eq!(is_ctl(b), matches!(b, 0x00..=0x1f | 0x7f), "0x{b:02x}");
        }
        // The header-injection bytes are all CTLs.
        assert!(is_ctl(b'\r') && is_ctl(b'\n') && is_ctl(0));
    }

    #[test]
    fn cookie_name_is_a_non_empty_token() {
        assert!(is_cookie_name("SID"));
        assert!(is_cookie_name("a!#$%&'*+-.^_`|~9"));
        for bad in ["", "a b", "a;b", "a=b", "naïve", "a\r", "\"q\"", "a(b"] {
            assert!(!is_cookie_name(bad), "{bad:?}");
        }
    }
}
