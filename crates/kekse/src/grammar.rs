//! RFC 6265 §4.1.1 / RFC 7230 grammar: the cookie-name and cookie-octet
//! predicates plus the percent-encode sets the value codec is built on — one
//! source of truth the writer and reader both borrow, so they can never drift.

use std::sync::OnceLock;

use http::header::HeaderName;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

/// Percent-encode set for cookie *values*, derived from RFC 6265 §4.1.1:
///
/// ```text
/// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
/// ```
///
/// i.e. encode the ASCII complement of cookie-octet — the C0 controls and DEL
/// (`CONTROLS`), space, `"`, `,`, `;`, and `\` — *plus* `%` itself. `%` is a
/// cookie-octet the RFC allows raw, but the escape introducer must self-encode
/// (`%` → `%25`) so decoding is unambiguous. `AsciiSet` governs ASCII only;
/// [`utf8_percent_encode`] always encodes bytes `>= 0x80`.
pub(crate) const ENCODE_FULL: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b',')
    .add(b';')
    .add(b'\\');

/// Like [`ENCODE_FULL`] but leaves `SP` and `HTAB` raw — for use *inside* a
/// quoted value, where whitespace is the one thing quoting buys over bare
/// cookie-octets. Every other non-octet (incl. `"`, `\`, `;`, `%`, controls,
/// non-ASCII) is still percent-encoded, so a quoted value never carries a raw
/// `"`/`\` and the wrapping quotes are unambiguous. Derived from [`ENCODE_FULL`]
/// by lifting out just `SP` and `HTAB`, so the two sets can never drift.
pub(crate) const ENCODE_IN_QUOTES: &AsciiSet = &ENCODE_FULL.remove(b' ').remove(b'\t');

/// Whether `b` is `SP` or `HTAB`.
pub(crate) fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Whether `c` is `SP` or `HTAB` — the `char` form, for `trim_matches`.
pub(crate) fn is_ws_char(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Whether `name` is a valid cookie-name. RFC 6265 §4.1.1 defines cookie-name as
/// an RFC 7230 token — exactly what [`HeaderName::from_bytes`] parses, so the
/// definition lives there rather than in a homemade byte table.
pub fn is_cookie_name(name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes()).is_ok()
}

/// Whether `b` is an RFC 6265 §4.1.1 cookie-octet — a byte a value may carry raw
/// on the wire. Derived once from `ENCODE_FULL` by checking which ASCII bytes
/// the encoder leaves untouched, then re-including `%` (a cookie-octet the
/// encoder force-escapes for unambiguity). Non-ASCII is never a cookie-octet.
///
/// `AsciiSet::contains` is `pub(crate)` upstream, so the set cannot be queried
/// directly; probing the encoder keeps this predicate the exact complement of
/// the encode set.
pub fn is_cookie_octet(b: u8) -> bool {
    static TABLE: OnceLock<[bool; 128]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [false; 128];
        for (byte, slot) in t.iter_mut().enumerate() {
            let s = (byte as u8 as char).to_string();
            *slot = utf8_percent_encode(&s, ENCODE_FULL).to_string() == s;
        }
        t[b'%' as usize] = true;
        t
    });
    (b as usize) < 128 && table[b as usize]
}

/// Whether `b` is an RFC 6265 §4.1.1 *av-octet* — a byte a `Set-Cookie`
/// attribute value (`Path`/`Domain`) may carry: `%x20-3A / %x3C-7E` (visible
/// ASCII and `SP`, minus `;` and `DEL`). Excludes control bytes, the `;`
/// attribute delimiter, and non-ASCII — exactly the bytes that could break out
/// of or inject into the header line.
pub(crate) fn is_av_octet(b: u8) -> bool {
    matches!(b, 0x20..=0x3a | 0x3c..=0x7e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_octet_matches_rfc_6265() {
        for b in 0u8..=255 {
            let rfc = matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e);
            assert_eq!(is_cookie_octet(b), rfc, "byte 0x{b:02x}");
        }
        // '%' is a cookie-octet (RFC) despite being force-encoded on write.
        assert!(is_cookie_octet(b'%'));
    }

    #[test]
    fn cookie_name_is_rfc_7230_token() {
        assert!(is_cookie_name("SID"));
        assert!(is_cookie_name("a!#$%&'*+-.^_`|~9"));
        for bad in ["", "a b", "a;b", "a=b", "naïve", "a\r", "\"q\""] {
            assert!(!is_cookie_name(bad), "{bad:?} must be rejected");
        }
    }
}
