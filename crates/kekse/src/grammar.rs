//! The percent-encode sets the cookie-value codec is built on, layered on the RFC 6265 §4.1.1
//! `cookie-octet` class. The byte-class *predicates* (`is_cookie_octet`, `is_av_octet`, `is_ws`,
//! and the cookie-name token) live in [`rfc_6265::grammar`]; this module keeps only the
//! percent-encoding strategy on top, with a test pinning the two together so they can't drift.

use percent_encoding::{AsciiSet, CONTROLS};

/// Percent-encode set for cookie *values*, the ASCII complement of RFC 6265 §4.1.1 `cookie-octet`:
///
/// ```text
/// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
/// ```
///
/// i.e. encode the C0 controls and DEL (`CONTROLS`), space, `"`, `,`, `;`, and `\` — *plus* `%`
/// itself. `%` is a cookie-octet the RFC allows raw, but the escape introducer must self-encode
/// (`%` → `%25`) so decoding is unambiguous. `AsciiSet` governs ASCII only; `utf8_percent_encode`
/// always encodes bytes `>= 0x80`.
pub(crate) const ENCODE_FULL: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b',')
    .add(b';')
    .add(b'\\');

/// Like [`ENCODE_FULL`] but leaves `SP` and `HTAB` raw — for use *inside* a quoted value, where
/// whitespace is the one thing quoting buys over bare cookie-octets. Every other non-octet (incl.
/// `"`, `\`, `;`, `%`, controls, non-ASCII) is still percent-encoded, so a quoted value never
/// carries a raw `"`/`\` and the wrapping quotes are unambiguous. Derived from [`ENCODE_FULL`] by
/// lifting out just `SP` and `HTAB`, so the two sets can never drift.
pub(crate) const ENCODE_IN_QUOTES: &AsciiSet = &ENCODE_FULL.remove(b' ').remove(b'\t');

/// Whether `c` is `SP` or `HTAB` — the `char` form, for `trim_matches`. (The byte form is
/// [`rfc_6265::grammar::is_ws`].)
pub(crate) const fn is_ws_char(c: char) -> bool {
    c == ' ' || c == '\t'
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::utf8_percent_encode;
    use rfc_6265::grammar::is_cookie_octet;

    #[test]
    fn encode_full_is_the_exact_complement_of_cookie_octet() {
        // The writer's encode set and the reader's cookie-octet predicate must never drift:
        // ENCODE_FULL leaves a byte bare iff it is a cookie-octet — except `%`, which is a
        // cookie-octet the encoder force-escapes (`%` → `%25`) for unambiguous decoding.
        for b in 0u8..=0x7f {
            let s = (b as char).to_string();
            let left_bare = utf8_percent_encode(&s, ENCODE_FULL).to_string() == s;
            assert_eq!(left_bare, is_cookie_octet(b) && b != b'%', "0x{b:02x}");
        }
    }
}
