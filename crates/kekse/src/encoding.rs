//! The cookie-value codec: [`ValueEncoding`] and [`encode_value`] for the write
//! side, plus the shared decode pipeline for the read side. Both are built on
//! the `grammar` predicates so the writer and reader can never drift.

use std::borrow::Cow;

use percent_encoding::{percent_decode_str, utf8_percent_encode};

use crate::grammar::{is_cookie_octet, is_ws, is_ws_char, ENCODE_FULL, ENCODE_IN_QUOTES};

/// How [`SetCookie`](crate::SetCookie) escapes a value for the wire. See the
/// [crate docs](crate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ValueEncoding {
    /// Bare when possible, quoted to carry whitespace, percent-encoded
    /// otherwise. "Quotes where necessary" — opt in when you want it.
    Auto,
    /// Always percent-encode non-octets; never quote. **The default** — the most
    /// compatible form, understood by every cookie parser.
    #[default]
    Percent,
    /// Always wrap in quotes; percent-encode (inside the quotes) any byte the
    /// bare quoted form cannot carry.
    Quoted,
    /// Emit verbatim — the caller guarantees wire-correctness.
    Raw,
}

/// Percent/quote-encode `value` per `encoding`. The inverse of
/// [`parse_pairs`](crate::parse_pairs) (and, for
/// [`Percent`](ValueEncoding::Percent), of
/// [`parse_pairs_strict`](crate::parse_pairs_strict)).
pub fn encode_value(value: &str, encoding: ValueEncoding) -> Cow<'_, str> {
    match encoding {
        ValueEncoding::Raw => Cow::Borrowed(value),
        ValueEncoding::Percent => utf8_percent_encode(value, ENCODE_FULL).into(),
        ValueEncoding::Quoted => Cow::Owned(quote(value)),
        ValueEncoding::Auto => {
            if value.bytes().all(|b| is_cookie_octet(b) && b != b'%') {
                Cow::Borrowed(value)
            } else if value.bytes().any(is_ws) {
                Cow::Owned(quote(value))
            } else {
                utf8_percent_encode(value, ENCODE_FULL).into()
            }
        }
    }
}

/// Wrap `value` in DQUOTEs, percent-encoding everything inside except raw
/// whitespace.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    out.extend(utf8_percent_encode(value, ENCODE_IN_QUOTES));
    out.push('"');
    out
}

/// The shared cookie-value pipeline, run by the request `Cookie:` reader
/// (`split_pairs`) and — once it lands — the response `Set-Cookie` reader, so
/// the read side can never drift from the write side ([`encode_value`]). Trims
/// surrounding `SP`/`HTAB`, strips one wrapping `DQUOTE` pair, requires every
/// remaining byte to be a cookie-octet (plus `SP`/`HTAB` when `allow_ws`), then
/// percent-decodes to UTF-8. Returns `None` if a byte is outside the accepted
/// set or the escapes do not decode to valid UTF-8.
///
/// Percent-decoding is lenient (a stray `%` passes through), which is safe
/// because [`encode_value`] always escapes `%`, so a value kekse produced
/// never carries an ambiguous escape.
pub(crate) fn decode_cookie_value(raw_value: &str, allow_ws: bool) -> Option<Cow<'_, str>> {
    let mut value = raw_value.trim_matches(is_ws_char);
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value = &value[1..value.len() - 1];
    }
    if !value
        .bytes()
        .all(|b| is_cookie_octet(b) || (allow_ws && is_ws(b)))
    {
        return None;
    }
    percent_decode_str(value).decode_utf8().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_emits_bare_quoted_or_percent() {
        // bare: octet-clean, no '%'
        assert_eq!(
            encode_value("deadBEEF09", ValueEncoding::Auto),
            "deadBEEF09"
        );
        // quoted: whitespace rides raw inside quotes
        assert_eq!(encode_value("a b", ValueEncoding::Auto), "\"a b\"");
        assert_eq!(
            encode_value("hello world", ValueEncoding::Auto),
            "\"hello world\""
        );
        // quoted with ',' percent-escaped inside, space raw
        assert_eq!(encode_value("a b,c", ValueEncoding::Auto), "\"a b%2Cc\"");
        // percent (no whitespace): ';' is not a cookie-octet → bare percent
        assert_eq!(encode_value("a;b", ValueEncoding::Auto), "a%3Bb");
        assert_eq!(encode_value("café", ValueEncoding::Auto), "caf%C3%A9");
        assert_eq!(encode_value("100%", ValueEncoding::Auto), "100%25");
        assert_eq!(encode_value("%41", ValueEncoding::Auto), "%2541");
        assert_eq!(encode_value("a\"b", ValueEncoding::Auto), "a%22b");
    }

    #[test]
    fn percent_always_encodes_never_quotes() {
        assert_eq!(encode_value("a b", ValueEncoding::Percent), "a%20b");
        assert_eq!(encode_value("a;b", ValueEncoding::Percent), "a%3Bb");
        assert_eq!(encode_value("deadbeef", ValueEncoding::Percent), "deadbeef");
        assert_eq!(encode_value("%41", ValueEncoding::Percent), "%2541");
    }

    #[test]
    fn quoted_always_wraps_losslessly() {
        assert_eq!(encode_value("plain", ValueEncoding::Quoted), "\"plain\"");
        assert_eq!(encode_value("a b", ValueEncoding::Quoted), "\"a b\"");
        assert_eq!(encode_value("a;b", ValueEncoding::Quoted), "\"a%3Bb\"");
        assert_eq!(encode_value("café", ValueEncoding::Quoted), "\"caf%C3%A9\"");
    }

    #[test]
    fn raw_is_verbatim() {
        assert_eq!(encode_value("a b;c\"\\", ValueEncoding::Raw), "a b;c\"\\");
    }

    #[test]
    fn managed_encodings_never_emit_injection_bytes() {
        let hostile = [
            "a;b",
            "a\r\nX: y",
            "a b",
            "café",
            "a,b",
            "a\"b",
            "a\\b",
            "\u{0}\u{1f}\u{7f}",
            "%41",
            "a b\nc",
        ];
        for v in hostile {
            for enc in [
                ValueEncoding::Auto,
                ValueEncoding::Percent,
                ValueEncoding::Quoted,
            ] {
                let out = encode_value(v, enc);
                assert!(
                    !out.contains(';')
                        && !out.contains('\r')
                        && !out.contains('\n')
                        && !out.contains('\0'),
                    "{enc:?} of {v:?} leaked an unsafe wire byte: {out:?}"
                );
            }
        }
    }
}
