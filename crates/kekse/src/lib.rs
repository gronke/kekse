//! # kekse
//!
//! A strict, dependency-light cookie codec: a [`SetCookie`] builder for
//! `Set-Cookie` response values and a [`parse_pairs`] reader for `Cookie`
//! request headers, built directly on the RFC 6265 §4.1.1 grammar. It carries
//! no cookie jar, no signing or encryption, and no date handling — a lifetime
//! is `Max-Age` seconds (`u64`), never an `Expires` date — so it pulls in no
//! `time`/`chrono`. It never panics on untrusted input.
//!
//! ## Encoding a value
//!
//! RFC 6265 lets a *cookie-value* carry only "cookie-octets"
//! (`%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`). Anything else — a space, a
//! `;`, a `"`, a control byte, any non-ASCII — has to be escaped to travel on
//! the wire. [`SetCookie::value_encoding`] picks how, via [`ValueEncoding`]:
//!
//! * [`Auto`](ValueEncoding::Auto) (default) — the sane choice. Emits the value
//!   bare when it is already cookie-octets, **wraps it in quotes** when it needs
//!   to carry whitespace (so `a b` rides as `"a b"`, not `a%20b`), and
//!   percent-encodes everything else losslessly. "Quotes where necessary."
//! * [`Percent`](ValueEncoding::Percent) — always percent-encode, never quote.
//!   The most compatible form, and what a security-sensitive cookie should use.
//! * [`Quoted`](ValueEncoding::Quoted) — always wrap in quotes (percent-encoding
//!   inside any byte the bare quoted form cannot carry).
//! * [`Raw`](ValueEncoding::Raw) — emit verbatim. The escape hatch for uncommon
//!   but deliberate shapes; the caller owns wire-correctness.
//!
//! Every managed encoding is lossless and unambiguous: `%` always self-encodes
//! to `%25`, and `"`/`\` inside a quoted value become `%22`/`%5C`, so the
//! wrapping quotes can never be faked and no backslash-escaping is needed.
//!
//! ## Parsing a header
//!
//! [`parse_pairs`] is the lenient, general reader — the inverse of every
//! [`ValueEncoding`] above: it strips one wrapping quote pair, accepts raw
//! whitespace in the value, and percent-decodes. [`parse_pairs_strict`] is its
//! security-grade sibling: it accepts *only* cookie-octets — whitespace and
//! every other non-octet are refused — which is what a session-cookie read
//! should use. Both are fail-soft (a malformed pair is skipped, never aborting
//! the header, so attacker-appended junk can never evict a later valid cookie)
//! and both refuse the injection-dangerous bytes (`;`, CR, LF, NUL, other
//! controls, raw non-ASCII) in every mode — the lenient/strict difference is
//! only whether raw whitespace is tolerated.
//!
//! ## A single source of truth for the grammar
//!
//! Cookie *names* are RFC 6265 cookie-names, i.e. RFC 7230 tokens — exactly what
//! the [`http`] crate's [`HeaderName`] parses, so [`is_cookie_name`] borrows
//! that definition rather than keep a homemade table. Cookie-octet membership
//! ([`is_cookie_octet`]) is derived once from the percent-encode set, so the
//! writer and the reader can never drift.

use std::borrow::Cow;
use std::fmt;
use std::sync::OnceLock;

use http::header::HeaderName;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

// ---- SameSite -------------------------------------------------------------

/// The `SameSite` cookie attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    /// Never sent on any cross-site request.
    Strict,
    /// Sent on top-level cross-site GET navigations only.
    Lax,
    /// Sent on every cross-site request — honored only alongside `Secure`.
    None,
}

impl SameSite {
    /// The token as it appears in a `Set-Cookie` header: `Strict`/`Lax`/`None`.
    pub fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---- value grammar + encode sets ------------------------------------------

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
const ENCODE_FULL: &AsciiSet = &CONTROLS
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
/// `"`/`\` and the wrapping quotes are unambiguous.
const ENCODE_IN_QUOTES: &AsciiSet = &CONTROLS
    .add(b'"')
    .add(b'%')
    .add(b',')
    .add(b';')
    .add(b'\\')
    .remove(b'\t');

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Whether `name` is a valid cookie-name. RFC 6265 §4.1.1 defines cookie-name as
/// an RFC 7230 token — exactly what [`HeaderName::from_bytes`] parses, so the
/// definition lives there rather than in a homemade byte table.
pub fn is_cookie_name(name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes()).is_ok()
}

/// Whether `b` is an RFC 6265 §4.1.1 cookie-octet — a byte a value may carry raw
/// on the wire. Derived once from [`ENCODE_FULL`] by checking which ASCII bytes
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

// ---- value encoding -------------------------------------------------------

/// How [`SetCookie`] escapes a value for the wire. See the [crate docs](crate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ValueEncoding {
    /// Bare when possible, quoted to carry whitespace, percent-encoded
    /// otherwise. The sane default.
    #[default]
    Auto,
    /// Always percent-encode non-octets; never quote.
    Percent,
    /// Always wrap in quotes; percent-encode (inside the quotes) any byte the
    /// bare quoted form cannot carry.
    Quoted,
    /// Emit verbatim — the caller guarantees wire-correctness.
    Raw,
}

/// Percent/quote-encode `value` per `encoding`. The inverse of [`parse_pairs`]
/// (and, for [`Percent`](ValueEncoding::Percent), of [`parse_pairs_strict`]).
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

// ---- Set-Cookie builder ---------------------------------------------------

/// A builder for a `Set-Cookie` header value.
///
/// Render it with [`to_string`](ToString::to_string) (via the [`Display`] impl).
/// Attributes are emitted in a fixed order — `HttpOnly`, `SameSite`, `Secure`,
/// `Path`, `Domain`, `Max-Age` — each only when set. The value is escaped per
/// the chosen [`ValueEncoding`] (default [`Auto`](ValueEncoding::Auto)); the
/// name is **not** validated here (check [`is_cookie_name`] at the call site if
/// the name is untrusted).
#[derive(Clone, Debug)]
pub struct SetCookie<'a> {
    name: &'a str,
    value: &'a str,
    encoding: ValueEncoding,
    http_only: bool,
    secure: bool,
    same_site: Option<SameSite>,
    path: Option<&'a str>,
    domain: Option<&'a str>,
    max_age: Option<u64>,
}

impl<'a> SetCookie<'a> {
    /// Start a `Set-Cookie` for `name=value` with no attributes set and the
    /// default [`Auto`](ValueEncoding::Auto) value encoding.
    pub fn new(name: &'a str, value: &'a str) -> Self {
        Self {
            name,
            value,
            encoding: ValueEncoding::Auto,
            http_only: false,
            secure: false,
            same_site: None,
            path: None,
            domain: None,
            max_age: None,
        }
    }

    /// Choose how the value is escaped for the wire.
    pub fn value_encoding(mut self, encoding: ValueEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Set or clear the `HttpOnly` attribute.
    pub fn http_only(mut self, yes: bool) -> Self {
        self.http_only = yes;
        self
    }

    /// Set or clear the `Secure` attribute.
    pub fn secure(mut self, yes: bool) -> Self {
        self.secure = yes;
        self
    }

    /// Set the `SameSite` attribute.
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Set the `Path` attribute.
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the `Domain` attribute. Omit for a host-only cookie.
    pub fn domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the `Max-Age` attribute, in seconds. `0` instructs the client to
    /// delete the cookie. Rendered as a `u64` decimal — no saturation.
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }
}

impl fmt::Display for SetCookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={}",
            self.name,
            encode_value(self.value, self.encoding)
        )?;
        if self.http_only {
            f.write_str("; HttpOnly")?;
        }
        if let Some(same_site) = self.same_site {
            write!(f, "; SameSite={}", same_site.as_str())?;
        }
        if self.secure {
            f.write_str("; Secure")?;
        }
        if let Some(path) = self.path {
            write!(f, "; Path={path}")?;
        }
        if let Some(domain) = self.domain {
            write!(f, "; Domain={domain}")?;
        }
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={max_age}")?;
        }
        Ok(())
    }
}

// ---- Cookie-header parsing ------------------------------------------------

/// Parse a request `Cookie` header into `(name, decoded value)` pairs, in order,
/// yielding every well-formed pair. Lenient: tolerates raw whitespace and the
/// quoted form. The inverse of [`encode_value`] / [`SetCookie`]. See the
/// [crate docs](crate).
pub fn parse_pairs(header: &str) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
    split_pairs(header, true)
}

/// Like [`parse_pairs`] but **strict**: a value byte outside the RFC 6265
/// cookie-octet set — including raw whitespace — causes that pair to be skipped.
/// Use this for a session cookie or any value you minted yourself, where a shape
/// you could not have emitted should not be trusted.
pub fn parse_pairs_strict(header: &str) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
    split_pairs(header, false)
}

/// Each `;`-separated segment runs an independent, fail-soft pipeline — a
/// malformed segment is skipped (logged at `debug`), never aborting the whole
/// header. Per segment: split at the first `=` (so `=` survives in a value);
/// trim `SP`/`HTAB` around name and value; the name must be a non-empty token;
/// one wrapping `DQUOTE` pair is stripped; every remaining value byte must be a
/// cookie-octet (plus `SP`/`HTAB` when `allow_ws`); finally the value is
/// percent-decoded, skipping any pair whose escapes are not valid UTF-8.
///
/// Percent-decoding is lenient (a stray `%` passes through), which is safe
/// because [`encode_value`] always escapes `%`, so a value kekse produced
/// never carries an ambiguous escape.
fn split_pairs(header: &str, allow_ws: bool) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
    header.split(';').filter_map(move |segment| {
        let (raw_name, raw_value) = segment.split_once('=')?;
        let name = raw_name.trim_matches(is_ws_char);
        if name.is_empty() || !is_cookie_name(name) {
            tracing::debug!(
                name = %name.escape_debug(),
                "ignoring a cookie pair with an empty or non-token name"
            );
            return None;
        }
        let mut value = raw_value.trim_matches(is_ws_char);
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = &value[1..value.len() - 1];
        }
        if !value
            .bytes()
            .all(|b| is_cookie_octet(b) || (allow_ws && is_ws(b)))
        {
            tracing::debug!(
                cookie = %name,
                "ignoring cookie: value carries a byte outside the accepted set"
            );
            return None;
        }
        match percent_decode_str(value).decode_utf8() {
            Ok(decoded) => Some((name, decoded)),
            Err(_) => {
                tracing::debug!(
                    cookie = %name,
                    "ignoring cookie: percent-escapes do not decode to valid UTF-8"
                );
                None
            }
        }
    })
}

fn is_ws_char(c: char) -> bool {
    c == ' ' || c == '\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lenient(header: &str) -> Vec<(&str, String)> {
        parse_pairs(header)
            .map(|(n, v)| (n, v.into_owned()))
            .collect()
    }
    fn strict(header: &str) -> Vec<(&str, String)> {
        parse_pairs_strict(header)
            .map(|(n, v)| (n, v.into_owned()))
            .collect()
    }
    fn lenient_first(header: &str) -> Option<String> {
        parse_pairs(header).next().map(|(_, v)| v.into_owned())
    }
    fn strict_first(header: &str) -> Option<String> {
        parse_pairs_strict(header)
            .next()
            .map(|(_, v)| v.into_owned())
    }

    // ---- grammar ----------------------------------------------------------

    #[test]
    fn same_site_tokens() {
        assert_eq!(SameSite::Strict.as_str(), "Strict");
        assert_eq!(SameSite::Lax.as_str(), "Lax");
        assert_eq!(SameSite::None.as_str(), "None");
    }

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

    // ---- builder ----------------------------------------------------------

    #[test]
    fn builder_attribute_order_is_fixed() {
        assert_eq!(SetCookie::new("n", "v").to_string(), "n=v");
        assert_eq!(
            SetCookie::new("n", "v").http_only(true).to_string(),
            "n=v; HttpOnly"
        );
        // Builder-call order is irrelevant; emission order is fixed.
        assert_eq!(
            SetCookie::new("n", "v")
                .max_age(60)
                .domain("example.test")
                .path("/app")
                .secure(true)
                .same_site(SameSite::None)
                .http_only(true)
                .to_string(),
            "n=v; HttpOnly; SameSite=None; Secure; Path=/app; Domain=example.test; Max-Age=60"
        );
        // Flags set to false are omitted.
        assert_eq!(
            SetCookie::new("n", "v")
                .http_only(false)
                .secure(false)
                .to_string(),
            "n=v"
        );
    }

    #[test]
    fn builder_max_age_is_u64_without_saturation() {
        assert!(SetCookie::new("n", "v")
            .max_age(u64::MAX)
            .to_string()
            .ends_with("; Max-Age=18446744073709551615"));
        assert!(SetCookie::new("n", "v")
            .max_age(0)
            .to_string()
            .ends_with("; Max-Age=0"));
    }

    #[test]
    fn hardened_session_cookie_shape() {
        // The shape an auth consumer composes (Percent encoding, full flags).
        let c = SetCookie::new("SID", "deadbeef")
            .value_encoding(ValueEncoding::Percent)
            .http_only(true)
            .same_site(SameSite::Strict)
            .secure(true)
            .path("/")
            .max_age(3600)
            .to_string();
        assert_eq!(
            c,
            "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
        );
    }

    // ---- encoding modes ---------------------------------------------------

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

    // ---- round-trips ------------------------------------------------------

    #[test]
    fn auto_round_trips_through_lenient() {
        for v in [
            "simple",
            "dead09",
            "a b",
            "hello world",
            "  leading and trailing  ",
            "a b,c",
            "a;b",
            "café",
            "🦀🍪",
            "100%",
            "%41",
            "a\"b",
            "a\\b",
            "a\tb",
            "a\r\nb",
        ] {
            let header = format!("n={}", encode_value(v, ValueEncoding::Auto));
            assert_eq!(
                lenient_first(&header).as_deref(),
                Some(v),
                "Auto→lenient round-trip for {v:?} (wire {header:?})"
            );
        }
    }

    #[test]
    fn percent_round_trips_through_strict() {
        for v in [
            "simple", "a b", "a;b", "café", "🦀", "100%", "%41", "a,b", "a\"b",
        ] {
            let header = format!("n={}", encode_value(v, ValueEncoding::Percent));
            assert_eq!(
                strict_first(&header).as_deref(),
                Some(v),
                "Percent→strict round-trip for {v:?} (wire {header:?})"
            );
        }
    }

    // ---- parser behaviour -------------------------------------------------

    #[test]
    fn parses_pairs_in_order_split_on_first_equals() {
        assert_eq!(
            lenient("a=1; b=2; c=3"),
            vec![
                ("a", "1".to_string()),
                ("b", "2".to_string()),
                ("c", "3".to_string())
            ]
        );
        assert_eq!(lenient_first("n=a=b").as_deref(), Some("a=b"));
        assert_eq!(lenient_first("n==x").as_deref(), Some("=x"));
    }

    #[test]
    fn skips_malformed_segments() {
        assert!(lenient_first("n").is_none()); // no '='
        assert!(lenient_first("=v").is_none()); // empty name
        assert!(lenient_first("  =v").is_none());
        assert_eq!(parse_pairs(";;;").count(), 0);
        assert_eq!(parse_pairs("").count(), 0);
        assert!(lenient_first("na me=v").is_none()); // non-token name
        assert!(lenient_first("naïve=v").is_none());
        assert!(strict_first("n").is_none());
        assert!(strict_first("=v").is_none());
    }

    #[test]
    fn junk_never_hides_a_later_valid_pair() {
        for h in [
            "n=a\u{1}b; m=ok",  // raw control
            "n=a\u{7f}b; m=ok", // raw DEL
            "n=café; m=ok",     // raw non-ASCII
            "n=a\\b; m=ok",     // raw backslash
        ] {
            assert_eq!(
                lenient(h).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                vec!["m"],
                "lenient {h:?}"
            );
            assert_eq!(
                strict(h).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                vec!["m"],
                "strict {h:?}"
            );
        }
    }

    #[test]
    fn quoted_values() {
        assert_eq!(lenient_first(r#"n="v""#).as_deref(), Some("v"));
        assert_eq!(lenient_first(r#"n="""#).as_deref(), Some("")); // empty quoted
        assert_eq!(lenient_first(r#"n="a b""#).as_deref(), Some("a b"));
        assert_eq!(lenient_first(r#"n="%41""#).as_deref(), Some("A")); // decoded inside
                                                                       // strict strips one quote pair, then requires octets
        assert_eq!(strict_first(r#"n="v""#).as_deref(), Some("v"));
        assert!(strict_first(r#"n="a b""#).is_none()); // space refused by strict
    }

    #[test]
    fn lenient_allows_whitespace_strict_refuses() {
        assert_eq!(lenient_first("n=a b").as_deref(), Some("a b"));
        assert!(strict_first("n=a b").is_none());
        // unquoted edges are trimmed; quoting preserves edge whitespace
        assert_eq!(lenient_first("  n  =  v  ").as_deref(), Some("v"));
        assert_eq!(lenient_first(r#"n=" v ""#).as_deref(), Some(" v "));
    }

    #[test]
    fn lenient_invalid_percent_escapes_pass_through() {
        for (input, expect) in [
            ("n=%4", "%4"),
            ("n=%GG", "%GG"),
            ("n=%", "%"),
            ("n=abc%", "abc%"),
        ] {
            assert_eq!(lenient_first(input).as_deref(), Some(expect), "{input:?}");
        }
    }

    #[test]
    fn invalid_utf8_escapes_skipped() {
        assert!(lenient_first("n=%FF").is_none());
        assert!(strict_first("n=%FF").is_none());
        assert!(lenient_first("n=%C3%28").is_none());
        assert_eq!(lenient_first("n=%C3%A9").as_deref(), Some("é"));
    }

    #[test]
    fn duplicates_yielded_in_order_case_sensitive() {
        assert_eq!(
            parse_pairs("k=1; k=2; k=3")
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        assert_eq!(
            parse_pairs("sid=lo; SID=hi")
                .find(|(n, _)| *n == "SID")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            Some("hi")
        );
        assert_eq!(
            parse_pairs("sid=lo; SID=hi")
                .find(|(n, _)| *n == "sid")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            Some("lo")
        );
    }

    #[test]
    fn adversarial_scale() {
        let mut h: String = (0..1000).map(|i| format!("k{i}=v{i}; ")).collect();
        h.push_str("target=found");
        assert_eq!(
            parse_pairs(&h)
                .find(|(n, _)| *n == "target")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            Some("found")
        );
        let big = "x".repeat(10_240);
        assert_eq!(
            lenient_first(&format!("k={big}")).as_deref(),
            Some(big.as_str())
        );
        // 10 KB control junk (carries '=' to reach the octet gate) between valid pairs.
        let junk = format!("j={}", "\u{1}".repeat(10_240));
        let header = format!("a=1; {junk}; b=2");
        assert_eq!(
            parse_pairs(&header).map(|(n, _)| n).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(parse_pairs("\u{1}\u{2}\u{3}").count(), 0);
    }
}
