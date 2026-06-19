//! The request `Cookie:` dialect: the [`parse_pairs`] / [`parse_pairs_strict`]
//! readers and the [`CookieJar`] typed view layered on them.

use std::borrow::Cow;

use crate::cookie::Cookie;
use crate::encoding::{decode_cookie_value, ValueEncoding};
use crate::grammar::{is_cookie_name, is_ws_char};
use http::header::{HeaderValue, InvalidHeaderValue};

/// Parse a request `Cookie` header into `(name, decoded value)` pairs, in order,
/// yielding every well-formed pair. Lenient: tolerates raw whitespace and the
/// quoted form. The inverse of [`encode_value`](crate::encode_value) /
/// [`SetCookie`](crate::SetCookie). See the [crate docs](crate).
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
/// trim `SP`/`HTAB` around the name; the name must be a non-empty token; then
/// the value runs through [`decode_cookie_value`].
fn split_pairs(header: &str, allow_ws: bool) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
    header.split(';').filter_map(move |segment| {
        let (raw_name, raw_value) = segment.split_once('=')?;
        let name = raw_name.trim_matches(is_ws_char);
        if name.is_empty() || !is_cookie_name(name) {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                name = %name.escape_debug(),
                "ignoring a cookie pair with an empty or non-token name"
            );
            return None;
        }
        let value = decode_cookie_value(raw_value, allow_ws);
        #[cfg(feature = "tracing")]
        if value.is_none() {
            tracing::debug!(
                cookie = %name,
                "ignoring cookie: value carries a byte outside the accepted \
                 set or percent-escapes that are not valid UTF-8"
            );
        }
        value.map(|value| (name, value))
    })
}

/// The baked cookies of a request `Cookie:` header, parsed in order. Borrows
/// the header; each [`Cookie`] is a name and its decoded value. Build it with
/// [`parse`](CookieJar::parse) (lenient) or
/// [`parse_strict`](CookieJar::parse_strict) — the readers behind [`parse_pairs`]
/// / [`parse_pairs_strict`], which the jar layers on — then query with
/// [`get`](CookieJar::get) / [`get_all`](CookieJar::get_all) or iterate.
#[derive(Clone, Debug, Default)]
pub struct CookieJar<'a> {
    cookies: Vec<Cookie<'a>>,
}

impl<'a> CookieJar<'a> {
    /// Parse a `Cookie:` header leniently — tolerating quoted and
    /// whitespace-bearing values (see [`parse_pairs`]).
    pub fn parse(header: &'a str) -> Self {
        Self {
            cookies: parse_pairs(header)
                .map(|(name, value)| Cookie::new(name, value))
                .collect(),
        }
    }

    /// Parse a `Cookie:` header strictly — cookie-octets only, whitespace
    /// refused (see [`parse_pairs_strict`]). The reader to use for a session
    /// cookie or any value you minted yourself.
    pub fn parse_strict(header: &'a str) -> Self {
        Self {
            cookies: parse_pairs_strict(header)
                .map(|(name, value)| Cookie::new(name, value))
                .collect(),
        }
    }

    /// The first cookie named `name`, in header order. RFC-faithful: a present
    /// cookie with an empty value still matches (an empty cookie is a cookie).
    /// To skip empties — so a stale `SID=` cannot shadow a later real one —
    /// filter [`get_all`](CookieJar::get_all):
    /// `jar.get_all(name).find(|c| !c.value().is_empty())`.
    pub fn get(&self, name: &str) -> Option<&Cookie<'a>> {
        self.cookies.iter().find(|c| c.name() == name)
    }

    /// Every cookie named `name`, in header order (duplicate names are legal on
    /// the wire).
    pub fn get_all<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Cookie<'a>> + 's {
        self.cookies.iter().filter(move |c| c.name() == name)
    }

    /// Iterate every cookie, in header order.
    pub fn iter(&self) -> std::slice::Iter<'_, Cookie<'a>> {
        self.cookies.iter()
    }

    /// The number of cookies parsed.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the jar holds no cookies.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// An empty jar to build up with [`add`](CookieJar::add) /
    /// [`replace`](CookieJar::replace) — the way to mint a request `Cookie:`
    /// header, or to rewrite one after [`parse`](CookieJar::parse).
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `cookie`, keeping any existing pair of the same name — duplicate
    /// names are legal on the wire, so this is order-preserving and additive.
    /// Use [`replace`](CookieJar::replace) to overwrite a name instead.
    pub fn add(&mut self, cookie: Cookie<'a>) {
        self.cookies.push(cookie);
    }

    /// Remove every cookie named `name`, returning how many were dropped.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.cookies.len();
        self.cookies.retain(|c| c.name() != name);
        before - self.cookies.len()
    }

    /// Make `cookie` the sole pair of its name: drop any existing same-name
    /// cookies, then append it. The canonical single-value write.
    pub fn replace(&mut self, cookie: Cookie<'a>) {
        self.remove(cookie.name());
        self.add(cookie);
    }

    /// Render the whole jar as one request `Cookie:` header string — each pair
    /// `name=value` escaped under `encoding`, joined with `"; "`. Values are
    /// re-encoded from their decoded form, so a parsed-then-rendered header is
    /// **canonical**: it carries no raw bytes the encoding would not itself emit
    /// (no raw retention). For the typed header use
    /// [`to_header_value`](CookieJar::to_header_value).
    pub fn to_header_string(&self, encoding: ValueEncoding) -> String {
        self.cookies
            .iter()
            .map(|c| c.to_pair(encoding))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Render the jar as an `http::HeaderValue` ready to set on a request.
    /// `Err` only under [`ValueEncoding::Raw`], where a value may carry bytes no
    /// header value can hold (CR/LF/NUL); the managed encodings are always
    /// header-safe, so they never fail here.
    pub fn to_header_value(
        &self,
        encoding: ValueEncoding,
    ) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(&self.to_header_string(encoding))
    }
}

impl<'a> IntoIterator for CookieJar<'a> {
    type Item = Cookie<'a>;
    type IntoIter = std::vec::IntoIter<Cookie<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.cookies.into_iter()
    }
}

impl<'a, 's> IntoIterator for &'s CookieJar<'a> {
    type Item = &'s Cookie<'a>;
    type IntoIter = std::slice::Iter<'s, Cookie<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.cookies.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_value, ValueEncoding};

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

    // ---- CookieJar --------------------------------------------------------

    #[test]
    fn jar_get_is_first_match_including_empty() {
        let jar = CookieJar::parse_strict("SID=; SID=x");
        // RFC-faithful: the first match wins even when its value is empty.
        assert_eq!(jar.get("SID").map(|c| c.value()), Some(""));
        // The "skip empties, first non-empty wins" idiom a session read uses.
        assert_eq!(
            jar.get_all("SID")
                .find(|c| !c.value().is_empty())
                .map(|c| c.value()),
            Some("x")
        );
    }

    #[test]
    fn jar_get_all_in_order_and_case_sensitive() {
        let jar = CookieJar::parse("k=1; k=2; k=3; K=upper");
        assert_eq!(
            jar.get_all("k").map(|c| c.value()).collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        assert_eq!(jar.get("K").map(|c| c.value()), Some("upper"));
        assert!(jar.get("missing").is_none());
    }

    #[test]
    fn jar_len_iter_and_empty() {
        let jar = CookieJar::parse("a=1; b=2");
        assert_eq!(jar.len(), 2);
        assert!(!jar.is_empty());
        assert_eq!(
            jar.iter()
                .map(|c| (c.name(), c.value()))
                .collect::<Vec<_>>(),
            vec![("a", "1"), ("b", "2")]
        );
        assert_eq!((&jar).into_iter().count(), 2);
        assert!(CookieJar::parse("").is_empty());
    }

    #[test]
    fn jar_value_borrows_when_octet_clean() {
        let jar = CookieJar::parse_strict("SID=deadbeef");
        let cookie = jar.into_iter().next().unwrap();
        assert!(matches!(cookie.into_value(), Cow::Borrowed(_)));
    }

    #[test]
    fn jar_is_fail_soft_like_the_parsers() {
        // A malformed pair is skipped; a later valid pair still parses.
        let jar = CookieJar::parse("n=a\u{1}b; m=ok");
        assert!(jar.get("n").is_none());
        assert_eq!(jar.get("m").map(|c| c.value()), Some("ok"));
    }

    // ---- write side: build / mutate / serialize ---------------------------

    #[test]
    fn new_starts_empty_and_add_appends_in_order() {
        let mut jar = CookieJar::new();
        assert!(jar.is_empty());
        jar.add(Cookie::new("a", "1"));
        jar.add(Cookie::new("b", "2"));
        jar.add(Cookie::new("a", "3")); // duplicate name is legal on the wire
        assert_eq!(
            jar.iter()
                .map(|c| (c.name(), c.value()))
                .collect::<Vec<_>>(),
            vec![("a", "1"), ("b", "2"), ("a", "3")]
        );
    }

    #[test]
    fn remove_drops_all_matches_and_returns_the_count() {
        let mut jar = CookieJar::parse("a=1; b=2; a=3");
        assert_eq!(jar.remove("a"), 2);
        assert_eq!(jar.remove("missing"), 0);
        assert_eq!(jar.iter().map(|c| c.name()).collect::<Vec<_>>(), vec!["b"]);
    }

    #[test]
    fn replace_is_the_canonical_single_value_write() {
        let mut jar = CookieJar::parse("SID=old; SID=stale; theme=dark");
        jar.replace(Cookie::new("SID", "new"));
        assert_eq!(
            jar.get_all("SID").map(|c| c.value()).collect::<Vec<_>>(),
            vec!["new"] // the stale duplicates are gone
        );
        assert_eq!(jar.get("theme").map(|c| c.value()), Some("dark"));
    }

    #[test]
    fn header_string_joins_pairs_and_round_trips() {
        let jar = CookieJar::parse_strict("a=1; b=2; c=3");
        let rendered = jar.to_header_string(ValueEncoding::Percent);
        assert_eq!(rendered, "a=1; b=2; c=3");
        let again = CookieJar::parse_strict(&rendered);
        assert_eq!(
            again
                .iter()
                .map(|c| (c.name(), c.value()))
                .collect::<Vec<_>>(),
            vec![("a", "1"), ("b", "2"), ("c", "3")]
        );
    }

    #[test]
    fn re_encode_is_canonical_no_raw_retention() {
        // Values that arrived quoted / percent-escaped are re-emitted in the one
        // canonical Percent form — the original wire shape is not retained.
        let jar = CookieJar::parse(r#"pref="a b"; name=caf%C3%A9"#);
        assert_eq!(
            jar.to_header_string(ValueEncoding::Percent),
            "pref=a%20b; name=caf%C3%A9"
        );
    }

    #[test]
    fn to_header_value_rejects_raw_injection_but_managed_neutralizes_it() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("SID", "x\r\nSet-Cookie: evil=1"));
        // Raw emits the bytes verbatim → not a valid header value.
        assert!(jar.to_header_value(ValueEncoding::Raw).is_err());
        // Percent neutralizes the CR/LF → header-safe.
        assert!(jar.to_header_value(ValueEncoding::Percent).is_ok());
    }
}
