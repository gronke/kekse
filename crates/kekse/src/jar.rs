//! The request `Cookie:` dialect: the [`parse_pairs`] / [`parse_pairs_strict`]
//! readers (with their [`parse_pairs_bytes`] / [`parse_pairs_bytes_strict`]
//! byte-level twins) and the [`CookieJar`] typed view layered on them.
//!
//! Every reader returns what it refused: the streams yield each refused pair
//! as a [`PairIssue`] in place, the jar constructors return [`Reported`].
//! Lenient and strict run one pipeline and differ only in grading — strict
//! accepts a subset of what lenient accepts, never something else — so the
//! severity of an issue is always the caller's choice, never the parser's.

use std::borrow::Cow;

use crate::cookie::Cookie;
use crate::encoding::{ValueEncoding, decode_cookie_value};
use crate::report::{PairIssue, Reported};
use crate::wire::{split_checked_pair, trim_ws};
use http::header::{HeaderValue, InvalidHeaderValue};

/// Parse a request `Cookie` header into `(name, decoded value)` pairs, in
/// order: every well-formed pair comes back as `Ok`, every refused pair as
/// `Err(`[`PairIssue`]`)` — same order, nothing dropped without a witness.
/// Lenient grading: tolerates raw whitespace and the quoted form. The inverse
/// of [`encode_value`](crate::encode_value) / [`SetCookie`](crate::SetCookie).
/// See the [crate docs](crate).
///
/// Fail-soft is one adapter away — `.filter_map(Result::ok)` — and fail-hard
/// is `.collect::<Result<Vec<_>, _>>()`, which stops at the first issue.
///
/// ```
/// use kekse::parse_pairs;
///
/// let mut pairs = parse_pairs("SID=deadbeef; garbage; theme=dark");
/// assert_eq!(pairs.next().unwrap().ok(), Some(("SID", "deadbeef".into())));
/// assert!(pairs.next().unwrap().is_err()); // `garbage` has no `=` — witnessed, not dropped
/// assert_eq!(pairs.next().unwrap().ok(), Some(("theme", "dark".into())));
/// assert!(pairs.next().is_none());
/// ```
pub fn parse_pairs(
    header: &str,
) -> impl Iterator<Item = Result<(&str, Cow<'_, str>), PairIssue<'_>>> {
    parse_pairs_bytes(header.as_bytes())
}

/// Like [`parse_pairs`] but with **strict** grading: a value byte outside the
/// RFC 6265 cookie-octet set — including raw whitespace — refuses that pair as
/// an [`InvalidValue`](PairIssue::InvalidValue). Everything lenient grading
/// refuses, strict refuses too, never the reverse. Use this for a session
/// cookie or any value you minted yourself, where a shape you could not have
/// emitted should not be trusted.
pub fn parse_pairs_strict(
    header: &str,
) -> impl Iterator<Item = Result<(&str, Cow<'_, str>), PairIssue<'_>>> {
    parse_pairs_bytes_strict(header.as_bytes())
}

/// [`parse_pairs`] on raw header bytes, for callers on the wire side of UTF-8 —
/// an `http` `HeaderValue` may legally carry obs-text (`>= 0x80`) that
/// `to_str()` refuses wholesale. The witness stays **per pair** here: a pair
/// carrying a non-ASCII byte is refused individually (raw non-ASCII is outside
/// the grammar in every grading), while its well-formed neighbors survive.
/// Names come back as `&str` for free (tokens are ASCII); values decode to
/// UTF-8 `Cow`s that borrow the buffer whenever no escape actually decoded.
pub fn parse_pairs_bytes(
    header: &[u8],
) -> impl Iterator<Item = Result<(&str, Cow<'_, str>), PairIssue<'_>>> {
    split_pairs_reported(header, true)
}

/// [`parse_pairs_strict`] on raw header bytes — see [`parse_pairs_bytes`].
pub fn parse_pairs_bytes_strict(
    header: &[u8],
) -> impl Iterator<Item = Result<(&str, Cow<'_, str>), PairIssue<'_>>> {
    split_pairs_reported(header, false)
}

/// The one reader core every entry point shares — the `&str` forms run it
/// over `as_bytes()`, the jar constructors collect it — so the stream and jar
/// views cannot drift. An empty or whitespace-only segment (a stray or
/// trailing `;`) is skipped without an issue — structural noise, not a
/// malformed pair.
fn split_pairs_reported(
    header: &[u8],
    allow_ws: bool,
) -> impl Iterator<Item = Result<(&str, Cow<'_, str>), PairIssue<'_>>> {
    header.split(|&b| b == b';').filter_map(move |segment| {
        if trim_ws(segment).is_empty() {
            return None;
        }
        let (name, raw_value) = match split_checked_pair(segment) {
            Ok(pair) => pair,
            Err(issue) => return Some(Err(issue)),
        };
        match decode_cookie_value(raw_value, allow_ws) {
            Some(value) => Some(Ok((name, value))),
            None => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    cookie = %name,
                    "ignoring cookie: value carries a byte outside the accepted \
                     set or percent-escapes that are not valid UTF-8"
                );
                Some(Err(PairIssue::InvalidValue {
                    name,
                    value: raw_value,
                }))
            }
        }
    })
}

/// The baked cookies of a request `Cookie:` header, parsed in order. Borrows
/// the header; each [`Cookie`] is a name and its decoded value. Build it with
/// [`parse`](CookieJar::parse) (lenient grading) or
/// [`parse_strict`](CookieJar::parse_strict) (strict grading) — the readers
/// behind [`parse_pairs`] / [`parse_pairs_strict`], which the jar layers on —
/// both returning the jar inside a [`Reported`] alongside every refused pair.
/// Query with [`get`](CookieJar::get) / [`get_all`](CookieJar::get_all) or
/// iterate.
#[derive(Clone, Debug, Default)]
pub struct CookieJar<'a> {
    cookies: Vec<Cookie<'a>>,
}

impl<'a> CookieJar<'a> {
    /// Parse a `Cookie:` header with lenient grading — tolerating quoted and
    /// whitespace-bearing values (see [`parse_pairs`]) — into the jar plus
    /// every refused pair as a [`PairIssue`], in wire order. `issues` is empty
    /// exactly when the header was fully well-formed, so the severity is the
    /// caller's choice: fail hard on a dirty header
    /// ([`Reported::into_result`]), log the issues and keep the jar, or
    /// discard the report ([`Reported::into_value`]).
    ///
    /// ```
    /// use kekse::CookieJar;
    ///
    /// let jar = CookieJar::parse("SID=deadbeef; theme=dark");
    /// assert!(jar.is_clean());
    /// assert_eq!(jar.value.get("theme").map(|c| c.value()), Some("dark"));
    /// ```
    pub fn parse(header: &'a str) -> Reported<Self, PairIssue<'a>> {
        Self::collect_reported(parse_pairs(header))
    }

    /// [`parse`](CookieJar::parse) with **strict** grading — cookie-octets
    /// only, whitespace refused (see [`parse_pairs_strict`]). The reader for a
    /// session cookie or any value you minted yourself. Same shape, same
    /// salvage: the jar holds every pair that passed the stricter gate, and
    /// everything refused — under either grading — is witnessed in `issues`.
    ///
    /// ```
    /// use kekse::{CookieJar, PairIssue};
    ///
    /// let strict = CookieJar::parse_strict("SID=dead beef; theme=dark");
    /// assert_eq!(strict.value.len(), 1); // the whitespace-bearing value is refused…
    /// assert!(matches!(
    ///     strict.issues[0],
    ///     PairIssue::InvalidValue { name: "SID", .. } // …and witnessed
    /// ));
    /// ```
    pub fn parse_strict(header: &'a str) -> Reported<Self, PairIssue<'a>> {
        Self::collect_reported(parse_pairs_strict(header))
    }

    /// [`parse`](CookieJar::parse) on raw header bytes (see
    /// [`parse_pairs_bytes`]): the witness stays per pair even when the header
    /// carries obs-text a `to_str()` boundary would have to refuse wholesale.
    pub fn parse_bytes(header: &'a [u8]) -> Reported<Self, PairIssue<'a>> {
        Self::collect_reported(parse_pairs_bytes(header))
    }

    /// [`parse_strict`](CookieJar::parse_strict) on raw header bytes (see
    /// [`parse_pairs_bytes_strict`]).
    pub fn parse_bytes_strict(header: &'a [u8]) -> Reported<Self, PairIssue<'a>> {
        Self::collect_reported(parse_pairs_bytes_strict(header))
    }

    /// Partition a reporting pair stream into the jar and its issue list.
    fn collect_reported(
        pairs: impl Iterator<Item = Result<(&'a str, Cow<'a, str>), PairIssue<'a>>>,
    ) -> Reported<Self, PairIssue<'a>> {
        let mut cookies = Vec::new();
        let mut issues = Vec::new();
        for pair in pairs {
            match pair {
                Ok((name, value)) => cookies.push(Cookie::new(name, value)),
                Err(issue) => issues.push(issue),
            }
        }
        Reported {
            value: Self { cookies },
            issues,
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
        // Decoded lengths lower-bound their encoded forms, so the reservation
        // is exact for clean values and a floor for values the encoding grows.
        let pairs: usize = self
            .cookies
            .iter()
            .map(|c| c.name().len() + 1 + c.value().len())
            .sum();
        let mut out = String::with_capacity(pairs + 2 * self.cookies.len().saturating_sub(1));
        for (i, cookie) in self.cookies.iter().enumerate() {
            if i > 0 {
                out.push_str("; ");
            }
            cookie.write_pair_into(&mut out, encoding);
        }
        out
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
    use crate::{ValueEncoding, encode_value};

    fn lenient(header: &str) -> Vec<(&str, String)> {
        parse_pairs(header)
            .filter_map(Result::ok)
            .map(|(n, v)| (n, v.into_owned()))
            .collect()
    }
    fn strict(header: &str) -> Vec<(&str, String)> {
        parse_pairs_strict(header)
            .filter_map(Result::ok)
            .map(|(n, v)| (n, v.into_owned()))
            .collect()
    }
    fn lenient_first(header: &str) -> Option<String> {
        parse_pairs(header)
            .filter_map(Result::ok)
            .next()
            .map(|(_, v)| v.into_owned())
    }
    fn strict_first(header: &str) -> Option<String> {
        parse_pairs_strict(header)
            .filter_map(Result::ok)
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
                .filter_map(Result::ok)
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        assert_eq!(
            parse_pairs("sid=lo; SID=hi")
                .filter_map(Result::ok)
                .find(|(n, _)| *n == "SID")
                .map(|(_, v)| v.into_owned())
                .as_deref(),
            Some("hi")
        );
        assert_eq!(
            parse_pairs("sid=lo; SID=hi")
                .filter_map(Result::ok)
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
                .filter_map(Result::ok)
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
            parse_pairs(&header)
                .filter_map(Result::ok)
                .map(|(n, _)| n)
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        // All-junk wire yields no pairs — but the refusal is still witnessed.
        let all_junk: Vec<_> = parse_pairs("\u{1}\u{2}\u{3}").collect();
        assert_eq!(all_junk.iter().filter(|r| r.is_ok()).count(), 0);
        assert_eq!(all_junk.iter().filter(|r| r.is_err()).count(), 1);
    }

    // ---- CookieJar --------------------------------------------------------

    #[test]
    fn jar_get_is_first_match_including_empty() {
        let jar = CookieJar::parse_strict("SID=; SID=x").into_value();
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
        let jar = CookieJar::parse("k=1; k=2; k=3; K=upper").into_value();
        assert_eq!(
            jar.get_all("k").map(|c| c.value()).collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        assert_eq!(jar.get("K").map(|c| c.value()), Some("upper"));
        assert!(jar.get("missing").is_none());
    }

    #[test]
    fn jar_len_iter_and_empty() {
        let jar = CookieJar::parse("a=1; b=2").into_value();
        assert_eq!(jar.len(), 2);
        assert!(!jar.is_empty());
        assert_eq!(
            jar.iter()
                .map(|c| (c.name(), c.value()))
                .collect::<Vec<_>>(),
            vec![("a", "1"), ("b", "2")]
        );
        assert_eq!((&jar).into_iter().count(), 2);
        assert!(CookieJar::parse("").value.is_empty());
    }

    #[test]
    fn jar_value_borrows_when_octet_clean() {
        let jar = CookieJar::parse_strict("SID=deadbeef").into_value();
        let cookie = jar.into_iter().next().unwrap();
        assert!(matches!(cookie.into_value(), Cow::Borrowed(_)));
    }

    #[test]
    fn jar_is_fail_soft_like_the_parsers() {
        // A malformed pair is skipped — witnessed, never silently — and a
        // later valid pair still parses.
        let reported = CookieJar::parse("n=a\u{1}b; m=ok");
        assert!(reported.value.get("n").is_none());
        assert_eq!(reported.value.get("m").map(|c| c.value()), Some("ok"));
        assert_eq!(reported.issues.len(), 1);
    }

    // ---- the bytes readers -------------------------------------------------

    #[test]
    fn bytes_and_str_readers_agree_on_utf8_input() {
        // The str readers ARE the bytes readers over as_bytes(); pin it anyway so a
        // future divergence (an extra gate on one side) fails here, over headers that
        // exercise quoting, escapes, whitespace, junk segments, and non-ASCII refusal.
        for header in [
            "",
            "a=1; b=2; c=3",
            "n=a=b",
            " n = v ; m=%41",
            "n=\"a b\"; strictfail=x y",
            ";; =v; novalue; ok=1",
            "n=caf\u{e9}; m=ok",
            "n=%C3%A9; bad=%FF; m=ok",
        ] {
            // Compare the FULL streams — Ok pairs and issues alike.
            let via_str: Vec<Result<(&str, String), PairIssue<'_>>> = parse_pairs(header)
                .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                .collect();
            let via_bytes: Vec<Result<(&str, String), PairIssue<'_>>> =
                parse_pairs_bytes(header.as_bytes())
                    .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                    .collect();
            assert_eq!(via_bytes, via_str, "lenient on {header:?}");

            let via_str: Vec<Result<(&str, String), PairIssue<'_>>> = parse_pairs_strict(header)
                .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                .collect();
            let via_bytes: Vec<Result<(&str, String), PairIssue<'_>>> =
                parse_pairs_bytes_strict(header.as_bytes())
                    .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                    .collect();
            assert_eq!(via_bytes, via_str, "strict on {header:?}");
        }
    }

    #[test]
    fn obs_text_pair_is_dropped_alone_not_the_header() {
        // Raw 0xE9 is obs-text a HeaderValue may carry but to_str() refuses wholesale.
        // The bytes reader keeps fail-soft per PAIR: only the carrying pair is refused.
        let wire = b"good=1; bad=caf\xE9; m=ok";
        let pairs: Vec<(&str, String)> = parse_pairs_bytes(wire)
            .filter_map(Result::ok)
            .map(|(n, v)| (n, v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![("good", "1".to_string()), ("m", "ok".to_string())]
        );
        // Same through the jar view, in both modes.
        let jar = CookieJar::parse_bytes(wire).into_value();
        assert_eq!(jar.len(), 2);
        assert!(jar.get("bad").is_none());
        let jar = CookieJar::parse_bytes_strict(wire).into_value();
        assert_eq!(jar.get("m").map(|c| c.value()), Some("ok"));
        // Even a non-UTF-8 NAME only costs its own pair.
        let pairs: Vec<(&str, String)> = parse_pairs_bytes(b"a\xFFb=v; m=ok")
            .filter_map(Result::ok)
            .map(|(n, v)| (n, v.into_owned()))
            .collect();
        assert_eq!(pairs, vec![("m", "ok".to_string())]);
    }

    #[test]
    fn bytes_value_borrows_when_octet_clean() {
        // The zero-copy pin, bytes-path twin of jar_value_borrows_when_octet_clean.
        let jar = CookieJar::parse_bytes_strict(b"SID=deadbeef").into_value();
        let cookie = jar.into_iter().next().unwrap();
        assert!(matches!(cookie.into_value(), Cow::Borrowed(_)));
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
        let mut jar = CookieJar::parse("a=1; b=2; a=3").into_value();
        assert_eq!(jar.remove("a"), 2);
        assert_eq!(jar.remove("missing"), 0);
        assert_eq!(jar.iter().map(|c| c.name()).collect::<Vec<_>>(), vec!["b"]);
    }

    #[test]
    fn replace_is_the_canonical_single_value_write() {
        let mut jar = CookieJar::parse("SID=old; SID=stale; theme=dark").into_value();
        jar.replace(Cookie::new("SID", "new"));
        assert_eq!(
            jar.get_all("SID").map(|c| c.value()).collect::<Vec<_>>(),
            vec!["new"] // the stale duplicates are gone
        );
        assert_eq!(jar.get("theme").map(|c| c.value()), Some("dark"));
    }

    #[test]
    fn replace_then_render_uses_the_argument_encoding_not_the_stored_one() {
        let mut jar = CookieJar::parse("pref=old; pref=stale").into_value();
        // Replace the duplicates with one value that needs escaping, built with a
        // DIFFERENT stored encoding (Auto) than the render calls will request.
        jar.replace(Cookie::new("pref", "a b").with_encoding(ValueEncoding::Auto));
        assert_eq!(
            jar.get_all("pref").map(|c| c.value()).collect::<Vec<_>>(),
            vec!["a b"] // replace collapsed the stale duplicates to the new value
        );
        // The jar re-encodes every pair under the ARGUMENT to to_header_value,
        // ignoring the cookie's stored Auto: Percent → a%20b.
        assert_eq!(
            jar.to_header_value(ValueEncoding::Percent)
                .unwrap()
                .to_str()
                .unwrap(),
            "pref=a%20b"
        );
        // Auto argument → whitespace rides quoted.
        assert_eq!(
            jar.to_header_value(ValueEncoding::Auto)
                .unwrap()
                .to_str()
                .unwrap(),
            "pref=\"a b\""
        );
    }

    #[test]
    fn header_string_joins_pairs_and_round_trips() {
        let jar = CookieJar::parse_strict("a=1; b=2; c=3").into_value();
        let rendered = jar.to_header_string(ValueEncoding::Percent);
        assert_eq!(rendered, "a=1; b=2; c=3");
        let again = CookieJar::parse_strict(&rendered).into_value();
        assert_eq!(
            again
                .iter()
                .map(|c| (c.name(), c.value()))
                .collect::<Vec<_>>(),
            vec![("a", "1"), ("b", "2"), ("c", "3")]
        );
    }

    #[test]
    fn header_string_equals_the_join_of_individual_pairs() {
        // The single-buffer writer and the per-pair renderer are the same
        // serialization: joining `to_pair` outputs with "; " reconstructs
        // `to_header_string` for every encoding, jar size, and value shape.
        let empty = CookieJar::new();
        let single = CookieJar::parse("SID=deadbeef").into_value();
        let mixed =
            CookieJar::parse(r#"a=1; pref="dark mode"; name=caf%C3%A9; q=100%25; e="#).into_value();
        for jar in [&empty, &single, &mixed] {
            for encoding in [
                ValueEncoding::Auto,
                ValueEncoding::Percent,
                ValueEncoding::Quoted,
                ValueEncoding::Raw,
            ] {
                let oracle = jar
                    .iter()
                    .map(|c| c.to_pair(encoding))
                    .collect::<Vec<_>>()
                    .join("; ");
                assert_eq!(jar.to_header_string(encoding), oracle, "{encoding:?}");
            }
        }
    }

    #[test]
    fn re_encode_is_canonical_no_raw_retention() {
        // Values that arrived quoted / percent-escaped are re-emitted in the one
        // canonical Percent form — the original wire shape is not retained.
        let jar = CookieJar::parse(r#"pref="a b"; name=caf%C3%A9"#).into_value();
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

    // ---- the reporting readers ---------------------------------------------

    /// The nasty-header table the equivalence pins sweep: quoting, escapes,
    /// whitespace, junk segments, missing `=`, bad names, bad values, non-ASCII.
    const NASTY_HEADERS: [&str; 10] = [
        "",
        "a=1; b=2; c=3",
        "n=a=b",
        " n = v ; m=%41",
        "n=\"a b\"; strictfail=x y",
        ";; =v; novalue; ok=1",
        "n=caf\u{e9}; m=ok",
        "n=%C3%A9; bad=%FF; m=ok",
        "garbage; =nix; na me=v; SID=deadbeef; ;;; theme",
        "n=a\u{1}b; m=ok",
    ];

    #[test]
    fn jar_collects_exactly_the_stream_partition() {
        // The jar constructor and the streaming reader are the same parse:
        // `value` is the Ok items, `issues` is the Err items, both in wire
        // order — for every grading and both input forms.
        for header in NASTY_HEADERS {
            for strict_grading in [false, true] {
                let stream: Vec<Result<(&str, String), PairIssue<'_>>> = if strict_grading {
                    parse_pairs_strict(header)
                        .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                        .collect()
                } else {
                    parse_pairs(header)
                        .map(|r| r.map(|(n, v)| (n, v.into_owned())))
                        .collect()
                };
                let jar = if strict_grading {
                    CookieJar::parse_strict(header)
                } else {
                    CookieJar::parse(header)
                };
                let jar_pairs: Vec<(&str, String)> = jar
                    .value
                    .iter()
                    .map(|c| (c.name(), c.value().to_owned()))
                    .collect();
                let ok_items: Vec<(&str, String)> =
                    stream.iter().filter_map(|r| r.clone().ok()).collect();
                let err_items: Vec<PairIssue<'_>> =
                    stream.iter().filter_map(|r| r.clone().err()).collect();
                assert_eq!(jar_pairs, ok_items, "strict={strict_grading} on {header:?}");
                assert_eq!(
                    jar.issues, err_items,
                    "strict={strict_grading} on {header:?}"
                );
            }
        }
    }

    #[test]
    fn lenient_issues_are_a_subset_of_strict_issues() {
        // The report dual of "strict pairs ⊆ lenient pairs": everything lenient
        // refuses, strict refuses too.
        for header in NASTY_HEADERS {
            let lenient_issues: Vec<_> = parse_pairs(header).filter_map(Result::err).collect();
            let strict_issues: Vec<_> =
                parse_pairs_strict(header).filter_map(Result::err).collect();
            for issue in &lenient_issues {
                assert!(
                    strict_issues.contains(issue),
                    "lenient-only issue {issue:?} on {header:?}"
                );
            }
        }
    }

    #[test]
    fn each_issue_variant_names_its_defect() {
        let issues: Vec<PairIssue<'_>> = parse_pairs("garbage; =v; na me=x; n=a\u{1}b; ok=1")
            .filter_map(Result::err)
            .collect();
        assert_eq!(
            issues,
            vec![
                PairIssue::MissingEquals {
                    segment: b"garbage"
                },
                PairIssue::InvalidName { name: b"" },
                PairIssue::InvalidName { name: b"na me" },
                PairIssue::InvalidValue {
                    name: "n",
                    value: b"a\x01b"
                },
            ],
            "issues arrive in wire order, one per refused pair"
        );
        // Strict-only issue: raw whitespace in the value.
        let strict_only: Vec<PairIssue<'_>> = parse_pairs_strict("n=a b")
            .filter_map(Result::err)
            .collect();
        assert_eq!(
            strict_only,
            vec![PairIssue::InvalidValue {
                name: "n",
                value: b"a b"
            }]
        );
        assert_eq!(parse_pairs("n=a b").filter_map(Result::err).count(), 0);
    }

    #[test]
    fn structural_noise_is_not_an_issue() {
        // Empty / OWS-only segments (stray or trailing `;`) never report.
        for header in ["", ";;;", "a=1;", "a=1;  ; b=2", " ; \t; "] {
            assert!(
                parse_pairs(header).filter_map(Result::err).count() == 0,
                "{header:?}"
            );
        }
    }

    #[test]
    fn issue_payloads_borrow_the_input_buffer() {
        // Zero-copy pin for the report path, sibling of
        // jar_value_borrows_when_octet_clean.
        let header = "bad=a\u{1}b; ok=1";
        let range = header.as_bytes().as_ptr_range();
        for issue in parse_pairs(header).filter_map(Result::err) {
            let PairIssue::InvalidValue { value, .. } = issue else {
                panic!("expected InvalidValue, got {issue:?}");
            };
            let value_range = value.as_ptr_range();
            assert!(
                range.start <= value_range.start && value_range.end <= range.end,
                "issue payload does not borrow the header buffer"
            );
        }
    }

    #[test]
    fn jar_partitions_pairs_and_issues() {
        let header = "garbage; SID=deadbeef; bad=a\u{1}b; theme=dark";
        let Reported { value: jar, issues } = CookieJar::parse(header);
        assert_eq!(jar.get("SID").map(|c| c.value()), Some("deadbeef"));
        assert_eq!(jar.get("theme").map(|c| c.value()), Some("dark"));
        assert_eq!(jar.len(), 2);
        assert_eq!(issues.len(), 2);
        // A clean header is clean in every constructor form.
        assert!(CookieJar::parse("a=1; b=2").is_clean());
        assert!(CookieJar::parse_strict("a=1; b=2").is_clean());
        assert!(CookieJar::parse_bytes(b"a=1; b=2").is_clean());
        assert!(CookieJar::parse_bytes_strict(b"a=1; b=2").is_clean());
        // into_result: the user-sketch view.
        let (salvaged, issues) = CookieJar::parse("junk; a=1").into_result().unwrap_err();
        assert_eq!(salvaged.len(), 1);
        assert_eq!(issues, vec![PairIssue::MissingEquals { segment: b"junk" }]);
    }

    #[test]
    fn fail_hard_is_one_collect_away() {
        // The documented fail-hard idiom over the streaming reader.
        let clean: Result<Vec<_>, _> = parse_pairs("a=1; b=2").collect();
        assert_eq!(clean.map(|pairs| pairs.len()), Ok(2));
        let dirty: Result<Vec<_>, _> = parse_pairs("a=1; garbage; b=2").collect();
        assert_eq!(
            dirty,
            Err(PairIssue::MissingEquals {
                segment: b" garbage"
            })
        );
    }

    #[test]
    fn readers_stay_send() {
        // The opaque iterators and the report are Send; a rework must not
        // lose it.
        fn assert_send<T: Send>(_: T) {}
        assert_send(parse_pairs("a=1"));
        assert_send(parse_pairs_strict("a=1"));
        assert_send(parse_pairs_bytes(b"a=1"));
        assert_send(CookieJar::parse("a=1"));
    }
}
