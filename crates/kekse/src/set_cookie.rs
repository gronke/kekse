//! The [`SetCookie`] recipe builder for a `Set-Cookie` response value, its
//! `Display` rendering, and the conversion straight into an `http::HeaderValue`.

use std::borrow::Cow;
use std::fmt;

use crate::cookie::Cookie;
use crate::encoding::{decode_cookie_value, encode_value, ValueEncoding};
use crate::grammar::{is_cookie_name, is_ws_char};
use crate::same_site::SameSite;

/// A builder for a `Set-Cookie` header value.
///
/// Render it with [`to_string`](ToString::to_string) (via the `Display` impl) or
/// convert it straight into an `http::HeaderValue` with `HeaderValue::try_from`.
/// Attributes are emitted in a fixed order — `HttpOnly`, `SameSite`, `Secure`,
/// `Path`, `Domain`, `Max-Age` — each only when set. The value is escaped per
/// the chosen [`ValueEncoding`] (default [`Percent`](ValueEncoding::Percent)); the name
/// is **not** validated here (check [`is_cookie_name`](crate::is_cookie_name) at
/// the call site if the name is untrusted).
#[derive(Clone, Debug)]
pub struct SetCookie<'a> {
    name: &'a str,
    value: Cow<'a, str>,
    encoding: ValueEncoding,
    http_only: bool,
    secure: bool,
    same_site: Option<SameSite>,
    path: Option<&'a str>,
    domain: Option<&'a str>,
    max_age: Option<u64>,
}

impl<'a> SetCookie<'a> {
    /// Build a recipe for `name`/`value` with no attributes and the default
    /// [`Percent`](ValueEncoding::Percent) encoding. The crate-internal constructor
    /// that takes an owned-or-borrowed value; [`new`](SetCookie::new) and
    /// [`Cookie::unbake`](crate::Cookie::unbake) both route through it.
    pub(crate) fn from_value(name: &'a str, value: Cow<'a, str>) -> Self {
        Self {
            name,
            value,
            encoding: ValueEncoding::Percent,
            http_only: false,
            secure: false,
            same_site: None,
            path: None,
            domain: None,
            max_age: None,
        }
    }

    /// Start a `Set-Cookie` for `name=value` with no attributes set and the
    /// default [`Percent`](ValueEncoding::Percent) value encoding.
    pub fn new(name: &'a str, value: &'a str) -> Self {
        Self::from_value(name, Cow::Borrowed(value))
    }

    /// Parse a single `Set-Cookie` header value into a recipe (RFC 6265 §5.2).
    ///
    /// Splits on the first `;` into the `name=value` pair and the attribute list,
    /// then the pair on its first `=`. The name must be a cookie-name token; the
    /// value runs through the same lenient pipeline as
    /// [`parse_pairs`](crate::parse_pairs) (one wrapping quote pair stripped,
    /// cookie-octets plus whitespace, percent-decoded), and the recipe carries the
    /// decoded value under the default [`Percent`](ValueEncoding::Percent) encoding.
    /// Attributes are matched ASCII-case-insensitively: `HttpOnly`, `Secure`,
    /// `SameSite` (`Strict`/`Lax`/`None`), `Path`, `Domain`, and `Max-Age` (a
    /// `u64`; a negative or non-numeric delta is dropped). `Expires` is **ignored**
    /// — kekse models a lifetime only as `Max-Age`, never a date. Unknown or
    /// malformed attributes are skipped, so a junk attribute never discards the
    /// cookie. Returns `None` only when there is no usable pair: no `=`, an empty
    /// or non-token name, or a value outside the accepted set / with escapes that
    /// are not valid UTF-8. Never panics.
    pub fn parse(header_value: &'a str) -> Option<Self> {
        let (pair, attrs) = match header_value.split_once(';') {
            Some((pair, rest)) => (pair, Some(rest)),
            None => (header_value, None),
        };
        let (raw_name, raw_value) = pair.split_once('=')?;
        let name = raw_name.trim_matches(is_ws_char);
        if name.is_empty() || !is_cookie_name(name) {
            return None;
        }
        let value = decode_cookie_value(raw_value, true)?;
        let mut cookie = Self::from_value(name, value);
        for piece in attrs.into_iter().flat_map(|a| a.split(';')) {
            let (attr, val) = match piece.split_once('=') {
                Some((a, v)) => (a.trim_matches(is_ws_char), v.trim_matches(is_ws_char)),
                None => (piece.trim_matches(is_ws_char), ""),
            };
            if attr.eq_ignore_ascii_case("HttpOnly") {
                cookie.http_only = true;
            } else if attr.eq_ignore_ascii_case("Secure") {
                cookie.secure = true;
            } else if attr.eq_ignore_ascii_case("SameSite") {
                cookie.same_site = parse_same_site(val);
            } else if attr.eq_ignore_ascii_case("Path") {
                cookie.path = Some(val);
            } else if attr.eq_ignore_ascii_case("Domain") {
                cookie.domain = Some(val);
            } else if attr.eq_ignore_ascii_case("Max-Age") {
                cookie.max_age = val.parse::<u64>().ok();
            }
            // `Expires` and any unknown attribute are ignored: kekse is
            // date-free and models a lifetime only as `Max-Age`.
        }
        Some(cookie)
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

    /// Drop every attribute, keeping just the name and value, to recover the
    /// baked [`Cookie`] this recipe stands for. A structural projection — the
    /// value is **not** re-encoded — so a borrowed recipe bakes to a borrowed
    /// cookie. The inverse of [`Cookie::unbake`].
    pub fn bake(self) -> Cookie<'a> {
        Cookie::new(self.name, self.value)
    }

    /// The cookie-name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The cookie-value, decoded — the logical value, not its wire encoding.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Parse a `SameSite` attribute value ASCII-case-insensitively; `None` for an
/// unrecognised token (the attribute is then dropped, not the cookie).
fn parse_same_site(value: &str) -> Option<SameSite> {
    if value.eq_ignore_ascii_case("Strict") {
        Some(SameSite::Strict)
    } else if value.eq_ignore_ascii_case("Lax") {
        Some(SameSite::Lax)
    } else if value.eq_ignore_ascii_case("None") {
        Some(SameSite::None)
    } else {
        None
    }
}

impl fmt::Display for SetCookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={}",
            self.name,
            encode_value(&self.value, self.encoding)
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

impl TryFrom<SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    /// Render the recipe — byte-identical to its `Display` — into a
    /// `Set-Cookie` `HeaderValue`. The managed encodings
    /// ([`Percent`](ValueEncoding::Percent), [`Percent`](ValueEncoding::Percent),
    /// [`Quoted`](ValueEncoding::Quoted)) are always visible-ASCII and never
    /// fail; only [`Raw`](ValueEncoding::Raw), where the caller owns
    /// wire-correctness, can produce bytes a header value rejects.
    fn try_from(cookie: SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_string())
    }
}

impl TryFrom<&SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    fn try_from(cookie: &SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn try_into_header_value_is_byte_pinned() {
        // The exact bytes the auth consumer pins (its m1 / hardened-session test).
        let hv = http::HeaderValue::try_from(
            SetCookie::new("SID", "deadbeef")
                .value_encoding(ValueEncoding::Percent)
                .http_only(true)
                .same_site(SameSite::Strict)
                .secure(true)
                .path("/")
                .max_age(3600),
        )
        .unwrap();
        assert_eq!(
            hv.to_str().unwrap(),
            "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
        );
    }

    #[test]
    fn try_into_header_value_matches_display() {
        let c = SetCookie::new("n", "v").http_only(true).max_age(60);
        let via_ref = http::HeaderValue::try_from(&c).unwrap();
        let via_owned = http::HeaderValue::try_from(c.clone()).unwrap();
        assert_eq!(via_ref.to_str().unwrap(), c.to_string());
        assert_eq!(via_owned, via_ref);
    }

    #[test]
    fn try_into_header_value_rejects_raw_injection() {
        // Raw hands wire-correctness to the caller, so a CR/LF smuggle is caught
        // at the header boundary rather than silently emitted.
        let c = SetCookie::new("n", "x\r\nSet-Cookie: evil=1").value_encoding(ValueEncoding::Raw);
        assert!(http::HeaderValue::try_from(c).is_err());
    }

    #[test]
    fn try_into_header_value_managed_never_errors() {
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
        ];
        for v in hostile {
            for enc in [
                ValueEncoding::Auto,
                ValueEncoding::Percent,
                ValueEncoding::Quoted,
            ] {
                let c = SetCookie::new("n", v).value_encoding(enc);
                let hv = http::HeaderValue::try_from(&c)
                    .unwrap_or_else(|e| panic!("managed {enc:?} of {v:?} must form a header: {e}"));
                assert_eq!(hv.to_str().unwrap(), c.to_string());
            }
        }
    }

    // ---- accessors --------------------------------------------------------

    #[test]
    fn name_and_value_accessors() {
        let c = SetCookie::new("SID", "deadbeef");
        assert_eq!(c.name(), "SID");
        assert_eq!(c.value(), "deadbeef");
    }

    // ---- parse (Set-Cookie -> recipe) ------------------------------------

    #[test]
    fn parse_round_trips_a_built_set_cookie() {
        let wire = SetCookie::new("SID", "deadbeef")
            .value_encoding(ValueEncoding::Percent)
            .http_only(true)
            .same_site(SameSite::Strict)
            .secure(true)
            .path("/")
            .max_age(3600)
            .to_string();
        let parsed = SetCookie::parse(&wire).unwrap();
        assert_eq!(parsed.name(), "SID");
        assert_eq!(parsed.value(), "deadbeef");
        assert!(parsed.http_only && parsed.secure);
        assert_eq!(parsed.same_site, Some(SameSite::Strict));
        assert_eq!(parsed.path, Some("/"));
        assert_eq!(parsed.max_age, Some(3600));
        assert_eq!(parsed.domain, None);
        // Re-render is canonical (Auto); deadbeef is octet-clean, so byte-equal.
        assert_eq!(parsed.to_string(), wire);
    }

    #[test]
    fn parse_decodes_value_like_the_request_reader() {
        assert_eq!(SetCookie::parse("pref=caf%C3%A9").unwrap().value(), "café");
        assert_eq!(SetCookie::parse(r#"pref="a b""#).unwrap().value(), "a b");
    }

    #[test]
    fn parse_attributes_are_case_insensitive() {
        let p =
            SetCookie::parse("n=v; SECURE; httponly; samesite=lax; PATH=/x; max-age=60").unwrap();
        assert!(p.secure && p.http_only);
        assert_eq!(p.same_site, Some(SameSite::Lax));
        assert_eq!(p.path, Some("/x"));
        assert_eq!(p.max_age, Some(60));
    }

    #[test]
    fn parse_ignores_expires_and_unknown_attributes() {
        let p = SetCookie::parse(
            "SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Priority=High; Max-Age=60",
        )
        .unwrap();
        assert_eq!(p.value(), "x");
        assert_eq!(p.max_age, Some(60));
        // No field exists for Expires/Priority — they simply do not survive.
        let no_max = SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT").unwrap();
        assert_eq!(no_max.max_age, None);
    }

    #[test]
    fn parse_skips_malformed_attributes_but_keeps_the_cookie() {
        let p = SetCookie::parse("SID=x; Max-Age=banana; SameSite=Bogus; HttpOnly").unwrap();
        assert!(p.http_only);
        assert_eq!(p.max_age, None); // non-numeric dropped
        assert_eq!(p.same_site, None); // unrecognised SameSite dropped
        assert_eq!(p.value(), "x"); // cookie survives
    }

    #[test]
    fn parse_max_age_u64_and_negative() {
        assert_eq!(
            SetCookie::parse("n=v; Max-Age=18446744073709551615")
                .unwrap()
                .max_age,
            Some(u64::MAX)
        );
        assert_eq!(SetCookie::parse("n=v; Max-Age=-1").unwrap().max_age, None);
    }

    #[test]
    fn parse_rejects_no_equals_and_bad_name() {
        assert!(SetCookie::parse("HttpOnly").is_none()); // no name=value pair
        assert!(SetCookie::parse("na me=v; Secure").is_none()); // non-token name
        assert!(SetCookie::parse("").is_none());
        assert!(SetCookie::parse("=v").is_none()); // empty name
    }

    #[test]
    fn parse_splits_first_semicolon_then_first_equals() {
        let p = SetCookie::parse("a=b=c; Path=/x").unwrap();
        assert_eq!(p.name(), "a");
        assert_eq!(p.value(), "b=c"); // only the first '=' splits name/value
        assert_eq!(p.path, Some("/x"));
    }
}
