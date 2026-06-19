//! The response [`SetCookie`] — a [`Cookie`] kernel plus [`CookieAttributes`] —
//! its `Set-Cookie` parse and serialize, and the conversion straight into an
//! `http::HeaderValue`.

use std::borrow::Cow;
use std::fmt;

use crate::attributes::{CookieAttributes, Domain, Path};
use crate::cookie::Cookie;
use crate::encoding::{decode_cookie_value, ValueEncoding};
use crate::grammar::{is_cookie_name, is_ws_char};
use crate::same_site::SameSite;

/// A `Set-Cookie:` response cookie: a [`Cookie`] kernel (name, value, wire
/// encoding) plus [`CookieAttributes`] (`HttpOnly`, `SameSite`, `Secure`,
/// `Path`, `Domain`, `Max-Age`). A `Set-Cookie` line is *fully observed*, so the
/// flags are plain `bool` — present or absent on the line — never an `Option`.
///
/// Build one from a request [`Cookie`] with
/// [`Cookie::into_set_cookie`](crate::Cookie::into_set_cookie) (default
/// attributes) or [`Cookie::with_attributes`](crate::Cookie::with_attributes) (a
/// prebuilt set), or from scratch with [`new`](SetCookie::new). Set attributes
/// with the fluent verbs — [`secure`](SetCookie::secure),
/// [`http_only`](SetCookie::http_only), [`path`](SetCookie::path), … — which
/// delegate to the embedded [`CookieAttributes`]; the valueless flags are
/// nullary. Read them back through [`attributes`](SetCookie::attributes) as
/// fields (`sc.attributes().secure`, `sc.attributes().max_age`). Render with
/// [`to_set_cookie`](SetCookie::to_set_cookie) or convert straight into an
/// `http::HeaderValue` with `HeaderValue::try_from`. Attributes emit in a fixed
/// order — `HttpOnly`, `SameSite`, `Secure`, `Path`, `Domain`, `Max-Age` — each
/// only when set. The builder does **not** validate the name (check
/// [`is_cookie_name`](crate::is_cookie_name) at the call site if it is
/// untrusted); [`parse`](SetCookie::parse) does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetCookie<'a> {
    cookie: Cookie<'a>,
    attributes: CookieAttributes<'a>,
}

impl<'a> SetCookie<'a> {
    /// Pair a [`Cookie`] kernel with a set of [`CookieAttributes`]. The one true
    /// constructor — [`new`](SetCookie::new), `From<Cookie>`,
    /// `From<(Cookie, CookieAttributes)>`,
    /// [`Cookie::into_set_cookie`](crate::Cookie::into_set_cookie), and
    /// [`Cookie::with_attributes`](crate::Cookie::with_attributes) all route here.
    pub fn from_parts(cookie: Cookie<'a>, attributes: CookieAttributes<'a>) -> Self {
        Self { cookie, attributes }
    }

    /// Start a `Set-Cookie` for `name=value` with no attributes set and the
    /// default [`ValueEncoding`]. Shorthand for
    /// `Cookie::new(name, value).into_set_cookie()`.
    pub fn new(name: &'a str, value: impl Into<Cow<'a, str>>) -> Self {
        Self::from_parts(Cookie::new(name, value), CookieAttributes::default())
    }

    /// Parse one `Set-Cookie` header value into a `SetCookie` (RFC 6265 §5.2). An
    /// **unrecognised attribute is ignored** and the cookie is kept, per §5.2 — so
    /// a modern attribute this version does not model (`Partitioned`, `Priority`,
    /// …) never costs you the cookie. Use
    /// [`parse_strict`](SetCookie::parse_strict) to reject on an unknown attribute
    /// instead.
    ///
    /// Splits on the first `;` into the `name=value` pair and the attribute list,
    /// then the pair on its first `=`. The name must be a cookie-name token; the
    /// value runs through the same lenient pipeline as
    /// [`parse_pairs`](crate::parse_pairs) (one wrapping quote pair stripped,
    /// cookie-octets plus whitespace, percent-decoded). Attributes are matched
    /// ASCII-case-insensitively: `HttpOnly`, `Secure`, `SameSite`
    /// (`Strict`/`Lax`/`None`), `Path`, `Domain`, and `Max-Age` (a `u64`; a
    /// negative or non-numeric delta is dropped). `Expires` is recognised but its
    /// value is not acted on yet — date handling is a planned follow-up. Returns
    /// `None` when there is no usable pair — no `=`, an empty or non-token name,
    /// or a value outside the accepted set / with escapes that are not valid
    /// UTF-8. Never panics.
    pub fn parse(header_value: &'a str) -> Option<Self> {
        Self::parse_with(header_value, false)
    }

    /// Like [`parse`](SetCookie::parse) but **strict**: an unrecognised attribute
    /// rejects the whole cookie (`None`) instead of being ignored. A tripwire for
    /// cookies you minted yourself, where an attribute you did not emit signals
    /// something is wrong. A malformed *known* attribute (e.g. a non-numeric
    /// `Max-Age`) is dropped, not fatal, in both modes.
    pub fn parse_strict(header_value: &'a str) -> Option<Self> {
        Self::parse_with(header_value, true)
    }

    fn parse_with(header_value: &'a str, strict: bool) -> Option<Self> {
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
        let mut set_cookie =
            Self::from_parts(Cookie::new(name, value), CookieAttributes::default());
        for piece in attrs.into_iter().flat_map(|a| a.split(';')) {
            let (attr, val) = match piece.split_once('=') {
                Some((a, v)) => (a.trim_matches(is_ws_char), v.trim_matches(is_ws_char)),
                None => (piece.trim_matches(is_ws_char), ""),
            };
            if attr.is_empty() {
                continue; // a stray or trailing `;` — not an attribute
            }
            if attr.eq_ignore_ascii_case(attr_name::HTTP_ONLY) {
                set_cookie.attributes.http_only = true;
            } else if attr.eq_ignore_ascii_case(attr_name::SECURE) {
                set_cookie.attributes.secure = true;
            } else if attr.eq_ignore_ascii_case(attr_name::SAME_SITE) {
                set_cookie.attributes.same_site = parse_same_site(val);
            } else if attr.eq_ignore_ascii_case(attr_name::PATH) {
                // An invalid value (control byte, `;`, non-ASCII) is dropped like a
                // malformed Max-Age — the cookie is kept, the attribute discarded.
                set_cookie.attributes.path = Path::new(val);
            } else if attr.eq_ignore_ascii_case(attr_name::DOMAIN) {
                set_cookie.attributes.domain = Domain::new(val);
            } else if attr.eq_ignore_ascii_case(attr_name::MAX_AGE) {
                set_cookie.attributes.max_age = val.parse::<u64>().ok();
            } else if attr.eq_ignore_ascii_case(attr_name::EXPIRES) {
                // Recognised, but date handling is deferred to a follow-up; the
                // value is not acted on yet.
            } else if strict {
                // Strict (opt-in): an unrecognised attribute rejects the cookie.
                return None;
            }
            // Default: an unrecognised attribute is ignored (RFC 6265 §5.2).
        }
        Some(set_cookie)
    }

    /// Choose how the value is escaped for the wire (delegates to the kernel).
    #[must_use]
    pub fn with_encoding(mut self, encoding: ValueEncoding) -> Self {
        self.cookie = self.cookie.with_encoding(encoding);
        self
    }

    /// Pair this cookie with a prebuilt [`CookieAttributes`] set, replacing any
    /// already attached — the way to apply a reusable, hardened attribute policy.
    #[must_use]
    pub fn with_attributes(mut self, attributes: CookieAttributes<'a>) -> Self {
        self.attributes = attributes;
        self
    }

    /// Add the `HttpOnly` attribute — a valueless presence flag (nullary). Reads
    /// back as `self.attributes().http_only`.
    #[must_use]
    pub fn http_only(mut self) -> Self {
        self.attributes.http_only = true;
        self
    }

    /// Add the `Secure` attribute — a valueless presence flag (nullary). Reads
    /// back as `self.attributes().secure`.
    #[must_use]
    pub fn secure(mut self) -> Self {
        self.attributes.secure = true;
        self
    }

    /// Set the `SameSite` attribute.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.attributes.same_site = Some(same_site);
        self
    }

    /// Set the `Path` attribute. An invalid path (control byte, `;`, or non-ASCII
    /// — see [`Path`](crate::Path)) is rejected and leaves the attribute unset.
    #[must_use]
    pub fn path(mut self, path: &'a str) -> Self {
        self.attributes.path = Path::new(path);
        self
    }

    /// Set the `Domain` attribute. Omit for a host-only cookie. An invalid domain
    /// (see [`Domain`](crate::Domain)) is rejected and leaves the attribute unset.
    #[must_use]
    pub fn domain(mut self, domain: &'a str) -> Self {
        self.attributes.domain = Domain::new(domain);
        self
    }

    /// Set the `Max-Age` attribute, in seconds. `0` instructs the client to
    /// delete the cookie. Rendered as a `u64` decimal — no saturation.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.attributes.max_age = Some(seconds);
        self
    }

    /// The cookie-name.
    pub fn name(&self) -> &str {
        self.cookie.name()
    }

    /// The cookie-value, decoded — the logical value, not its wire encoding.
    pub fn value(&self) -> &str {
        self.cookie.value()
    }

    /// The value's wire encoding.
    pub fn encoding(&self) -> ValueEncoding {
        self.cookie.encoding()
    }

    /// Borrow the request [`Cookie`] kernel — name, value, encoding — setting the
    /// response attributes aside by *view*.
    pub fn cookie(&self) -> &Cookie<'a> {
        &self.cookie
    }

    /// Borrow the response [`CookieAttributes`]. Read a single attribute as a
    /// field: `sc.attributes().secure`, `sc.attributes().max_age`.
    pub fn attributes(&self) -> &CookieAttributes<'a> {
        &self.attributes
    }

    /// Drop the attributes, recovering the request [`Cookie`] kernel. A
    /// structural move — the value is **not** re-encoded, so a borrowed value
    /// stays borrowed. The inverse of
    /// [`Cookie::into_set_cookie`](crate::Cookie::into_set_cookie).
    pub fn into_cookie(self) -> Cookie<'a> {
        self.cookie
    }

    /// Take the response [`CookieAttributes`], discarding the kernel.
    pub fn into_attributes(self) -> CookieAttributes<'a> {
        self.attributes
    }

    /// Render the request `Cookie:` pair (`name=value`) — attributes ignored.
    /// Delegates to [`Cookie::to_request_pair`](crate::Cookie::to_request_pair).
    pub fn to_request_pair(&self) -> String {
        self.cookie.to_request_pair()
    }

    /// Render the response `Set-Cookie:` value — `name=value` plus the set
    /// attributes, in the fixed order `HttpOnly`, `SameSite`, `Secure`, `Path`,
    /// `Domain`, `Max-Age` (each only when set; a flag only when `true`).
    ///
    /// The pair and each rendered attribute are joined with `"; "` exactly once.
    /// Each attribute is a typed value that renders itself, and its name comes
    /// from the same constants the parser matches, so the separator and every
    /// attribute name live in a single place.
    pub fn to_set_cookie(&self) -> String {
        let attributes = self.set_cookie_attributes();
        std::iter::once(self.cookie.to_request_pair())
            .chain(attributes.iter().map(|attribute| attribute.to_string()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The set response attributes as typed values, in the canonical `Set-Cookie`
    /// order. A boolean flag appears only when `true`; an unset flag or absent
    /// attribute is omitted.
    fn set_cookie_attributes(&self) -> Vec<SetCookieAttribute<'a>> {
        let a = &self.attributes;
        [
            a.http_only.then_some(SetCookieAttribute::HttpOnly),
            a.same_site.map(SetCookieAttribute::SameSite),
            a.secure.then_some(SetCookieAttribute::Secure),
            a.path.map(|p| SetCookieAttribute::Path(p.as_str())),
            a.domain.map(|d| SetCookieAttribute::Domain(d.as_str())),
            a.max_age.map(SetCookieAttribute::MaxAge),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl<'a> From<(Cookie<'a>, CookieAttributes<'a>)> for SetCookie<'a> {
    /// Pair a kernel with attributes — same as
    /// [`from_parts`](SetCookie::from_parts).
    fn from((cookie, attributes): (Cookie<'a>, CookieAttributes<'a>)) -> Self {
        SetCookie::from_parts(cookie, attributes)
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

/// Canonical `Set-Cookie` attribute names — the single source of truth shared by
/// the parser (matched ASCII-case-insensitively) and the serializer (the
/// `Display` for `SetCookieAttribute`), so the reader and the writer can't drift.
mod attr_name {
    pub const HTTP_ONLY: &str = "HttpOnly";
    pub const SECURE: &str = "Secure";
    pub const SAME_SITE: &str = "SameSite";
    pub const PATH: &str = "Path";
    pub const DOMAIN: &str = "Domain";
    pub const MAX_AGE: &str = "Max-Age";
    pub const EXPIRES: &str = "Expires";
}

/// One rendered `Set-Cookie` attribute — the typed unit the serializer emits.
///
/// [`to_set_cookie`](SetCookie::to_set_cookie) turns each set attribute into one
/// of these and joins their [`Display`](fmt::Display) with `"; "`. Their names
/// come from the `attr_name` constants the parser also matches, so the wire form
/// has a single source of truth. Boolean flags are presence-only: `HttpOnly` and
/// `Secure` render bare, with no `=value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetCookieAttribute<'a> {
    HttpOnly,
    SameSite(SameSite),
    Secure,
    Path(&'a str),
    Domain(&'a str),
    MaxAge(u64),
}

impl fmt::Display for SetCookieAttribute<'_> {
    /// Render the attribute *without* a leading separator;
    /// [`to_set_cookie`](SetCookie::to_set_cookie) joins the pieces with `"; "`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::HttpOnly => f.write_str(attr_name::HTTP_ONLY),
            Self::SameSite(same_site) => {
                write!(f, "{}={}", attr_name::SAME_SITE, same_site.as_str())
            }
            Self::Secure => f.write_str(attr_name::SECURE),
            Self::Path(path) => write!(f, "{}={}", attr_name::PATH, path),
            Self::Domain(domain) => write!(f, "{}={}", attr_name::DOMAIN, domain),
            Self::MaxAge(seconds) => write!(f, "{}={}", attr_name::MAX_AGE, seconds),
        }
    }
}

impl TryFrom<SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    /// Render the **`Set-Cookie`** form (via
    /// [`to_set_cookie`](SetCookie::to_set_cookie)) into a `HeaderValue`. The
    /// managed encodings are always visible-ASCII and never fail; only
    /// [`Raw`](ValueEncoding::Raw), where the caller owns wire-correctness, can
    /// produce bytes a header value rejects. For the request `Cookie:` form,
    /// build from [`to_request_pair`](SetCookie::to_request_pair).
    fn try_from(cookie: SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_set_cookie())
    }
}

impl TryFrom<&SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    fn try_from(cookie: &SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_set_cookie())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- rendering --------------------------------------------------------

    #[test]
    fn builder_attribute_order_is_fixed() {
        assert_eq!(SetCookie::new("n", "v").to_set_cookie(), "n=v");
        assert_eq!(
            SetCookie::new("n", "v").http_only().to_set_cookie(),
            "n=v; HttpOnly"
        );
        // Builder-call order is irrelevant; emission order is fixed.
        assert_eq!(
            SetCookie::new("n", "v")
                .max_age(60)
                .domain("example.test")
                .path("/app")
                .secure()
                .same_site(SameSite::None)
                .http_only()
                .to_set_cookie(),
            "n=v; HttpOnly; SameSite=None; Secure; Path=/app; Domain=example.test; Max-Age=60"
        );
        // A flag never called is simply absent.
        assert_eq!(
            SetCookie::new("n", "v")
                .same_site(SameSite::Lax)
                .to_set_cookie(),
            "n=v; SameSite=Lax"
        );
    }

    #[test]
    fn builder_max_age_is_u64_without_saturation() {
        assert!(SetCookie::new("n", "v")
            .max_age(u64::MAX)
            .to_set_cookie()
            .ends_with("; Max-Age=18446744073709551615"));
        assert!(SetCookie::new("n", "v")
            .max_age(0)
            .to_set_cookie()
            .ends_with("; Max-Age=0"));
    }

    #[test]
    fn hardened_session_cookie_shape() {
        // The shape an auth consumer composes (Percent encoding, full flags).
        let c = SetCookie::new("SID", "deadbeef")
            .with_encoding(ValueEncoding::Percent)
            .http_only()
            .same_site(SameSite::Strict)
            .secure()
            .path("/")
            .max_age(3600)
            .to_set_cookie();
        assert_eq!(
            c,
            "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
        );
    }

    #[test]
    fn with_attributes_applies_a_prebuilt_set() {
        // A hardened policy built once, attached to a kernel.
        let hardened = CookieAttributes::default()
            .http_only()
            .secure()
            .same_site(SameSite::Strict)
            .path("/")
            .max_age(3600);
        let c = Cookie::new("SID", "deadbeef")
            .with_encoding(ValueEncoding::Percent)
            .with_attributes(hardened);
        assert_eq!(
            c.to_set_cookie(),
            "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
        );
        // The (Cookie, CookieAttributes) tuple conversion is the same pairing.
        let parts: SetCookie<'_> =
            (Cookie::new("n", "v"), CookieAttributes::default().secure()).into();
        assert_eq!(parts.to_set_cookie(), "n=v; Secure");
    }

    #[test]
    fn set_cookie_attributes_are_typed_and_in_canonical_order() {
        let c = SetCookie::new("n", "v")
            .max_age(60)
            .domain("example.test")
            .path("/app")
            .secure()
            .same_site(SameSite::Lax)
            .http_only();
        // Builder-call order is irrelevant; the typed list is canonically ordered.
        assert_eq!(
            c.set_cookie_attributes(),
            vec![
                SetCookieAttribute::HttpOnly,
                SetCookieAttribute::SameSite(SameSite::Lax),
                SetCookieAttribute::Secure,
                SetCookieAttribute::Path("/app"),
                SetCookieAttribute::Domain("example.test"),
                SetCookieAttribute::MaxAge(60),
            ]
        );
        // A bare cookie has none.
        assert!(SetCookie::new("n", "v").set_cookie_attributes().is_empty());
    }

    #[test]
    fn set_cookie_attribute_renders_without_a_leading_separator() {
        assert_eq!(SetCookieAttribute::HttpOnly.to_string(), "HttpOnly");
        assert_eq!(SetCookieAttribute::Secure.to_string(), "Secure");
        assert_eq!(
            SetCookieAttribute::SameSite(SameSite::Strict).to_string(),
            "SameSite=Strict"
        );
        assert_eq!(SetCookieAttribute::Path("/").to_string(), "Path=/");
        assert_eq!(
            SetCookieAttribute::Domain("a.test").to_string(),
            "Domain=a.test"
        );
        assert_eq!(SetCookieAttribute::MaxAge(0).to_string(), "Max-Age=0");
    }

    // ---- accessors + transforms ------------------------------------------

    #[test]
    fn accessors_delegate_to_the_kernel_and_flags_are_bool() {
        let c = SetCookie::new("SID", "deadbeef").with_encoding(ValueEncoding::Percent);
        assert_eq!(c.name(), "SID");
        assert_eq!(c.value(), "deadbeef");
        assert_eq!(c.encoding(), ValueEncoding::Percent);
        // Flags are plain bool fields on the attributes — false on a fresh cookie.
        assert!(!c.attributes().http_only);
        assert!(!c.attributes().secure);
    }

    #[test]
    fn cookie_and_into_cookie_recover_the_kernel() {
        let sc = SetCookie::new("n", "v").path("/x").secure();
        // The borrowed view ignores the attributes.
        assert_eq!(sc.cookie().name(), "n");
        assert_eq!(sc.cookie().to_request_pair(), "n=v");
        // The attributes are readable as fields.
        assert!(sc.attributes().secure);
        assert_eq!(sc.attributes().path.map(|v| v.as_str()), Some("/x"));
        // Owned demotion drops the attributes; the request pair carries none.
        assert_eq!(sc.into_cookie().to_request_pair(), "n=v");
    }

    #[test]
    fn into_attributes_takes_the_attribute_set() {
        let attrs = SetCookie::new("n", "v")
            .secure()
            .max_age(60)
            .into_attributes();
        assert!(attrs.secure);
        assert_eq!(attrs.max_age, Some(60));
    }

    // ---- SetCookie -> HeaderValue ----------------------------------------

    #[test]
    fn try_into_header_value_is_byte_pinned() {
        // The exact bytes the auth consumer pins (its hardened-session test).
        let hv = http::HeaderValue::try_from(
            SetCookie::new("SID", "deadbeef")
                .with_encoding(ValueEncoding::Percent)
                .http_only()
                .same_site(SameSite::Strict)
                .secure()
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
    fn try_into_header_value_matches_to_set_cookie() {
        let c = SetCookie::new("n", "v").http_only().max_age(60);
        let via_ref = http::HeaderValue::try_from(&c).unwrap();
        let via_owned = http::HeaderValue::try_from(c.clone()).unwrap();
        assert_eq!(via_ref.to_str().unwrap(), c.to_set_cookie());
        assert_eq!(via_owned, via_ref);
    }

    #[test]
    fn try_into_header_value_rejects_raw_injection() {
        // Raw hands wire-correctness to the caller, so a CR/LF smuggle is caught
        // at the header boundary rather than silently emitted.
        let c = SetCookie::new("n", "x\r\nSet-Cookie: evil=1").with_encoding(ValueEncoding::Raw);
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
                let c = SetCookie::new("n", v).with_encoding(enc);
                let hv = http::HeaderValue::try_from(&c)
                    .unwrap_or_else(|e| panic!("managed {enc:?} of {v:?} must form a header: {e}"));
                assert_eq!(hv.to_str().unwrap(), c.to_set_cookie());
            }
        }
    }

    // ---- parse (Set-Cookie -> SetCookie) ---------------------------------

    #[test]
    fn parse_round_trips_a_built_set_cookie() {
        let wire = SetCookie::new("SID", "deadbeef")
            .with_encoding(ValueEncoding::Percent)
            .http_only()
            .same_site(SameSite::Strict)
            .secure()
            .path("/")
            .max_age(3600)
            .to_set_cookie();
        let parsed = SetCookie::parse(&wire).unwrap();
        assert_eq!(parsed.name(), "SID");
        assert_eq!(parsed.value(), "deadbeef");
        assert!(parsed.attributes().http_only && parsed.attributes().secure);
        assert_eq!(parsed.attributes().same_site, Some(SameSite::Strict));
        assert_eq!(parsed.attributes().path.map(|v| v.as_str()), Some("/"));
        assert_eq!(parsed.attributes().max_age, Some(3600));
        assert_eq!(parsed.attributes().domain, None);
        // Re-render is byte-equal (deadbeef is octet-clean).
        assert_eq!(parsed.to_set_cookie(), wire);
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
        assert!(p.attributes().secure && p.attributes().http_only);
        assert_eq!(p.attributes().same_site, Some(SameSite::Lax));
        assert_eq!(p.attributes().path.map(|v| v.as_str()), Some("/x"));
        assert_eq!(p.attributes().max_age, Some(60));
    }

    #[test]
    fn parse_strict_rejects_unknown_default_ignores() {
        // Strict (opt-in): an unrecognised attribute (`Priority`) rejects it.
        assert!(SetCookie::parse_strict("SID=x; Priority=High; Max-Age=60").is_none());
        // Default (RFC §5.2): the unknown attribute is ignored and the cookie survives.
        let p = SetCookie::parse("SID=x; Priority=High; Max-Age=60").unwrap();
        assert_eq!(p.value(), "x");
        assert_eq!(p.attributes().max_age, Some(60));
    }

    #[test]
    fn parse_recognises_expires_without_acting_on_it() {
        // `Expires` is a known attribute (not "unknown"), so strict keeps the
        // cookie; its value is not acted on yet (date handling is a follow-up).
        let p =
            SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=60").unwrap();
        assert_eq!(p.value(), "x");
        assert_eq!(p.attributes().max_age, Some(60));
        let no_max = SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT").unwrap();
        assert_eq!(no_max.attributes().max_age, None);
    }

    #[test]
    fn parse_strict_tolerates_empty_and_trailing_semicolons() {
        // A stray or trailing `;` is not an "unknown attribute" — strict keeps it.
        assert_eq!(SetCookie::parse("SID=x;").unwrap().value(), "x");
        let p = SetCookie::parse("SID=x; ; Secure").unwrap();
        assert_eq!(p.value(), "x");
        assert!(p.attributes().secure);
    }

    #[test]
    fn parse_skips_malformed_attributes_but_keeps_the_cookie() {
        let p = SetCookie::parse("SID=x; Max-Age=banana; SameSite=Bogus; HttpOnly").unwrap();
        assert!(p.attributes().http_only);
        assert_eq!(p.attributes().max_age, None); // non-numeric dropped
        assert_eq!(p.attributes().same_site, None); // unrecognised SameSite dropped
        assert_eq!(p.value(), "x"); // cookie survives
    }

    #[test]
    fn parse_max_age_u64_and_negative() {
        assert_eq!(
            SetCookie::parse("n=v; Max-Age=18446744073709551615")
                .unwrap()
                .attributes()
                .max_age,
            Some(u64::MAX)
        );
        assert_eq!(
            SetCookie::parse("n=v; Max-Age=-1")
                .unwrap()
                .attributes()
                .max_age,
            None
        );
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
        assert_eq!(p.attributes().path.map(|v| v.as_str()), Some("/x"));
    }
}
