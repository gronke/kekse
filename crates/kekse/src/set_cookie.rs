//! The response [`SetCookie`] — a [`Cookie`] kernel plus [`CookieAttributes`] —
//! its `Set-Cookie` parse and serialize, and the conversion straight into an
//! `http::HeaderValue`.

use std::borrow::Cow;
use std::fmt;

use rfc_6265::OffsetDateTime;
use rfc_6265::date::{format_imf_fixdate, parse_cookie_date, parse_imf_fixdate};

use crate::attributes::{CookieAttributes, Domain, Path};
use crate::cookie::Cookie;
use crate::encoding::{ValueEncoding, decode_cookie_value};
use crate::grammar::is_ws_char;
use crate::same_site::SameSite;
use crate::wire::split_checked_pair;

/// A `Set-Cookie:` response cookie: a [`Cookie`] kernel (name, value, wire
/// encoding) plus [`CookieAttributes`] (`HttpOnly`, `SameSite`, `Secure`,
/// `Path`, `Domain`, `Expires`, `Max-Age`). A `Set-Cookie` line is *fully
/// observed*, so the
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
/// order — `HttpOnly`, `SameSite`, `Secure`, `Path`, `Domain`, `Expires`,
/// `Max-Age` — each only when set. The builder does **not** validate the name (check
/// [`is_cookie_name`](crate::is_cookie_name) at the call site if it is
/// untrusted); [`parse`](SetCookie::parse) does.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    /// (`Strict`/`Lax`/`None`), `Path`, `Domain`, `Max-Age` (a `u64`; a negative
    /// or non-numeric delta is dropped), and `Expires` (the lenient RFC 6265
    /// §5.1.1 cookie-date here; [`parse_strict`](SetCookie::parse_strict) takes
    /// only the RFC 7231 IMF-fixdate — an unparseable date is dropped, cookie
    /// kept). Returns
    /// `None` when there is no usable pair — no `=`, an empty or non-token name,
    /// or a value outside the accepted set / with escapes that are not valid
    /// UTF-8. Never panics.
    pub fn parse(header_value: &'a str) -> Option<Self> {
        Self::parse_with(header_value, false)
    }

    /// Like [`parse`](SetCookie::parse) but **strict**: an unrecognised attribute — or a
    /// **duplicate** of any attribute — rejects the whole cookie (`None`) instead of being ignored.
    /// A tripwire for cookies you minted yourself, where an attribute you did not emit (or emitted
    /// twice) signals something is wrong. A malformed *known* attribute (e.g. a non-numeric
    /// `Max-Age`) is dropped, not fatal, in both modes; lenient [`parse`](SetCookie::parse)
    /// tolerates duplicates (last-wins).
    ///
    /// Unlike [`parse_pairs_strict`](crate::parse_pairs_strict), strict mode does **not** tighten
    /// the cookie-*value* pipeline: one wrapping quote pair is still stripped and raw `SP`/`HTAB`
    /// inside the value is still accepted, exactly as in [`parse`](SetCookie::parse). This is
    /// deliberate — every managed [`ValueEncoding`], including
    /// [`Quoted`](ValueEncoding::Quoted) (which carries whitespace raw inside its quotes), must
    /// round-trip through the strict reader. Response-side strictness polices the *attributes*,
    /// not the value's escaping.
    pub fn parse_strict(header_value: &'a str) -> Option<Self> {
        Self::parse_with(header_value, true)
    }

    fn parse_with(header_value: &'a str, strict: bool) -> Option<Self> {
        // The leading segment is the `name=value` pair; everything after the first `;`
        // is attributes. `str::split` always yields the leading segment, even for "".
        let mut segments = header_value.split(';');
        let (name, raw_value) = split_checked_pair(segments.next()?.as_bytes())?;
        // The value pipeline is deliberately the lenient one in BOTH modes — see
        // `parse_strict`'s docs: every managed encoding must round-trip through it.
        let Some(value) = decode_cookie_value(raw_value, true) else {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                cookie = %name,
                "rejecting Set-Cookie: value carries a byte outside the accepted \
                 set or percent-escapes that are not valid UTF-8"
            );
            return None;
        };
        let mut set_cookie =
            Self::from_parts(Cookie::new(name, value), CookieAttributes::default());
        // Bits of recognised attributes already seen, so strict mode can reject a duplicate
        // (e.g. two `Domain=`). Lenient keeps last-wins, consistent across every attribute.
        let mut seen: u8 = 0;
        for piece in segments {
            let (attr, val) = match piece.split_once('=') {
                Some((a, v)) => (a.trim_matches(is_ws_char), v.trim_matches(is_ws_char)),
                None => (piece.trim_matches(is_ws_char), ""),
            };
            if attr.is_empty() {
                continue; // a stray or trailing `;` — not an attribute
            }
            let Some(known) = KnownAttribute::recognize(attr) else {
                if strict {
                    // Strict (opt-in): an unrecognised attribute rejects the cookie.
                    return None;
                }
                // Default: an unrecognised attribute is ignored (RFC 6265 §5.2).
                continue;
            };
            if strict && seen & known.bit() != 0 {
                return None; // strict: a repeated attribute rejects the whole cookie
            }
            seen |= known.bit();
            let attributes = &mut set_cookie.attributes;
            match known {
                KnownAttribute::HttpOnly => attributes.http_only = true,
                KnownAttribute::Secure => attributes.secure = true,
                // `.ok()` drops an unrecognised token (keeping the cookie), same as
                // a malformed Max-Age — see `SameSite`'s case-insensitive `FromStr`.
                KnownAttribute::SameSite => {
                    attributes.same_site = noted(val.parse::<SameSite>().ok(), known, val);
                }
                // An invalid value (control byte, `;`, non-ASCII) is dropped like a
                // malformed Max-Age — the cookie is kept, the attribute discarded.
                KnownAttribute::Path => attributes.path = noted(Path::new(val), known, val),
                KnownAttribute::Domain => attributes.domain = noted(Domain::new(val), known, val),
                KnownAttribute::MaxAge => {
                    attributes.max_age = noted(val.parse::<u64>().ok(), known, val);
                }
                // RFC 6265 §5.1.1 (lenient) / RFC 7231 IMF-fixdate (strict). An
                // unparseable date is dropped like any malformed known attribute —
                // the cookie survives.
                KnownAttribute::Expires => {
                    let parsed = if strict {
                        parse_imf_fixdate(val)
                    } else {
                        parse_cookie_date(val)
                    };
                    attributes.expires = noted(parsed, known, val);
                }
            }
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

    /// Set the `Expires` attribute — an absolute expiry instant, rendered as the
    /// RFC 7231 IMF-fixdate (always in GMT). Independent of
    /// [`max_age`](SetCookie::max_age); a client given both lets `Max-Age` win
    /// (RFC 6265 §5.3), but that is the client's concern, not the codec's.
    #[must_use]
    pub fn expires(mut self, when: OffsetDateTime) -> Self {
        self.attributes.expires = Some(when);
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
    /// `Domain`, `Expires`, `Max-Age` (each only when set; a flag only when
    /// `true`).
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
            a.expires.map(SetCookieAttribute::Expires),
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

/// A recognised `Set-Cookie` attribute — the parser's dispatch unit. Recognition
/// ([`recognize`](KnownAttribute::recognize)), strict duplicate accounting
/// ([`bit`](KnownAttribute::bit)), and application (the `match` in `parse_with`)
/// are separate phases: the compiler forces [`name`](KnownAttribute::name) and
/// the applying `match` to cover every variant, and the duplicate bit derives
/// from the discriminant, so none of the three can drift the way a hand-numbered
/// bitmask across an `if`/`else` chain could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KnownAttribute {
    HttpOnly,
    Secure,
    SameSite,
    Path,
    Domain,
    MaxAge,
    Expires,
}

impl KnownAttribute {
    /// Every recognisable attribute. [`recognize`](KnownAttribute::recognize)
    /// scans this list, so a variant missing here would be unreachable from the
    /// wire — the recognition test walks it against every canonical name.
    const ALL: [Self; 7] = [
        Self::HttpOnly,
        Self::Secure,
        Self::SameSite,
        Self::Path,
        Self::Domain,
        Self::MaxAge,
        Self::Expires,
    ];

    /// The canonical wire name — the same `attr_name` constant the serializer
    /// renders, so reader and writer share one spelling per attribute.
    const fn name(self) -> &'static str {
        match self {
            Self::HttpOnly => attr_name::HTTP_ONLY,
            Self::Secure => attr_name::SECURE,
            Self::SameSite => attr_name::SAME_SITE,
            Self::Path => attr_name::PATH,
            Self::Domain => attr_name::DOMAIN,
            Self::MaxAge => attr_name::MAX_AGE,
            Self::Expires => attr_name::EXPIRES,
        }
    }

    /// Match a wire attribute name, ASCII-case-insensitively (RFC 6265 §5.2).
    fn recognize(attr: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|known| attr.eq_ignore_ascii_case(known.name()))
    }

    /// This attribute's bit in the strict-mode duplicate mask, derived from the
    /// discriminant (7 variants fit a `u8`) — collision-free by construction.
    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// Pass a known attribute's parse result through, debug-logging the fail-soft
/// drop when it is `None` — the malformed-known-attribute skip the crate docs
/// promise, observable like the readers' pair-level skips. The cookie is kept
/// either way; only the attribute is lost (and in lenient last-wins, an earlier
/// good occurrence is still overwritten by a later malformed one).
fn noted<T>(parsed: Option<T>, attribute: KnownAttribute, raw_value: &str) -> Option<T> {
    #[cfg(feature = "tracing")]
    if parsed.is_none() {
        tracing::debug!(
            attribute = attribute.name(),
            value = %raw_value.escape_debug(),
            "dropping a malformed known attribute; the cookie is kept"
        );
    }
    #[cfg(not(feature = "tracing"))]
    let _ = (attribute, raw_value);
    parsed
}

/// One rendered `Set-Cookie` attribute — the typed unit the serializer emits.
///
/// [`to_set_cookie`](SetCookie::to_set_cookie) turns each set attribute into one
/// of these and joins their [`Display`](fmt::Display) with `"; "`. Their names
/// come from the `attr_name` constants the parser also matches, so the wire form
/// has a single source of truth. Boolean flags are presence-only: `HttpOnly` and
/// `Secure` render bare, with no `=value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SetCookieAttribute<'a> {
    HttpOnly,
    SameSite(SameSite),
    Secure,
    Path(&'a str),
    Domain(&'a str),
    Expires(OffsetDateTime),
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
            Self::Expires(when) => {
                write!(f, "{}={}", attr_name::EXPIRES, format_imf_fixdate(when))
            }
            Self::MaxAge(seconds) => write!(f, "{}={}", attr_name::MAX_AGE, seconds),
        }
    }
}

impl TryFrom<SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    /// Render the **`Set-Cookie`** form (via
    /// [`to_set_cookie`](SetCookie::to_set_cookie)) into a `HeaderValue`. For the
    /// request `Cookie:` form, build from
    /// [`to_request_pair`](SetCookie::to_request_pair).
    ///
    /// # Errors
    ///
    /// Only under [`Raw`](ValueEncoding::Raw), where the caller owns
    /// wire-correctness, and only for a byte no header value may hold (CR, LF,
    /// NUL, or another control). The managed encodings are always header-safe and
    /// never error here.
    fn try_from(cookie: SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_set_cookie())
    }
}

impl TryFrom<&SetCookie<'_>> for http::HeaderValue {
    type Error = http::header::InvalidHeaderValue;

    /// Borrowing counterpart to the owned `SetCookie` → `HeaderValue` conversion
    /// — renders the `Set-Cookie` form without consuming the cookie.
    ///
    /// # Errors
    ///
    /// Same as the owned conversion: only [`Raw`](ValueEncoding::Raw) with a
    /// header-unsafe byte (CR, LF, NUL, or another control) errors.
    fn try_from(cookie: &SetCookie<'_>) -> Result<Self, Self::Error> {
        http::HeaderValue::try_from(cookie.to_set_cookie())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the KnownAttribute dispatch table ---------------------------------

    #[test]
    fn known_attribute_bits_are_distinct_and_recognition_is_case_insensitive() {
        let mut mask = 0u8;
        for known in KnownAttribute::ALL {
            // Every bit is fresh — the mask can address each attribute independently.
            assert_eq!(mask & known.bit(), 0, "{known:?} bit collides");
            mask |= known.bit();
            // The canonical name and its case variants all recognize back to the variant.
            assert_eq!(KnownAttribute::recognize(known.name()), Some(known));
            assert_eq!(
                KnownAttribute::recognize(&known.name().to_ascii_uppercase()),
                Some(known)
            );
            assert_eq!(
                KnownAttribute::recognize(&known.name().to_ascii_lowercase()),
                Some(known)
            );
        }
        // An attribute this version does not model stays unrecognised.
        assert_eq!(KnownAttribute::recognize("Partitioned"), None);
        assert_eq!(KnownAttribute::recognize(""), None);
    }

    #[test]
    fn strict_rejects_a_duplicate_of_every_attribute() {
        // One duplicated occurrence per recognisable attribute — each must reject in
        // strict and keep last-wins in lenient.
        for (known, dup) in [
            (KnownAttribute::HttpOnly, "HttpOnly; HttpOnly"),
            (KnownAttribute::Secure, "Secure; Secure"),
            (KnownAttribute::SameSite, "SameSite=Lax; SameSite=Strict"),
            (KnownAttribute::Path, "Path=/a; Path=/b"),
            (KnownAttribute::Domain, "Domain=a.test; Domain=b.test"),
            (KnownAttribute::MaxAge, "Max-Age=1; Max-Age=2"),
            (
                KnownAttribute::Expires,
                "Expires=Sun, 06 Nov 1994 08:49:37 GMT; Expires=Mon, 07 Nov 1994 08:49:37 GMT",
            ),
        ] {
            let header = format!("n=v; {dup}");
            assert!(
                SetCookie::parse_strict(&header).is_none(),
                "strict must reject the duplicated {:?} in {header:?}",
                known.name()
            );
            assert!(
                SetCookie::parse(&header).is_some(),
                "lenient must keep the cookie for {header:?}"
            );
        }
        // The ALL table drives the loop above; make sure the loop covered it fully.
        assert_eq!(KnownAttribute::ALL.len(), 7);
    }

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
        assert!(
            SetCookie::new("n", "v")
                .max_age(u64::MAX)
                .to_set_cookie()
                .ends_with("; Max-Age=18446744073709551615")
        );
        assert!(
            SetCookie::new("n", "v")
                .max_age(0)
                .to_set_cookie()
                .ends_with("; Max-Age=0")
        );
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
    fn raw_lets_non_ascii_through_construction_but_not_as_text() {
        // Raw hands wire-correctness to the caller. Non-ASCII UTF-8 bytes (>= 0x80)
        // are obs-text: HeaderValue *construction* accepts them — only CR/LF/NUL and
        // other controls are refused — so a Raw "café" forms a header value, but one
        // whose bytes are not visible-ASCII text, so `to_str()` then fails.
        let raw = http::HeaderValue::try_from(
            SetCookie::new("n", "café").with_encoding(ValueEncoding::Raw),
        )
        .expect("obs-text bytes are valid at header construction");
        assert!(
            raw.to_str().is_err(),
            "the header carries raw non-ASCII bytes, not visible-ASCII text"
        );
        // A managed encoding escapes the non-ASCII losslessly, so it stays header text.
        let managed = http::HeaderValue::try_from(
            SetCookie::new("n", "café").with_encoding(ValueEncoding::Percent),
        )
        .unwrap();
        assert_eq!(managed.to_str().unwrap(), "n=caf%C3%A9");
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
    fn parse_reads_expires_as_a_date() {
        use time::macros::datetime;
        // `Expires` is a known attribute, parsed into an `OffsetDateTime` (lenient
        // RFC 6265 §5.1.1 here); the cookie and a coexisting `Max-Age` are kept.
        let p =
            SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=60").unwrap();
        assert_eq!(p.value(), "x");
        assert_eq!(
            p.attributes().expires,
            Some(datetime!(2021-06-09 10:18:14 UTC))
        );
        assert_eq!(p.attributes().max_age, Some(60));
        // An unparseable date is dropped like any malformed known attribute; the
        // cookie survives.
        let bad = SetCookie::parse("SID=x; Expires=not-a-date").unwrap();
        assert_eq!(bad.attributes().expires, None);
        assert_eq!(bad.value(), "x");
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
