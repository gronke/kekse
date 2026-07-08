//! The response [`SetCookie`] — a [`Cookie`] kernel plus [`CookieAttributes`] —
//! its `Set-Cookie` parse and serialize, and the conversion straight into an
//! `http::HeaderValue`.

use std::borrow::Cow;
use std::fmt;

use rfc_6265::OffsetDateTime;
use rfc_6265::date::{ImfFixdate, parse_cookie_date, parse_imf_fixdate};
use rfc_6265::grammar::{has_host_prefix, has_secure_prefix};

use crate::attributes::{CookieAttributes, Domain, Path};
use crate::cookie::Cookie;
use crate::encoding::{ValueEncoding, decode_cookie_value};
use crate::grammar::is_ws_char;
use crate::report::{PairIssue, Reported};
use crate::same_site::SameSite;
use crate::wire::split_checked_pair;

/// A `Set-Cookie:` response cookie: a [`Cookie`] kernel (name, value, wire
/// encoding) plus [`CookieAttributes`] (`HttpOnly`, `SameSite`, `Secure`,
/// `Partitioned`, `Path`, `Domain`, `Expires`, `Max-Age`). A `Set-Cookie` line
/// is *fully observed*, so the
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
/// order — `HttpOnly`, `SameSite`, `Secure`, `Partitioned`, `Path`, `Domain`,
/// `Expires`, `Max-Age` — each only when set. The builder does **not** validate the name (check
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

    /// Parse one `Set-Cookie` header value (RFC 6265 §5.2): `Ok` carries the
    /// cookie plus every recovered deviation as a [`SetCookieIssue`], in wire
    /// order; `Err` is the single fatal issue — without a usable `name=value`
    /// pair there is no cookie to salvage. Lenient grading: an **unrecognised
    /// attribute is ignored** and reported, per §5.2 — so a modern attribute
    /// this version does not model (`Priority`, …) never costs you the cookie,
    /// and never vanishes without a trace. A duplicate keeps
    /// last-wins, a malformed known value is dropped (§5.2.2), a valued flag
    /// still sets — each recovered piece lands in `issues`, and
    /// [`is_clean`](Reported::is_clean) is the opt-in fail-hard gate. After
    /// the attribute loop, the cross-field constraints (the RFC 6265bis
    /// `__Host-`/`__Secure-` name prefixes and CHIPS' `Partitioned`/`Secure`
    /// pairing) are checked the same way: a violation is a
    /// [`ConstraintViolation`](SetCookieIssue::ConstraintViolation) issue, the
    /// cookie kept as written.
    ///
    /// Splits on the first `;` into the `name=value` pair and the attribute list,
    /// then the pair on its first `=`. The name must be a cookie-name token; the
    /// value runs through the same lenient pipeline as
    /// [`parse_pairs`](crate::parse_pairs) (one wrapping quote pair stripped,
    /// cookie-octets plus whitespace, percent-decoded). Attributes are matched
    /// ASCII-case-insensitively: `HttpOnly`, `Secure`, `Partitioned`, `SameSite`
    /// (`Strict`/`Lax`/`None`), `Path`, `Domain`, `Max-Age` (a `u64`; a negative
    /// or non-numeric delta is dropped), and `Expires` (the lenient RFC 6265
    /// §5.1.1 cookie-date here; [`parse_strict`](SetCookie::parse_strict) takes
    /// only the RFC 7231 IMF-fixdate). Never panics.
    ///
    /// # Errors
    ///
    /// The fatal issue: no `=`, an empty or non-token name, or a value outside
    /// the accepted set / with escapes that are not valid UTF-8.
    ///
    /// ```
    /// use kekse::SetCookie;
    ///
    /// let parsed = SetCookie::parse("SID=x; HttpOnly; Priority=High")?;
    /// assert_eq!(parsed.value.name(), "SID");
    /// assert!(parsed.value.attributes().http_only);
    /// assert_eq!(parsed.issues.len(), 1); // the unmodeled attribute, witnessed
    /// # Ok::<(), kekse::PairIssue<'static>>(())
    /// ```
    pub fn parse(
        header_value: &'a str,
    ) -> Result<Reported<Self, SetCookieIssue<'a>>, PairIssue<'a>> {
        let mut issues = Vec::new();
        let value = Self::parse_with(header_value, false, &mut issues)?;
        Ok(Reported { value, issues })
    }

    /// Like [`parse`](SetCookie::parse) but with **strict** grading: the same
    /// interface, the same salvage, the same single fatal case — only the
    /// grading narrows. `Expires` must be the RFC 7231 IMF-fixdate here; every
    /// lenient-only RFC 6265 §5.1.1 cookie-date shape is dropped from the
    /// salvage and reported as an
    /// [`InvalidAttributeValue`](SetCookieIssue::InvalidAttributeValue).
    /// Everything strict salvages, [`parse`](SetCookie::parse) salvages too —
    /// strict never accepts more, and never rejects without a witness.
    ///
    /// The tripwire for cookies you minted yourself is the report: your own
    /// emitter produces a clean parse, so gate on
    /// [`is_clean`](Reported::is_clean) (or [`Reported::into_result`]) and any
    /// attribute you did not emit — unknown, duplicated, malformed, or a
    /// valued flag — fails the gate with the evidence in hand.
    ///
    /// Unlike [`parse_pairs_strict`](crate::parse_pairs_strict), strict grading does **not**
    /// tighten the cookie-*value* pipeline: one wrapping quote pair is still stripped and raw
    /// `SP`/`HTAB` inside the value is still accepted, exactly as in [`parse`](SetCookie::parse).
    /// This is deliberate — every managed [`ValueEncoding`], including
    /// [`Quoted`](ValueEncoding::Quoted) (which carries whitespace raw inside its quotes), must
    /// round-trip through the strict reader. Response-side strictness polices the *attributes*,
    /// not the value's escaping.
    ///
    /// # Errors
    ///
    /// Exactly [`parse`](SetCookie::parse)'s: the [`PairIssue`] of an
    /// unusable `name=value` pair. Fatality is grading-independent.
    ///
    /// ```
    /// use kekse::{KnownAttribute, SetCookie, SetCookieIssue};
    ///
    /// // An RFC 850 date parses under lenient grading…
    /// let wire = "SID=x; Expires=Sunday, 06-Nov-94 08:49:37 GMT";
    /// assert!(SetCookie::parse(wire)?.is_clean());
    ///
    /// // …strict grading salvages the cookie, drops the date, and says so.
    /// let strict = SetCookie::parse_strict(wire)?;
    /// assert_eq!(strict.value.attributes().expires, None);
    /// assert!(matches!(
    ///     strict.issues[..],
    ///     [SetCookieIssue::InvalidAttributeValue {
    ///         attribute: KnownAttribute::Expires,
    ///         ..
    ///     }]
    /// ));
    /// # Ok::<(), kekse::PairIssue<'static>>(())
    /// ```
    pub fn parse_strict(
        header_value: &'a str,
    ) -> Result<Reported<Self, SetCookieIssue<'a>>, PairIssue<'a>> {
        let mut issues = Vec::new();
        let value = Self::parse_with(header_value, true, &mut issues)?;
        Ok(Reported { value, issues })
    }

    fn parse_with(
        header_value: &'a str,
        strict: bool,
        report: &mut Vec<SetCookieIssue<'a>>,
    ) -> Result<Self, PairIssue<'a>> {
        // The leading segment is the `name=value` pair; everything after the first `;`
        // is attributes. `str::split` always yields the leading segment, even for "".
        let mut segments = header_value.split(';');
        let (name, raw_value) = split_checked_pair(segments.next().unwrap_or_default().as_bytes())?;
        // The value pipeline is deliberately the lenient one in BOTH modes — see
        // `parse_strict`'s docs: every managed encoding must round-trip through it.
        let Some(value) = decode_cookie_value(raw_value, true) else {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                cookie = %name,
                "rejecting Set-Cookie: value carries a byte outside the accepted \
                 set or percent-escapes that are not valid UTF-8"
            );
            return Err(PairIssue::InvalidValue {
                name,
                value: raw_value,
            });
        };
        let mut set_cookie =
            Self::from_parts(Cookie::new(name, value), CookieAttributes::default());
        // Bits of recognised attributes already seen, so a repeat (e.g. two `Domain=`)
        // is recognised and reported. Last-wins among the occurrences that parse,
        // consistent across every attribute and both gradings.
        let mut seen: u16 = 0;
        for piece in segments {
            let (attr, val) = match piece.split_once('=') {
                Some((a, v)) => (a.trim_matches(is_ws_char), v.trim_matches(is_ws_char)),
                None => (piece.trim_matches(is_ws_char), ""),
            };
            if attr.is_empty() && val.is_empty() {
                continue; // a stray or trailing `;` — structural noise, not an attribute
            }
            // An empty name *carrying a value* (`; =V`) is not noise: it falls
            // through to `recognize`, which cannot match it, so the segment is
            // witnessed as an unknown attribute — the same stance the request
            // reader takes on a `=v` pair.
            let Some(known) = KnownAttribute::recognize(attr) else {
                // An unrecognised attribute is ignored (RFC 6265 §5.2) — logged
                // and reported, so a mistyped flag never vanishes without a
                // trace.
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    attribute = %attr.escape_debug(),
                    "ignoring an unrecognised attribute; the cookie is kept (RFC 6265 §5.2)"
                );
                report.push(SetCookieIssue::UnknownAttribute { name: attr });
                continue;
            };
            if seen & known.bit() != 0 {
                // Last-wins — logged and reported, since the overwrite is
                // invisible in the parsed result.
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    attribute = known.name(),
                    "duplicate attribute; the last occurrence that parses wins"
                );
                report.push(SetCookieIssue::DuplicateAttribute { attribute: known });
            }
            seen |= known.bit();
            let attributes = &mut set_cookie.attributes;
            match known {
                // The flags are presence-only: a value on them is not RFC 6265
                // shape, so it is reported — but the flag still sets, as ever.
                KnownAttribute::HttpOnly => {
                    if !val.is_empty() {
                        report.push(SetCookieIssue::FlagWithValue {
                            attribute: known,
                            value: val,
                        });
                    }
                    attributes.http_only = true;
                }
                KnownAttribute::Secure => {
                    if !val.is_empty() {
                        report.push(SetCookieIssue::FlagWithValue {
                            attribute: known,
                            value: val,
                        });
                    }
                    attributes.secure = true;
                }
                KnownAttribute::Partitioned => {
                    if !val.is_empty() {
                        report.push(SetCookieIssue::FlagWithValue {
                            attribute: known,
                            value: val,
                        });
                    }
                    attributes.partitioned = true;
                }
                // `.ok()` drops an unrecognised token (keeping the cookie), same as
                // a malformed Max-Age — see `SameSite`'s case-insensitive `FromStr`.
                KnownAttribute::SameSite => {
                    if let Some(v) = noted(val.parse::<SameSite>().ok(), known, val, report) {
                        attributes.same_site = Some(v);
                    }
                }
                // An invalid value (control byte, `;`, non-ASCII) is dropped like a
                // malformed Max-Age — the cookie is kept, the attribute discarded,
                // and an earlier valid occurrence survives (RFC 6265 §5.2.2:
                // "ignore the cookie-av", not the attribute).
                KnownAttribute::Path => {
                    if let Some(v) = noted(Path::new(val).ok(), known, val, report) {
                        attributes.path = Some(v);
                    }
                }
                KnownAttribute::Domain => {
                    if let Some(v) = noted(Domain::new(val).ok(), known, val, report) {
                        attributes.domain = Some(v);
                    }
                }
                KnownAttribute::MaxAge => {
                    if let Some(v) = noted(val.parse::<u64>().ok(), known, val, report) {
                        attributes.max_age = Some(v);
                    }
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
                    if let Some(v) = noted(parsed, known, val, report) {
                        attributes.expires = Some(v);
                    }
                }
            }
        }
        // With every attribute in hand, witness the cross-field constraints —
        // grading-independent, after all wire-order attribute issues.
        push_constraint_issues(name, &set_cookie.attributes, report);
        Ok(set_cookie)
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

    /// Add the `Partitioned` attribute (CHIPS) — a valueless presence flag
    /// (nullary). Reads back as `self.attributes().partitioned`. CHIPS requires
    /// `Secure` alongside it.
    #[must_use]
    pub fn partitioned(mut self) -> Self {
        self.attributes.partitioned = true;
        self
    }

    /// Set the `SameSite` attribute.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.attributes.same_site = Some(same_site);
        self
    }

    /// Set the `Path` attribute from a validated [`Path`](crate::Path) —
    /// [`Path::new`](crate::Path::new) is where an invalid value surfaces, so
    /// the chain itself cannot swallow one.
    #[must_use]
    pub fn path(mut self, path: Path<'a>) -> Self {
        self.attributes.path = Some(path);
        self
    }

    /// Set the `Domain` attribute from a validated [`Domain`](crate::Domain) —
    /// [`Domain::new`](crate::Domain::new) is where an invalid value surfaces,
    /// so the chain itself cannot swallow one. Omit for a host-only cookie.
    #[must_use]
    pub fn domain(mut self, domain: Domain<'a>) -> Self {
        self.attributes.domain = Some(domain);
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

    /// Every cross-field constraint this cookie violates — the RFC 6265bis
    /// §4.1.3 name-prefix rules and CHIPS' `Partitioned`/`Secure` pairing —
    /// empty when conformant. The very checker [`parse`](SetCookie::parse)
    /// runs after its attribute loop, exposed for cookies you build: the
    /// codec never enforces a [`CookieConstraint`], so this is the
    /// builder-side gate.
    ///
    /// ```
    /// use kekse::{CookieConstraint, Path, SetCookie, SetCookieIssue};
    ///
    /// let ok = SetCookie::new("__Host-SID", "x").secure().path(Path::new("/")?);
    /// assert!(ok.constraint_violations().is_empty());
    ///
    /// let violations = SetCookie::new("__Host-SID", "x").constraint_violations();
    /// assert!(matches!(
    ///     violations[..],
    ///     [
    ///         SetCookieIssue::ConstraintViolation {
    ///             constraint: CookieConstraint::HostPrefixWithoutSecure,
    ///             ..
    ///         },
    ///         SetCookieIssue::ConstraintViolation {
    ///             constraint: CookieConstraint::HostPrefixWithoutRootPath,
    ///             ..
    ///         },
    ///     ]
    /// ));
    /// # Ok::<(), kekse::InvalidPath<'static>>(())
    /// ```
    #[must_use]
    pub fn constraint_violations(&self) -> Vec<SetCookieIssue<'static>> {
        let mut violations = Vec::new();
        push_constraint_issues(self.cookie.name(), &self.attributes, &mut violations);
        violations
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
    /// attributes, in the fixed order `HttpOnly`, `SameSite`, `Secure`,
    /// `Partitioned`, `Path`, `Domain`, `Expires`, `Max-Age` (each only when
    /// set; a flag only when `true`).
    ///
    /// The pair and each rendered attribute are joined with `"; "` exactly once.
    /// Each attribute is a typed value that renders itself, and its name comes
    /// from the same constants the parser matches, so the separator and every
    /// attribute name live in a single place.
    pub fn to_set_cookie(&self) -> String {
        use std::fmt::Write as _;
        // One up-front reservation: the pair at its decoded size (a lower bound
        // of the encoded size, exact for clean values) plus every attribute at
        // its rendered upper bound.
        let attributes_len: usize = self
            .attributes_in_order()
            .map(|attribute| 2 + attribute.rendered_len_upper())
            .sum();
        let mut out = String::with_capacity(
            self.cookie.name().len() + 1 + self.cookie.value().len() + attributes_len,
        );
        self.cookie
            .write_pair_into(&mut out, self.cookie.encoding());
        for attribute in self.attributes_in_order() {
            out.push_str("; ");
            // Writing into a `String` cannot fail; only an (unreachable)
            // attribute-rendering error could surface here, matching the date
            // formatter's own panic-on-impossible stance.
            write!(out, "{attribute}")
                .expect("rendering a Set-Cookie attribute into a String is infallible");
        }
        out
    }

    /// The set response attributes as typed values, in the canonical `Set-Cookie`
    /// order, streamed without materializing a collection. A boolean flag appears
    /// only when `true`; an unset flag or absent attribute is omitted.
    fn attributes_in_order(&self) -> impl Iterator<Item = SetCookieAttribute<'a>> {
        let a = &self.attributes;
        [
            a.http_only.then_some(SetCookieAttribute::HttpOnly),
            a.same_site.map(SetCookieAttribute::SameSite),
            a.secure.then_some(SetCookieAttribute::Secure),
            a.partitioned.then_some(SetCookieAttribute::Partitioned),
            a.path.map(|p| SetCookieAttribute::Path(p.as_str())),
            a.domain.map(|d| SetCookieAttribute::Domain(d.as_str())),
            a.expires.map(SetCookieAttribute::Expires),
            a.max_age.map(SetCookieAttribute::MaxAge),
        ]
        .into_iter()
        .flatten()
    }

    /// [`attributes_in_order`](SetCookie::attributes_in_order), collected — the
    /// form the canonical-order unit test asserts against.
    #[cfg(test)]
    fn set_cookie_attributes(&self) -> Vec<SetCookieAttribute<'a>> {
        self.attributes_in_order().collect()
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
    pub const PARTITIONED: &str = "Partitioned";
    pub const SAME_SITE: &str = "SameSite";
    pub const PATH: &str = "Path";
    pub const DOMAIN: &str = "Domain";
    pub const MAX_AGE: &str = "Max-Age";
    pub const EXPIRES: &str = "Expires";
}

/// A recognised `Set-Cookie` attribute — the parser's dispatch unit, and the
/// attribute identity a [`SetCookieIssue`] names. Recognition (the private
/// `recognize`), strict duplicate accounting (`bit`), and application (the
/// `match` in `parse_with`) are separate phases: the compiler forces
/// [`name`](KnownAttribute::name) and the applying `match` to cover every
/// variant, and the duplicate bit derives from the discriminant, so none of the
/// three can drift the way a hand-numbered bitmask across an `if`/`else` chain
/// could.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KnownAttribute {
    /// The `HttpOnly` presence flag.
    HttpOnly,
    /// The `Secure` presence flag.
    Secure,
    /// The `SameSite` attribute.
    SameSite,
    /// The `Path` attribute.
    Path,
    /// The `Domain` attribute.
    Domain,
    /// The `Max-Age` attribute.
    MaxAge,
    /// The `Expires` attribute.
    Expires,
    /// The `Partitioned` presence flag (CHIPS).
    Partitioned,
}

impl KnownAttribute {
    /// Every recognisable attribute. [`recognize`](KnownAttribute::recognize)
    /// scans this list, so a variant missing here would be unreachable from the
    /// wire — the recognition test walks it against every canonical name.
    const ALL: [Self; 8] = [
        Self::HttpOnly,
        Self::Secure,
        Self::SameSite,
        Self::Path,
        Self::Domain,
        Self::MaxAge,
        Self::Expires,
        Self::Partitioned,
    ];

    /// The canonical wire name — the same `attr_name` constant the serializer
    /// renders, so reader and writer share one spelling per attribute.
    pub const fn name(self) -> &'static str {
        match self {
            Self::HttpOnly => attr_name::HTTP_ONLY,
            Self::Secure => attr_name::SECURE,
            Self::SameSite => attr_name::SAME_SITE,
            Self::Path => attr_name::PATH,
            Self::Domain => attr_name::DOMAIN,
            Self::MaxAge => attr_name::MAX_AGE,
            Self::Expires => attr_name::EXPIRES,
            Self::Partitioned => attr_name::PARTITIONED,
        }
    }

    /// Match a wire attribute name, ASCII-case-insensitively (RFC 6265 §5.2).
    fn recognize(attr: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|known| attr.eq_ignore_ascii_case(known.name()))
    }

    /// This attribute's bit in the duplicate mask, derived from the
    /// discriminant — collision-free by construction, and `u16` leaves
    /// headroom far past the current eight variants.
    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// Everything a `Set-Cookie` parse recovers from and reports, with the
/// offending wire slice — borrowed from the header value, never allocated.
///
/// Fills [`Reported::issues`] for [`SetCookie::parse`] /
/// [`SetCookie::parse_strict`]. Every variant is a *recovered* deviation —
/// nothing here is fatal; the one fatal case (no usable `name=value` pair) is
/// the readers' `Err`, a [`PairIssue`]. The grading decides only what counts
/// as a deviation (strict grades `Expires` against the IMF-fixdate alone);
/// the severity of an issue is always the caller's choice. The
/// [`Display`](fmt::Display) form escapes the wire slices, so a rendered issue
/// never carries a raw control byte (CR/LF, NUL, …).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SetCookieIssue<'a> {
    /// An attribute name this version does not model — a genuinely new
    /// attribute (`Priority`, …), a mistyped one (`HttpOnlyy`), two
    /// attributes fused by a forgotten `;`, or an empty name in front of a
    /// value (`; =v`). Ignored (RFC 6265 §5.2) and reported, in both
    /// gradings.
    #[non_exhaustive]
    UnknownAttribute {
        /// The unrecognised, OWS-trimmed attribute name.
        name: &'a str,
    },
    /// A repeated known attribute. Last-wins in both gradings — reported
    /// because the overwrite is invisible in the parsed result.
    #[non_exhaustive]
    DuplicateAttribute {
        /// The attribute that repeated.
        attribute: KnownAttribute,
    },
    /// A recognised attribute whose value did not parse under the grading in
    /// force (`Max-Age=banana`, an unparseable `Expires`, an invalid
    /// `Path`/`Domain`/`SameSite`). The attribute is dropped, the cookie
    /// kept.
    #[non_exhaustive]
    InvalidAttributeValue {
        /// The attribute whose value was refused.
        attribute: KnownAttribute,
        /// The OWS-trimmed value that did not parse.
        value: &'a str,
    },
    /// A value on a presence-only flag (`Secure=1`, `HttpOnly=x`). The flag is
    /// set and the value discarded, as ever — reported because that discard is
    /// otherwise invisible.
    #[non_exhaustive]
    FlagWithValue {
        /// The flag that carried a value.
        attribute: KnownAttribute,
        /// The discarded value.
        value: &'a str,
    },
    /// A violated cross-field requirement — an RFC 6265bis §4.1.3 name prefix
    /// or CHIPS' `Partitioned`/`Secure` pairing. Nothing is dropped or
    /// altered: name, flags, and attributes stay exactly as parsed; the
    /// violation is witnessed, identically in both gradings, and it is a
    /// property of the cookie itself —
    /// [`constraint_violations`](SetCookie::constraint_violations) reports the
    /// same thing for a cookie you built.
    #[non_exhaustive]
    ConstraintViolation {
        /// The violated constraint.
        constraint: CookieConstraint,
    },
}

impl fmt::Display for SetCookieIssue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAttribute { name } => {
                write!(f, "unrecognised attribute `{}`", name.escape_debug())
            }
            Self::DuplicateAttribute { attribute } => {
                write!(f, "duplicate `{}` attribute", attribute.name())
            }
            Self::InvalidAttributeValue { attribute, value } => {
                write!(
                    f,
                    "malformed `{}` value `{}` (attribute dropped, cookie kept)",
                    attribute.name(),
                    value.escape_debug()
                )
            }
            Self::FlagWithValue { attribute, value } => {
                write!(
                    f,
                    "value `{}` on the presence-only `{}` flag (flag set, value discarded)",
                    value.escape_debug(),
                    attribute.name()
                )
            }
            Self::ConstraintViolation { constraint } => {
                write!(f, "{constraint} (cookie kept as written)")
            }
        }
    }
}

impl std::error::Error for SetCookieIssue<'_> {}

/// A cross-field requirement a `Set-Cookie` can violate: the RFC 6265bis
/// §4.1.3 cookie-name prefixes and CHIPS' `Partitioned`/`Secure` pairing.
/// §4.1.3's server contract spells the prefixes case-sensitively (a
/// conformant server emits exactly `__Secure-` / `__Host-`), while user
/// agents enforce the rules case-insensitively; the checks here match the
/// enforcement side ([`has_secure_prefix`] / [`has_host_prefix`]), so a
/// case-variant spelling cannot dodge them.
///
/// The codec never *enforces* a constraint: the parse keeps the cookie exactly
/// as written and witnesses the violation as a
/// [`SetCookieIssue::ConstraintViolation`] in both gradings, and
/// [`SetCookie::constraint_violations`] runs the same checks on a cookie you
/// built. [`is_clean`](crate::Reported::is_clean) — or an explicit check — is
/// the gate.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.3> ·
/// <https://wicg.github.io/CHIPS/>
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CookieConstraint {
    /// A prefix spelled in a non-canonical case (`__host-`, `__SeCuRe-`):
    /// user agents still enforce it, but the §4.1.3 server contract is exactly
    /// `__Secure-` / `__Host-`, and agents that match case-sensitively (curl
    /// does) silently lose the protection for such a spelling.
    NonCanonicalPrefixCase,
    /// A `__Secure-`-prefixed name without the `Secure` attribute.
    SecurePrefixWithoutSecure,
    /// A `__Host-`-prefixed name without the `Secure` attribute.
    HostPrefixWithoutSecure,
    /// A `__Host-`-prefixed name carrying a `Domain` attribute.
    HostPrefixWithDomain,
    /// A `__Host-`-prefixed name whose `Path` is not exactly `/`.
    HostPrefixWithoutRootPath,
    /// The `Partitioned` flag without the `Secure` attribute (CHIPS).
    PartitionedWithoutSecure,
}

impl fmt::Display for CookieConstraint {
    /// Static, control-free text — a constraint names no wire bytes, so there
    /// is nothing to escape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NonCanonicalPrefixCase => {
                "a `__Secure-`/`__Host-` prefix spelled in a non-canonical case (the server \
                 contract is exactly `__Secure-` / `__Host-`)"
            }
            Self::SecurePrefixWithoutSecure => {
                "a `__Secure-`-prefixed cookie requires the `Secure` attribute"
            }
            Self::HostPrefixWithoutSecure => {
                "a `__Host-`-prefixed cookie requires the `Secure` attribute"
            }
            Self::HostPrefixWithDomain => {
                "a `__Host-`-prefixed cookie must not carry a `Domain` attribute"
            }
            Self::HostPrefixWithoutRootPath => {
                "a `__Host-`-prefixed cookie requires `Path=/` exactly"
            }
            Self::PartitionedWithoutSecure => {
                "a `Partitioned` cookie requires the `Secure` attribute (CHIPS)"
            }
        })
    }
}

/// Append every violated cross-field constraint to `report`, in a fixed order:
/// the prefix casing, the `__Secure-` rule, the three `__Host-` rules
/// (`Secure`, `Domain`, `Path`), then the CHIPS pairing. Shared verbatim by the parse (after its
/// attribute loop) and [`SetCookie::constraint_violations`], so reader and
/// builder can never disagree on what conformant means.
fn push_constraint_issues<'i>(
    name: &str,
    attributes: &CookieAttributes<'_>,
    report: &mut Vec<SetCookieIssue<'i>>,
) {
    let mut note = |constraint: CookieConstraint| {
        #[cfg(feature = "tracing")]
        tracing::debug!(%constraint, "cross-field constraint violated; the cookie is kept");
        report.push(SetCookieIssue::ConstraintViolation { constraint });
    };
    let secure_prefix = has_secure_prefix(name);
    let host_prefix = has_host_prefix(name);
    if (secure_prefix && !name.starts_with("__Secure-"))
        || (host_prefix && !name.starts_with("__Host-"))
    {
        note(CookieConstraint::NonCanonicalPrefixCase);
    }
    if secure_prefix && !attributes.secure {
        note(CookieConstraint::SecurePrefixWithoutSecure);
    }
    if host_prefix {
        if !attributes.secure {
            note(CookieConstraint::HostPrefixWithoutSecure);
        }
        if attributes.domain.is_some() {
            note(CookieConstraint::HostPrefixWithDomain);
        }
        if attributes.path.is_none_or(|p| p.as_str() != "/") {
            note(CookieConstraint::HostPrefixWithoutRootPath);
        }
    }
    if attributes.partitioned && !attributes.secure {
        note(CookieConstraint::PartitionedWithoutSecure);
    }
}

/// Pass a known attribute's parse result through, debug-logging and reporting
/// the fail-soft drop when it is `None` — the malformed-known-attribute skip the
/// crate docs promise, observable like the readers' pair-level skips. The cookie
/// is kept either way; only the malformed occurrence is lost, and it never
/// erases an earlier valid one — RFC 6265 §5.2.2 ignores the *cookie-av*, not
/// the attribute (last-wins applies among the occurrences that parse).
fn noted<'a, T>(
    parsed: Option<T>,
    attribute: KnownAttribute,
    raw_value: &'a str,
    report: &mut Vec<SetCookieIssue<'a>>,
) -> Option<T> {
    if parsed.is_none() {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            attribute = attribute.name(),
            value = %raw_value.escape_debug(),
            "dropping a malformed known attribute; the cookie is kept"
        );
        report.push(SetCookieIssue::InvalidAttributeValue {
            attribute,
            value: raw_value,
        });
    }
    parsed
}

/// One rendered `Set-Cookie` attribute — the typed unit the serializer emits.
///
/// [`to_set_cookie`](SetCookie::to_set_cookie) turns each set attribute into one
/// of these and joins their [`Display`](fmt::Display) with `"; "`. Their names
/// come from the `attr_name` constants the parser also matches, so the wire form
/// has a single source of truth. Boolean flags are presence-only: `HttpOnly`,
/// `Secure`, and `Partitioned` render bare, with no `=value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SetCookieAttribute<'a> {
    HttpOnly,
    SameSite(SameSite),
    Secure,
    Partitioned,
    Path(&'a str),
    Domain(&'a str),
    Expires(OffsetDateTime),
    MaxAge(u64),
}

impl SetCookieAttribute<'_> {
    /// An upper bound of this attribute's rendered length, for pre-sizing the
    /// output buffer — a reservation hint only, never a correctness input.
    fn rendered_len_upper(self) -> usize {
        match self {
            Self::HttpOnly => attr_name::HTTP_ONLY.len(),
            Self::SameSite(same_site) => attr_name::SAME_SITE.len() + 1 + same_site.as_str().len(),
            Self::Secure => attr_name::SECURE.len(),
            Self::Partitioned => attr_name::PARTITIONED.len(),
            Self::Path(path) => attr_name::PATH.len() + 1 + path.len(),
            Self::Domain(domain) => attr_name::DOMAIN.len() + 1 + domain.len(),
            // An IMF-fixdate is 29 bytes for the four-digit years `time` emits.
            Self::Expires(_) => attr_name::EXPIRES.len() + 1 + 29,
            // `u64::MAX` spans 20 decimal digits.
            Self::MaxAge(_) => attr_name::MAX_AGE.len() + 1 + 20,
        }
    }
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
            Self::Partitioned => f.write_str(attr_name::PARTITIONED),
            Self::Path(path) => write!(f, "{}={}", attr_name::PATH, path),
            Self::Domain(domain) => write!(f, "{}={}", attr_name::DOMAIN, domain),
            Self::Expires(when) => {
                write!(f, "{}={}", attr_name::EXPIRES, ImfFixdate(when))
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
        let mut mask = 0u16;
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
        assert_eq!(KnownAttribute::recognize("Priority"), None);
        assert_eq!(KnownAttribute::recognize(""), None);
    }

    #[test]
    fn a_duplicate_of_every_attribute_recovers_with_a_witness() {
        // One duplicated occurrence per recognisable attribute — each keeps
        // last-wins and is witnessed, identically in both gradings.
        for (known, dup) in [
            (KnownAttribute::HttpOnly, "HttpOnly; HttpOnly"),
            (KnownAttribute::Secure, "Secure; Secure"),
            (KnownAttribute::Partitioned, "Partitioned; Partitioned"),
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
            for (grading, parsed) in [
                ("strict", SetCookie::parse_strict(&header)),
                ("lenient", SetCookie::parse(&header)),
            ] {
                let reported = parsed
                    .unwrap_or_else(|_| panic!("{grading} must keep the cookie for {header:?}"));
                assert!(
                    reported
                        .issues
                        .contains(&SetCookieIssue::DuplicateAttribute { attribute: known }),
                    "{grading} must witness the duplicated {:?} in {header:?}, got {:?}",
                    known.name(),
                    reported.issues
                );
            }
        }
        // The ALL table drives the loop above; make sure the loop covered it fully.
        assert_eq!(KnownAttribute::ALL.len(), 8);
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
                .domain(Domain::new("example.test").unwrap())
                .path(Path::new("/app").unwrap())
                .partitioned()
                .secure()
                .same_site(SameSite::None)
                .http_only()
                .to_set_cookie(),
            "n=v; HttpOnly; SameSite=None; Secure; Partitioned; Path=/app; Domain=example.test; \
             Max-Age=60"
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
            .path(Path::new("/").unwrap())
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
            .path(Path::new("/").unwrap())
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
            .domain(Domain::new("example.test").unwrap())
            .path(Path::new("/app").unwrap())
            .partitioned()
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
                SetCookieAttribute::Partitioned,
                SetCookieAttribute::Path("/app"),
                SetCookieAttribute::Domain("example.test"),
                SetCookieAttribute::MaxAge(60),
            ]
        );
        // A bare cookie has none.
        assert!(SetCookie::new("n", "v").set_cookie_attributes().is_empty());
    }

    #[test]
    fn to_set_cookie_equals_the_joined_attribute_renderings() {
        // The single-buffer writer is byte-identical to joining the pair and
        // each attribute's own rendering with "; " — checked over every one of
        // the 2^8 set/unset attribute combinations, with a value the default
        // encoding escapes.
        use time::macros::datetime;
        for mask in 0u16..256 {
            let mut sc = SetCookie::new("SID", "dead beef");
            if mask & 1 != 0 {
                sc = sc.http_only();
            }
            if mask & 2 != 0 {
                sc = sc.same_site(SameSite::Lax);
            }
            if mask & 4 != 0 {
                sc = sc.secure();
            }
            if mask & 8 != 0 {
                sc = sc.path(Path::new("/app").unwrap());
            }
            if mask & 16 != 0 {
                sc = sc.domain(Domain::new("example.test").unwrap());
            }
            if mask & 32 != 0 {
                sc = sc.expires(datetime!(2021-06-09 10:18:14 UTC));
            }
            if mask & 64 != 0 {
                sc = sc.max_age(3600);
            }
            if mask & 128 != 0 {
                sc = sc.partitioned();
            }
            let oracle = std::iter::once(sc.to_request_pair())
                .chain(sc.set_cookie_attributes().iter().map(ToString::to_string))
                .collect::<Vec<_>>()
                .join("; ");
            assert_eq!(sc.to_set_cookie(), oracle, "mask {mask:#09b}");
        }
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
        let sc = SetCookie::new("n", "v")
            .path(Path::new("/x").unwrap())
            .secure();
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
                .path(Path::new("/").unwrap())
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
            .path(Path::new("/").unwrap())
            .max_age(3600)
            .to_set_cookie();
        let parsed = SetCookie::parse(&wire).unwrap().into_value();
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
        assert_eq!(
            SetCookie::parse("pref=caf%C3%A9").unwrap().value.value(),
            "café"
        );
        assert_eq!(
            SetCookie::parse(r#"pref="a b""#).unwrap().value.value(),
            "a b"
        );
    }

    #[test]
    fn parse_attributes_are_case_insensitive() {
        let p = SetCookie::parse("n=v; SECURE; httponly; samesite=lax; PATH=/x; max-age=60")
            .unwrap()
            .into_value();
        assert!(p.attributes().secure && p.attributes().http_only);
        assert_eq!(p.attributes().same_site, Some(SameSite::Lax));
        assert_eq!(p.attributes().path.map(|v| v.as_str()), Some("/x"));
        assert_eq!(p.attributes().max_age, Some(60));
    }

    #[test]
    fn unknown_attribute_is_witnessed_in_both_gradings() {
        // An unrecognised attribute (`Priority`) is recovered and witnessed
        // under strict grading — enforcement is the caller's is_clean gate.
        let strict = SetCookie::parse_strict("SID=x; Priority=High; Max-Age=60").unwrap();
        assert!(!strict.is_clean());
        assert_eq!(strict.value.attributes().max_age, Some(60));
        // Default (RFC §5.2): the unknown attribute is ignored and the cookie survives.
        let p = SetCookie::parse("SID=x; Priority=High; Max-Age=60")
            .unwrap()
            .into_value();
        assert_eq!(p.value(), "x");
        assert_eq!(p.attributes().max_age, Some(60));
    }

    #[test]
    fn parse_reads_expires_as_a_date() {
        use time::macros::datetime;
        // `Expires` is a known attribute, parsed into an `OffsetDateTime` (lenient
        // RFC 6265 §5.1.1 here); the cookie and a coexisting `Max-Age` are kept.
        let p = SetCookie::parse("SID=x; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=60")
            .unwrap()
            .into_value();
        assert_eq!(p.value(), "x");
        assert_eq!(
            p.attributes().expires,
            Some(datetime!(2021-06-09 10:18:14 UTC))
        );
        assert_eq!(p.attributes().max_age, Some(60));
        // An unparseable date is dropped like any malformed known attribute; the
        // cookie survives.
        let bad = SetCookie::parse("SID=x; Expires=not-a-date")
            .unwrap()
            .into_value();
        assert_eq!(bad.attributes().expires, None);
        assert_eq!(bad.value(), "x");
    }

    #[test]
    fn parse_strict_tolerates_empty_and_trailing_semicolons() {
        // A stray or trailing `;` is not an "unknown attribute" — strict keeps it.
        assert_eq!(SetCookie::parse("SID=x;").unwrap().value.value(), "x");
        let p = SetCookie::parse("SID=x; ; Secure").unwrap().into_value();
        assert_eq!(p.value(), "x");
        assert!(p.attributes().secure);
    }

    #[test]
    fn parse_skips_malformed_attributes_but_keeps_the_cookie() {
        let p = SetCookie::parse("SID=x; Max-Age=banana; SameSite=Bogus; HttpOnly")
            .unwrap()
            .into_value();
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
                .value
                .attributes()
                .max_age,
            Some(u64::MAX)
        );
        assert_eq!(
            SetCookie::parse("n=v; Max-Age=-1")
                .unwrap()
                .value
                .attributes()
                .max_age,
            None
        );
    }

    #[test]
    fn parse_rejects_no_equals_and_bad_name() {
        assert!(SetCookie::parse("HttpOnly").is_err()); // no name=value pair
        assert!(SetCookie::parse("na me=v; Secure").is_err()); // non-token name
        assert!(SetCookie::parse("").is_err());
        assert!(SetCookie::parse("=v").is_err()); // empty name
    }

    #[test]
    fn parse_splits_first_semicolon_then_first_equals() {
        let p = SetCookie::parse("a=b=c; Path=/x").unwrap().into_value();
        assert_eq!(p.name(), "a");
        assert_eq!(p.value(), "b=c"); // only the first '=' splits name/value
        assert_eq!(p.attributes().path.map(|v| v.as_str()), Some("/x"));
    }

    // ---- the reporting readers ---------------------------------------------

    #[test]
    fn mistyped_or_fused_attribute_is_reported_not_silent() {
        // The safety case that motivated the report: a misspelled HttpOnly.
        let reported = SetCookie::parse("SID=x; Secure; HttpOnlyy").unwrap();
        assert!(reported.value.attributes().secure);
        assert!(!reported.value.attributes().http_only); // still dropped (§5.2)…
        assert_eq!(
            reported.issues,
            vec![SetCookieIssue::UnknownAttribute { name: "HttpOnlyy" }] // …but visible
        );
        // A forgotten `;` fusing two flags: both vanish from the parsed cookie,
        // one UnknownAttribute names the fused token.
        let reported = SetCookie::parse("SID=x; Secure HttpOnly").unwrap();
        assert!(!reported.value.attributes().secure);
        assert!(!reported.value.attributes().http_only);
        assert_eq!(
            reported.issues,
            vec![SetCookieIssue::UnknownAttribute {
                name: "Secure HttpOnly"
            }]
        );
        // Strict grading recovers and witnesses it identically — enforcement
        // is the caller's is_clean gate.
        let strict = SetCookie::parse_strict("SID=x; HttpOnlyy").unwrap();
        assert!(!strict.is_clean());
        assert_eq!(
            strict.issues,
            vec![SetCookieIssue::UnknownAttribute { name: "HttpOnlyy" }]
        );
    }

    #[test]
    fn malformed_known_values_are_reported_in_both_modes() {
        for (header, attribute, value) in [
            ("n=v; Max-Age=banana", KnownAttribute::MaxAge, "banana"),
            ("n=v; SameSite=Bogus", KnownAttribute::SameSite, "Bogus"),
            ("n=v; Expires=nonsense", KnownAttribute::Expires, "nonsense"),
            ("n=v; Path=a\u{1}b", KnownAttribute::Path, "a\u{1}b"),
        ] {
            let expected = vec![SetCookieIssue::InvalidAttributeValue { attribute, value }];
            let lenient = SetCookie::parse(header).unwrap();
            assert_eq!(lenient.issues, expected, "lenient {header:?}");
            // Strict keeps the cookie too — the drop is reported, not fatal —
            // so `!is_clean()` is the caller's stricter-than-strict gate.
            let strict = SetCookie::parse_strict(header).unwrap();
            assert_eq!(strict.issues, expected, "strict {header:?}");
            assert!(!strict.is_clean());
        }
        // Mode-relative dates: an RFC 850 date parses leniently but is an issue
        // under strict's IMF-fixdate-only reader.
        let rfc850 = "n=v; Expires=Sunday, 06-Nov-94 08:49:37 GMT";
        assert!(SetCookie::parse(rfc850).unwrap().is_clean());
        let strict = SetCookie::parse_strict(rfc850).unwrap();
        assert_eq!(
            strict.issues,
            vec![SetCookieIssue::InvalidAttributeValue {
                attribute: KnownAttribute::Expires,
                value: "Sunday, 06-Nov-94 08:49:37 GMT"
            }]
        );
    }

    #[test]
    fn duplicates_and_valued_flags_are_reported() {
        let reported = SetCookie::parse("n=v; Path=/a; Path=/b; Secure=1").unwrap();
        assert_eq!(
            reported.issues,
            vec![
                SetCookieIssue::DuplicateAttribute {
                    attribute: KnownAttribute::Path
                },
                SetCookieIssue::FlagWithValue {
                    attribute: KnownAttribute::Secure,
                    value: "1"
                },
            ],
            "issues arrive in wire order"
        );
        // Last-wins and flag-sets behave exactly as in plain parse.
        assert_eq!(
            reported.value.attributes().path.map(|p| p.as_str()),
            Some("/b")
        );
        assert!(reported.value.attributes().secure);
        // Strict grading witnesses the duplicate the same way.
        let strict = SetCookie::parse_strict("n=v; Path=/a; Path=/b").unwrap();
        assert_eq!(
            strict.issues,
            vec![SetCookieIssue::DuplicateAttribute {
                attribute: KnownAttribute::Path
            }]
        );
    }

    #[test]
    fn fatal_pair_issues_carry_the_pair_defect() {
        assert_eq!(
            SetCookie::parse("HttpOnly"),
            Err(PairIssue::MissingEquals {
                segment: b"HttpOnly"
            })
        );
        assert_eq!(
            SetCookie::parse("na me=v; Secure"),
            Err(PairIssue::InvalidName { name: b"na me" })
        );
        assert_eq!(
            SetCookie::parse("n=a\u{1}b; Secure"),
            Err(PairIssue::InvalidValue {
                name: "n",
                value: b"a\x01b"
            })
        );
    }

    #[test]
    fn parse_keeps_earlier_valid_attribute_over_later_malformed() {
        // RFC 6265 §5.2.2: an unparseable cookie-av is ignored — it must not
        // erase an earlier valid occurrence of the same attribute.
        let p = SetCookie::parse("n=v; Max-Age=60; Max-Age=banana")
            .unwrap()
            .into_value();
        assert_eq!(p.attributes().max_age, Some(60));
        let p = SetCookie::parse("n=v; Domain=valid.example.com; Domain=café")
            .unwrap()
            .into_value();
        assert_eq!(
            p.attributes().domain.map(|d| d.as_str()),
            Some("valid.example.com")
        );
        // Among occurrences that PARSE, last-wins is unchanged.
        let p = SetCookie::parse("n=v; Max-Age=1; Max-Age=2")
            .unwrap()
            .into_value();
        assert_eq!(p.attributes().max_age, Some(2));
        // A malformed occurrence with no valid predecessor still leaves the
        // attribute unset.
        let p = SetCookie::parse("n=v; Max-Age=banana")
            .unwrap()
            .into_value();
        assert_eq!(p.attributes().max_age, None);
        // The report sees both the duplicate and the malformed value.
        let reported = SetCookie::parse("n=v; Max-Age=60; Max-Age=banana").unwrap();
        assert_eq!(
            reported.issues,
            vec![
                SetCookieIssue::DuplicateAttribute {
                    attribute: KnownAttribute::MaxAge
                },
                SetCookieIssue::InvalidAttributeValue {
                    attribute: KnownAttribute::MaxAge,
                    value: "banana"
                },
            ]
        );
        assert_eq!(reported.value.attributes().max_age, Some(60));
    }

    #[test]
    fn issue_display_never_echoes_wire_dangerous_bytes() {
        let issues = [
            SetCookieIssue::UnknownAttribute {
                name: "Http\u{1}Only; evil",
            },
            SetCookieIssue::InvalidAttributeValue {
                attribute: KnownAttribute::Expires,
                value: "a\r\nSet-Cookie: evil=1",
            },
            SetCookieIssue::FlagWithValue {
                attribute: KnownAttribute::Secure,
                value: "x\u{0}y",
            },
            SetCookieIssue::ConstraintViolation {
                constraint: CookieConstraint::HostPrefixWithoutRootPath,
            },
        ];
        for issue in issues {
            let rendered = issue.to_string();
            for byte in [b'\r', b'\n', b'\0'] {
                assert!(
                    !rendered.bytes().any(|b| b == byte),
                    "{rendered:?} echoes {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn empty_attribute_name_with_a_value_is_witnessed() {
        // `; =V` is not structural noise: the segment carries payload, so the
        // conservation law demands a witness — an unknown (empty) name. Found
        // by the generative property suite as an unwitnessed drop.
        for wire in ["SID=x; =evil", "SID=x; \t= y"] {
            for (grading, parsed) in [
                ("lenient", SetCookie::parse(wire)),
                ("strict", SetCookie::parse_strict(wire)),
            ] {
                let reported = parsed.unwrap_or_else(|_| panic!("{wire:?} must salvage"));
                assert!(
                    matches!(
                        reported.issues[..],
                        [SetCookieIssue::UnknownAttribute { name: "" }]
                    ),
                    "{grading} must witness the empty-name attribute in {wire:?}, got {:?}",
                    reported.issues
                );
            }
        }
        // A segment with no payload stays structural noise in both gradings.
        assert!(SetCookie::parse("SID=x; ; \t;").unwrap().is_clean());
        assert!(SetCookie::parse_strict("SID=x; = ;").unwrap().is_clean());
    }

    // ---- cross-field constraints ------------------------------------------

    /// The constraint suffix of a parse's issues, for comparing against
    /// `constraint_violations`.
    fn constraints_of(issues: &[SetCookieIssue<'_>]) -> Vec<CookieConstraint> {
        issues
            .iter()
            .filter_map(|issue| match issue {
                SetCookieIssue::ConstraintViolation { constraint } => Some(*constraint),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_constraint_is_witnessed_and_nothing_is_dropped() {
        use CookieConstraint::*;
        // (wire, expected constraint issues, in the checker's fixed order) —
        // identical under both gradings, with the cookie kept as written.
        for (wire, expected) in [
            ("__Secure-a=b", &[SecurePrefixWithoutSecure][..]),
            ("__secure-a=b; Secure", &[NonCanonicalPrefixCase]),
            ("__Secure-a=b; Secure", &[]),
            ("__Host-a=b; Secure; Path=/", &[]),
            ("__Host-a=b; Path=/", &[HostPrefixWithoutSecure]),
            (
                "__Host-a=b; Secure; Path=/; Domain=example.test",
                &[HostPrefixWithDomain],
            ),
            (
                "__Host-a=b; Secure; Path=/app",
                &[HostPrefixWithoutRootPath],
            ),
            ("__Host-a=b; Secure", &[HostPrefixWithoutRootPath]),
            (
                "__Host-a=b",
                &[HostPrefixWithoutSecure, HostPrefixWithoutRootPath],
            ),
            (
                "__hOsT-a=b",
                &[
                    NonCanonicalPrefixCase,
                    HostPrefixWithoutSecure,
                    HostPrefixWithoutRootPath,
                ],
            ),
            ("a=b; Partitioned", &[PartitionedWithoutSecure]),
            ("a=b; Partitioned; Secure", &[]),
            ("a=b; Secure", &[]),
        ] {
            for (grading, parsed) in [
                ("lenient", SetCookie::parse(wire)),
                ("strict", SetCookie::parse_strict(wire)),
            ] {
                let reported = parsed.unwrap_or_else(|_| panic!("{wire:?} must salvage"));
                assert_eq!(
                    constraints_of(&reported.issues),
                    expected,
                    "{grading} constraint issues for {wire:?}"
                );
                assert!(
                    reported.issues.len() == expected.len(),
                    "{grading} must witness only constraints for {wire:?}: {:?}",
                    reported.issues
                );
            }
        }
        // Nothing is dropped or altered: the violating attributes stay set.
        let kept = SetCookie::parse("__Host-a=b; Secure; Path=/app; Domain=example.test")
            .unwrap()
            .value;
        assert_eq!(kept.attributes().path.map(|p| p.as_str()), Some("/app"));
        assert_eq!(
            kept.attributes().domain.map(|d| d.as_str()),
            Some("example.test")
        );
        let kept = SetCookie::parse("a=b; Partitioned").unwrap().value;
        assert!(kept.attributes().partitioned);
    }

    #[test]
    fn prefix_constraints_match_case_insensitively() {
        for wire in ["__SECURE-a=b", "__secure-a=b", "__SeCuRe-a=b"] {
            assert_eq!(
                constraints_of(&SetCookie::parse(wire).unwrap().issues),
                [
                    CookieConstraint::NonCanonicalPrefixCase,
                    CookieConstraint::SecurePrefixWithoutSecure,
                ],
                "{wire:?}"
            );
        }
        assert_eq!(
            constraints_of(&SetCookie::parse("__host-a=b; Secure").unwrap().issues),
            [
                CookieConstraint::NonCanonicalPrefixCase,
                CookieConstraint::HostPrefixWithoutRootPath,
            ],
            "a case-variant `__host-` still triggers the prefix rules"
        );
        // A conformant cookie under a case-variant spelling is witnessed for
        // the casing alone — the two concerns are independent.
        assert_eq!(
            constraints_of(
                &SetCookie::parse("__host-a=b; Secure; Path=/")
                    .unwrap()
                    .issues
            ),
            [CookieConstraint::NonCanonicalPrefixCase],
        );
        // The canonical spellings never trigger the casing witness.
        assert!(
            SetCookie::parse("__Secure-a=b; Secure").unwrap().is_clean()
                && SetCookie::parse("__Host-a=b; Secure; Path=/")
                    .unwrap()
                    .is_clean()
        );
    }

    #[test]
    fn constraint_issues_follow_the_wire_order_attribute_issues() {
        // Attribute issues come out in wire order; the constraint pass appends
        // after them, so a log reads the wire first and the verdict second.
        let parsed = SetCookie::parse("__Secure-a=b; Priority=x; Max-Age=banana").unwrap();
        assert!(matches!(
            parsed.issues[..],
            [
                SetCookieIssue::UnknownAttribute {
                    name: "Priority",
                    ..
                },
                SetCookieIssue::InvalidAttributeValue {
                    attribute: KnownAttribute::MaxAge,
                    ..
                },
                SetCookieIssue::ConstraintViolation {
                    constraint: CookieConstraint::SecurePrefixWithoutSecure,
                    ..
                },
            ]
        ));
    }

    #[test]
    fn constraint_violations_agree_with_the_parse() {
        // The builder-side checker is the same function the parse runs: for
        // any built cookie, re-parsing its rendering witnesses exactly the
        // standing violations.
        let built = SetCookie::new("__Host-SID", "x").domain(Domain::new("example.test").unwrap());
        let violations = built.constraint_violations();
        assert_eq!(
            constraints_of(&violations),
            [
                CookieConstraint::HostPrefixWithoutSecure,
                CookieConstraint::HostPrefixWithDomain,
                CookieConstraint::HostPrefixWithoutRootPath,
            ]
        );
        let rendered = built.to_set_cookie();
        let reparsed = SetCookie::parse(&rendered).unwrap();
        assert_eq!(reparsed.issues, violations, "for {rendered:?}");

        // A conformant build is silent, and its parse is clean.
        let ok = SetCookie::new("__Host-SID", "x")
            .secure()
            .path(Path::new("/").unwrap());
        assert!(ok.constraint_violations().is_empty());
        assert!(
            SetCookie::parse_strict(&ok.to_set_cookie())
                .unwrap()
                .is_clean()
        );
    }
}
