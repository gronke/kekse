//! The `Set-Cookie` response attributes as a standalone [`CookieAttributes`] —
//! the part a request `Cookie:` cookie does not carry. A
//! [`SetCookie`](crate::SetCookie) is a [`Cookie`](crate::Cookie) kernel plus a
//! `CookieAttributes`. The `Path` and `Domain` values are validated [`Path`] /
//! [`Domain`] newtypes, so the public fields cannot carry an injection byte.

use std::fmt;

use rfc_6265::OffsetDateTime;
use rfc_6265::grammar::is_av_octet;

use crate::same_site::SameSite;

/// A validated `Path` attribute value: RFC 6265 §4.1.1 av-octets only — no
/// control byte, no `;`, ASCII — so it can never break out of or inject into a
/// `Set-Cookie` line. The newtype makes the public [`CookieAttributes::path`]
/// field **unforgeable**: the only way to obtain one is [`Path::new`], which
/// validates. Read the inner string with [`as_str`](Path::as_str).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Path<'a>(&'a str);

impl<'a> Path<'a> {
    /// `Ok(Path)` iff every byte is an av-octet; the [`InvalidPath`] refusal
    /// otherwise — a control byte, a `;`, or non-ASCII, anything that could
    /// break the header line — carrying the refused value.
    ///
    /// ```
    /// use kekse::Path;
    ///
    /// assert_eq!(Path::new("/app")?.as_str(), "/app");
    /// assert!(Path::new("/a;b").is_err()); // `;` would split the header line
    /// # Ok::<(), kekse::InvalidPath<'static>>(())
    /// ```
    pub fn new(value: &'a str) -> Result<Self, InvalidPath<'a>> {
        if value.bytes().all(is_av_octet) {
            Ok(Self(value))
        } else {
            Err(InvalidPath { value })
        }
    }

    /// The validated path value.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl AsRef<str> for Path<'_> {
    /// Borrow the validated path as `&str`.
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The refusal [`Path::new`] returns: the would-be `Path` value carries a byte
/// outside the RFC 6265 §4.1.1 av-octet set — a control byte, a `;`, or
/// non-ASCII — which could break the `Set-Cookie` line it would be rendered
/// into. Carries the refused value; the [`Display`](fmt::Display) form escapes
/// it (`escape_debug`), so a rendered refusal never carries a raw control byte.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidPath<'a> {
    /// The refused value.
    pub value: &'a str,
}

impl fmt::Display for InvalidPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cookie Path `{}` carries a byte outside the av-octet set",
            self.value.escape_debug()
        )
    }
}

impl std::error::Error for InvalidPath<'_> {}

/// A validated `Domain` attribute value — the same av-octet guarantee as
/// [`Path`], so the public [`CookieAttributes::domain`] field is unforgeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Domain<'a>(&'a str);

impl<'a> Domain<'a> {
    /// `Ok(Domain)` iff every byte is an av-octet (no control byte, `;`, or non-ASCII). With any
    /// Domain-hardening feature on (`psl` / `idna` — the `hardened` build has both), the value must
    /// also be LDH host-name syntax ([`rfc_6265::domain::is_host_name`], after stripping the one
    /// leading dot of the RFC 6265 §5.2.3 wire form) — a `Domain` that could never domain-match is
    /// refused rather than stored as dead weight. On top of that, the `psl` feature refuses a
    /// public-suffix value (a supercookie `Domain` such as `com` / `.co.uk`) and the `idna` feature
    /// refuses malformed punycode. A refusal is the [`InvalidDomain`] naming the failed gate and
    /// carrying the refused value.
    ///
    /// ```
    /// use kekse::Domain;
    ///
    /// assert_eq!(Domain::new("example.test")?.as_str(), "example.test");
    /// assert!(Domain::new("ex\u{0}ample").is_err()); // control byte
    /// # Ok::<(), kekse::InvalidDomain<'static>>(())
    /// ```
    pub fn new(value: &'a str) -> Result<Self, InvalidDomain<'a>> {
        if !value.bytes().all(is_av_octet) {
            return Err(InvalidDomain::NotAvOctets { value });
        }
        // Host-name syntax (any hardening feature): the policies below are only meaningful over a
        // well-formed host name, and `domain_matches` requires one anyway — a stored `Domain` it
        // could never match would be dead weight. Checked on the effective cookie-domain: one
        // leading dot is the §5.2.3 wire form consumers strip (`is_public_suffix` already ignores
        // it too). The pure-codec default stays byte-identical.
        #[cfg(any(feature = "psl", feature = "idna"))]
        if !rfc_6265::domain::is_host_name(value.strip_prefix('.').unwrap_or(value)) {
            return Err(InvalidDomain::NotAHostName { value });
        }
        // Supercookie defense (`psl`): a `Domain` that is itself a public suffix can never be set,
        // so a cookie cannot escape its registrable domain.
        #[cfg(feature = "psl")]
        if rfc_6265::domain::is_public_suffix(value) {
            return Err(InvalidDomain::PublicSuffix { value });
        }
        // IDN validation (`idna`): reject an av-octet-clean but malformed punycode label.
        #[cfg(feature = "idna")]
        if !rfc_6265::domain::is_valid_domain(value) {
            return Err(InvalidDomain::MalformedIdn { value });
        }
        Ok(Self(value))
    }

    /// The validated domain value.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl AsRef<str> for Domain<'_> {
    /// Borrow the validated domain as `&str`.
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The refusal [`Domain::new`] returns, naming the failed gate and carrying
/// the refused value. The byte gate always applies; the other three arise only
/// with the matching Domain-hardening feature enabled, so which variants a
/// build can produce follows its feature set. The [`Display`](fmt::Display)
/// form escapes the value (`escape_debug`), so a rendered refusal never
/// carries a raw control byte.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvalidDomain<'a> {
    /// A byte outside the RFC 6265 §4.1.1 av-octet set — a control byte, a
    /// `;`, or non-ASCII — which could break the `Set-Cookie` line.
    #[non_exhaustive]
    NotAvOctets {
        /// The refused value.
        value: &'a str,
    },
    /// Not RFC 952/1123 LDH host-name syntax, checked after stripping the one
    /// leading dot of the RFC 6265 §5.2.3 wire form — produced only with a
    /// hardening feature (`psl` / `idna`) enabled.
    #[non_exhaustive]
    NotAHostName {
        /// The refused value.
        value: &'a str,
    },
    /// The value is itself a public suffix — a supercookie `Domain` such as
    /// `com` / `.co.uk` — produced only with the `psl` feature.
    #[non_exhaustive]
    PublicSuffix {
        /// The refused value.
        value: &'a str,
    },
    /// No canonical ASCII form under UTS-46 (malformed punycode) — produced
    /// only with the `idna` feature.
    #[non_exhaustive]
    MalformedIdn {
        /// The refused value.
        value: &'a str,
    },
}

impl fmt::Display for InvalidDomain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvOctets { value } => write!(
                f,
                "cookie Domain `{}` carries a byte outside the av-octet set",
                value.escape_debug()
            ),
            Self::NotAHostName { value } => write!(
                f,
                "cookie Domain `{}` is not an LDH host name",
                value.escape_debug()
            ),
            Self::PublicSuffix { value } => write!(
                f,
                "cookie Domain `{}` is a public suffix",
                value.escape_debug()
            ),
            Self::MalformedIdn { value } => write!(
                f,
                "cookie Domain `{}` has no canonical ASCII form",
                value.escape_debug()
            ),
        }
    }
}

impl std::error::Error for InvalidDomain<'_> {}

/// The response attributes of a `Set-Cookie:` line: `HttpOnly`, `Secure`,
/// `Partitioned`, `SameSite`, `Path`, `Domain`, `Max-Age` — everything a
/// request `Cookie:` cookie does not carry. A [`SetCookie`](crate::SetCookie)
/// is a [`Cookie`](crate::Cookie) kernel plus one of these.
///
/// The fields are **public and read directly** (`attrs.secure`, `attrs.max_age`);
/// the **same-named methods set them** as a fluent builder. Field access and the
/// method are told apart by the call parentheses — `attrs.secure` is the `bool`,
/// `attrs.secure()` returns a `CookieAttributes` with the flag turned on — so a
/// forgotten `()` in a builder chain is a *type error*, not a silent bug.
/// [`Default`] is "nothing set": the baseline a freshly completed cookie carries
/// and the one [`SetCookie::new`](crate::SetCookie::new) starts from.
///
/// `HttpOnly`, `Secure`, and `Partitioned` are valueless presence flags on the
/// wire, so their setters are **nullary**: calling
/// [`http_only`](CookieAttributes::http_only), [`secure`](CookieAttributes::secure),
/// or [`partitioned`](CookieAttributes::partitioned) adds the attribute; not
/// calling it omits it. There is no "set to false" — leave it unset. `path` / `domain`
/// take the validated [`Path`] / [`Domain`] newtypes (read them with
/// `.as_str()`), so construction — [`Path::new`] / [`Domain::new`] — is where
/// an invalid value surfaces, as an error naming the refused value; a chain
/// can never swallow one.
///
/// ```
/// use kekse::{CookieAttributes, Path, SameSite};
///
/// // Define a hardened policy once, reuse it across cookies.
/// let hardened = CookieAttributes::default()
///     .http_only()
///     .secure()
///     .same_site(SameSite::Strict)
///     .path(Path::new("/")?);
/// assert!(hardened.secure); // read a field
/// assert_eq!(hardened.path.map(|p| p.as_str()), Some("/"));
/// # Ok::<(), kekse::InvalidPath<'static>>(())
/// ```
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CookieAttributes<'a> {
    /// The `HttpOnly` flag.
    pub http_only: bool,
    /// The `Secure` flag.
    pub secure: bool,
    /// The `Partitioned` flag (CHIPS) — the cookie is keyed to the top-level
    /// site it was set under. CHIPS requires `Secure` alongside it.
    pub partitioned: bool,
    /// The `SameSite` attribute, if set.
    pub same_site: Option<SameSite>,
    /// The `Path` attribute, if set — a validated [`Path`].
    pub path: Option<Path<'a>>,
    /// The `Domain` attribute, if set — a validated [`Domain`]. Omit for a
    /// host-only cookie.
    pub domain: Option<Domain<'a>>,
    /// The `Max-Age` attribute in seconds, if set. `0` deletes the cookie.
    pub max_age: Option<u64>,
    /// The `Expires` attribute, if set — an absolute expiry instant. Stored
    /// independently of [`max_age`](Self::max_age); when a client is given both,
    /// RFC 6265 §5.3 lets `Max-Age` win, but that precedence is a cookie-*store*
    /// concern and is out of scope here.
    pub expires: Option<OffsetDateTime>,
}

impl<'a> CookieAttributes<'a> {
    /// Add the `HttpOnly` attribute — a valueless presence flag (nullary: there
    /// is no "set to false", just leave it unset). Reads back as the field
    /// `attributes.http_only`.
    #[must_use]
    pub fn http_only(mut self) -> Self {
        self.http_only = true;
        self
    }

    /// Add the `Secure` attribute — a valueless presence flag (nullary). Reads
    /// back as the field `attributes.secure`.
    #[must_use]
    pub fn secure(mut self) -> Self {
        self.secure = true;
        self
    }

    /// Add the `Partitioned` attribute (CHIPS) — a valueless presence flag
    /// (nullary). Reads back as the field `attributes.partitioned`. CHIPS
    /// requires `Secure` alongside it.
    #[must_use]
    pub fn partitioned(mut self) -> Self {
        self.partitioned = true;
        self
    }

    /// Set the `SameSite` attribute.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Set the `Path` attribute from a validated [`Path`] — [`Path::new`] is
    /// where an invalid value surfaces, so the chain itself cannot swallow one.
    #[must_use]
    pub fn path(mut self, path: Path<'a>) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the `Domain` attribute from a validated [`Domain`] — [`Domain::new`]
    /// is where an invalid value surfaces, so the chain itself cannot swallow
    /// one. Omit for a host-only cookie.
    #[must_use]
    pub fn domain(mut self, domain: Domain<'a>) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the `Max-Age` attribute, in seconds. `0` instructs the client to
    /// delete the cookie. Rendered as a `u64` decimal — no saturation.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Set the `Expires` attribute — an absolute expiry instant, rendered as the
    /// RFC 7231 IMF-fixdate (always in GMT).
    #[must_use]
    pub fn expires(mut self, when: OffsetDateTime) -> Self {
        self.expires = Some(when);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_unset() {
        let a = CookieAttributes::default();
        assert!(!a.http_only);
        assert!(!a.secure);
        assert!(!a.partitioned);
        assert_eq!(a.same_site, None);
        assert_eq!(a.path, None);
        assert_eq!(a.domain, None);
        assert_eq!(a.max_age, None);
    }

    #[test]
    fn field_read_and_same_named_setter_coexist() {
        // `a.secure` is the field; `a.secure()` is the builder. Both compile.
        let a = CookieAttributes::default();
        let off: bool = a.secure;
        assert!(!off);
        let a = a.secure();
        assert!(a.secure);
    }

    #[test]
    fn builders_set_each_attribute() {
        let a = CookieAttributes::default()
            .http_only()
            .secure()
            .partitioned()
            .same_site(SameSite::Lax)
            .path(Path::new("/app").unwrap())
            .domain(Domain::new("example.test").unwrap())
            .max_age(60);
        assert!(a.http_only && a.secure && a.partitioned);
        assert_eq!(a.same_site, Some(SameSite::Lax));
        assert_eq!(a.path, Path::new("/app").ok());
        assert_eq!(a.domain, Domain::new("example.test").ok());
        assert_eq!(a.max_age, Some(60));
    }

    #[test]
    fn path_and_domain_reject_injection() {
        // A `;` or a control byte cannot be smuggled into a Path/Domain value;
        // the refusal names the value, so nothing is dropped without a trace.
        assert_eq!(Path::new("/a;b"), Err(InvalidPath { value: "/a;b" }));
        assert_eq!(Path::new("/a\r\nb"), Err(InvalidPath { value: "/a\r\nb" }));
        assert_eq!(
            Domain::new("ex\0ample"),
            Err(InvalidDomain::NotAvOctets { value: "ex\0ample" })
        );
        // A clean value round-trips.
        assert_eq!(Path::new("/ok").map(|p| p.as_str()), Ok("/ok"));
    }

    #[test]
    fn refusals_render_without_control_bytes() {
        // The refusal's own no-echo promise: printing what was refused must
        // not let the refused bytes break the log line they land in.
        let rendered = [
            Path::new("/a\r\n\0b").unwrap_err().to_string(),
            Domain::new("ex\0am\rple").unwrap_err().to_string(),
        ];
        for line in rendered {
            assert!(
                !line.bytes().any(|b| b.is_ascii_control()),
                "{line:?} carries a raw control byte"
            );
        }
    }

    #[test]
    fn as_ref_matches_as_str() {
        fn borrow(s: impl AsRef<str>) -> String {
            s.as_ref().to_owned()
        }
        let p = Path::new("/app").unwrap();
        assert_eq!(p.as_ref(), p.as_str());
        assert_eq!(borrow(p), "/app");
        let d = Domain::new("example.test").unwrap();
        assert_eq!(d.as_ref(), d.as_str());
        assert_eq!(borrow(d), "example.test");
    }

    #[test]
    fn path_domain_av_octet_edge_cases() {
        // av-octet = 0x20..=0x3a | 0x3c..=0x7e: SP and digits are in; HTAB, `;`,
        // controls, and non-ASCII are out (the rejections are pinned above).
        // Empty: every byte is an av-octet (vacuously). `Path` always accepts it; `Domain` accepts
        // it in the pure-codec default, but any hardening feature refuses it — an empty string is
        // not a host name (and under `idna` it is not a valid domain either).
        assert_eq!(Path::new("").map(|p| p.as_str()), Ok(""));
        #[cfg(not(any(feature = "psl", feature = "idna")))]
        assert_eq!(Domain::new("").map(|d| d.as_str()), Ok(""));
        #[cfg(any(feature = "psl", feature = "idna"))]
        assert_eq!(
            Domain::new(""),
            Err(InvalidDomain::NotAHostName { value: "" })
        );
        // SP (0x20) is an av-octet → space-only paths are valid.
        assert!(Path::new(" ").is_ok());
        assert!(Path::new("   ").is_ok());
        // HTAB (0x09) is a control, not an av-octet → rejected.
        assert!(Path::new("\t").is_err());
        assert!(Path::new("a\tb").is_err());
        // Digits (0x30..=0x39) are av-octets.
        assert!(Path::new("12345").is_ok());
        // A bare single label is a public suffix under the `psl` rule, so only assert the default
        // (av-octet-only) acceptance here; `psl` Domain behaviour is pinned separately.
        #[cfg(not(feature = "psl"))]
        assert!(Domain::new("123").is_ok());
    }

    #[cfg(any(feature = "psl", feature = "idna"))]
    #[test]
    fn hardening_features_require_host_name_syntax() {
        // av-octet-clean shapes that are not LDH host names: stored by the pure codec
        // (pinned by keksbruch's `domain-not-a-host-name` scenario), refused under any
        // hardening feature — `domain_matches` could never match them, so storing them
        // would be dead weight.
        for refused in [
            "ex_ample.com",     // underscore is not LDH
            "a..b",             // empty label
            "example.com.",     // FQDN root dot: unmatchable suffix
            "exa mple.com",     // SP is av-octet but never LDH
            "example.com:8080", // smuggled port
        ] {
            assert_eq!(
                Domain::new(refused),
                Err(InvalidDomain::NotAHostName { value: refused })
            );
        }
        // One leading dot is the RFC 6265 §5.2.3 wire form — stripped before the check,
        // consistent with `is_public_suffix`. (Under `psl` the example must not be a
        // public suffix, so use a registrable name.)
        assert!(Domain::new(".example.com").is_ok());
        // LDH includes digits: an IP-shaped value still stores (it domain-matches by
        // identity), and hyphens are fine anywhere `is_host_name` allows them.
        assert!(Domain::new("192.168.0.1").is_ok());
        assert!(Domain::new("my-host.example.com").is_ok());
    }

    #[cfg(feature = "psl")]
    #[test]
    fn psl_feature_rejects_public_suffix_domains() {
        // Supercookie defense: a public-suffix value can never become a `Domain`.
        for refused in ["com", "co.uk", ".com"] {
            // The leading dot is stripped before the check, so `.com` is refused too.
            assert_eq!(
                Domain::new(refused),
                Err(InvalidDomain::PublicSuffix { value: refused })
            );
        }
        // A registrable domain is still accepted.
        assert!(Domain::new("example.com").is_ok());
        assert!(Domain::new("example.co.uk").is_ok());
    }

    #[cfg(feature = "idna")]
    #[test]
    fn idna_feature_rejects_malformed_punycode() {
        // Malformed punycode in a registrable shape — only the IDN gate can
        // refuse it, so the reason is stable across feature combinations.
        assert_eq!(
            Domain::new("xn--.de"),
            Err(InvalidDomain::MalformedIdn { value: "xn--.de" })
        );
        // A bare `xn--` is refused in every hardened build, but the gate that
        // catches it differs: with `psl` on, the PSL wildcard rule claims a
        // lone label as a public suffix before the IDN check runs.
        assert!(Domain::new("xn--").is_err());
        assert!(Domain::new("xn--mnchen-3ya.de").is_ok()); // valid punycode IDN
        assert!(Domain::new("example.com").is_ok());
    }
}
