//! The `Set-Cookie` response attributes as a standalone [`CookieAttributes`] —
//! the part a request `Cookie:` cookie does not carry. A
//! [`SetCookie`](crate::SetCookie) is a [`Cookie`](crate::Cookie) kernel plus a
//! `CookieAttributes`. The `Path` and `Domain` values are validated [`Path`] /
//! [`Domain`] newtypes, so the public fields cannot carry an injection byte.

use crate::grammar::is_av_octet;
use crate::same_site::SameSite;

/// A validated `Path` attribute value: RFC 6265 §4.1.1 av-octets only — no
/// control byte, no `;`, ASCII — so it can never break out of or inject into a
/// `Set-Cookie` line. The newtype makes the public [`CookieAttributes::path`]
/// field **unforgeable**: the only way to obtain one is [`Path::new`], which
/// validates. Read the inner string with [`as_str`](Path::as_str).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Path<'a>(&'a str);

impl<'a> Path<'a> {
    /// `Some(Path)` iff every byte is an av-octet; `None` otherwise — a control
    /// byte, a `;`, or non-ASCII, anything that could break the header line.
    pub fn new(value: &'a str) -> Option<Self> {
        value.bytes().all(is_av_octet).then_some(Self(value))
    }

    /// The validated path value.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl AsRef<str> for Path<'_> {
    /// Borrow the validated path as `&str`.
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// A validated `Domain` attribute value — the same av-octet guarantee as
/// [`Path`], so the public [`CookieAttributes::domain`] field is unforgeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Domain<'a>(&'a str);

impl<'a> Domain<'a> {
    /// `Some(Domain)` iff every byte is an av-octet (no control byte, `;`, or
    /// non-ASCII).
    pub fn new(value: &'a str) -> Option<Self> {
        value.bytes().all(is_av_octet).then_some(Self(value))
    }

    /// The validated domain value.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl AsRef<str> for Domain<'_> {
    /// Borrow the validated domain as `&str`.
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The response attributes of a `Set-Cookie:` line: `HttpOnly`, `Secure`,
/// `SameSite`, `Path`, `Domain`, `Max-Age` — everything a request `Cookie:`
/// cookie does not carry. A [`SetCookie`](crate::SetCookie) is a
/// [`Cookie`](crate::Cookie) kernel plus one of these.
///
/// The fields are **public and read directly** (`attrs.secure`, `attrs.max_age`);
/// the **same-named methods set them** as a fluent builder. Field access and the
/// method are told apart by the call parentheses — `attrs.secure` is the `bool`,
/// `attrs.secure()` returns a `CookieAttributes` with the flag turned on — so a
/// forgotten `()` in a builder chain is a *type error*, not a silent bug.
/// [`Default`] is "nothing set": the baseline a freshly completed cookie carries
/// and the one [`SetCookie::new`](crate::SetCookie::new) starts from.
///
/// `HttpOnly` and `Secure` are valueless presence flags on the wire, so their
/// setters are **nullary**: calling [`http_only`](CookieAttributes::http_only)
/// or [`secure`](CookieAttributes::secure) adds the attribute; not calling it
/// omits it. There is no "set to false" — leave it unset. `path` / `domain` are
/// validated [`Path`] / [`Domain`] newtypes (read them with `.as_str()`); an
/// invalid value leaves the attribute unset.
///
/// ```
/// use kekse::{CookieAttributes, Path, SameSite};
///
/// // Define a hardened policy once, reuse it across cookies.
/// let hardened = CookieAttributes::default()
///     .http_only()
///     .secure()
///     .same_site(SameSite::Strict)
///     .path("/");
/// assert!(hardened.secure); // read a field
/// assert_eq!(hardened.path, Path::new("/"));
/// ```
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CookieAttributes<'a> {
    /// The `HttpOnly` flag.
    pub http_only: bool,
    /// The `Secure` flag.
    pub secure: bool,
    /// The `SameSite` attribute, if set.
    pub same_site: Option<SameSite>,
    /// The `Path` attribute, if set — a validated [`Path`].
    pub path: Option<Path<'a>>,
    /// The `Domain` attribute, if set — a validated [`Domain`]. Omit for a
    /// host-only cookie.
    pub domain: Option<Domain<'a>>,
    /// The `Max-Age` attribute in seconds, if set. `0` deletes the cookie.
    pub max_age: Option<u64>,
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

    /// Set the `SameSite` attribute.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Set the `Path` attribute. An invalid path (a control byte, `;`, or
    /// non-ASCII — see [`Path`]) is rejected and leaves the attribute unset.
    #[must_use]
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Path::new(path);
        self
    }

    /// Set the `Domain` attribute. Omit for a host-only cookie. An invalid domain
    /// (see [`Domain`]) is rejected and leaves the attribute unset.
    #[must_use]
    pub fn domain(mut self, domain: &'a str) -> Self {
        self.domain = Domain::new(domain);
        self
    }

    /// Set the `Max-Age` attribute, in seconds. `0` instructs the client to
    /// delete the cookie. Rendered as a `u64` decimal — no saturation.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
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
            .same_site(SameSite::Lax)
            .path("/app")
            .domain("example.test")
            .max_age(60);
        assert!(a.http_only && a.secure);
        assert_eq!(a.same_site, Some(SameSite::Lax));
        assert_eq!(a.path, Path::new("/app"));
        assert_eq!(a.domain, Domain::new("example.test"));
        assert_eq!(a.max_age, Some(60));
    }

    #[test]
    fn path_and_domain_reject_injection() {
        // A `;` or a control byte cannot be smuggled into a Path/Domain value.
        assert_eq!(Path::new("/a;b"), None);
        assert_eq!(Path::new("/a\r\nb"), None);
        assert_eq!(Domain::new("ex\0ample"), None);
        // The attribute setter drops an invalid value rather than storing it.
        assert_eq!(CookieAttributes::default().path("/a\0b").path, None);
        // A clean value round-trips.
        assert_eq!(Path::new("/ok").map(|p| p.as_str()), Some("/ok"));
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
        // Empty: every byte is an av-octet (vacuously) → accepted.
        assert_eq!(Path::new("").map(|p| p.as_str()), Some(""));
        assert_eq!(Domain::new("").map(|d| d.as_str()), Some(""));
        // SP (0x20) is an av-octet → space-only paths are valid.
        assert!(Path::new(" ").is_some());
        assert!(Path::new("   ").is_some());
        // HTAB (0x09) is a control, not an av-octet → rejected.
        assert!(Path::new("\t").is_none());
        assert!(Path::new("a\tb").is_none());
        // Digits (0x30..=0x39) are av-octets.
        assert!(Path::new("12345").is_some());
        assert!(Domain::new("123").is_some());
    }
}
