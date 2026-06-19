//! The `Set-Cookie` response attributes as a standalone [`CookieAttributes`] —
//! the part a request `Cookie:` cookie does not carry. A
//! [`SetCookie`](crate::SetCookie) is a [`Cookie`](crate::Cookie) kernel plus a
//! `CookieAttributes`.

use crate::same_site::SameSite;

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
/// omits it. There is no "set to false" — leave it unset.
///
/// ```
/// use kekse::{CookieAttributes, SameSite};
///
/// // Define a hardened policy once, reuse it across cookies.
/// let hardened = CookieAttributes::default()
///     .http_only()
///     .secure()
///     .same_site(SameSite::Strict)
///     .path("/");
/// assert!(hardened.secure);            // read a field
/// assert_eq!(hardened.path, Some("/"));
/// ```
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct CookieAttributes<'a> {
    /// The `HttpOnly` flag.
    pub http_only: bool,
    /// The `Secure` flag.
    pub secure: bool,
    /// The `SameSite` attribute, if set.
    pub same_site: Option<SameSite>,
    /// The `Path` attribute, if set.
    pub path: Option<&'a str>,
    /// The `Domain` attribute, if set. Omit for a host-only cookie.
    pub domain: Option<&'a str>,
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

    /// Set the `Path` attribute.
    #[must_use]
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the `Domain` attribute. Omit for a host-only cookie.
    #[must_use]
    pub fn domain(mut self, domain: &'a str) -> Self {
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
        assert_eq!(a.path, Some("/app"));
        assert_eq!(a.domain, Some("example.test"));
        assert_eq!(a.max_age, Some(60));
    }
}
