//! The request [`Cookie`] — a `name=value` kernel with no attributes — and its
//! completion into the response [`SetCookie`](crate::SetCookie).

use std::borrow::Cow;

use crate::attributes::CookieAttributes;
use crate::encoding::{encode_value, ValueEncoding};
use crate::set_cookie::SetCookie;

/// The request `Cookie:` cookie: a `name=value` pair with no attributes. It is
/// also the shared **kernel** a [`SetCookie`](crate::SetCookie) composes — the
/// `name`, `value`, and wire [`ValueEncoding`] every cookie carries in both
/// directions. A `Cookie:` header carries only pairs, so this type *has* no
/// attribute fields at all: whether an attribute is known is answered by which
/// type you hold, not by an `Option`.
///
/// The value is the **decoded** form the application reads, held as a [`Cow`] so
/// a value that parsed untouched stays borrowed and a decoded one is owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cookie<'a> {
    name: &'a str,
    value: Cow<'a, str>,
    encoding: ValueEncoding,
}

impl<'a> Cookie<'a> {
    /// A cookie named `name` carrying `value` (a borrowed `&str` or an owned
    /// `String` — anything `Into<Cow<str>>`), with the default [`ValueEncoding`].
    pub fn new(name: &'a str, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name,
            value: value.into(),
            encoding: ValueEncoding::default(),
        }
    }

    /// Choose how the value is escaped for the wire (default
    /// [`ValueEncoding::default`]).
    pub fn with_encoding(mut self, encoding: ValueEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// The cookie-name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The decoded cookie-value — the logical value, not its wire encoding.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Take the value, reusing the allocation when it is already owned and
    /// borrowing otherwise — the zero-copy way to lift a parsed value out.
    pub fn into_value(self) -> Cow<'a, str> {
        self.value
    }

    /// The value's wire encoding.
    pub fn encoding(&self) -> ValueEncoding {
        self.encoding
    }

    /// Render the request `Cookie:` pair — `name=value`, with the value escaped
    /// per the cookie's own [`encoding`](Cookie::encoding). Join several with
    /// `"; "` to build the header, or let
    /// [`CookieJar::to_header_value`](crate::CookieJar::to_header_value) build
    /// the whole header for you.
    pub fn to_request_pair(&self) -> String {
        self.to_pair(self.encoding)
    }

    /// Render the pair under an explicit `encoding`, overriding the cookie's own
    /// — the form [`CookieJar`](crate::CookieJar) uses to re-encode an entire
    /// header to one canonical encoding regardless of how each value arrived.
    pub fn to_pair(&self, encoding: ValueEncoding) -> String {
        format!("{}={}", self.name, encode_value(&self.value, encoding))
    }

    /// Complete this request kernel into a response
    /// [`SetCookie`](crate::SetCookie) with no attributes set — the
    /// [`CookieAttributes::default`] baseline — ready to decorate with the fluent
    /// setters. The central request→response transform, and the inverse of
    /// [`SetCookie::into_cookie`](crate::SetCookie::into_cookie). To apply a
    /// prebuilt attribute set instead, use
    /// [`with_attributes`](Cookie::with_attributes).
    pub fn into_set_cookie(self) -> SetCookie<'a> {
        self.with_attributes(CookieAttributes::default())
    }

    /// Complete this kernel into a [`SetCookie`](crate::SetCookie) carrying
    /// `attributes` — the way to apply a reusable, hardened attribute policy
    /// defined once and shared across cookies.
    pub fn with_attributes(self, attributes: CookieAttributes<'a>) -> SetCookie<'a> {
        SetCookie::from_parts(self, attributes)
    }
}

impl<'a> From<Cookie<'a>> for SetCookie<'a> {
    /// Same as [`Cookie::into_set_cookie`] — completes with default attributes.
    fn from(cookie: Cookie<'a>) -> Self {
        cookie.into_set_cookie()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_a_bare_pair_with_the_default_encoding() {
        let c = Cookie::new("SID", "deadbeef");
        assert_eq!(c.name(), "SID");
        assert_eq!(c.value(), "deadbeef");
        assert_eq!(c.encoding(), ValueEncoding::default());
    }

    #[test]
    fn value_borrows_when_clean() {
        assert!(matches!(
            Cookie::new("n", "deadbeef").into_value(),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn to_request_pair_escapes_per_encoding() {
        // Default Percent: a space rides as %20 (the request pair carries no attrs).
        assert_eq!(Cookie::new("pref", "a b").to_request_pair(), "pref=a%20b");
        // Auto quotes whitespace instead.
        assert_eq!(
            Cookie::new("pref", "a b")
                .with_encoding(ValueEncoding::Auto)
                .to_request_pair(),
            "pref=\"a b\""
        );
    }

    #[test]
    fn to_pair_honors_the_passed_encoding_over_the_stored_one() {
        // Stored encoding is the default Percent...
        let c = Cookie::new("pref", "a b");
        assert_eq!(c.to_pair(ValueEncoding::Percent), "pref=a%20b");
        // ...but to_pair renders under whatever encoding it is handed.
        assert_eq!(c.to_pair(ValueEncoding::Auto), "pref=\"a b\"");
        // to_request_pair stays the stored-encoding shorthand.
        assert_eq!(c.to_request_pair(), c.to_pair(ValueEncoding::Percent));
    }

    #[test]
    fn into_set_cookie_starts_bare() {
        let sc = Cookie::new("n", "v").into_set_cookie();
        assert_eq!(sc.name(), "n");
        assert_eq!(sc.value(), "v");
        // Every attribute absent: the default CookieAttributes is all-unset.
        assert_eq!(*sc.attributes(), crate::CookieAttributes::default());
        assert!(!sc.attributes().http_only);
        assert!(!sc.attributes().secure);
        assert_eq!(sc.attributes().same_site, None);
        assert_eq!(sc.attributes().path, None);
        assert_eq!(sc.attributes().domain, None);
        assert_eq!(sc.attributes().max_age, None);
        // `From` is the same transform.
        assert_eq!(
            SetCookie::from(Cookie::new("n", "v")).to_set_cookie(),
            "n=v"
        );
    }

    #[test]
    fn completion_then_demotion_round_trips_the_kernel() {
        let c = Cookie::new("n", "v").with_encoding(ValueEncoding::Percent);
        // Completing into a SetCookie then dropping the attributes recovers the kernel.
        assert_eq!(c.clone().into_set_cookie().into_cookie(), c);
    }

    #[test]
    fn completion_is_value_identity_not_wire_identity() {
        // The value string is carried verbatim into the recipe...
        let sc = Cookie::new("n", "a b").into_set_cookie();
        assert_eq!(sc.value(), "a b");
        // ...but rendering re-encodes under the default Percent (space → %20).
        assert_eq!(sc.to_set_cookie(), "n=a%20b");
    }
}
