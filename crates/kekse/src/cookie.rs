//! The baked [`Cookie`] — a request `name=value` with no attributes — and its
//! bridge back to the [`SetCookie`](crate::SetCookie) recipe via `unbake`.

use std::borrow::Cow;

use crate::set_cookie::SetCookie;

/// A *baked* cookie: the `name=value` a request `Cookie:` header carries, with
/// no attributes (those live only on the recipe, [`SetCookie`](crate::SetCookie)).
/// The value is the **decoded** form the application reads, held as a [`Cow`] so
/// a value that parsed untouched stays borrowed and a decoded one is owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie<'a> {
    name: &'a str,
    value: Cow<'a, str>,
}

impl<'a> Cookie<'a> {
    /// A cookie named `name` carrying `value` (a borrowed `&str` or an owned
    /// `String` — anything `Into<Cow<str>>`).
    pub fn new(name: &'a str, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    /// The cookie-name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The decoded cookie-value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Take the value, reusing the allocation when it is already owned and
    /// borrowing otherwise — the zero-copy way to lift a parsed value out.
    pub fn into_value(self) -> Cow<'a, str> {
        self.value
    }

    /// Promote a baked cookie back into a [`SetCookie`](crate::SetCookie) recipe
    /// with no attributes and the default [`Auto`](crate::ValueEncoding::Auto)
    /// encoding, ready to decorate and re-emit. The value is carried verbatim (a
    /// decoded value stays decoded), so `unbake` round-trips the value *string*,
    /// not the wire bytes — re-rendering under `Auto` re-encodes as needed. The
    /// inverse of [`SetCookie::bake`](crate::SetCookie::bake).
    pub fn unbake(self) -> SetCookie<'a> {
        SetCookie::from_value(self.name, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bake_drops_attributes_keeps_value() {
        let cookie = SetCookie::new("n", "v")
            .secure(true)
            .max_age(9)
            .path("/x")
            .bake();
        assert_eq!(cookie.name(), "n");
        assert_eq!(cookie.value(), "v");
        // Re-emitting the baked cookie is a bare pair — the attributes are gone.
        assert_eq!(cookie.unbake().to_string(), "n=v");
    }

    #[test]
    fn unbake_defaults_to_a_bare_pair() {
        assert_eq!(Cookie::new("n", "v").unbake().to_string(), "n=v");
    }

    #[test]
    fn bake_unbake_is_value_identity_not_wire_identity() {
        let cookie = Cookie::new("n", "a b");
        // The value string is carried verbatim...
        assert_eq!(cookie.value(), "a b");
        // ...but a re-rendered recipe re-encodes under the default Percent
        // (whitespace → %20), so bake∘unbake round-trips the value, not the wire.
        assert_eq!(cookie.unbake().to_string(), "n=a%20b");
    }

    #[test]
    fn bake_keeps_a_clean_value_borrowed() {
        // bake is a structural move: a borrowed recipe yields a borrowed cookie.
        assert!(matches!(
            SetCookie::new("n", "deadbeef").bake().into_value(),
            Cow::Borrowed(_)
        ));
    }
}
