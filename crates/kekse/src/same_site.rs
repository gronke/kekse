//! The `SameSite` cookie attribute.

use std::fmt;
use std::str::FromStr;

/// The `SameSite` cookie attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Never sent on any cross-site request.
    Strict,
    /// Sent on top-level cross-site GET navigations only.
    Lax,
    /// Sent on every cross-site request — honored only alongside `Secure`.
    None,
}

impl SameSite {
    /// The token as it appears in a `Set-Cookie` header: `Strict`/`Lax`/`None`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SameSite {
    type Err = ParseSameSiteError;

    /// Parse a `SameSite` token ASCII-case-insensitively — `Strict`, `Lax`, or
    /// `None` in any case — the inverse of [`as_str`](SameSite::as_str) /
    /// [`Display`](SameSite). Any other token is a [`ParseSameSiteError`]. Since
    /// `Display` always emits the canonical casing, `s.to_string().parse()`
    /// round-trips.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("Strict") {
            Ok(SameSite::Strict)
        } else if s.eq_ignore_ascii_case("Lax") {
            Ok(SameSite::Lax)
        } else if s.eq_ignore_ascii_case("None") {
            Ok(SameSite::None)
        } else {
            Err(ParseSameSiteError)
        }
    }
}

/// The error returned when a string is not a `SameSite` token (`Strict`/`Lax`/
/// `None`, case-insensitive) — see [`SameSite`]'s [`FromStr`] impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseSameSiteError;

impl fmt::Display for ParseSameSiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid SameSite value")
    }
}

impl std::error::Error for ParseSameSiteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_site_tokens() {
        assert_eq!(SameSite::Strict.as_str(), "Strict");
        assert_eq!(SameSite::Lax.as_str(), "Lax");
        assert_eq!(SameSite::None.as_str(), "None");
    }

    #[test]
    fn from_str_is_case_insensitive_and_round_trips() {
        assert_eq!("Strict".parse(), Ok(SameSite::Strict));
        assert_eq!("strict".parse(), Ok(SameSite::Strict));
        assert_eq!("LAX".parse(), Ok(SameSite::Lax));
        assert_eq!("nOnE".parse(), Ok(SameSite::None));
        assert!("bogus".parse::<SameSite>().is_err());
        assert!("".parse::<SameSite>().is_err());
        // Display emits the canonical casing, which FromStr accepts: round-trip.
        for s in [SameSite::Strict, SameSite::Lax, SameSite::None] {
            assert_eq!(s.to_string().parse::<SameSite>(), Ok(s));
        }
    }
}
