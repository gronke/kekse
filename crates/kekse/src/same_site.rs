//! The `SameSite` cookie attribute.

use std::fmt;

/// The `SameSite` cookie attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub fn as_str(self) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_site_tokens() {
        assert_eq!(SameSite::Strict.as_str(), "Strict");
        assert_eq!(SameSite::Lax.as_str(), "Lax");
        assert_eq!(SameSite::None.as_str(), "None");
    }
}
