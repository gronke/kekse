//! axum integration (behind the `axum` feature): extract the request `Cookie:`
//! header as an owned [`CookieJarBuf`].
//!
//! [`CookieJar`] borrows the header it parses, so it cannot be returned by an
//! extractor (which must own what it hands the handler). [`CookieJarBuf`] is its
//! owned counterpart — `String`-backed, the way [`PathBuf`] backs [`Path`] —
//! and lends a borrowed [`CookieJar`] on demand.
//!
//! The implementation depends only on `axum-core`, not the whole `axum` crate,
//! so turning the feature on stays light; it targets the very
//! `FromRequestParts` trait `axum` re-exports, so it drops straight into a
//! handler signature.

use std::convert::Infallible;

use axum_core::extract::FromRequestParts;
use http::header::COOKIE;
use http::request::Parts;

use crate::jar::CookieJar;

/// An owned request `Cookie:` header — the `String`-backed counterpart to the
/// borrowing [`CookieJar`], as [`PathBuf`] is to [`Path`]. Use it as an axum
/// extractor; extraction is **infallible** — a missing or malformed header just
/// yields an empty (or partial) jar, matching kekse's fail-soft parsing.
///
/// It keeps the raw header and defers parsing to the call site, because the read
/// *mode* is a per-handler security choice: take [`jar_strict`] for a session id
/// or any value you minted yourself (cookie-octets only), and [`jar`] for a
/// display preference or other value that may legitimately arrive quoted or
/// whitespace-bearing. Picking for you would take that choice away.
///
/// ```no_run
/// use axum::routing::get;
/// use axum::Router;
/// use kekse::CookieJarBuf;
///
/// async fn whoami(cookies: CookieJarBuf) -> String {
///     cookies
///         .jar_strict()
///         .get_all("SID")
///         .find(|c| !c.value().is_empty())
///         .map(|c| c.value().to_owned())
///         .unwrap_or_else(|| "anonymous".to_owned())
/// }
///
/// let app: Router = Router::new().route("/", get(whoami));
/// # let _ = app;
/// ```
///
/// [`PathBuf`]: std::path::PathBuf
/// [`Path`]: std::path::Path
/// [`jar`]: CookieJarBuf::jar
/// [`jar_strict`]: CookieJarBuf::jar_strict
#[derive(Clone, Debug, Default)]
pub struct CookieJarBuf {
    raw: String,
}

impl CookieJarBuf {
    /// Wrap a raw `Cookie:` header value. Handy for tests and non-axum callers;
    /// the extractor builds this for you from the request.
    pub fn from_header(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    /// The **lenient** [`CookieJar`] view (tolerates the quoted and
    /// whitespace-bearing forms). Parses on demand, borrowing the owned header.
    pub fn jar(&self) -> CookieJar<'_> {
        CookieJar::parse(&self.raw)
    }

    /// The **strict** [`CookieJar`] view (cookie-octets only; whitespace and
    /// every other non-octet refused). The reader for a session id or any value
    /// you minted yourself. Parses on demand, borrowing the owned header.
    pub fn jar_strict(&self) -> CookieJar<'_> {
        CookieJar::parse_strict(&self.raw)
    }

    /// The raw `Cookie:` header this was built from (repeats joined with `; `).
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl<S> FromRequestParts<S> for CookieJarBuf
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        // A compliant request sends a single `Cookie:` header; join any repeats
        // with `; ` so a split header still reads as one pair list. A non-ASCII
        // header value can't carry a valid cookie pair, so skipping it (rather
        // than erroring) keeps extraction infallible — malformed input is
        // dropped later, at parse time, not here.
        let raw = parts
            .headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join("; ");
        Ok(Self { raw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_header_lends_both_views() {
        let buf = CookieJarBuf::from_header(r#"a=1; SID=x; pref="dark mode""#);
        assert_eq!(buf.as_str(), r#"a=1; SID=x; pref="dark mode""#);

        // Lenient sees the quoted preference and the session id.
        assert_eq!(buf.jar().get("pref").map(|c| c.value()), Some("dark mode"));
        assert_eq!(buf.jar().get("SID").map(|c| c.value()), Some("x"));

        // Strict keeps the octet-clean SID but drops the spaced preference.
        assert_eq!(buf.jar_strict().get("SID").map(|c| c.value()), Some("x"));
        assert!(buf.jar_strict().get("pref").is_none());
    }

    #[test]
    fn empty_header_yields_empty_jars() {
        let buf = CookieJarBuf::default();
        assert!(buf.jar().is_empty());
        assert!(buf.jar_strict().is_empty());
        assert_eq!(buf.as_str(), "");
    }
}
