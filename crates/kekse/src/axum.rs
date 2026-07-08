//! axum integration (behind the `axum` feature), both directions: extract the
//! request `Cookie:` header as an owned [`CookieJarBuf`], and append response
//! `Set-Cookie` headers by returning a [`SetCookie`] straight from a handler.
//!
//! [`CookieJar`] borrows the header it parses, so it cannot be returned by an
//! extractor (which must own what it hands the handler). [`CookieJarBuf`] is its
//! owned counterpart — bytes-backed, the way [`PathBuf`] backs [`Path`] — and
//! lends a borrowed [`CookieJar`] on demand.
//!
//! On the response side, [`SetCookie`] implements `IntoResponseParts` (and
//! `IntoResponse`), so a handler returns `(set_cookie, body)` and the header is
//! **appended** — cookies accumulate, never overwrite. Several cookies compose
//! as tuple elements, and `Option<SetCookie>` works through axum's blanket
//! impl. The one failable case is a [`Raw`](crate::ValueEncoding::Raw) value
//! carrying a header-illegal byte: that returns a typed [`BadSetCookie`]
//! (`500`), never a silently dropped cookie.
//!
//! ```no_run
//! use axum::routing::get;
//! use axum::Router;
//! use kekse::{Path, SameSite, SetCookie};
//!
//! async fn login() -> (SetCookie<'static>, &'static str) {
//!     let cookie = SetCookie::new("SID", "deadbeef")
//!         .http_only()
//!         .secure()
//!         .same_site(SameSite::Strict)
//!         .path(Path::new("/").expect("`/` is a valid path"))
//!         .max_age(3600);
//!     (cookie, "logged in")
//! }
//!
//! let app: Router = Router::new().route("/login", get(login));
//! # let _ = app;
//! ```
//!
//! The implementation depends only on `axum-core`, not the whole `axum` crate,
//! so turning the feature on stays light; it targets the very
//! `FromRequestParts` / `IntoResponseParts` traits `axum` re-exports, so it
//! drops straight into a handler signature.

use std::convert::Infallible;
use std::fmt;

use axum_core::extract::FromRequestParts;
use axum_core::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use http::StatusCode;
use http::header::{COOKIE, SET_COOKIE};
use http::request::Parts;

use crate::jar::CookieJar;
use crate::report::{PairIssue, Reported};
use crate::set_cookie::SetCookie;

/// An owned request `Cookie:` header — the owned counterpart to the borrowing
/// [`CookieJar`], as [`PathBuf`] is to [`Path`]. Use it as an axum extractor;
/// extraction is **infallible** — a missing or malformed header just yields an
/// empty (or partial) jar, matching kekse's fail-soft parsing.
///
/// It keeps the raw header *bytes* and defers parsing to the call site, because
/// the read *mode* is a per-handler security choice: take [`jar_strict`] for a
/// session id or any value you minted yourself (cookie-octets only), and
/// [`jar`] for a display preference or other value that may legitimately arrive
/// quoted or whitespace-bearing. Picking for you would take that choice away.
///
/// Bytes, not a `String`: a `HeaderValue` may legally carry obs-text
/// (`>= 0x80`), and the byte-level readers keep fail-soft **per pair** — a pair
/// carrying a stray byte is refused individually (see
/// [`parse_pairs_bytes`](crate::parse_pairs_bytes)) instead of costing the
/// whole header at a `to_str()` boundary.
///
/// ```no_run
/// use axum::routing::get;
/// use axum::Router;
/// use kekse::CookieJarBuf;
///
/// async fn whoami(cookies: CookieJarBuf) -> String {
///     let strict = cookies.jar_strict(); // the jar plus every refused pair
///     strict
///         .value
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
    raw: Vec<u8>,
}

impl CookieJarBuf {
    /// Wrap a raw `Cookie:` header value (`&str`, `String`, `&[u8]`, `Vec<u8>` —
    /// anything `Into<Vec<u8>>`). Handy for tests and non-axum callers; the
    /// extractor builds this for you from the request.
    pub fn from_header(raw: impl Into<Vec<u8>>) -> Self {
        Self { raw: raw.into() }
    }

    /// The **lenient** view: the [`CookieJar`] plus every refused pair as a
    /// [`PairIssue`] (tolerates the quoted and whitespace-bearing forms).
    /// Parses on demand, borrowing the owned header.
    pub fn jar(&self) -> Reported<CookieJar<'_>, PairIssue<'_>> {
        CookieJar::parse_bytes(&self.raw)
    }

    /// The **strict** view (cookie-octets only; whitespace and every other
    /// non-octet refused — and witnessed in the report). The reader for a
    /// session id or any value you minted yourself. Parses on demand,
    /// borrowing the owned header.
    pub fn jar_strict(&self) -> Reported<CookieJar<'_>, PairIssue<'_>> {
        CookieJar::parse_bytes_strict(&self.raw)
    }

    /// The fail-hard **lenient** read: the jar if every pair parsed, else a
    /// ready-to-return [`BadCookieHeader`] rejection (`400 Bad Request`). The
    /// one-line opt-out of fail-soft for a handler that would rather refuse a
    /// mangled header than serve a partial jar:
    ///
    /// ```no_run
    /// use axum::routing::get;
    /// use axum::Router;
    /// use kekse::{BadCookieHeader, CookieJarBuf};
    ///
    /// async fn whoami(cookies: CookieJarBuf) -> Result<String, BadCookieHeader> {
    ///     let jar = cookies.try_jar_strict()?; // anything wrong -> 400
    ///     Ok(jar.get("SID").map(|c| c.value().to_owned()).unwrap_or_default())
    /// }
    ///
    /// let app: Router = Router::new().route("/", get(whoami));
    /// # let _ = app;
    /// ```
    ///
    /// The error is owned (a count, not the header bytes), so returning it
    /// while the jar borrows `self` composes; for the issue details, read
    /// [`jar`](CookieJarBuf::jar) instead.
    pub fn try_jar(&self) -> Result<CookieJar<'_>, BadCookieHeader> {
        Self::clean_or_reject(self.jar())
    }

    /// The fail-hard **strict** read — see [`try_jar`](CookieJarBuf::try_jar).
    /// Strict counts whitespace-bearing values among the issues, so this is the
    /// gate for a session id or any value you minted yourself.
    pub fn try_jar_strict(&self) -> Result<CookieJar<'_>, BadCookieHeader> {
        Self::clean_or_reject(self.jar_strict())
    }

    fn clean_or_reject<'a>(
        reported: Reported<CookieJar<'a>, PairIssue<'a>>,
    ) -> Result<CookieJar<'a>, BadCookieHeader> {
        match reported.into_result() {
            Ok(jar) => Ok(jar),
            Err((_, issues)) => Err(BadCookieHeader {
                issues: issues.len(),
            }),
        }
    }

    /// The raw `Cookie:` header bytes this was built from (repeats joined with
    /// `; `). Bytes, not `&str` — the buffer may carry obs-text that is not
    /// UTF-8; the parsed views ([`jar`](CookieJarBuf::jar) /
    /// [`jar_strict`](CookieJarBuf::jar_strict)) are where validated text lives.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// The rejection [`CookieJarBuf::try_jar`] / [`try_jar_strict`](CookieJarBuf::try_jar_strict)
/// return: the request's `Cookie:` header carried at least one malformed pair.
/// As a response it is `400 Bad Request` with a static body — it reports the
/// issue *count* only and never echoes header bytes, so a corrupted cookie
/// cannot ride an error page back out.
#[derive(Clone, Debug)]
pub struct BadCookieHeader {
    issues: usize,
}

impl BadCookieHeader {
    /// How many pairs were refused.
    pub fn issues(&self) -> usize {
        self.issues
    }
}

impl fmt::Display for BadCookieHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} malformed pair(s) in the Cookie header", self.issues)
    }
}

impl std::error::Error for BadCookieHeader {}

impl IntoResponse for BadCookieHeader {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

/// The rejection [`SetCookie`]'s `IntoResponseParts` returns: the rendered
/// cookie is not a valid header value. Only possible under
/// [`Raw`](crate::ValueEncoding::Raw) with a header-illegal byte (CR, LF, NUL,
/// or another control) — every managed encoding is always header-safe. As a
/// response it is `500 Internal Server Error` with a static body: the failure
/// is the handler's bug, never the client's, and like [`BadCookieHeader`] it
/// never echoes cookie bytes. The underlying `InvalidHeaderValue` rides as
/// [`source`](std::error::Error::source) for logs.
///
/// The axum-extra convention of silently dropping such a cookie is deliberately
/// rejected here: a security cookie that fails to set must fail loudly.
#[derive(Debug)]
pub struct BadSetCookie {
    source: http::header::InvalidHeaderValue,
}

impl fmt::Display for BadSetCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a Set-Cookie value could not form a header value \
             (a Raw-encoded value carrying a header-illegal byte)",
        )
    }
}

impl std::error::Error for BadSetCookie {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl IntoResponse for BadSetCookie {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

impl IntoResponseParts for SetCookie<'_> {
    type Error = BadSetCookie;

    /// **Append** the rendered `Set-Cookie` header — never insert, so multiple
    /// cookies (tuple elements, middleware layers) accumulate on the response.
    ///
    /// # Errors
    ///
    /// Only a [`Raw`](crate::ValueEncoding::Raw) value carrying a
    /// header-illegal byte fails, as the typed 500 [`BadSetCookie`]; the
    /// managed encodings never error here.
    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        let value = http::HeaderValue::try_from(&self).map_err(|source| BadSetCookie { source })?;
        res.headers_mut().append(SET_COOKIE, value);
        Ok(res)
    }
}

impl IntoResponse for SetCookie<'_> {
    /// A lone [`SetCookie`] as the whole response: the header plus an empty
    /// body — the standard composition over the `IntoResponseParts` impl.
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}

impl<S> FromRequestParts<S> for CookieJarBuf
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        // A compliant request sends a single `Cookie:` header; join any repeats
        // with `; ` so a split header still reads as one pair list. The bytes are
        // taken verbatim — no `to_str()` gate — so a header value carrying
        // obs-text loses only the pair that carries it, at parse time, not every
        // pair it arrived with. Extraction stays infallible.
        let values = parts.headers.get_all(COOKIE);
        let (count, bytes) = values
            .iter()
            .fold((0usize, 0usize), |(count, bytes), value| {
                (count + 1, bytes + value.as_bytes().len())
            });
        // Exact size: every value plus one "; " joint between adjacent ones.
        let mut raw = Vec::with_capacity(bytes + 2 * count.saturating_sub(1));
        for value in values {
            if !raw.is_empty() {
                raw.extend_from_slice(b"; ");
            }
            raw.extend_from_slice(value.as_bytes());
        }
        Ok(Self { raw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_header_lends_both_views() {
        let buf = CookieJarBuf::from_header(r#"a=1; SID=x; pref="dark mode""#);
        assert_eq!(buf.as_bytes(), br#"a=1; SID=x; pref="dark mode""#);

        // Lenient sees the quoted preference and the session id.
        assert_eq!(
            buf.jar().value.get("pref").map(|c| c.value()),
            Some("dark mode")
        );
        assert_eq!(buf.jar().value.get("SID").map(|c| c.value()), Some("x"));

        // Strict keeps the octet-clean SID but drops the spaced preference.
        assert_eq!(
            buf.jar_strict().value.get("SID").map(|c| c.value()),
            Some("x")
        );
        assert!(buf.jar_strict().value.get("pref").is_none());
    }

    #[test]
    fn empty_header_yields_empty_jars() {
        let buf = CookieJarBuf::default();
        assert!(buf.jar().value.is_empty());
        assert!(buf.jar_strict().value.is_empty());
        assert_eq!(buf.as_bytes(), b"");
    }

    #[test]
    fn obs_text_costs_only_its_own_pair() {
        // 0xE9 is valid obs-text in a HeaderValue but not UTF-8; the old
        // String-backed buffer had to drop the whole header at to_str().
        let buf = CookieJarBuf::from_header(&b"good=1; bad=caf\xE9; SID=deadbeef"[..]);
        assert_eq!(buf.jar().value.get("good").map(|c| c.value()), Some("1"));
        assert_eq!(
            buf.jar_strict().value.get("SID").map(|c| c.value()),
            Some("deadbeef")
        );
        assert!(buf.jar().value.get("bad").is_none());
    }

    // ---- the response side -------------------------------------------------

    #[test]
    fn set_cookie_into_response_appends_the_header() {
        let response = SetCookie::new("SID", "x").secure().into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let values: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "SID=x; Secure");
    }

    #[test]
    fn cookies_accumulate_through_append_never_insert() {
        // Tuple composition (axum's IntoResponseParts chaining) must yield one
        // Set-Cookie header per cookie, in order — insert would keep only one.
        let response = (SetCookie::new("a", "1"), SetCookie::new("b", "2"), "ok").into_response();
        let values: Vec<String> = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(values, ["a=1", "b=2"]);
    }

    #[test]
    fn raw_injection_becomes_the_typed_500_not_a_silent_drop() {
        let bad = SetCookie::new("SID", "x\r\nSet-Cookie: evil=1")
            .with_encoding(crate::ValueEncoding::Raw);
        let response = bad.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(SET_COOKIE).is_none());
    }

    #[test]
    fn bad_set_cookie_display_never_echoes_cookie_bytes() {
        // The Display is static text; the offending bytes ride only as the
        // structured Error::source for logs.
        let source = http::HeaderValue::from_str("a\r\nb").unwrap_err();
        let error = BadSetCookie { source };
        assert_eq!(
            error.to_string(),
            "a Set-Cookie value could not form a header value \
             (a Raw-encoded value carrying a header-illegal byte)"
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}
