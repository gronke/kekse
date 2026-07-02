//! The `axum` feature's `CookieJarBuf` extractor, driven through a real axum
//! router — proving the `axum-core` impl plugs into a live `axum` handler and
//! honours kekse's contracts: the handler picks the read mode (strict for a
//! session id, lenient for a preference), and extraction is infallible.
#![cfg(feature = "axum")]

use axum::Router;
use axum::body::Body;
use axum::http::header::COOKIE;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use tower::ServiceExt; // oneshot

use kekse::CookieJarBuf;

/// Reads the session id strictly: a `SID` is cookie-octets, so a spaced or
/// otherwise non-octet value is refused rather than trusted.
async fn read_sid(cookies: CookieJarBuf) -> String {
    cookies
        .jar_strict()
        .get_all("SID")
        .find(|c| !c.value().is_empty())
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "<none>".to_owned())
}

/// Reads a display preference leniently: the quoted / whitespace form is fine.
async fn read_pref(cookies: CookieJarBuf) -> String {
    cookies
        .jar()
        .get("pref")
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "<none>".to_owned())
}

fn app() -> Router {
    Router::new()
        .route("/sid", get(read_sid))
        .route("/pref", get(read_pref))
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn get_request(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(COOKIE, c);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn extracts_and_reads_session_strictly() {
    let resp = app()
        .oneshot(get_request("/sid", Some("a=1; SID=deadbeef; b=2")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "deadbeef");
}

#[tokio::test]
async fn strict_view_refuses_a_spaced_session_value() {
    // `SID=dead beef` is a valid header (space is allowed on the wire), but the
    // space is not a cookie-octet, so the strict view skips it.
    let resp = app()
        .oneshot(get_request("/sid", Some("SID=dead beef")))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "<none>");
}

#[tokio::test]
async fn missing_cookie_header_extracts_infallibly() {
    // No `Cookie:` header at all: extraction still succeeds with an empty jar.
    let resp = app().oneshot(get_request("/sid", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "<none>");
}

#[tokio::test]
async fn lenient_view_reads_a_quoted_preference() {
    let resp = app()
        .oneshot(get_request("/pref", Some(r#"pref="dark mode""#)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "dark mode");
}

#[tokio::test]
async fn fail_soft_junk_never_hides_the_session_cookie() {
    // Header-safe junk around a valid SID must not evict it.
    let header = "theme; consent=\"a, b\"; SID=deadbeef; tracking=";
    let resp = app()
        .oneshot(get_request("/sid", Some(header)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "deadbeef");
}

#[tokio::test]
async fn obs_text_in_the_header_never_hides_the_session_cookie() {
    // 0xE9 is obs-text: a perfectly legal HeaderValue byte that is not UTF-8.
    // The extractor takes the header bytes verbatim, so only the pair carrying
    // the stray byte is refused — the session cookie beside it still reads.
    // (The String-backed extractor dropped this ENTIRE header at to_str().)
    let header = axum::http::HeaderValue::from_bytes(b"pref=caf\xE9; SID=deadbeef").unwrap();
    let request = Request::builder()
        .uri("/sid")
        .header(COOKIE, header)
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "deadbeef");
}
