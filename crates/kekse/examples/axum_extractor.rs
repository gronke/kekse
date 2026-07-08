//! The axum integration (feature `axum`), both directions, driven in-memory:
//! a handler *sets* a cookie by returning it, and the extractor reads it back.
//!
//! Run with: `cargo run -p kekse --example axum_extractor --features axum`

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::routing::get;
use kekse::{BadCookieHeader, CookieJarBuf, Path, SameSite, SetCookie};
use tower::ServiceExt; // for `oneshot`

/// The response side: return the cookie and the body — the `IntoResponseParts`
/// impl appends the `Set-Cookie` header, and a `Raw` value with an illegal
/// byte would become a typed 500 instead of a silently dropped cookie.
async fn login() -> (SetCookie<'static>, &'static str) {
    let cookie = SetCookie::new("SID", "deadbeef")
        .http_only()
        .secure()
        .same_site(SameSite::Strict)
        .path(Path::new("/").expect("`/` is a valid path"))
        .max_age(3600);
    (cookie, "logged in")
}

/// A handler that reads the session id from the request cookies. Extraction is
/// infallible — a missing or malformed `Cookie:` header yields an empty jar —
/// and `jar_strict` reads the id as cookie-octets, skipping a stale empty `SID=`.
async fn whoami(cookies: CookieJarBuf) -> String {
    cookies
        .jar_strict()
        .value
        .get_all("SID")
        .find(|c| !c.value().is_empty())
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "anonymous".to_owned())
}

/// The fail-hard sibling: a handler that refuses a mangled header outright.
/// `try_jar_strict` returns the jar only when every pair parsed; the `?` turns
/// anything less into a ready-made `400 Bad Request` that reports a count and
/// never echoes header bytes.
async fn whoami_or_400(cookies: CookieJarBuf) -> Result<String, BadCookieHeader> {
    let jar = cookies.try_jar_strict()?;
    Ok(jar
        .get("SID")
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "anonymous".to_owned()))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", get(login))
        .route("/", get(whoami))
        .route("/checked", get(whoami_or_400));

    // The full browser dance, in-memory: /login mints the cookie, the client
    // echoes the `name=value` pair back, and the extractor reads it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("infallible router");
    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .expect("login sets a cookie")
        .to_str()
        .expect("ASCII header")
        .to_owned();
    println!("GET /login -> Set-Cookie: {set_cookie}");
    let pair = set_cookie.split(';').next().expect("leading pair");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(COOKIE, pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("infallible router");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collected");
    let whoami_body = String::from_utf8(bytes.to_vec()).expect("ASCII body");
    println!("GET / with Cookie: {pair:?} -> {whoami_body}");
    assert_eq!(whoami_body, "deadbeef");

    // `tower::oneshot` drives the router in-memory — no socket, no port.
    for (uri, cookie, want) in [
        ("/", "SID=deadbeef; theme=dark", "deadbeef"),
        ("/", "SID=; SID=real", "real"), // stale empty SID skipped
        ("/", "", "anonymous"),          // no Cookie header at all
        ("/checked", "SID=deadbeef", "deadbeef"),
        // The fail-hard route: one spaced pair → 400, not a partial jar.
        (
            "/checked",
            "SID=dead beef",
            "1 malformed pair(s) in the Cookie header",
        ),
    ] {
        let mut builder = Request::builder().uri(uri);
        if !cookie.is_empty() {
            builder = builder.header(COOKIE, cookie);
        }
        let request = builder.body(Body::empty()).expect("valid request");

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("infallible router");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collected");
        let got = String::from_utf8(bytes.to_vec()).expect("ASCII body");

        println!("GET {uri} with Cookie: {cookie:?} -> {status} {got}");
        assert_eq!(got, want);
    }
}
