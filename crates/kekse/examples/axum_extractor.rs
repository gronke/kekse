//! The `CookieJarBuf` axum extractor (feature `axum`), driven in-memory.
//!
//! Run with: `cargo run -p kekse --example axum_extractor --features axum`

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header::COOKIE};
use axum::routing::get;
use kekse::{BadCookieHeader, CookieJarBuf};
use tower::ServiceExt; // for `oneshot`

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
        .route("/", get(whoami))
        .route("/checked", get(whoami_or_400));

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
