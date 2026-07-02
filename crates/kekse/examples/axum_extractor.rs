//! The `CookieJarBuf` axum extractor (feature `axum`), driven in-memory.
//!
//! Run with: `cargo run -p kekse --example axum_extractor --features axum`

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header::COOKIE};
use axum::routing::get;
use kekse::CookieJarBuf;
use tower::ServiceExt; // for `oneshot`

/// A handler that reads the session id from the request cookies. Extraction is
/// infallible — a missing or malformed `Cookie:` header yields an empty jar —
/// and `jar_strict` reads the id as cookie-octets, skipping a stale empty `SID=`.
async fn whoami(cookies: CookieJarBuf) -> String {
    cookies
        .jar_strict()
        .get_all("SID")
        .find(|c| !c.value().is_empty())
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "anonymous".to_owned())
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(whoami));

    // `tower::oneshot` drives the router in-memory — no socket, no port.
    for (cookie, want) in [
        ("SID=deadbeef; theme=dark", "deadbeef"),
        ("SID=; SID=real", "real"), // stale empty SID skipped
        ("", "anonymous"),          // no Cookie header at all
    ] {
        let mut builder = Request::builder().uri("/");
        if !cookie.is_empty() {
            builder = builder.header(COOKIE, cookie);
        }
        let request = builder.body(Body::empty()).expect("valid request");

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("infallible router");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collected");
        let got = String::from_utf8(bytes.to_vec()).expect("ASCII body");

        println!("Cookie: {cookie:?} -> {got}");
        assert_eq!(got, want);
    }
}
