//! Integration tests: kekse driven through real axum request/response types.
//!
//! These challenge the two promises a consumer leans on when wiring kekse
//! into an axum app:
//!
//! 1. every managed [`SetCookie`] rendering is a valid `HeaderValue`, so
//!    *setting* a cookie never fails on the HTTP layer (and `Raw` injection is
//!    caught there, not smuggled);
//! 2. [`parse_pairs`] / [`parse_pairs_strict`] read back what was set, fail
//!    soft, straight off a live `Cookie` request header — including the browser
//!    dance of set-cookie-then-send-it-back.

use axum::body::Body;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt; // oneshot

use kekse::{parse_pairs, parse_pairs_strict, SameSite, SetCookie, ValueEncoding};

/// Values a real app might try to stuff into a cookie — separators, control
/// bytes, quotes, percent, non-ASCII, whitespace.
const HOSTILE: &[&str] = &[
    "plain",
    "deadbeef",
    "a b",
    "hello world",
    "a;b",
    "a,b",
    "a\"b",
    "a\\b",
    "café",
    "🦀🍪",
    "100%",
    "%41",
    "a\r\nX-Injected: y",
    "\u{0}\u{1f}\u{7f}",
    "  spaced  ",
    "a b;c d",
];

// ---- (1) managed renderings are always valid HeaderValues -----------------

#[test]
fn managed_set_cookie_is_always_a_valid_header_value() {
    for v in HOSTILE {
        for enc in [
            ValueEncoding::Auto,
            ValueEncoding::Percent,
            ValueEncoding::Quoted,
        ] {
            let rendered = SetCookie::new("SID", *v)
                .with_encoding(enc)
                .http_only()
                .secure()
                .same_site(SameSite::Strict)
                .path("/")
                .max_age(3600)
                .to_set_cookie();
            let hv = HeaderValue::from_str(&rendered);
            assert!(
                hv.is_ok(),
                "{enc:?} of {v:?} must be a valid HeaderValue, got {rendered:?}"
            );
            // The header value round-trips byte-for-byte (output is pure ASCII).
            assert_eq!(hv.unwrap().to_str().unwrap(), rendered);
        }
    }
}

#[test]
fn raw_injection_is_caught_by_the_header_layer() {
    // `Raw` is the caller's responsibility; a value with CR/LF cannot become a
    // HeaderValue, so a consumer's clearing-cookie fallback engages instead of
    // a smuggled header.
    let rendered = SetCookie::new("SID", "x\r\nSet-Cookie: evil=1")
        .with_encoding(ValueEncoding::Raw)
        .to_set_cookie();
    assert!(HeaderValue::from_str(&rendered).is_err());
}

// ---- (2) the cookie round-trip through a live router ----------------------

/// Mints a session cookie the way an auth consumer does: strict `Percent`.
async fn set_handler() -> impl IntoResponse {
    let hv = HeaderValue::from_str(
        &SetCookie::new("SID", "deadbeefcafe")
            .with_encoding(ValueEncoding::Percent)
            .http_only()
            .secure()
            .same_site(SameSite::Strict)
            .path("/")
            .max_age(3600)
            .to_set_cookie(),
    )
    .unwrap();
    ([(SET_COOKIE, hv)], "set")
}

/// Reads the SID strictly — a session id is cookie-octets, so a spaced or
/// otherwise non-octet value is refused rather than trusted.
async fn read_sid(headers: HeaderMap) -> String {
    headers
        .get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            parse_pairs_strict(h)
                .find(|(n, v)| *n == "SID" && !v.is_empty())
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_else(|| "<none>".to_string())
}

/// Reads a general preference cookie leniently (tolerates the quoted /
/// whitespace form kekse's `Auto` encoder emits).
async fn read_pref(headers: HeaderMap) -> String {
    headers
        .get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            parse_pairs(h)
                .find(|(n, _)| *n == "pref")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_else(|| "<none>".to_string())
}

fn app() -> Router {
    Router::new()
        .route("/set", get(set_handler))
        .route("/read", get(read_sid))
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
async fn set_cookie_then_read_it_back_through_axum() {
    let app = app();

    // 1. hit /set, capture the Set-Cookie header it minted.
    let resp = app
        .clone()
        .oneshot(get_request("/set", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("SID=deadbeefcafe;"));

    // 2. a browser echoes just `name=value` back as a Cookie header.
    let pair = set_cookie.split(';').next().unwrap();
    let resp = app
        .clone()
        .oneshot(get_request("/read", Some(pair)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "deadbeefcafe");
}

#[tokio::test]
async fn lenient_reads_quoted_and_spaced_values_off_a_real_header() {
    let app = app();
    // `Auto` quotes to carry the space (opt-in now that `Percent` is the
    // default); the lenient reader handles the quoted form off a real header.
    let rendered = SetCookie::new("pref", "dark mode")
        .with_encoding(ValueEncoding::Auto)
        .to_set_cookie();
    assert_eq!(rendered, "pref=\"dark mode\"");
    let resp = app
        .clone()
        .oneshot(get_request("/pref", Some(&rendered)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "dark mode");
}

#[tokio::test]
async fn strict_sid_read_refuses_a_spaced_value_the_lenient_path_would_take() {
    let app = app();
    // `SID=dead beef` is a valid HeaderValue (space is allowed), but the space
    // is not a cookie-octet, so the strict SID read refuses it.
    let resp = app
        .clone()
        .oneshot(get_request("/read", Some("SID=dead beef")))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "<none>");
}

#[tokio::test]
async fn fail_soft_junk_never_hides_the_session_cookie() {
    let app = app();
    // Header-safe junk around a valid SID: a malformed pair (no `=`), a foreign
    // quoted cookie carrying a comma, and an empty trailing pair must not evict
    // the SID a later segment carries.
    let header = "theme; consent=\"a, b\"; SID=deadbeef; tracking=";
    let resp = app
        .clone()
        .oneshot(get_request("/read", Some(header)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "deadbeef");
}

#[tokio::test]
async fn many_cookies_session_at_the_end_is_found() {
    let app = app();
    let mut cookies: Vec<String> = (0..60).map(|i| format!("c{i}=v{i}")).collect();
    cookies.push("SID=feedface".to_string());
    let header = cookies.join("; ");
    let resp = app
        .clone()
        .oneshot(get_request("/read", Some(&header)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "feedface");
}

#[test]
fn percent_encoded_value_round_trips_through_the_http_layer() {
    // A non-octet value Percent-encodes to a valid HeaderValue and decodes back.
    for v in ["café", "a;b", "a b", "🦀", "100%"] {
        let rendered = SetCookie::new("SID", v)
            .with_encoding(ValueEncoding::Percent)
            .to_set_cookie();
        let hv = HeaderValue::from_str(&rendered).expect("percent output is header-safe");
        let on_wire = hv.to_str().unwrap();
        let pair = on_wire.split(';').next().unwrap();
        let got = parse_pairs_strict(pair)
            .find(|(n, _)| *n == "SID")
            .map(|(_, value)| value.into_owned());
        assert_eq!(got.as_deref(), Some(v), "round-trip {v:?} via {pair:?}");
    }
}
