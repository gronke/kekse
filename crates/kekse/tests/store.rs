//! End-to-end `CookieStore` coverage (the `store` feature): a capture-then-
//! replay session across origins, and a generative invariant — every cookie
//! the store attaches independently satisfies the RFC 6265 §5.4 send gates.

#![cfg(feature = "store")]

use kekse::{CookieStore, Insertion, OffsetDateTime, StoreConfig};
use time::macros::datetime;

const NOW: OffsetDateTime = datetime!(2026-07-11 12:00 UTC);

fn u(s: &str) -> url::Url {
    url::Url::parse(s).expect("test url")
}

fn header(store: &CookieStore, url: &url::Url, at: OffsetDateTime) -> String {
    store
        .cookie_header(url, at)
        .map(|h| {
            h.to_str()
                .expect("percent-encoded header is ASCII")
                .to_owned()
        })
        .unwrap_or_default()
}

/// One shopping session, captured from responses and replayed onto requests:
/// a Secure session cookie, a checkout-scoped token, and a registrable-domain
/// tracker — each travels exactly where §5.3/§5.4 say, and logout's deletion
/// idiom removes the session without touching the rest.
#[test]
fn capture_then_replay_across_origins() {
    let mut store = CookieStore::new();
    let login = u("https://shop.example.test/login");

    let mut response = http::HeaderMap::new();
    for line in [
        "SID=deadbeef; Secure; HttpOnly; Path=/",
        "csrf=t0ken; Secure; Path=/checkout",
        "seen=1; Domain=example.test; Max-Age=86400",
    ] {
        response.append(http::header::SET_COOKIE, line.parse().unwrap());
    }
    store.insert_response(&login, &response, NOW);
    assert_eq!(store.len(), 3);

    // The checkout page gets all three, longest path first (§5.4.2).
    let checkout = u("https://shop.example.test/checkout/pay");
    assert_eq!(
        header(&store, &checkout, NOW),
        "csrf=t0ken; SID=deadbeef; seen=1"
    );

    // A sibling host on the same registrable domain gets only the tracker…
    let blog = u("https://blog.example.test/");
    assert_eq!(header(&store, &blog, NOW), "seen=1");
    // …an unrelated host gets nothing at all.
    assert_eq!(store.cookie_header(&u("https://other.test/"), NOW), None);

    // A plain-HTTP request to the shop leaks neither Secure cookie.
    let insecure = u("http://shop.example.test/checkout/pay");
    assert_eq!(header(&store, &insecure, NOW), "seen=1");

    // Logout: the deletion idiom evicts the session cookie, nothing else.
    assert_eq!(
        store.insert(&login, "SID=; Path=/; Max-Age=0", NOW),
        Insertion::Deleted
    );
    assert_eq!(header(&store, &checkout, NOW), "csrf=t0ken; seen=1");

    // A day later the tracker has expired out too.
    let tomorrow = NOW + time::Duration::days(1);
    assert_eq!(header(&store, &checkout, tomorrow), "csrf=t0ken");
}

mod send_gate_invariants {
    use proptest::prelude::*;

    use super::*;

    /// Hosts that exercise identity, subdomain, sibling, and stranger
    /// relations (all LDH, so every hardening build parses them alike).
    const HOSTS: [&str; 4] = ["a.test", "sub.a.test", "b.test", "deep.sub.a.test"];
    const PATHS: [&str; 4] = ["/", "/x", "/x/y", "/xy"];

    fn wire(
        name: &str,
        domain: Option<&str>,
        path: Option<&str>,
        secure: bool,
        max_age: Option<i64>,
    ) -> String {
        let mut line = format!("{name}=v");
        if let Some(d) = domain {
            line.push_str("; Domain=");
            line.push_str(d);
        }
        if let Some(p) = path {
            line.push_str("; Path=");
            line.push_str(p);
        }
        if secure {
            line.push_str("; Secure");
        }
        if let Some(m) = max_age {
            line.push_str(&format!("; Max-Age={m}"));
        }
        line
    }

    proptest! {
        /// Feed the store random Set-Cookie shapes from random origins, then
        /// check every §5.4 gate on every cookie of every answer — matching
        /// must hold per cookie, regardless of what storage accepted.
        #[test]
        fn every_attached_cookie_satisfies_every_send_gate(
            inserts in proptest::collection::vec(
                (
                    0usize..HOSTS.len(),                       // origin host
                    0usize..PATHS.len(),                       // origin path
                    any::<bool>(),                             // origin secure
                    "[a-z]{1,3}",                              // cookie name
                    proptest::option::of(0usize..HOSTS.len()), // Domain attr
                    proptest::option::of(0usize..PATHS.len()), // Path attr
                    any::<bool>(),                             // Secure attr
                    proptest::option::of(-2i64..600),          // Max-Age attr
                ),
                0..24,
            ),
            request_host in 0usize..HOSTS.len(),
            request_path in 0usize..PATHS.len(),
            request_secure in any::<bool>(),
            elapsed in 0i64..600,
        ) {
            let mut store = CookieStore::with_config(StoreConfig {
                max_cookies: 16,
                max_cookies_per_domain: 4,
            });
            for (oh, op, os, name, dom, path, secure, max_age) in &inserts {
                let scheme = if *os { "https" } else { "http" };
                let origin = u(&format!("{scheme}://{}{}", HOSTS[*oh], PATHS[*op]));
                let line = wire(
                    name,
                    dom.map(|d| HOSTS[d]),
                    path.map(|p| PATHS[p]),
                    *secure,
                    *max_age,
                );
                let _ = store.insert(&origin, &line, NOW);
            }

            let scheme = if request_secure { "https" } else { "http" };
            let request = u(&format!("{scheme}://{}{}", HOSTS[request_host], PATHS[request_path]));
            let at = NOW + time::Duration::seconds(elapsed);
            let host = HOSTS[request_host]; // already lowercase, and never loopback
            let request_path = PATHS[request_path];
            let mut last_path_len = usize::MAX;
            for cookie in store.matches(&request, at) {
                // §5.4 step 1: host or domain match…
                if cookie.host_only() {
                    prop_assert_eq!(host, cookie.domain());
                } else {
                    prop_assert!(
                        host == cookie.domain()
                            || host
                                .strip_suffix(cookie.domain())
                                .is_some_and(|prefix| prefix.ends_with('.')),
                        "{} does not domain-match {}", host, cookie.domain()
                    );
                }
                // …path match…
                prop_assert!(
                    request_path == cookie.path()
                        || (request_path.starts_with(cookie.path())
                            && (cookie.path().ends_with('/')
                                || request_path.as_bytes()[cookie.path().len()] == b'/')),
                    "{} does not path-match {}", request_path, cookie.path()
                );
                // …the Secure gate, and expiry at `at`.
                prop_assert!(!cookie.secure() || request_secure);
                if let Some(expires) = cookie.expires() {
                    prop_assert!(expires > at);
                }
                // §5.4.2: longer paths never follow shorter ones.
                prop_assert!(cookie.path().len() <= last_path_len);
                last_path_len = cookie.path().len();
            }
        }
    }
}
