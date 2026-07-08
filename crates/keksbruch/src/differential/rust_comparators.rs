//! The in-process Rust comparators: kekse itself (all three modes), the `cookie`
//! crate, and `biscotti`. Called directly — they are Rust — with each call
//! wrapped in `catch_unwind` so a panic becomes a recorded finding, not a crash.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::differential::result::{CookieView, ParseOutcome, SetCookieView};
use crate::taxonomy::Direction;

/// An in-process Rust cookie parser, normalized into the common schema.
pub trait RustComparator {
    /// `(lang, dependency)` — the matrix column identity.
    fn id(&self) -> (&'static str, &'static str);
    fn parse_request(&self, wire: &str) -> ParseOutcome;
    fn parse_response(&self, wire: &str) -> ParseOutcome;

    /// Run one payload in `direction`, catching a panic as a `Panicked` finding.
    fn run(&self, wire: &str, direction: Direction) -> ParseOutcome {
        catch_unwind(AssertUnwindSafe(|| match direction {
            Direction::Request => self.parse_request(wire),
            Direction::Response => self.parse_response(wire),
        }))
        .unwrap_or_else(|_| ParseOutcome::Panicked {
            message: "parser panicked".to_string(),
        })
    }
}

/// The Rust comparators, in matrix-column order.
pub fn rust_comparators() -> Vec<Box<dyn RustComparator>> {
    vec![
        Box::new(KekseLenient),
        Box::new(KekseStrict),
        Box::new(KekseFailHard),
        Box::new(CookieCrate),
        Box::new(CookieStore),
        Box::new(Biscotti),
        Box::new(AxumExtra),
    ]
}

pub struct KekseLenient;
pub struct KekseStrict;
pub struct KekseFailHard;
pub struct CookieCrate;
pub struct CookieStore;
pub struct Biscotti;
pub struct AxumExtra;

impl RustComparator for KekseLenient {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "kekse (lenient)")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        kekse_pairs_outcome(kekse::parse_pairs(wire))
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        match kekse::SetCookie::parse(wire) {
            Ok(reported) => ParseOutcome::SetCookie {
                set_cookie: kekse_view(&reported.value),
                issues: rendered_issues(&reported.issues),
            },
            Err(fatal) => ParseOutcome::SetCookieRejected {
                error: fatal.to_string(),
            },
        }
    }
}

impl RustComparator for KekseStrict {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "kekse (strict)")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        kekse_pairs_outcome(kekse::parse_pairs_strict(wire))
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        // Strict is a grading, not a different parser: the salvage plus its
        // (strictly graded) issue list, with only an unusable pair fatal.
        match kekse::SetCookie::parse_strict(wire) {
            Ok(reported) => ParseOutcome::SetCookie {
                set_cookie: kekse_view(&reported.value),
                issues: rendered_issues(&reported.issues),
            },
            Err(fatal) => ParseOutcome::SetCookieRejected {
                error: fatal.to_string(),
            },
        }
    }
}

impl RustComparator for KekseFailHard {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "kekse (fail-hard)")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        // Opt-in fail-hard read: any refused pair rejects the whole header (the
        // `try_jar_strict` / `Reported::is_clean` gate), where the strict *reader*
        // would fail-soft and drop it. A clean header yields the same cookies as strict.
        let reported = kekse::CookieJar::parse_strict(wire);
        if reported.is_clean() {
            ParseOutcome::Cookies {
                cookies: kekse::parse_pairs_strict(wire)
                    .filter_map(Result::ok)
                    .map(|(n, v)| CookieView::new(n, v))
                    .collect(),
                issues: Vec::new(),
            }
        } else {
            // The rejection names every refused pair — the gate's evidence,
            // not just its count.
            ParseOutcome::Rejected {
                error: format!(
                    "{} refused pair(s): {}",
                    reported.issues.len(),
                    rendered_issues(&reported.issues).join("; ")
                ),
            }
        }
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        // Stricter than strict: a fatal issue *or* any reported (dropped) attribute
        // rejects the cookie, rather than keeping it and dropping the bad piece.
        match kekse::SetCookie::parse_strict(wire) {
            Ok(reported) if reported.is_clean() => ParseOutcome::SetCookie {
                set_cookie: kekse_view(&reported.value),
                issues: Vec::new(),
            },
            Ok(reported) => ParseOutcome::SetCookieRejected {
                error: format!(
                    "{} issue(s): {}",
                    reported.issues.len(),
                    rendered_issues(&reported.issues).join("; ")
                ),
            },
            Err(e) => ParseOutcome::SetCookieRejected {
                error: e.to_string(),
            },
        }
    }
}

/// Render a typed issue list to the protocol's free-form strings.
fn rendered_issues<I: std::fmt::Display>(issues: &[I]) -> Vec<String> {
    issues.iter().map(ToString::to_string).collect()
}

/// Collect a kekse pair stream into the outcome: `Ok` pairs as cookies, every
/// refusal as a rendered issue — the stream partition, on the wire protocol.
fn kekse_pairs_outcome<'a>(
    stream: impl Iterator<Item = Result<(&'a str, std::borrow::Cow<'a, str>), kekse::PairIssue<'a>>>,
) -> ParseOutcome {
    let mut cookies = Vec::new();
    let mut issues = Vec::new();
    for item in stream {
        match item {
            Ok((n, v)) => cookies.push(CookieView::new(n, v)),
            Err(issue) => issues.push(issue.to_string()),
        }
    }
    ParseOutcome::Cookies { cookies, issues }
}

fn kekse_view(sc: &kekse::SetCookie) -> SetCookieView {
    let a = sc.attributes();
    SetCookieView {
        name: sc.name().to_string(),
        value: sc.value().to_string(),
        http_only: a.http_only,
        secure: a.secure,
        partitioned: Some(a.partitioned),
        same_site: a.same_site.map(|s| s.as_str().to_string()),
        path: a.path.map(|p| p.as_str().to_string()),
        domain: a.domain.map(|d| d.as_str().to_string()),
        max_age: a.max_age.map(|m| m as i64),
        expires: a.expires.map(|dt| dt.unix_timestamp()),
    }
}

impl RustComparator for CookieCrate {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "cookie")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        // `_encoded` percent-decodes, matching kekse's default decode, so the
        // value column is comparable. Each `;`-segment is its own Result; keep the
        // Ok pairs (the cookie crate's effective fail-soft) and surface each
        // refusal on the issue channel instead of dropping it.
        let mut cookies = Vec::new();
        let mut issues = Vec::new();
        for parsed in cookie::Cookie::split_parse_encoded(wire.to_string()) {
            match parsed {
                Ok(c) => {
                    let (name, value) = c.name_value();
                    cookies.push(CookieView::new(name, value));
                }
                Err(e) => issues.push(e.to_string()),
            }
        }
        ParseOutcome::Cookies { cookies, issues }
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        match cookie::Cookie::parse_encoded(wire.to_string()) {
            Ok(c) => ParseOutcome::SetCookie {
                set_cookie: cookie_view(&c),
                // The cookie crate reports no recovered issues on an accept.
                issues: Vec::new(),
            },
            Err(e) => ParseOutcome::SetCookieRejected {
                error: e.to_string(),
            },
        }
    }
}

fn cookie_view(c: &cookie::Cookie) -> SetCookieView {
    SetCookieView {
        name: c.name().to_string(),
        value: c.value().to_string(),
        http_only: c.http_only().unwrap_or(false),
        secure: c.secure().unwrap_or(false),
        // The `cookie` crate has no CHIPS model, so the attribute is genuinely
        // dropped — an explicit `false`, not an unobservable `None`.
        partitioned: Some(false),
        same_site: c.same_site().map(|s| format!("{s:?}")),
        path: c.path().map(str::to_string),
        domain: c.domain().map(str::to_string),
        max_age: c.max_age().map(|d| d.whole_seconds()),
        expires: cookie_expires(c),
    }
}

/// The parsed `Expires` of a `cookie`-crate cookie as a Unix timestamp — `None` for a session
/// cookie or no `Expires`. The `cookie` crate keeps `Expires` and `Max-Age` as distinct parsed
/// attributes (it does not fold one into the other), so this is the literal parsed date.
fn cookie_expires(c: &cookie::Cookie) -> Option<i64> {
    match c.expires() {
        Some(cookie::Expiration::DateTime(dt)) => Some(dt.unix_timestamp()),
        _ => None,
    }
}

impl RustComparator for CookieStore {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "cookie_store")
    }
    fn parse_request(&self, _wire: &str) -> ParseOutcome {
        // cookie_store is a client Set-Cookie jar; it does not parse request headers.
        ParseOutcome::NotApplicable
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        // Parse the Set-Cookie as a browser would — against a request URL — so cookie_store
        // applies RFC 6265 domain-match: a `Domain` that does not match example.com (or a
        // public suffix) is refused. The Rust "client store" view, like tough-cookie, as
        // opposed to the pure `cookie` crate parse.
        let url = match url::Url::parse("https://example.com/") {
            Ok(u) => u,
            Err(_) => {
                return ParseOutcome::SetCookieRejected {
                    error: "bad base url".to_string(),
                };
            }
        };
        let mut store = cookie_store::CookieStore::new();
        match store.parse(wire, &url) {
            Ok(_) => match store.iter_any().next() {
                Some(c) => ParseOutcome::SetCookie {
                    set_cookie: cookie_store_view(c),
                    // cookie_store reports no recovered issues on an accept.
                    issues: Vec::new(),
                },
                None => ParseOutcome::SetCookieRejected {
                    error: "stored no cookie".to_string(),
                },
            },
            Err(e) => ParseOutcome::SetCookieRejected {
                error: e.to_string(),
            },
        }
    }
}

/// cookie_store's `Cookie` derefs to the `cookie` crate's, exposing the *parsed*
/// attributes (the Domain attribute as written, not cookie_store's computed effective
/// host), so the column compares like the others.
fn cookie_store_view(c: &cookie_store::Cookie<'_>) -> SetCookieView {
    SetCookieView {
        name: c.name().to_string(),
        value: c.value().to_string(),
        http_only: c.http_only().unwrap_or(false),
        secure: c.secure().unwrap_or(false),
        // Derefs to the `cookie` crate's cookie, which has no CHIPS model — a
        // genuine drop (`Some(false)`), not an unobservable `None`.
        partitioned: Some(false),
        same_site: c.same_site().map(|s| format!("{s:?}")),
        path: c.path().map(str::to_string),
        domain: c.domain().map(str::to_string),
        max_age: c.max_age().map(|d| d.whole_seconds()),
        // Derefs to the `cookie` crate's cookie, so the parsed `Expires` reads the same way.
        expires: cookie_expires(c),
    }
}

impl RustComparator for Biscotti {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "biscotti")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        let processor: biscotti::Processor = biscotti::ProcessorConfig::default().into();
        match biscotti::RequestCookies::parse_header(wire, &processor) {
            Ok(jar) => ParseOutcome::Cookies {
                cookies: biscotti_cookies(&jar, wire),
                // biscotti is fail-hard: an accept had nothing to recover from.
                issues: Vec::new(),
            },
            // biscotti is fail-hard: one malformed segment aborts the whole header.
            Err(e) => ParseOutcome::Rejected {
                error: e.to_string(),
            },
        }
    }
    fn parse_response(&self, _wire: &str) -> ParseOutcome {
        // biscotti has no Set-Cookie parser by design.
        ParseOutcome::NotApplicable
    }
}

/// biscotti exposes only `get`/`get_all` by name — no general iterator — so
/// enumerate the candidate names from the wire (first-seen order) and query each.
/// (That query-only shape is itself a finding the matrix legend notes.)
fn biscotti_cookies(jar: &biscotti::RequestCookies, wire: &str) -> Vec<CookieView> {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for segment in wire.split(';') {
        let name = segment.split('=').next().unwrap_or("").trim();
        if name.is_empty() || seen.contains(&name) {
            continue;
        }
        seen.push(name);
        if let Some(values) = jar.get_all(name) {
            for value in values.values() {
                out.push(CookieView::new(name, value.to_string()));
            }
        }
    }
    out
}

/// An in-process client jar for the jar probes: store one `Set-Cookie` as if
/// received from `origin_url` (§5.3), then report the cookies it would attach to a
/// request to `request_url` (§5.4) as [`ParseOutcome::Cookies`] — an empty list
/// (`∅`) meaning "not sent", whether storage refused the cookie or the match
/// failed. The wire-parsing [`RustComparator`] axis stays separate; a type may
/// implement both (cookie_store does), landing in one column.
pub trait JarComparator {
    /// `(lang, dependency)` — the matrix column identity. Matching a
    /// [`RustComparator`] id merges the probe cells into that column.
    fn id(&self) -> (&'static str, &'static str);
    fn probe(&self, set_cookie: &str, origin_url: &str, request_url: &str) -> ParseOutcome;

    /// Run one probe, catching a panic as a `Panicked` finding.
    fn run(&self, set_cookie: &str, origin_url: &str, request_url: &str) -> ParseOutcome {
        catch_unwind(AssertUnwindSafe(|| {
            self.probe(set_cookie, origin_url, request_url)
        }))
        .unwrap_or_else(|_| ParseOutcome::Panicked {
            message: "jar panicked".to_string(),
        })
    }
}

/// The in-process jar comparators, in matrix-column order.
pub fn jar_comparators() -> Vec<Box<dyn JarComparator>> {
    vec![Box::new(Rfc6265Reference), Box::new(CookieStore)]
}

/// The RFC 6265 §5.3/§5.4 algorithm executed directly from rfc_6265's primitives
/// (`crate::reference`) — the jar-probe table's baseline column, and a subject
/// (like kekse) kept off the consensus vote.
pub struct Rfc6265Reference;

impl JarComparator for Rfc6265Reference {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "rfc_6265 (reference)")
    }
    fn probe(&self, set_cookie: &str, origin_url: &str, request_url: &str) -> ParseOutcome {
        ParseOutcome::Cookies {
            cookies: crate::reference::probe_retrieval(set_cookie, origin_url, request_url)
                .into_iter()
                .map(|(n, v)| CookieView::new(n, v))
                .collect(),
            // A jar probe reports retrieved state, not parse diagnostics.
            issues: Vec::new(),
        }
    }
}

impl JarComparator for CookieStore {
    fn id(&self) -> (&'static str, &'static str) {
        // The same column as its wire (RustComparator) identity — one tool, two axes.
        ("rust", "cookie_store")
    }
    fn probe(&self, set_cookie: &str, origin_url: &str, request_url: &str) -> ParseOutcome {
        let (Ok(origin), Ok(request)) = (url::Url::parse(origin_url), url::Url::parse(request_url))
        else {
            return ParseOutcome::Rejected {
                error: "bad probe url".to_string(),
            };
        };
        let mut store = cookie_store::CookieStore::new();
        // A storage refusal (domain mismatch, public suffix) is "not sent" — ∅ —
        // exactly like a stored cookie the request then fails to match.
        let _ = store.parse(set_cookie, &origin);
        ParseOutcome::Cookies {
            issues: Vec::new(),
            cookies: store
                .get_request_values(&request)
                .map(|(n, v)| CookieView::new(n, v))
                .collect(),
        }
    }
}

impl RustComparator for AxumExtra {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "axum-extra")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        // axum-extra reads cookies from a real request `HeaderMap`, so a wire that
        // is not a valid header value (CR/LF/NUL, raw non-ASCII) is refused at the
        // HTTP layer before the extractor runs — the realistic axum path. Its
        // parsing itself is the `cookie` crate's, so clean wires mirror that column.
        let Ok(value) = http::HeaderValue::from_str(wire) else {
            return ParseOutcome::Rejected {
                error: "not a valid header value".to_string(),
            };
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::COOKIE, value);
        let jar = axum_extra::extract::cookie::CookieJar::from_headers(&headers);
        // The underlying jar is a hash map: it dedups by name and iterates in no
        // defined order. Sort (name, value) so the cell is reproducible — the lost
        // wire order is itself visible as a divergence from the order-preserving
        // parsers.
        let mut cookies: Vec<CookieView> = jar
            .iter()
            .map(|c| CookieView::new(c.name(), c.value()))
            .collect();
        cookies.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));
        ParseOutcome::Cookies {
            cookies,
            issues: Vec::new(),
        }
    }
    fn parse_response(&self, _wire: &str) -> ParseOutcome {
        // axum-extra builds Set-Cookie responses; it does not parse them.
        ParseOutcome::NotApplicable
    }
}
