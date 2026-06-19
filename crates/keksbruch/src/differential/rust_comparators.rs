//! The in-process Rust comparators: kekse itself (both modes), the `cookie`
//! crate, and `biscotti`. Called directly — they are Rust — with each call
//! wrapped in `catch_unwind` so a panic becomes a recorded finding, not a crash.

use std::panic::{catch_unwind, AssertUnwindSafe};

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
        Box::new(CookieCrate),
        Box::new(Biscotti),
        Box::new(AxumExtra),
    ]
}

pub struct KekseLenient;
pub struct KekseStrict;
pub struct CookieCrate;
pub struct Biscotti;
pub struct AxumExtra;

impl RustComparator for KekseLenient {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "kekse (lenient)")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        ParseOutcome::Cookies {
            cookies: kekse::parse_pairs(wire)
                .map(|(n, v)| CookieView {
                    name: n.to_string(),
                    value: v.into_owned(),
                })
                .collect(),
        }
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        match kekse::SetCookie::parse_lenient(wire) {
            Some(sc) => ParseOutcome::SetCookie {
                set_cookie: kekse_view(&sc),
            },
            None => ParseOutcome::SetCookieRejected {
                error: "None".to_string(),
            },
        }
    }
}

impl RustComparator for KekseStrict {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "kekse (strict)")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        ParseOutcome::Cookies {
            cookies: kekse::parse_pairs_strict(wire)
                .map(|(n, v)| CookieView {
                    name: n.to_string(),
                    value: v.into_owned(),
                })
                .collect(),
        }
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        // kekse's default `parse` is strict: an unknown attribute rejects.
        match kekse::SetCookie::parse(wire) {
            Some(sc) => ParseOutcome::SetCookie {
                set_cookie: kekse_view(&sc),
            },
            None => ParseOutcome::SetCookieRejected {
                error: "None".to_string(),
            },
        }
    }
}

fn kekse_view(sc: &kekse::SetCookie) -> SetCookieView {
    let a = sc.attributes();
    SetCookieView {
        name: sc.name().to_string(),
        value: sc.value().to_string(),
        http_only: a.http_only,
        secure: a.secure,
        same_site: a.same_site.map(|s| s.as_str().to_string()),
        path: a.path.map(str::to_string),
        domain: a.domain.map(str::to_string),
        max_age: a.max_age.map(|m| m as i64),
    }
}

impl RustComparator for CookieCrate {
    fn id(&self) -> (&'static str, &'static str) {
        ("rust", "cookie")
    }
    fn parse_request(&self, wire: &str) -> ParseOutcome {
        // `_encoded` percent-decodes, matching kekse's default decode, so the
        // value column is comparable. Each `;`-segment is its own Result; keep the
        // Ok pairs (the cookie crate's effective fail-soft) and drop the rest.
        let cookies = cookie::Cookie::split_parse_encoded(wire.to_string())
            .filter_map(Result::ok)
            .map(|c| {
                let (name, value) = c.name_value();
                CookieView {
                    name: name.to_string(),
                    value: value.to_string(),
                }
            })
            .collect();
        ParseOutcome::Cookies { cookies }
    }
    fn parse_response(&self, wire: &str) -> ParseOutcome {
        match cookie::Cookie::parse_encoded(wire.to_string()) {
            Ok(c) => ParseOutcome::SetCookie {
                set_cookie: cookie_view(&c),
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
        same_site: c.same_site().map(|s| format!("{s:?}")),
        path: c.path().map(str::to_string),
        domain: c.domain().map(str::to_string),
        max_age: c.max_age().map(|d| d.whole_seconds()),
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
                out.push(CookieView {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
        }
    }
    out
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
            .map(|c| CookieView {
                name: c.name().to_string(),
                value: c.value().to_string(),
            })
            .collect();
        cookies.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));
        ParseOutcome::Cookies { cookies }
    }
    fn parse_response(&self, _wire: &str) -> ParseOutcome {
        // axum-extra builds Set-Cookie responses; it does not parse them.
        ParseOutcome::NotApplicable
    }
}
