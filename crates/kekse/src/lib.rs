//! # kekse
//!
//! A strict, dependency-light cookie codec. It reads — and writes — a request
//! `Cookie:` header through a [`CookieJar`] of [`Cookie`]s (over the lower-level
//! [`parse_pairs`] iterators), builds and parses response `Set-Cookie:` values through the
//! [`SetCookie`] type, and converts one straight into an `http` `HeaderValue` —
//! all on the RFC 6265 §4.1.1 grammar. It carries no cookie *store* (no
//! persistence, eviction, or domain/path send-matching) and no signing or
//! encryption, but it does parse and render dates: a lifetime is `Max-Age`
//! seconds (`u64`) or an `Expires` timestamp (an `OffsetDateTime`). It is
//! designed not to panic on untrusted input.
//!
//! ## Three types, two headers
//!
//! A [`Cookie`] is the request `Cookie:` cookie — a `name=value` kernel (plus its
//! wire [`ValueEncoding`]) with no attributes, because a `Cookie:` header carries
//! only pairs. A [`SetCookie`] is the response `Set-Cookie:` cookie — a [`Cookie`]
//! kernel plus [`CookieAttributes`] (`HttpOnly`, `Secure`, `SameSite`, `Path`,
//! `Domain`, `Expires`, `Max-Age`). A `Set-Cookie` line is fully observed, so the
//! flags are
//! plain `bool` — whether an attribute is *known* is answered by which type you
//! hold, not by an `Option`.
//!
//! Set attributes with the fluent verbs — the valueless flags
//! [`secure`](SetCookie::secure) / [`http_only`](SetCookie::http_only) are
//! nullary (calling adds the attribute), the rest take a value
//! ([`same_site`](SetCookie::same_site), [`path`](SetCookie::path), …) — and read
//! them back as fields through [`attributes`](SetCookie::attributes)
//! (`sc.attributes().secure`). The same verbs build a [`CookieAttributes`]
//! standalone, so a hardened policy can be defined once and reused across cookies.
//!
//! Completing a request [`Cookie`] into a [`SetCookie`] is the deliberate, typed
//! transform [`Cookie::into_set_cookie`] (default attributes) or
//! [`Cookie::with_attributes`] (a prebuilt set); [`SetCookie::into_cookie`] /
//! [`SetCookie::cookie`] demote back to the kernel. Render the request form with
//! [`Cookie::to_request_pair`] and the response form with
//! [`SetCookie::to_set_cookie`] or `HeaderValue::try_from` (the managed encodings
//! are always valid header bytes; only [`Raw`](ValueEncoding::Raw) can fail). A
//! [`CookieJar`] is the in-order, typed view of a request `Cookie:` header
//! ([`get`](CookieJar::get) / [`get_all`](CookieJar::get_all) / iterate); it is
//! also writable — [`add`](CookieJar::add) / [`replace`](CookieJar::replace) /
//! [`remove`](CookieJar::remove), then render the whole header back with
//! [`to_header_value`](CookieJar::to_header_value), re-encoded canonically. A
//! parsed-and-rebuildable view of kernels, not a stateful store.
//!
//! ## Encoding a value
//!
//! RFC 6265 lets a *cookie-value* carry only "cookie-octets"
//! (`%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`). Anything else — a space, a
//! `;`, a `"`, a control byte, any non-ASCII — has to be escaped to travel on
//! the wire. [`Cookie::with_encoding`] (and [`SetCookie::with_encoding`]) pick
//! how, via [`ValueEncoding`]:
//!
//! * [`Auto`](ValueEncoding::Auto) — emits the value bare when it is already
//!   cookie-octets, **wraps it in quotes** when it needs to carry whitespace (so
//!   `a b` rides as `"a b"`, not `a%20b`), and percent-encodes everything else
//!   losslessly. "Quotes where necessary."
//! * [`Percent`](ValueEncoding::Percent) (default) — always percent-encode,
//!   never quote. The most compatible form, understood by every cookie parser;
//!   the sane default unless you choose otherwise.
//! * [`Quoted`](ValueEncoding::Quoted) — always wrap in quotes (percent-encoding
//!   inside any byte the bare quoted form cannot carry).
//! * [`Raw`](ValueEncoding::Raw) — emit verbatim. The escape hatch for uncommon
//!   but deliberate shapes; the caller owns wire-correctness.
//!
//! Every managed encoding is lossless and unambiguous: `%` always self-encodes
//! to `%25`, and `"`/`\` inside a quoted value become `%22`/`%5C`, so the
//! wrapping quotes can never be faked and no backslash-escaping is needed.
//!
//! ## Parsing a header
//!
//! One interface, two gradings. Every reader returns what it refused alongside
//! what it parsed, and the lenient/strict choice dials only how permissive the
//! grading is — strict accepts a subset of what lenient accepts, never
//! something else, and neither ever drops silently.
//!
//! [`parse_pairs`] is the lenient stream — the inverse of every
//! [`ValueEncoding`] above: it strips one wrapping quote pair, accepts raw
//! whitespace in the value, and percent-decodes; every well-formed pair comes
//! back as `Ok`, every refused pair as an `Err(`[`PairIssue`]`)` in place.
//! [`parse_pairs_strict`] is the security grading: it accepts *only*
//! cookie-octets — whitespace and every other non-octet are refused, and
//! witnessed — which is what a session-cookie read should use. Both are
//! fail-soft (a refused pair never aborts the header, so attacker-appended
//! junk can never evict a later valid cookie) and both refuse the
//! injection-dangerous bytes (`;`, CR, LF, NUL, other controls, raw non-ASCII)
//! under either grading. Fail-soft is `.filter_map(Result::ok)`; fail-hard is
//! `.collect::<Result<Vec<_>, _>>()`.
//!
//! [`CookieJar::parse`] / [`CookieJar::parse_strict`] collect the same streams
//! into a typed jar inside a [`Reported`] — the jar plus every refused pair as
//! a [`PairIssue`] — and the byte-level twins ([`parse_pairs_bytes`],
//! [`CookieJar::parse_bytes`], …) serve callers holding raw header bytes: an
//! `http` `HeaderValue` may legally carry obs-text (`>= 0x80`) that `to_str()`
//! refuses *wholesale*, while the bytes readers refuse only the pair that
//! carries it. The severity of an issue is always the caller's choice, never
//! the parser's: gate on [`Reported::is_clean`] / [`Reported::into_result`] to
//! fail hard, log [`Reported::issues`] to observe, or [`Reported::into_value`]
//! to move on.
//!
//! ```
//! use kekse::CookieJar;
//!
//! let strict = CookieJar::parse_strict("SID=deadbeef; theme=dark mode");
//! assert_eq!(strict.value.get("SID").map(|c| c.value()), Some("deadbeef"));
//! assert_eq!(strict.issues.len(), 1); // the whitespace-bearing pair, witnessed
//! ```
//!
//! On the response side, [`SetCookie::parse`] reads one `Set-Cookie` header
//! value back into a salvaged [`SetCookie`] plus its [`SetCookieIssue`]s
//! (RFC 6265 §5.2, attributes matched case-insensitively): an unrecognised
//! attribute is ignored and witnessed — so a newer attribute like
//! `Partitioned` never costs the cookie, and never vanishes — a duplicate
//! keeps last-wins, a malformed known value is dropped, each with its issue.
//! The one fatal case, in either grading, is a header without a usable
//! `name=value` pair. [`SetCookie::parse_strict`] narrows only the grading:
//! `Expires` must be the RFC 7231 IMF-fixdate (lenient
//! [`parse`](SetCookie::parse) accepts the RFC 6265 §5.1.1 cookie-date), so
//! gating on a clean strict parse is the tripwire for cookies you minted
//! yourself.
//!
//! ## An axum extractor (optional)
//!
//! With the `axum` feature, `CookieJarBuf` is a `FromRequestParts` extractor:
//! it owns the request `Cookie:` header and lends the borrowed, reported
//! [`CookieJar`] view through `jar()` (lenient) / `jar_strict()` (strict), so
//! the *handler* picks the grading and holds the issue list. Extraction is
//! infallible — a missing or malformed header just yields an empty jar — and
//! it pulls in only `axum-core`, not the whole framework. A handler that would
//! rather refuse a mangled header than serve a partial jar opts out per read:
//! `cookies.try_jar_strict()?` turns any refused pair into a ready-made
//! `400 Bad Request` (`BadCookieHeader`).
//!
//! ## Hardening (optional)
//!
//! By default kekse is a pure codec that stores whatever `Domain` the wire carries. The opt-in
//! `hardened` feature (= `psl` + `idna`) makes it *enforce* policy on the `Domain` attribute.
//! Either sub-feature first requires LDH host-name syntax (after stripping the RFC 6265 §5.2.3
//! leading dot): a `Domain` like `ex_ample.com` or `a..b` that could never domain-match is refused
//! instead of stored as dead weight. On top of that, `psl` refuses a public-suffix value (`com`,
//! `co.uk`, …) — the supercookie defense — and `idna` refuses malformed punycode. Both pull extra
//! tables (the Public Suffix List / IDNA, via `rfc_6265`), so they are not in the default,
//! dependency-light build. A `Domain` these gates refuse is dropped from the salvage and
//! witnessed as an [`InvalidAttributeValue`](SetCookieIssue::InvalidAttributeValue) issue, and
//! [`Domain::new`] returns the same refusal as a typed [`InvalidDomain`].
//!
//! ## A single source of truth for the grammar
//!
//! Cookie *names* are RFC 6265 cookie-names (RFC 7230 tokens), and cookie-name / cookie-octet /
//! av-octet membership all come from the `rfc_6265` crate, where each predicate is a `const fn`
//! pinned by an exhaustive byte sweep. kekse's percent-encode set is tested to stay the exact
//! complement of [`is_cookie_octet`], so the writer and the reader can never drift.
//!
//! ## Module layout
//!
//! One concept per module — `grammar` (the value codec's percent-encode sets, on top of
//! `rfc_6265`'s byte classes), `wire` (the shared byte-level `name=value` segmentation both
//! readers run), `encoding` (the value codec), `same_site`, `cookie` (the request
//! [`Cookie`] kernel), `attributes` (the response [`CookieAttributes`]),
//! `set_cookie` (the response [`SetCookie`] = kernel + attributes, with its
//! `Set-Cookie` parse/serialize), `jar` (the request-`Cookie:` reader *and*
//! writer), and `report` (what a parse refused, as data — [`Reported`] and the
//! issue types) — all re-exported flat from the crate root. With the `axum`
//! feature, an `axum` module adds the `CookieJarBuf` extractor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod attributes;
#[cfg(feature = "axum")]
mod axum;
mod cookie;
mod encoding;
mod grammar;
mod jar;
mod report;
mod same_site;
mod set_cookie;
mod wire;

pub use attributes::{CookieAttributes, Domain, InvalidDomain, InvalidPath, Path};
#[cfg(feature = "axum")]
pub use axum::{BadCookieHeader, CookieJarBuf};
pub use cookie::Cookie;
pub use encoding::{ValueEncoding, encode_value};
pub use jar::{
    CookieJar, parse_pairs, parse_pairs_bytes, parse_pairs_bytes_strict, parse_pairs_strict,
};
pub use report::{PairIssue, Reported};
pub use rfc_6265::grammar::{is_cookie_name, is_cookie_name_bytes, is_cookie_octet};
pub use same_site::{ParseSameSiteError, SameSite};
pub use set_cookie::{KnownAttribute, SetCookie, SetCookieIssue};

/// The timestamp type used by the `Expires` attribute, re-exported from `rfc_6265` (itself the
/// `time` crate's `OffsetDateTime`) so callers can name it without depending on `time` directly.
pub use rfc_6265::OffsetDateTime;
