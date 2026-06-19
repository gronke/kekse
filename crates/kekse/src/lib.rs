//! # kekse
//!
//! A strict, dependency-light cookie codec. It reads — and writes — a request
//! `Cookie:` header through a [`CookieJar`] of [`Cookie`]s (over the lower-level
//! [`parse_pairs`] iterators), builds and parses response `Set-Cookie:` values through the
//! [`SetCookie`] type, and converts one straight into an `http` `HeaderValue` —
//! all on the RFC 6265 §4.1.1 grammar. It carries no cookie *store* (no
//! persistence, eviction, or domain/path send-matching), no signing or
//! encryption, and no date handling — a lifetime is `Max-Age` seconds (`u64`),
//! never an `Expires` date — so it pulls in no `time`/`chrono`. It never panics
//! on untrusted input.
//!
//! ## Three types, two headers
//!
//! A [`Cookie`] is the request `Cookie:` cookie — a `name=value` kernel (plus its
//! wire [`ValueEncoding`]) with no attributes, because a `Cookie:` header carries
//! only pairs. A [`SetCookie`] is the response `Set-Cookie:` cookie — a [`Cookie`]
//! kernel plus [`CookieAttributes`] (`HttpOnly`, `Secure`, `SameSite`, `Path`,
//! `Domain`, `Max-Age`). A `Set-Cookie` line is fully observed, so the flags are
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
//! [`parse_pairs`] is the lenient, general reader — the inverse of every
//! [`ValueEncoding`] above: it strips one wrapping quote pair, accepts raw
//! whitespace in the value, and percent-decodes. [`parse_pairs_strict`] is its
//! security-grade sibling: it accepts *only* cookie-octets — whitespace and
//! every other non-octet are refused — which is what a session-cookie read
//! should use. Both are fail-soft (a malformed pair is skipped, never aborting
//! the header, so attacker-appended junk can never evict a later valid cookie)
//! and both refuse the injection-dangerous bytes (`;`, CR, LF, NUL, other
//! controls, raw non-ASCII) in every mode — the lenient/strict difference is
//! only whether raw whitespace is tolerated.
//!
//! On the response side, [`SetCookie::parse`] reads one `Set-Cookie` header value
//! back into a [`SetCookie`] (RFC 6265 §5.2, attributes matched
//! case-insensitively). Per §5.2 an **unrecognised attribute is ignored** and the
//! cookie kept (so a newer attribute like `Partitioned` never costs the cookie);
//! [`SetCookie::parse_strict`] rejects on an unknown attribute instead.
//! (`Expires` is recognised; date handling is a planned follow-up.)
//!
//! ## A single source of truth for the grammar
//!
//! Cookie *names* are RFC 6265 cookie-names, i.e. RFC 7230 tokens — exactly what
//! the [`http`] crate's [`HeaderName`](http::header::HeaderName) parses, so
//! [`is_cookie_name`] borrows that definition rather than keep a homemade table.
//! Cookie-octet membership ([`is_cookie_octet`]) is derived once from the
//! percent-encode set, so the writer and the reader can never drift.
//!
//! ## Module layout
//!
//! One concept per module — `grammar` (name/octet predicates and the encode
//! sets), `encoding` (the value codec), `same_site`, `cookie` (the request
//! [`Cookie`] kernel), `attributes` (the response [`CookieAttributes`]),
//! `set_cookie` (the response [`SetCookie`] = kernel + attributes, with its
//! `Set-Cookie` parse/serialize), and `jar` (the request-`Cookie:` reader *and*
//! writer) — all re-exported flat from the crate root.

mod attributes;
mod cookie;
mod encoding;
mod grammar;
mod jar;
mod same_site;
mod set_cookie;

pub use attributes::{CookieAttributes, Domain, Path};
pub use cookie::Cookie;
pub use encoding::{encode_value, ValueEncoding};
pub use grammar::{is_cookie_name, is_cookie_octet};
pub use jar::{parse_pairs, parse_pairs_strict, CookieJar};
pub use same_site::SameSite;
pub use set_cookie::SetCookie;
