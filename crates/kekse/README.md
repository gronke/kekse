# kekse

A strict, dependency-light cookie codec.
It builds `Set-Cookie` response values from a `SetCookie`, reads *and writes* a `Cookie` request header through a `CookieJar` of typed `Cookie`s, and converts either straight into an `http::HeaderValue` — directly on the RFC 6265 §4.1.1 grammar.
There is no cookie *store* (no persistence, eviction, or domain/path send-matching), no signing or encryption, and no date handling — a lifetime is `Max-Age` seconds (a `u64`), never an `Expires` date — so the crate pulls in no `time`/`chrono`.
It never panics on untrusted input, and a malformed pair in a header is skipped rather than aborting the parse, so attacker-appended junk can never evict a later valid cookie.

It depends only on `percent-encoding` (the value codec) and `http` (the RFC 7230 token grammar for cookie-names, borrowed rather than re-implemented as a homemade table).

## Building a value

RFC 6265 lets a cookie value carry only "cookie-octets".
Anything else — a space, a `;`, a `"`, a control byte, any non-ASCII — has to be escaped to travel on the wire.
The `with_encoding` builder chooses how:

| `ValueEncoding` | Behaviour |
| --- | --- |
| `Auto` | Bare when the value is already cookie-octets, quoted to carry whitespace (`a b` → `"a b"`), percent-encoded otherwise. "Quotes where necessary." |
| `Percent` (default) | Always percent-encode, never quote. The most compatible form, understood by every parser — the sane default. |
| `Quoted` | Always wrap in quotes, percent-encoding inside any byte the bare quoted form cannot carry. |
| `Raw` | Emit verbatim. The escape hatch for uncommon but deliberate shapes; the caller owns wire-correctness. |

Every managed encoding is lossless and unambiguous.
`%` always self-encodes to `%25`, and a quoted value never carries a raw `"`/`\` (they become `%22`/`%5C`), so the wrapping quotes can never be faked.

```rust
use kekse::{SetCookie, SameSite, ValueEncoding};

let header = SetCookie::new("SID", "deadbeef")
    .with_encoding(ValueEncoding::Percent)
    .http_only()
    .same_site(SameSite::Strict)
    .secure()
    .path("/")
    .max_age(3600)
    .to_set_cookie();
assert_eq!(header, "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600");
```

Attributes are emitted in a fixed order: `HttpOnly`, `SameSite`, `Secure`, `Path`, `Domain`, `Max-Age`, each only when set.

To hand the cookie straight to `http`, use `HeaderValue::try_from(set_cookie)` (or `&set_cookie`) instead of `.to_set_cookie()`: the managed encodings are always valid header bytes, so it fails only for a `Raw` value the caller deliberately built with non-header bytes.

## Parsing a header

`parse_pairs` is the lenient, general reader — the inverse of every `ValueEncoding`.
It strips one wrapping quote pair, accepts raw whitespace, and percent-decodes.

`parse_pairs_strict` is its security-grade sibling.
It accepts only cookie-octets — whitespace and every other non-octet are refused — which is what a session-cookie read should use.

Both refuse the injection-dangerous bytes (`;`, CR, LF, NUL, other controls, raw non-ASCII) in every mode.
The only difference between them is whether raw whitespace is tolerated.

```rust
let value = kekse::parse_pairs_strict("SID=deadbeef; theme=dark")
    .find(|(name, _)| *name == "SID")
    .map(|(_, value)| value.into_owned());
assert_eq!(value.as_deref(), Some("deadbeef"));
```

## Three types, two headers

`parse_pairs` yields `(name, value)` tuples; `CookieJar` is the typed view over it.
A `Cookie` is the request `Cookie:` cookie — the `name=value` a request carries (plus its wire encoding), with no attributes; it is the shared kernel a `SetCookie` composes.
A `SetCookie` is the response `Set-Cookie:` cookie — a `Cookie` kernel plus `CookieAttributes` (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, `Max-Age`), with plain-`bool` flags.
Set attributes with the fluent verbs — the valueless flags `http_only()` / `secure()` are nullary, the rest take a value (`same_site(..)`, `path(..)`, …) — and read them back as fields via `set_cookie.attributes()` (e.g. `sc.attributes().secure`). The same verbs build a `CookieAttributes` on its own, so a hardened policy can be defined once and reused across cookies.
`Cookie::into_set_cookie()` (default attributes) or `Cookie::with_attributes(..)` (a prebuilt set) completes a request cookie into a `SetCookie` to emit; `SetCookie::into_cookie()` / `cookie()` drop back to the kernel.

```rust
use kekse::CookieJar;

let jar = CookieJar::parse_strict("SID=deadbeef; theme=dark");
// First non-empty match, so a stale `SID=` can't shadow a later real one.
let sid = jar
    .get_all("SID")
    .find(|c| !c.value().is_empty())
    .map(|c| c.value().to_owned());
assert_eq!(sid.as_deref(), Some("deadbeef"));
```

`CookieJar` reads one `Cookie:` header in order, and is writable too — `add` / `replace` / `remove`, then `jar.to_header_value(encoding)` renders the whole header back, each value re-encoded canonically from its decoded form (no raw retention). It is a parsed-and-rebuildable view, not a stateful cookie store (persistence and domain/path send-matching are out of scope).

## License & Disclaimer

Copyright © 2026 Stefan Grönke.

Licensed under the MIT License — see [`LICENSE`](LICENSE).

This software is provided free of charge and **“as is,” without warranty of any kind**, as specified in the MIT License.
No support, maintenance, updates, or assurance of correctness, security, or fitness for a particular purpose is provided.

**Use at your own risk, subject to applicable law.**
