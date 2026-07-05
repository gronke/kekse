# kekse

> **Kekse** /ˈkeːksə/ — German for "cookies" 

A strict, dependency-light cookie **codec** for Rust.

## Highlights

- **Built to RFC 6265.** With RFC 7230 tokens, RFC 7231 dates, and RFC 6265bis `SameSite` — see [Standards](#standards).
- **Strict mode.** Brutally strict — cookie-octets only.
- **Lenient mode.** Compliant and tolerant — yet, like strict, refuses injection bytes (`;`, CR, LF, NUL, controls, raw non-ASCII).
- **Strongly typed.** `Cookie`, `SetCookie`, `CookieJar`, `SameSite`, and typed attributes — never stringly-typed maps.
- **No `unsafe`.**
- **Fail-soft by design.** Property-tested and pinned by [`keksbruch`](crates/keksbruch), the differential test harness, and its 30+ parser matrix — designed not to panic on, or echo injection bytes from, malformed input.
- **Both directions.** Reads a `Cookie:` request header into a `CookieJar` of typed `Cookie`s, builds and parses `Set-Cookie:` responses through `SetCookie`, and converts either straight into an `http::HeaderValue`.
- **A codec, not a store.** No persistence, eviction, domain/path send-matching, signing, or encryption — just a correct, fail-soft wire codec.
- **Lightweight.** Just three dependencies (`percent-encoding`, `http`, `time`) and no default features.
- **Rust 1.88.0+.**

## Quick start

```rust
use kekse::{CookieJar, SameSite, SetCookie};

// WRITE — build a hardened `Set-Cookie` response value.
let header = SetCookie::new("SID", "deadbeef")
    .http_only()
    .secure()
    .same_site(SameSite::Strict)
    .path("/")
    .max_age(3600)
    .to_set_cookie();
assert_eq!(header, "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600");

// READ — parse a `Cookie` header; take the first NON-EMPTY `SID`, so a planted
// empty `SID=` can't shadow the real session id that follows it.
let jar = CookieJar::parse_strict("SID=; SID=deadbeef; theme=dark");
let sid = jar.get_all("SID").find(|c| !c.value().is_empty()).map(|c| c.value());
assert_eq!(sid, Some("deadbeef"));
```

More runnable programs live in [`crates/kekse/examples/`](crates/kekse/examples), and the [crate README](crates/kekse/README.md) covers the encoding modes (`Auto`/`Percent`/`Quoted`/`Raw`) and the lenient versus strict parsers in full.

## Standards

| RFC | What kekse uses it for |
| --- | --- |
| **RFC 6265** | The core: §4.1.1 cookie grammar (the cookie-octet alphabet, the cookie-name token), §5.2 `Set-Cookie` parsing (unknown attributes are ignored, not fatal), §5.1.1 cookie-date, §5.4 the `Cookie` request header. |
| **RFC 7230** §3.2.6 | The `token` grammar for cookie-names — borrowed from the `http` crate, not re-implemented as a homemade table. |
| **RFC 7231** §7.1.1.1 | IMF-fixdate, the strict `Expires` format. |
| **RFC 6265bis** (draft) | The `SameSite` attribute (`Strict` / `Lax` / `None`). |

## Tested hard — keksbruch & the parser matrix

[`keksbruch`](crates/keksbruch) /ˈkeːksˌbʁʊx/ ("broken biscuits") is kekse's adversarial test harness: it feeds a broad corpus of malformed and edge-case cookie wire — unbalanced quotes, spliced control bytes, truncated escapes, smuggled `;`, garbage attributes — to many parsers and measures how they cope, so kekse's behaviour on difficult input stays correct and well understood.

- **Layer A** runs in CI, pinning kekse's fail-soft behaviour (never panics, never echoes an injection byte, strict ⊆ lenient) across 80+ malformed and edge-case scenarios.
- The **differential matrix** feeds the same payloads to 30+ cookie parsers across Rust, Python, Node, Go, .NET, PHP, nginx/Lua, Java, and C, tabulating where they diverge from the RFC and from real-world consensus.

**[Parser-divergence Matrix](https://gronke.github.io/kekse/COOKIE_MATRIX.html)**

## Crates

- [`kekse`](crates/kekse) — the library (depend on this).
- [`keksbruch`](crates/keksbruch) — the differential test harness (unpublished).
- [`rfc_6265`](crates/rfc_6265) — reusable, thoroughly tested RFC 6265 primitives (grammar byte-classes, cookie-date parsing, domain/path matching).

## License

Licensed under the [MIT License](LICENSE).

The published crates (`kekse`, `rfc_6265`) are entirely MIT.
Some third-party test fixtures bundled in [`keksbruch`](crates/keksbruch) (e.g. the BSD-2-Clause `lua-resty-cookie`) remain under their own licenses — see [`crates/keksbruch/NOTICE`](crates/keksbruch/NOTICE).
