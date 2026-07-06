# kekse

A strict, dependency-light cookie codec.

## Highlights

- **Both directions.** Build `Set-Cookie` via `SetCookie`. Read and write `Cookie` via a `CookieJar` of typed `Cookie`s. Convert either into an `http::HeaderValue`.
- **Built to RFC 6265.** Plus RFC 7230 tokens, RFC 7231 dates, and RFC 6265bis `SameSite`.
- **Strict and lenient readers.** Both refuse injection bytes (`;`, CR, LF, NUL, controls, non-ASCII). Strict also demands cookie-octets only.
- **Fail-soft, never silent.** A junk pair is skipped, not fatal. It can't evict a valid cookie. Every reader has a reporting twin, plus an opt-in axum `400`.
- **Strongly typed.** `Cookie`, `SetCookie`, `CookieJar`, and typed attributes. Never string maps.
- **A codec, not a store.** No persistence, eviction, send-matching, signing, or encryption.
- **Dates handled.** `Max-Age` seconds (a `u64`) or an `Expires` timestamp, via the `time` crate.
- **Light and safe.** Three dependencies — `percent-encoding`, `http`, `time`. No default features, no `unsafe`. Rust 1.88+.

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

The verbs are optional sugar over `CookieAttributes`, a plain `Default` struct; the [`build_set_cookie`](examples/build_set_cookie.rs) example builds the same cookie three ways.

Attributes are emitted in a fixed order: `HttpOnly`, `SameSite`, `Secure`, `Path`, `Domain`, `Expires`, `Max-Age`, each only when set.

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

Both readers are fail-soft: a malformed pair is skipped, never aborting the header.
But the drop need not be silent — every plain reader has a **reporting** twin that also hands back what it skipped.
`try_parse_pairs*` yields `Result` items, so `.collect::<Result<Vec<_>, _>>()` is fail-hard for free.
`CookieJar::parse_reported` and friends return a `Reported`: the jar, plus every refused pair as a `PairIssue`.
`SetCookie::try_parse` / `try_parse_strict` report each dropped attribute as a `SetCookieIssue` — an ignored unknown, a duplicate, or a malformed known value.
Strictness decides which issues are *fatal*.
Gating on `Reported::is_clean()` is stricter than strict: nothing is ever dropped silently.

With the `axum` feature, that gate is one line in a handler — anything wrong with the header becomes a `400 Bad Request` that reports a count and never echoes header bytes:

```rust,ignore
async fn whoami(cookies: CookieJarBuf) -> Result<String, BadCookieHeader> {
    let jar = cookies.try_jar_strict()?; // any malformed pair -> 400
    Ok(jar.get("SID").map(|c| c.value().to_owned()).unwrap_or_default())
}
```

## Three types, two headers

| Type | What it is |
| --- | --- |
| `Cookie` | one `name=value` from a request `Cookie:` header — no attributes; the shared core |
| `SetCookie` | a response `Set-Cookie:` — a `Cookie` plus typed `CookieAttributes` (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, `Expires`, `Max-Age`) |
| `CookieJar` | an ordered, writable view over a `Cookie:` header — parsed and rebuildable, not a store |

A request `Cookie` completes into a `SetCookie` with `into_set_cookie()` (default attributes) or `with_attributes(..)`, and drops back with `into_cookie()`. The attribute verbs also build a standalone `CookieAttributes`, so one hardened policy can be reused across cookies.

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

The jar is writable too: `add` / `replace` / `remove`, then `to_header_value(encoding)` re-encodes the whole header canonically from its decoded form.

## Examples

Runnable programs live in [`examples/`](examples).
Each prints its output and asserts the invariant it documents, so it doubles as a smoke test.

| Example | Shows |
| --- | --- |
| `build_set_cookie` | Three ways to build a `SetCookie` — inline builder, a reusable `CookieAttributes` policy, a struct literal — plus the `HeaderValue` conversion and a parse round-trip. |
| `parse_request` | Reading and rewriting a `Cookie:` request header through a `CookieJar`. |
| `encodings` | How each `ValueEncoding` escapes one tricky value for the wire. |
| `strict_vs_lenient` | The lenient and strict readers side by side on a quoted value. |
| `fail_soft` | Fail-soft parsing, the issue report for the same header, and the no-panic behaviour on hostile input. |
| `axum_extractor` | The `CookieJarBuf` axum extractor, including the fail-hard `try_jar_strict` → 400 route (needs `--features axum`). |

```sh
cargo run -p kekse --example build_set_cookie
cargo run -p kekse --example axum_extractor --features axum
```

## License

Licensed under the [MIT License](LICENSE).
