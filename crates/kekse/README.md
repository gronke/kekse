# kekse

A strict, dependency-light cookie codec.
It builds `Set-Cookie` response values and parses `Cookie` request headers, directly on the RFC 6265 §4.1.1 grammar.
There is no cookie jar, no signing or encryption, and no date handling — a lifetime is `Max-Age` seconds (a `u64`), never an `Expires` date — so the crate pulls in no `time`/`chrono`.
It never panics on untrusted input, and a malformed pair in a header is skipped rather than aborting the parse, so attacker-appended junk can never evict a later valid cookie.

It depends only on `percent-encoding` (the value codec) and `http` (the RFC 7230 token grammar for cookie-names, borrowed rather than re-implemented as a homemade table).

## Building a value

RFC 6265 lets a cookie value carry only "cookie-octets".
Anything else — a space, a `;`, a `"`, a control byte, any non-ASCII — has to be escaped to travel on the wire.
`SetCookie::value_encoding` chooses how:

| `ValueEncoding` | Behaviour |
| --- | --- |
| `Auto` (default) | Bare when the value is already cookie-octets, quoted to carry whitespace (`a b` → `"a b"`), percent-encoded otherwise. "Quotes where necessary." |
| `Percent` | Always percent-encode, never quote. The most compatible form, and what a security-sensitive cookie should use. |
| `Quoted` | Always wrap in quotes, percent-encoding inside any byte the bare quoted form cannot carry. |
| `Raw` | Emit verbatim. The escape hatch for uncommon but deliberate shapes; the caller owns wire-correctness. |

Every managed encoding is lossless and unambiguous.
`%` always self-encodes to `%25`, and a quoted value never carries a raw `"`/`\` (they become `%22`/`%5C`), so the wrapping quotes can never be faked.

```rust
use kekse::{SetCookie, SameSite, ValueEncoding};

let header = SetCookie::new("SID", "deadbeef")
    .value_encoding(ValueEncoding::Percent)
    .http_only(true)
    .same_site(SameSite::Strict)
    .secure(true)
    .path("/")
    .max_age(3600)
    .to_string();
assert_eq!(header, "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600");
```

Attributes are emitted in a fixed order: `HttpOnly`, `SameSite`, `Secure`, `Path`, `Domain`, `Max-Age`, each only when set.

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

## License & Disclaimer

Copyright © 2026 Stefan Grönke.

Licensed under the MIT License — see [`LICENSE`](LICENSE).

This software is provided free of charge and **“as is,” without warranty of any kind**, as specified in the MIT License.
No support, maintenance, updates, or assurance of correctness, security, or fitness for a particular purpose is provided.

**Use at your own risk, subject to applicable law.**
