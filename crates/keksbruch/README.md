# keksbruch

kekse's *chaos monkey* — a differential test harness for cookie *wire*.
It runs a growing body of behavioural tests that surface divergence and drift across cookie implementations, so [`kekse`](../kekse) stays correct, compliant, and robust even on bad input.

Where kekse emits only honest, canonical cookies, keksbruch exercises the hard cases — unbalanced quotes, spliced control bytes, truncated percent-escapes, smuggled `;`, garbage `Set-Cookie` attributes, and the malformed shapes commonly seen in injection attempts, because that is exactly where implementations diverge most.
A `KeksbruchRecipe` renders the same logical cookie two ways: a clean `baseline()` *through kekse*, and a malformed `render()` built directly as bytes (kekse's encoders refuse to emit injection bytes, so keksbruch constructs that wire by hand) — then checks how each parser copes.

## Two layers

- **Layer A** (`tests/keksbruch_layer_a.rs`, runs in CI) pins kekse's own behaviour against the curated `scenarios()` corpus. Every `Keksbruch` is checked against the universal invariants — **never panics**, **never echoes an injection byte** (`;`/CR/LF/NUL), **strict ⊆ lenient** — plus a per-scenario `Expect`. Pure Rust, no external dependencies.

  ```
  cargo test -p keksbruch
  ```

- **The differential matrix** (opt-in, behind a `differential` feature, never in the gating CI) feeds the same payloads to cookie parsers across languages — Rust (`cookie`, `biscotti`, `axum-extra`), Python (stdlib `SimpleCookie`, Werkzeug), Node (`cookie`, `tough-cookie`), Go (`net/http`), .NET (`Microsoft.Net.Http.Headers`), PHP (native `$_COOKIE`), nginx (openresty — native `$cookie_<name>`, `lua-resty-cookie`, and `proxy` forwarding fidelity), and Java (Tomcat's `Rfc6265CookieProcessor` + `LegacyCookieProcessor`, and the `jakarta.ws.rs` cookie API via both RESTEasy and Jersey) — and tabulates where they diverge, to see whether kekse is *standard*-compliant (RFC 6265) and *expectation*-compliant (what real parsers do). It writes `COOKIE_MATRIX.md` (one row per tool, one column per test), `COOKIE_MATRIX.csv`, and a self-contained `COOKIE_MATRIX.html` report — every untrusted cell entity-encoded, so a corrupted cookie's markup renders as text and never as live HTML; a sidecar whose toolchain is absent degrades to `SKIP`.

  ```
  cargo test -p keksbruch --features differential -- --ignored --nocapture
  ```

  The **Differential matrix** GitHub Action runs this in a clean environment with every toolchain installed (so no column is `SKIP`), uploads the three files as build artifacts, and (on `main`) publishes them to **GitHub Pages** — the HTML report (`COOKIE_MATRIX.html`) is the readable view, the `.md`/`.csv` sit beside it as downloads. The deploy job reports the live URL. Each sidecar speaks a small base64-JSONL protocol — see [`fixtures/PROTOCOL.md`](fixtures/PROTOCOL.md) for the contract and how to add one.

## Why

kekse is, by design, the paranoid outlier: fail-soft (a malformed pair is skipped, never aborting the header), strict cookie-octet enforcement, case-sensitive names. The corpus makes those choices **visible and deliberate** — and a permanent regression oracle against accidental drift.

## What keksbruch is (and is not)

keksbruch is a **test and research harness** — a quality-assurance tool, not a production library and not a cookie parser.
Its job is to *verify* how parsers handle difficult input, so **do not depend on it at runtime**.
The library under test is [`kekse`](../kekse); depend on that instead.

## Known limitations

- keksbruch generates malformed and edge-case cookie wire (injection-style bytes, smuggled `;`, control characters, truncated escapes) purely as **test input**, to probe where parsers diverge. It is a measurement tool, not a certification.
- The differential matrix reports *observed divergence* between parsers — an insight and comparison aid, **not** a conformance certification of any parser, including kekse.
- The corpus is not claimed to be exhaustive; it grows with every test added, and passing Layer A does not prove a parser free of defects.

## Third-party fixtures

`fixtures/` vendors third-party parser source for the differential matrix (e.g. CloudFlare's BSD-licensed `lua-resty-cookie`) and drives others through their own build-time dependencies (Go, C, Node, PHP, Python, .NET, Java).
Vendored files remain under their respective upstream licenses; see [`NOTICE`](NOTICE) and each file's header.

## License

MIT © 2026 Stefan Grönke — see [`LICENSE`](LICENSE).
