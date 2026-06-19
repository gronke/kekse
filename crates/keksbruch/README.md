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

- **The differential matrix** (a later, opt-in layer behind a `differential` feature, never in CI) feeds the same payloads to cookie parsers in other languages (Python, Node) and the Rust `cookie`/`biscotti` crates, then tabulates where they diverge — to see whether kekse is *standard*-compliant (matches RFC 6265) and *expectation*-compliant (matches what real parsers actually do).

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

## License

MIT © 2026 Stefan Grönke — see [`LICENSE`](LICENSE).
