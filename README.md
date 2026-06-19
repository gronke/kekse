# kekse

A pure-Rust toolkit for cookies — parsing, building, manipulation, and testing.

This repository is a Cargo workspace.

## Crates

[`kekse`](crates/kekse) is the library: a strict, dependency-light cookie codec.
It reads a `Cookie:` request header into a `CookieJar` of `Cookie`s, builds and parses `Set-Cookie:` response values through the `SetCookie` type, and converts one straight into an `http::HeaderValue` — directly on the RFC 6265 §4.1.1 grammar.
There is no cookie *store* (no persistence, eviction, or domain/path send-matching), no signing or encryption, and no date handling — a lifetime is `Max-Age` seconds, never an `Expires` date — so it pulls in neither `time` nor `chrono`.
It never panics on untrusted input, and a malformed pair in a header is skipped rather than aborting the parse, so attacker-appended junk can never evict a later valid cookie.
See its [README](crates/kekse/README.md) for the builder's encoding modes and the lenient and strict parsers.

`keksbruch` (planned) is the companion test-payload generator.
It takes kekse structures and re-emits them both in unusual-but-valid encodings and in malformed ones — unequal quotes, doubled quotes, injection bytes — so the codec can be challenged in both directions, when building and when parsing.

## Dependencies and support

The library depends only on `percent-encoding` (the value codec) and `http` (the RFC 7230 token grammar for cookie-names).
It targets Rust 1.77.2.

## License & Disclaimer

Copyright © 2026 Stefan Grönke.

Licensed under the MIT License — see [`LICENSE`](LICENSE).

This software is provided free of charge and **“as is,” without warranty of any kind**, as specified in the MIT License.
No support, maintenance, updates, or assurance of correctness, security, or fitness for a particular purpose is provided.

**Use at your own risk, subject to applicable law.**
