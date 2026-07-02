# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-02

### Added

- First public release of the `kekse` cookie codec and the `rfc_6265` primitives crate.
- Strict and lenient `Cookie`-header parsing on the RFC 6265 §4.1.1 grammar: fail-soft, never panics, refuses injection bytes in every mode.
- `SetCookie` builder and parser with typed attributes and `SameSite`, plus lossless managed value encodings (`Auto`, `Percent`, `Quoted`, `Raw`).
- `CookieJar` reads one `Cookie:` header in order and writes it back canonically; either direction converts into `http::HeaderValue`.
- `Expires`/`Max-Age` through the `time` crate: the tolerant RFC 6265 §5.1.1 cookie-date scan and the strict RFC 7231 IMF-fixdate.
- `rfc_6265`: reusable grammar byte classes, cookie-date parsing, and domain/path matching, with opt-in `idna`/`psl` features and LDH host-name validation.
- An optional axum extractor for the request `Cookie` header (`--features axum`).
- keksbruch (unpublished): the differential QA harness pinning kekse across 80+ scenarios and a 40+ parser cross-language matrix.
- No `unsafe`; three dependencies (`percent-encoding`, `http`, `time`); Rust 1.88+.

[Unreleased]: https://github.com/gronke/kekse/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gronke/kekse/releases/tag/v0.2.0
