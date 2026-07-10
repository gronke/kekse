# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `rfc_6265`: `date::ImfFixdate`, a lazy `Display` of the canonical IMF-fixdate that renders onto a stack buffer; `format_imf_fixdate` delegates to it.
- Criterion benchmarks for the codec hot paths (`benches/codec.rs`) and a deterministic allocation-count companion (`benches/allocs.rs`), both dev-only.
- `InvalidPath` / `InvalidDomain`: the typed refusals of `Path::new` / `Domain::new`, naming the failed gate and carrying the refused value, rendered control-byte-free.
- keksbruch: two universal invariants — conservation (every non-noise request segment yields an `Ok` pair or an issue) and divergence witness (a salvaged `Set-Cookie` covers every dropped attribute segment with an issue and is a render/re-parse fixpoint) — plus exact per-scenario `IssueKind` pins.
- `rfc_6265`: `has_secure_prefix` / `has_host_prefix` (and bytes twins) — `const` predicates for the RFC 6265bis §4.1.3 cookie-name prefixes, matched ASCII-case-insensitively the way user agents enforce them (the §4.1.3 server contract spells them case-sensitively).
- The CHIPS `Partitioned` attribute as a typed presence flag: a `CookieAttributes` field with a nullary builder, a parse arm that witnesses a valued flag, a render slot after `Secure`, and the `partitioned` field in keksbruch's sidecar schema.
- `CookieConstraint` / `SetCookieIssue::ConstraintViolation` / `SetCookie::constraint_violations`: the cross-field rules (`__Host-`/`__Secure-` prefix requirements, non-canonical prefix casing, `Partitioned` needs `Secure`) are witnessed in both gradings — the cookie is kept as written, never enforced against — and the same checker gates cookies you build.
- With the `axum` feature, `SetCookie` implements `IntoResponseParts` and `IntoResponse`: a handler returns `(set_cookie, body)` and the `Set-Cookie` header is appended (never inserted, so cookies accumulate); the one failable case — a `Raw` value carrying a header-illegal byte — is the typed `BadSetCookie` `500`, never a silent drop.
- keksbruch: the sidecar protocol carries an optional per-parser `issues` array (accepted-with-issues, shown as a display-only `⚠️` with the list in the tooltip, never affecting the consensus vote); the kekse columns surface every witnessed issue and the fail-hard rejections name the refused pieces.
- keksbruch: a generated **calibration** section grades kekse's dials against the answering columns on every matrix run — strict-clean must be majority-accepted, majority-accepted must be lenient-accepted — with twelve deliberate lenient deviations documented in an allowlist; a violation fails the run.
- keksbruch: the attribute-fidelity grid covers all seven non-date attributes with tri-state cells (kept / dropped / not observable), and the Go, python, and node drivers report `Partitioned` where their libraries model it.
- keksbruch: two dozen prefix/CHIPS scenario rows with exact issue pins — conformant and violating shapes, valued and case-variant flags, name-position probes — plus `IssueKind::Constraint`, a `partitioned` pin on `Expect::ResponseValue`, and a tri-state `partitioned` field in the sidecar schema (kept/dropped/not-observable).

### Fixed

- kekse: a `; =V` segment — an empty attribute name carrying a value — is witnessed as an unknown attribute instead of vanishing as structural noise (found by the generative property suite's conservation law).
- keksbruch: `PROPTEST_CASES` deepening actually works; the config literal had silently overridden the documented env var.
- keksbruch: the browser sidecar's per-record cleanup missed CHIPS-partitioned cookies (classic WebDriver's delete is partition-blind), so a stale `SID=abc` shadowed later browser cells — most visibly "accepting" wires the engines reject; every record now verifies the jar is empty and relaunches the engine on any survivor.

### Changed

- **Breaking:** every reader returns the observable form, and the lenient/strict choice dials only the grading — strict accepts a subset of what lenient accepts, and nothing is ever dropped silently.
  The `parse_pairs` family yields `Result` items, `CookieJar::parse` / `parse_strict` (and the bytes twins) return `Reported<CookieJar, PairIssue>`, and `SetCookie::parse` / `parse_strict` return the salvaged cookie plus its `SetCookieIssue`s with the unusable pair as the `PairIssue` error.
  The `try_` / `_reported` twins are gone — their behavior is the only behavior — and `Reported` is `#[must_use]`.
- **Breaking:** `Set-Cookie` fatality is grading-independent.
  Strict grading no longer rejects an unknown or duplicate attribute; like lenient it recovers (ignore per RFC 6265 §5.2, last-wins) and witnesses the deviation, and the gradings differ only in the `Expires` dialect (IMF-fixdate vs cookie-date).
  Enforcement is the `is_clean` gate; `SetCookieIssue::InvalidPair` is removed.
- **Breaking:** `Path::new` / `Domain::new` return `Result`, and the `path` / `domain` setters take the validated newtypes — a builder chain can no longer swallow an invalid value.
- **Breaking:** a wire carrying `Partitioned` parses into the typed flag instead of an `UnknownAttribute` witness, and `CookieAttributes` gained the public `partitioned` field (breaking for exhaustive struct literals).
- keksbruch: the divergence-witness fixpoint and baseline laws now expect a render to read back with exactly its standing constraint violations, and the response no-injection law is restated on the wire side — a percent-escape may decode a delimiter into the logical value (the encodings are lossless), but it can never re-reach a header unescaped.
- The axum `jar()` / `jar_strict()` views return the reported jar; `jar_reported` / `jar_strict_reported` are merged away, and `try_jar` / `try_jar_strict` keep the one-line 400 gate.

- The value decoder gates and escape-scans each value in one pass, so a clean value skips percent-decoding entirely; typical `Cookie:` headers parse 25-30% faster.
- Pairs, jars, and `Set-Cookie` values render into one pre-sized buffer: a full `Set-Cookie` makes a single heap request (previously thirteen), and `CookieJar::to_header_string` one (previously two per cookie plus the join).
- The axum extractor sizes its joined header buffer exactly instead of growing it per value.

## [0.1.0]

### Added

- First public release of the `kekse` cookie codec and the `rfc_6265` primitives crate.
- Strict and lenient `Cookie`-header parsing on the RFC 6265 §4.1.1 grammar: fail-soft, designed not to panic, refuses injection bytes in every mode.
- `SetCookie` builder and parser with typed attributes and `SameSite`, plus lossless managed value encodings (`Auto`, `Percent`, `Quoted`, `Raw`).
- `CookieJar` reads one `Cookie:` header in order and writes it back canonically; either direction converts into `http::HeaderValue`.
- `Expires`/`Max-Age` through the `time` crate: the tolerant RFC 6265 §5.1.1 cookie-date scan and the strict RFC 7231 IMF-fixdate.
- `rfc_6265`: reusable grammar byte classes, cookie-date parsing, and domain/path matching, with opt-in `idna`/`psl` features and LDH host-name validation.
- An optional axum extractor for the request `Cookie` header (`--features axum`).
- keksbruch (unpublished): the differential QA harness pinning kekse across 80+ scenarios and a 30+ parser cross-language matrix.
- No `unsafe`; three dependencies (`percent-encoding`, `http`, `time`); Rust 1.88+.

[Unreleased]: https://github.com/gronke/kekse/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gronke/kekse/releases/tag/v0.1.0
