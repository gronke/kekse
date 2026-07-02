# rfc_6265

Reusable, exhaustively-tested primitives and algorithms from [RFC 6265] (HTTP State Management) and the grammar it borrows from RFC 7230 — the side-effect-free building blocks an HTTP cookie implementation needs, each defined once so the essential bits and bytes can't drift.

- `grammar` — §4.1.1 byte classes (cookie-octet, av-octet) and the RFC 7230 token for cookie-names. Always available, dependency-free, all `const fn`.
- `date` (feature) — the tolerant RFC 6265 §5.1.1 cookie-date scan, the strict RFC 7231 IMF-fixdate, and formatters for each HTTP-date variant. Built on `time`; parsing is never hand-rolled.
- `domain` (feature) — §5.1.3 domain matching and §5.1.2 host canonicalization.
- `path` (feature) — §5.1.4 path matching and default-path.
- `idna` (feature) — §5.1.2 IDN ↔ punycode (UTS-46) canonicalization, via `idna` (implies `domain`).
- `psl` (feature) — §4.1.2.3 / §5.3 public-suffix (supercookie) checks, via `psl` (implies `domain`).

It is deliberately *not* a cookie store (§5.3) nor a `Set-Cookie`/`Cookie` codec (§5.2/§5.4) — those belong to a higher layer (e.g. the [`kekse`](https://crates.io/crates/kekse) crate).

[RFC 6265]: https://www.rfc-editor.org/rfc/rfc6265

## License & Disclaimer

Copyright © 2026 Stefan Grönke.

Licensed under the MIT License — see [`LICENSE`](LICENSE).

This software is provided free of charge and **“as is,” without warranty of any kind**, as specified in the MIT License.
No support, maintenance, updates, or assurance of correctness, security, or fitness for a particular purpose is provided.

**Use at your own risk, subject to applicable law.**

Security reports: see [`SECURITY.md`](../../SECURITY.md).
