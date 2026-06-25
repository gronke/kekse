# rfc_6265

Reusable, exhaustively-tested primitives and algorithms from [RFC 6265] (HTTP State Management) and the grammar it borrows from RFC 7230 — the side-effect-free building blocks an HTTP cookie implementation needs, each defined once so the essential bits and bytes can't drift.

- `grammar` — §4.1.1 byte classes (cookie-octet, av-octet) and the RFC 7230 token for cookie-names. Always available, dependency-free, all `const fn`.
- `date` (feature) — §5.1.1 cookie-date parsing and the RFC 7231 IMF-fixdate, built on `time` (never hand-rolled).
- `domain` (feature) — §5.1.3 domain matching.
- `path` (feature) — §5.1.4 path matching and default-path.

It is deliberately *not* a cookie store (§5.3) nor a `Set-Cookie`/`Cookie` codec (§5.2/§5.4) — those belong to a higher layer (e.g. the [`kekse`](https://crates.io/crates/kekse) crate).

[RFC 6265]: https://www.rfc-editor.org/rfc/rfc6265

## License

Copyright © 2026 Stefan Grönke.

Licensed under the MIT License — see [`LICENSE`](LICENSE).
