//! Reusable primitives and algorithms from **RFC 6265** (HTTP State Management Mechanism) and the
//! grammar it borrows from **RFC 7230**.
//!
//! This crate collects the *side-effect-free* building blocks an RFC 6265 implementation needs,
//! each defined once and exhaustively tested, so the essential bits and bytes can't drift:
//!
//! - `grammar` — §4.1.1 byte classes (cookie-octet, av-octet) and the RFC 7230 token used for
//!   cookie-names. Always available, dependency-free, all `const fn`.
//! - `date` (feature `date`) — §5.1.1 cookie-date parsing and the RFC 7231 IMF-fixdate, built on
//!   the `time` crate. Date parsing is never hand-rolled.
//! - `domain` (feature `domain`) — §5.1.3 domain matching.
//! - `path` (feature `path`) — §5.1.4 path matching and default-path.
//! - `idna` (feature `idna`) — §5.1.2 IDN ↔ punycode canonicalization (implies `domain`).
//! - `psl` (feature `psl`) — §4.1.2.3 / §5.3 public-suffix (supercookie) checks (implies `domain`).
//!
//! It is deliberately *not* a cookie store (§5.3) nor a `Set-Cookie`/`Cookie` codec (§5.2/§5.4) —
//! those belong to a higher layer (e.g. the `kekse` crate).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod grammar;

#[cfg(feature = "date")]
pub mod date;
#[cfg(feature = "domain")]
pub mod domain;
#[cfg(feature = "path")]
pub mod path;

/// The timestamp type the [`date`] module parses into and formats, re-exported from the `time`
/// crate so callers can name it without depending on `time` directly.
#[cfg(feature = "date")]
pub use time::OffsetDateTime;
