//! # keksbruch
//!
//! kekse's *chaos monkey*. Where kekse emits only honest, canonical cookie wire,
//! keksbruch exercises the hard cases — unbalanced quotes, spliced control bytes,
//! truncated escapes, smuggled `;`, garbage attributes, and the malformed shapes
//! seen in injection attempts — to verify how a cookie parser behaves on difficult
//! input, and to surface divergence and drift across implementations.
//!
//! ## Two layers
//!
//! - **Layer A** ([`scenarios`] + the `keksbruch_layer_a` test) pins kekse's own
//!   behaviour: every `Keksbruch` is fed through [`parse_pairs`](kekse::parse_pairs)
//!   / [`SetCookie::parse`](kekse::SetCookie::parse) and checked against the
//!   universal invariants (never panics, never echoes an injection byte,
//!   strict ⊆ lenient) plus a per-scenario [`Expect`]. It is pure Rust with no
//!   external dependencies, so it runs in CI as a regression oracle.
//! - **The differential matrix** (a later, opt-in layer) will feed the same
//!   payloads to cookie parsers in other languages and tabulate where they
//!   diverge — to see whether kekse is *standard*-compliant (matches the RFC)
//!   and *expectation*-compliant (matches what real parsers do).
//!
//! ## Anatomy
//!
//! A [`LogicalCookie`] is the honest cookie a scenario is about. A
//! [`KeksbruchRecipe`] pairs it with a [`Keksbruch`] and a [`Direction`]:
//! [`LogicalCookie::baseline`] renders the clean wire *through kekse*, while
//! [`KeksbruchRecipe::render`] hand-crafts the corrupted bytes directly (kekse
//! would refuse to emit them). [`payloads`] is the generator over the
//! corpus; [`scenarios`] is the curated, [`Expect`]-annotated subset.

mod invariants;
mod recipe;
mod scenario;
mod taxonomy;

pub use invariants::{assert_no_injection_echo, assert_strict_subset_of_lenient, drive};
pub use recipe::{KeksbruchRecipe, LogicalCookie};
pub use scenario::{scenarios, Expect, Scenario};
pub use taxonomy::{Direction, Keksbruch};

/// The generator over the whole corpus — every `Keksbruch` recipe Layer A and the
/// matrix run. Today it is the [`scenarios`] recipes; it gains breadth (more
/// bases per `Keksbruch`) when the differential matrix lands.
pub fn payloads() -> impl Iterator<Item = KeksbruchRecipe<'static>> {
    scenarios().into_iter().map(|scenario| scenario.recipe)
}
