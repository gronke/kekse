//! # keksbruch
//!
//! kekse's adversarial test harness. Where kekse emits only honest, canonical cookie wire,
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
//!   strict ⊆ lenient, every drop and mutation witnessed) plus a per-scenario
//!   [`Expect`] with its pinned [`IssueKind`]s. It is pure Rust with no
//!   external dependencies, so it runs in CI as a regression oracle.
//! - **The differential matrix** (the `differential` feature, run by the
//!   dedicated matrix workflow, not the CI gate) feeds the same payloads to
//!   cookie parsers across languages and tabulates where they diverge — to see
//!   whether kekse is *standard*-compliant (matches the RFC) and
//!   *expectation*-compliant (matches what real parsers do).
//!
//! ## Anatomy
//!
//! A [`LogicalCookie`] is the honest cookie a scenario is about. A
//! [`KeksbruchRecipe`] pairs it with a [`Keksbruch`] and a [`Direction`]:
//! [`LogicalCookie::baseline`] renders the clean wire *through kekse*, while
//! [`KeksbruchRecipe::render`] hand-crafts the corrupted bytes directly (kekse
//! would refuse to emit them). [`payloads`] is the generator over the
//! corpus; [`scenarios`] is the curated, [`Expect`]-annotated subset.

#[cfg(feature = "differential")]
pub mod differential;
mod invariants;
mod probe;
mod recipe;
mod reference;
mod scenario;
mod taxonomy;

pub use invariants::{
    assert_baseline_parses_clean, assert_no_injection_echo, assert_no_injection_echo_bytes,
    assert_pair_conservation, assert_pair_conservation_bytes, assert_report_consistency,
    assert_report_consistency_bytes, assert_response_divergence_witnessed,
    assert_set_cookie_report_consistency, assert_strict_subset_of_lenient,
    assert_strict_subset_of_lenient_bytes, drive, drive_bytes,
};
pub use probe::{JarProbe, jar_probes};
pub use recipe::{KeksbruchRecipe, LogicalCookie};
pub use reference::probe_retrieval;
pub use scenario::{Expect, IssueKind, Scenario, scenarios};
pub use taxonomy::{Direction, Keksbruch};

/// The generator over the whole corpus — every `Keksbruch` recipe Layer A and
/// the differential matrix run: the [`scenarios`] recipes.
pub fn payloads() -> impl Iterator<Item = KeksbruchRecipe<'static>> {
    scenarios().into_iter().map(|scenario| scenario.recipe)
}
