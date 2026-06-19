//! The opt-in differential matrix. NOT run in CI — it spawns Python/Node sidecars
//! and needs the `differential` feature. Run it locally with:
//!
//! ```text
//! cargo test -p keksbruch --features differential -- --ignored --nocapture
//! ```
//!
//! It renders the `(Lang+Dependency) × Scenario` matrix to stdout and writes
//! both `COOKIE_MATRIX.md` (scenario rows, with a `payload` column) and
//! `COOKIE_MATRIX.csv` (transposed: one row per tool, one column per test).
//! Comparators whose interpreter or dependency is missing degrade to `SKIP`, so
//! a partial run still produces a useful matrix.
#![cfg(feature = "differential")]

#[test]
#[ignore = "differential matrix: needs the `differential` feature + python/node; run with --ignored"]
fn render_parser_divergence_matrix() {
    let markdown = keksbruch::differential::run_matrix();
    assert!(
        markdown.contains("parser divergence matrix"),
        "the matrix should render its heading"
    );
}
