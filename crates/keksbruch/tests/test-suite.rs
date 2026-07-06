//! The opt-in differential matrix. NOT run in CI — it spawns Python/Node sidecars
//! and needs the `differential` feature. Run it locally with:
//!
//! ```text
//! cargo test -p keksbruch --features differential -- --ignored --nocapture
//! ```
//!
//! It renders the `(Lang+Dependency) × Scenario` matrix to stdout and writes
//! three views beside the crate: `COOKIE_MATRIX.md` (scenario rows, with a
//! `payload` column), `COOKIE_MATRIX.csv` (transposed: one row per tool, one
//! column per test), and a self-contained `COOKIE_MATRIX.html` report (every
//! untrusted cell entity-encoded; the GitHub Pages view). Comparators whose
//! interpreter or dependency is missing degrade to `SKIP`, so a partial run
//! still produces a useful matrix.
#![cfg(feature = "differential")]

#[test]
#[ignore = "differential matrix: needs the `differential` feature + python/node; run with --ignored"]
fn render_parser_divergence_matrix() {
    let markdown = keksbruch::differential::run_matrix();
    // The template wired up: the title and every section heading rendered, and the
    // legend's typo fix landed (`unavailable`, once `unavailabfetle`).
    for anchor in [
        "parser divergence matrix",
        "## Legend",
        "## Request `Cookie:` parsers",
        "## Jar probes",
        "## Attribute fidelity",
        "## Tested scenarios",
        "## Remarks",
        "## Tested against",
        "unavailable",
        // The footer: a repo link + license remark at the bottom of both variants.
        "[gronke/kekse](https://github.com/gronke/kekse) · MIT licensed",
    ] {
        assert!(
            markdown.contains(anchor),
            "the matrix should render {anchor:?}"
        );
    }
    // No fragment marker leaked: every `{{ … }}` was substituted by Tera.
    assert!(
        !markdown.contains("{{"),
        "an unsubstituted template marker leaked into the output"
    );
}
