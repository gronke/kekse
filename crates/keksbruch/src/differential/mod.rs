//! The opt-in differential matrix (behind the `differential` feature, never run
//! in CI): feed every payload to cookie parsers across languages and tabulate
//! where they diverge — to see whether kekse is *standard* (RFC) and
//! *expectation* (real-world) compliant.

pub mod matrix;
pub mod result;
pub mod rust_comparators;
pub mod sidecar;
pub mod table;

use std::path::Path;

use crate::scenario::scenarios;
use matrix::Column;
use result::ParseOutcome;
use rust_comparators::rust_comparators;

/// Run the whole matrix: every scenario through the in-process Rust comparators
/// and the language sidecars; render it to Markdown, CSV, a self-contained HTML
/// report, and a machine-readable JSON document; print the Markdown; and write
/// `COOKIE_MATRIX.{md,csv,html,json}` next to the crate (the HTML report is the
/// GitHub Pages view; the JSON is the source of truth for later stats/probing).
/// Returns the Markdown.
pub fn run_matrix() -> String {
    let scenarios = scenarios();
    let mut columns: Vec<Column> = Vec::new();

    // In-process Rust comparators. A &str parser cannot see a non-UTF-8 wire, so
    // those payloads are n/a for the Rust side (the http layer rejects them).
    for comparator in rust_comparators() {
        let (lang, dep) = comparator.id();
        let cells = scenarios
            .iter()
            .map(|s| match s.recipe.render_str() {
                Some(wire) => comparator.run(&wire, s.direction),
                None => ParseOutcome::NotApplicable,
            })
            .collect();
        columns.push(Column {
            lang: lang.to_string(),
            dep: dep.to_string(),
            cells,
        });
    }

    // Language sidecars (graceful SKIP if an interpreter or dependency is absent).
    let (sidecar_cols, sidecar_versions) = sidecar::sidecar_columns(&scenarios);
    columns.extend(sidecar_cols);

    // Record exactly what was tested against: the Rust comparator versions from
    // the lockfile, plus the runtimes/deps each sidecar reported.
    let mut versions = vec![rust_versions()];
    versions.extend(sidecar_versions);

    let markdown = matrix::render(&scenarios, &columns, &versions);
    println!("{markdown}");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.md"), &markdown) {
        eprintln!("could not write COOKIE_MATRIX.md: {e}");
    }
    // The transposed CSV companion (tool rows × test columns) for analysis.
    let csv = matrix::render_csv(&scenarios, &columns);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.csv"), &csv) {
        eprintln!("could not write COOKIE_MATRIX.csv: {e}");
    }
    // The self-contained HTML report — the well-readable, publishable view (the
    // matrix's GitHub Pages page). Not printed; the Markdown is the stdout view.
    let html = matrix::render_html(&scenarios, &columns, &versions);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.html"), &html) {
        eprintln!("could not write COOKIE_MATRIX.html: {e}");
    }
    // The machine-readable JSON — scenario → target → full ParseOutcome, plus
    // per-scenario metadata (direction, wire, RFC verdict, consensus). The source
    // of truth for later statistics and proxy-probing.
    let json = matrix::render_json(&scenarios, &columns, &versions);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.json"), &json) {
        eprintln!("could not write COOKIE_MATRIX.json: {e}");
    }
    markdown
}

/// The Rust comparator versions, read from the committed workspace `Cargo.lock`
/// (the matrix only ever runs in-workspace, so the lockfile is always present).
fn rust_versions() -> String {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let text = std::fs::read_to_string(lock).unwrap_or_default();
    let v = |name: &str| lock_version(&text, name).unwrap_or_else(|| "?".to_string());
    format!(
        "Rust — kekse (this tree), cookie {}, biscotti {}, axum-extra {}",
        v("cookie"),
        v("biscotti"),
        v("axum-extra")
    )
}

/// Pull a package's version out of a `Cargo.lock`: the `version = "…"` line that
/// follows its `name = "<name>"` line.
fn lock_version(lock: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    let block = &lock[lock.find(&needle)?..];
    let line = block
        .lines()
        .find(|l| l.trim_start().starts_with("version = "))?;
    line.split('"').nth(1).map(str::to_string)
}
